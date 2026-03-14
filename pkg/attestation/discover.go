package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

var allowedCommandNames = map[string]struct{}{
	"cosign": {},
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	commandName := filepath.Base(strings.TrimSpace(name))
	if _, ok := allowedCommandNames[commandName]; !ok {
		return nil, nil, fmt.Errorf("disallowed command: %s", name)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type RegistryClient interface {
	ResolveImage(ctx context.Context, imageRef string) (ResolvedImage, error)
	ListReferrers(ctx context.Context, digestRef string) ([]Referrer, error)
	FetchArtifact(ctx context.Context, referrer Referrer) (Artifact, error)
}

type ResolvedImage struct {
	ImageRef     string
	CanonicalRef string
	ImageDigest  string
	DigestRef    string
}

type Referrer struct {
	Repository string
	Descriptor v1.Descriptor
}

type Artifact struct {
	Descriptor  v1.Descriptor
	Annotations map[string]string
	Manifest    *v1.Manifest
	Layers      []ArtifactLayer
}

type ArtifactLayer struct {
	Descriptor v1.Descriptor
	Data       []byte
}

type Discoverer struct {
	cfg      Config
	registry RegistryClient
	runner   CommandRunner
}

func NewDiscoverer(cfg Config) *Discoverer {
	return &Discoverer{
		cfg:      cfg,
		registry: newRemoteRegistry(),
		runner:   ExecCommandRunner{},
	}
}

func (d *Discoverer) Discover(ctx context.Context, imageRef string) (Result, error) {
	resolved, err := d.registry.ResolveImage(ctx, imageRef)
	if err != nil {
		return Result{}, fmt.Errorf("resolve image reference: %w", err)
	}

	referrers, err := d.registry.ListReferrers(ctx, resolved.DigestRef)
	if err != nil {
		return Result{}, fmt.Errorf("list referrers: %w", err)
	}

	signatures := make([]Record, 0)
	attestations := make([]Record, 0)
	var mu sync.Mutex

	group, groupCtx := errgroup.WithContext(ctx)
	for _, referrer := range referrers {
		referrer := referrer
		group.Go(func() error {
			artifact, err := d.registry.FetchArtifact(groupCtx, referrer)
			if err != nil {
				return fmt.Errorf("fetch artifact %s: %w", referrer.Descriptor.Digest.String(), err)
			}

			record := analyzeArtifact(referrer, artifact)
			mu.Lock()
			switch record.Kind {
			case KindSignature:
				signatures = append(signatures, record)
			case KindAttestation:
				attestations = append(attestations, record)
			}
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return Result{}, err
	}

	sortRecords(signatures)
	sortRecords(attestations)

	if len(signatures) > 0 {
		applyVerification(signatures, d.verify(ctx, false, resolved.CanonicalRef))
	}
	if len(attestations) > 0 {
		applyVerification(attestations, d.verify(ctx, true, resolved.CanonicalRef))
	}

	result := Result{
		ImageRef:     resolved.ImageRef,
		CanonicalRef: resolved.CanonicalRef,
		ImageDigest:  resolved.ImageDigest,
		Signatures:   signatures,
		Attestations: attestations,
		UpdatedAt:    time.Now().UTC(),
	}
	result.Summary = summarize(result)
	return result, nil
}

func analyzeArtifact(referrer Referrer, artifact Artifact) Record {
	record := Record{
		Digest:             referrer.Descriptor.Digest.String(),
		MediaType:          string(referrer.Descriptor.MediaType),
		ArtifactType:       firstNonEmpty(referrer.Descriptor.ArtifactType, inferredArtifactType(artifact.Manifest)),
		Source:             "oci-referrers",
		VerificationStatus: VerificationStatusUnverified,
		Annotations:        copyStringMap(artifact.Annotations),
	}
	if artifact.Manifest != nil && artifact.Manifest.Subject != nil {
		record.SubjectDigest = artifact.Manifest.Subject.Digest.String()
	}

	mergeAnnotationMetadata(&record, artifact.Annotations)
	for _, layer := range artifact.Layers {
		enrichRecordFromArtifact(&record, layer.Descriptor, layer.Data)
	}

	if record.Kind == "" {
		record.Kind = classifyArtifact(record)
	}
	if len(record.Annotations) == 0 {
		record.Annotations = nil
	}
	return record
}

func classifyArtifact(record Record) string {
	joined := strings.ToLower(strings.Join([]string{
		record.MediaType,
		record.ArtifactType,
		record.PredicateType,
		record.StatementType,
		record.DSSEPayloadType,
	}, " "))
	switch {
	case strings.Contains(joined, "simplesigning"), strings.Contains(joined, "signature"):
		return KindSignature
	case strings.Contains(joined, "dsse"), strings.Contains(joined, "in-toto"), strings.Contains(joined, "attestation"), strings.Contains(joined, "slsa"):
		return KindAttestation
	default:
		return KindAttestation
	}
}

type verificationOutcome struct {
	Status    string
	Message   string
	Signer    string
	Issuer    string
	Timestamp *time.Time
}

func (d *Discoverer) verify(ctx context.Context, attestations bool, imageRef string) verificationOutcome {
	verifyCtx := ctx
	cancel := func() {}
	if d.cfg.CosignTimeout > 0 {
		verifyCtx, cancel = context.WithTimeout(ctx, d.cfg.CosignTimeout)
	}
	defer cancel()

	args := []string{"verify", "--output", "json"}
	if attestations {
		args[0] = "verify-attestation"
	}
	if key := strings.TrimSpace(d.cfg.CosignPublicKey); key != "" {
		args = append(args, "--key", key)
	} else {
		args = append(args,
			"--certificate-identity-regexp", d.cfg.CertificateIdentityRegex,
			"--certificate-oidc-issuer-regexp", d.cfg.OIDCIssuerRegex,
		)
	}
	args = append(args, imageRef)

	stdout, stderr, err := d.runner.Run(verifyCtx, d.cfg.CosignBinary, args...)
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if message == "" {
			message = strings.TrimSpace(string(stdout))
		}
		if errors.Is(err, exec.ErrNotFound) {
			if message == "" {
				message = "cosign binary is not available"
			}
			return verificationOutcome{Status: VerificationStatusUnverified, Message: message}
		}
		if message == "" {
			message = err.Error()
		}
		return verificationOutcome{Status: VerificationStatusInvalid, Message: message}
	}

	outcome := verificationOutcome{Status: VerificationStatusValid}
	var entries []json.RawMessage
	if err := json.Unmarshal(stdout, &entries); err == nil {
		outcome.Signer, outcome.Issuer, outcome.Timestamp = extractVerificationMetadata(entries)
		return outcome
	}

	return outcome
}

func applyVerification(records []Record, outcome verificationOutcome) {
	for i := range records {
		records[i].VerificationStatus = outcome.Status
		records[i].VerificationMessage = outcome.Message
		if records[i].Signer == "" {
			records[i].Signer = outcome.Signer
		}
		if records[i].Issuer == "" {
			records[i].Issuer = outcome.Issuer
		}
		if records[i].Timestamp == nil {
			records[i].Timestamp = outcome.Timestamp
		}
	}
}

func summarize(result Result) Summary {
	summary := Summary{
		Total:                len(result.Signatures) + len(result.Attestations),
		Signatures:           len(result.Signatures),
		Attestations:         len(result.Attestations),
		ByVerificationStatus: map[string]int{},
	}

	for _, record := range append(append([]Record{}, result.Signatures...), result.Attestations...) {
		summary.ByVerificationStatus[record.VerificationStatus]++
		if record.Provenance != nil || isSLSAPredicate(record.PredicateType) {
			summary.Provenance++
		}
	}
	return summary
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].PredicateType != records[j].PredicateType {
			return records[i].PredicateType < records[j].PredicateType
		}
		if records[i].Digest != records[j].Digest {
			return records[i].Digest < records[j].Digest
		}
		return records[i].ArtifactType < records[j].ArtifactType
	})
}

func inferredArtifactType(manifest *v1.Manifest) string {
	if manifest == nil {
		return ""
	}
	value := strings.TrimSpace(string(manifest.Config.MediaType))
	switch value {
	case "", "application/vnd.oci.empty.v1+json", "application/vnd.unknown.config.v1+json":
		return ""
	default:
		return value
	}
}

func copyStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func extractVerificationMetadata(entries []json.RawMessage) (string, string, *time.Time) {
	var signer string
	var issuer string
	var ts *time.Time

	for _, entry := range entries {
		var decoded any
		if err := json.Unmarshal(entry, &decoded); err != nil {
			continue
		}
		walkJSON(decoded, func(path []string, value any) {
			if signer == "" && isSignerPath(path) {
				if text := stringValue(value); text != "" && !strings.Contains(strings.ToLower(text), "docker-reference") {
					signer = text
				}
			}
			if issuer == "" && isIssuerPath(path) {
				if text := stringValue(value); text != "" {
					issuer = text
				}
			}
			if ts == nil {
				if parsed := parseTimestampValue(strings.ToLower(strings.Join(path, ".")), value); parsed != nil {
					ts = parsed
				}
			}
		})
	}
	return signer, issuer, ts
}

func walkJSON(value any, visit func(path []string, value any)) {
	var walk func(path []string, value any)
	walk = func(path []string, value any) {
		visit(path, value)
		switch typed := value.(type) {
		case map[string]any:
			for key, item := range typed {
				walk(append(path, key), item)
			}
		case []any:
			for _, item := range typed {
				walk(path, item)
			}
		}
	}
	walk(nil, value)
}

func isSignerPath(path []string) bool {
	if len(path) == 0 {
		return false
	}
	key := strings.ToLower(path[len(path)-1])
	return key == "subject" || key == "email" || key == "uri"
}

func isIssuerPath(path []string) bool {
	if len(path) == 0 {
		return false
	}
	key := strings.ToLower(path[len(path)-1])
	return key == "issuer" || key == "issuername"
}

type remoteRegistry struct {
	options []remote.Option
}

func newRemoteRegistry() RegistryClient {
	return &remoteRegistry{
		options: []remote.Option{
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		},
	}
}

func (r *remoteRegistry) ResolveImage(ctx context.Context, imageRef string) (ResolvedImage, error) {
	ref, err := name.ParseReference(strings.TrimSpace(imageRef))
	if err != nil {
		return ResolvedImage{}, err
	}
	desc, err := remote.Get(ref, append(r.options, remote.WithContext(ctx))...)
	if err != nil {
		return ResolvedImage{}, err
	}

	canonical := ref.Context().Digest(desc.Digest.String()).String()
	return ResolvedImage{
		ImageRef:     imageRef,
		CanonicalRef: canonical,
		ImageDigest:  desc.Digest.String(),
		DigestRef:    canonical,
	}, nil
}

func (r *remoteRegistry) ListReferrers(ctx context.Context, digestRef string) ([]Referrer, error) {
	ref, err := name.NewDigest(digestRef, name.WeakValidation)
	if err != nil {
		return nil, err
	}

	index, err := remote.Referrers(ref, append(r.options, remote.WithContext(ctx))...)
	if err != nil {
		return nil, err
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}

	referrers := make([]Referrer, 0, len(manifest.Manifests))
	for _, descriptor := range manifest.Manifests {
		referrers = append(referrers, Referrer{
			Repository: ref.Context().Name(),
			Descriptor: descriptor,
		})
	}
	return referrers, nil
}

func (r *remoteRegistry) FetchArtifact(ctx context.Context, referrer Referrer) (Artifact, error) {
	ref, err := name.NewDigest(fmt.Sprintf("%s@%s", referrer.Repository, referrer.Descriptor.Digest.String()), name.WeakValidation)
	if err != nil {
		return Artifact{}, err
	}

	desc, err := remote.Get(ref, append(r.options, remote.WithContext(ctx))...)
	if err != nil {
		return Artifact{}, err
	}

	artifact := Artifact{
		Descriptor: desc.Descriptor,
	}

	var manifest v1.Manifest
	if err := json.Unmarshal(desc.Manifest, &manifest); err == nil {
		artifact.Manifest = &manifest
		artifact.Annotations = copyStringMap(manifest.Annotations)
	}

	image, err := desc.Image()
	if err != nil || artifact.Manifest == nil {
		return artifact, nil
	}

	layers := make([]ArtifactLayer, 0, len(artifact.Manifest.Layers))
	for _, layerDescriptor := range artifact.Manifest.Layers {
		layer, err := image.LayerByDigest(layerDescriptor.Digest)
		if err != nil {
			return Artifact{}, err
		}
		reader, err := layer.Compressed()
		if err != nil {
			return Artifact{}, err
		}
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			return Artifact{}, err
		}
		layers = append(layers, ArtifactLayer{
			Descriptor: layerDescriptor,
			Data:       data,
		})
	}
	artifact.Layers = layers
	return artifact, nil
}
