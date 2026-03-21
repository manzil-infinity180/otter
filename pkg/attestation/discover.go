package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	trimmedName := strings.TrimSpace(name)
	if strings.ContainsRune(trimmedName, filepath.Separator) || strings.ContainsRune(trimmedName, '\\') {
		return nil, nil, fmt.Errorf("disallowed command path: %s", name)
	}

	commandName := filepath.Base(trimmedName)
	if _, ok := allowedCommandNames[commandName]; !ok {
		return nil, nil, fmt.Errorf("disallowed command: %s", name)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, commandName, args...)
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

type discoveredRecord struct {
	record  Record
	matcher verificationMatcher
}

type verificationMatcher struct {
	fingerprints  map[string]struct{}
	subjectDigest string
	predicateType string
	signer        string
	issuer        string
	timestamp     *time.Time
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

	signatures := make([]discoveredRecord, 0)
	attestations := make([]discoveredRecord, 0)
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
			switch record.record.Kind {
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
		Signatures:   unwrapRecords(signatures),
		Attestations: unwrapRecords(attestations),
		UpdatedAt:    time.Now().UTC(),
	}
	result.Summary = summarize(result)
	return result, nil
}

func analyzeArtifact(referrer Referrer, artifact Artifact) discoveredRecord {
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
	return discoveredRecord{
		record:  record,
		matcher: buildVerificationMatcher(record, artifact),
	}
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

type verifiedEntry struct {
	matcher verificationMatcher
	outcome verificationOutcome
}

type verificationReport struct {
	Entries         []verifiedEntry
	DefaultOutcome  verificationOutcome
	StrictUnmatched bool
}

func (d *Discoverer) verify(ctx context.Context, attestations bool, imageRef string) verificationReport {
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
	entries, parseErr := parseVerificationEntries(stdout)
	report := verificationReport{
		Entries:        buildVerifiedEntries(entries),
		DefaultOutcome: verificationOutcome{Status: VerificationStatusInvalid},
	}
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if message == "" {
			message = strings.TrimSpace(string(stdout))
		}
		if errors.Is(err, exec.ErrNotFound) {
			if message == "" {
				message = "cosign binary is not available"
			}
			report.DefaultOutcome = verificationOutcome{Status: VerificationStatusUnverified, Message: message}
			return report
		}
		if message == "" {
			message = err.Error()
		}
		report.DefaultOutcome = verificationOutcome{Status: VerificationStatusInvalid, Message: message}
		report.StrictUnmatched = len(report.Entries) > 0
		return report
	}

	report.DefaultOutcome = verificationOutcome{
		Status:  VerificationStatusInvalid,
		Message: "record was discovered but was not returned by cosign verification",
	}
	report.StrictUnmatched = true
	if parseErr != nil {
		report.Entries = nil
		report.DefaultOutcome = verificationOutcome{
			Status:  VerificationStatusValid,
			Message: "",
		}
		report.StrictUnmatched = false
	}
	return report
}

func applyVerification(records []discoveredRecord, report verificationReport) {
	used := make([]bool, len(records))
	for _, entry := range report.Entries {
		index := matchVerificationRecord(records, used, entry)
		if index < 0 {
			continue
		}
		used[index] = true
		records[index].record.VerificationStatus = entry.outcome.Status
		records[index].record.VerificationMessage = entry.outcome.Message
		if records[index].record.Signer == "" {
			records[index].record.Signer = entry.outcome.Signer
		}
		if records[index].record.Issuer == "" {
			records[index].record.Issuer = entry.outcome.Issuer
		}
		if records[index].record.Timestamp == nil {
			records[index].record.Timestamp = entry.outcome.Timestamp
		}
	}
	for i := range records {
		if used[i] {
			continue
		}
		if !report.StrictUnmatched && len(report.Entries) > 0 {
			continue
		}
		records[i].record.VerificationStatus = report.DefaultOutcome.Status
		records[i].record.VerificationMessage = report.DefaultOutcome.Message
		if records[i].record.Signer == "" {
			records[i].record.Signer = report.DefaultOutcome.Signer
		}
		if records[i].record.Issuer == "" {
			records[i].record.Issuer = report.DefaultOutcome.Issuer
		}
		if records[i].record.Timestamp == nil {
			records[i].record.Timestamp = report.DefaultOutcome.Timestamp
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

func sortRecords(records []discoveredRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].record.PredicateType != records[j].record.PredicateType {
			return records[i].record.PredicateType < records[j].record.PredicateType
		}
		if records[i].record.Digest != records[j].record.Digest {
			return records[i].record.Digest < records[j].record.Digest
		}
		return records[i].record.ArtifactType < records[j].record.ArtifactType
	})
}

func unwrapRecords(records []discoveredRecord) []Record {
	result := make([]Record, 0, len(records))
	for _, record := range records {
		result = append(result, record.record)
	}
	return result
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

func buildVerificationMatcher(record Record, artifact Artifact) verificationMatcher {
	matcher := verificationMatcher{
		fingerprints:  make(map[string]struct{}),
		subjectDigest: strings.TrimSpace(record.SubjectDigest),
		predicateType: strings.TrimSpace(record.PredicateType),
		signer:        strings.TrimSpace(record.Signer),
		issuer:        strings.TrimSpace(record.Issuer),
		timestamp:     record.Timestamp,
	}

	for _, layer := range artifact.Layers {
		addFingerprint(&matcher, layer.Data)
		decoded := decodeDSSEPayload(layer.Data)
		addFingerprint(&matcher, decoded)
	}
	if len(matcher.fingerprints) == 0 {
		matcher.fingerprints = nil
	}
	return matcher
}

func parseVerificationEntries(stdout []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var array []json.RawMessage
	if err := json.Unmarshal(trimmed, &array); err == nil {
		return array, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	entries := make([]json.RawMessage, 0)
	for {
		var entry json.RawMessage
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		entry = bytes.TrimSpace(entry)
		if len(entry) == 0 || bytes.Equal(entry, []byte("null")) {
			continue
		}
		entries = append(entries, append(json.RawMessage(nil), entry...))
	}
	return entries, nil
}

func buildVerifiedEntries(entries []json.RawMessage) []verifiedEntry {
	result := make([]verifiedEntry, 0, len(entries))
	for _, entry := range entries {
		matcher := buildVerificationMatcherFromJSON(entry)
		outcome := verificationOutcome{
			Status:    VerificationStatusValid,
			Signer:    matcher.signer,
			Issuer:    matcher.issuer,
			Timestamp: matcher.timestamp,
		}
		result = append(result, verifiedEntry{
			matcher: matcher,
			outcome: outcome,
		})
	}
	return result
}

func buildVerificationMatcherFromJSON(document []byte) verificationMatcher {
	matcher := verificationMatcher{
		fingerprints: make(map[string]struct{}),
	}
	addFingerprint(&matcher, document)
	decoded := decodeDSSEPayload(document)
	addFingerprint(&matcher, decoded)

	var payload any
	if err := json.Unmarshal(document, &payload); err == nil {
		if typed, ok := payload.(map[string]any); ok {
			matcher.subjectDigest = strings.TrimSpace(firstNonEmpty(
				nestedString(typed, "critical", "image", "docker-manifest-digest"),
				nestedString(typed, "Critical", "Image", "Docker-manifest-digest"),
			))
			matcher.predicateType = strings.TrimSpace(firstNonEmpty(
				stringValue(typed["predicateType"]),
				stringValue(typed["PredicateType"]),
			))
		}
	}

	signer, issuer, timestamp := extractVerificationMetadata([]json.RawMessage{document})
	matcher.signer = signer
	matcher.issuer = issuer
	matcher.timestamp = timestamp
	if len(matcher.fingerprints) == 0 {
		matcher.fingerprints = nil
	}
	return matcher
}

func addFingerprint(matcher *verificationMatcher, document []byte) {
	if matcher == nil {
		return
	}
	sum, ok := canonicalJSONFingerprint(document)
	if !ok {
		return
	}
	if matcher.fingerprints == nil {
		matcher.fingerprints = make(map[string]struct{})
	}
	matcher.fingerprints[sum] = struct{}{}
}

func canonicalJSONFingerprint(document []byte) (string, bool) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return "", false
	}
	var decoded any
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return "", false
	}
	normalized, err := json.Marshal(decoded)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:]), true
}

func decodeDSSEPayload(document []byte) []byte {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return nil
	}
	var envelope dsseEnvelope
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil
	}
	if strings.TrimSpace(envelope.Payload) == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || !json.Valid(decoded) {
		return nil
	}
	return decoded
}

func matchVerificationRecord(records []discoveredRecord, used []bool, entry verifiedEntry) int {
	bestIndex := -1
	bestScore := 0
	for i, record := range records {
		if used[i] {
			continue
		}
		score := verificationMatchScore(record.matcher, entry.matcher)
		if score > bestScore {
			bestScore = score
			bestIndex = i
		}
	}
	return bestIndex
}

func verificationMatchScore(record verificationMatcher, entry verificationMatcher) int {
	score := 0
	matchedFingerprint := false
	for fingerprint := range entry.fingerprints {
		if _, ok := record.fingerprints[fingerprint]; ok {
			score += 100
			matchedFingerprint = true
		}
	}
	if !matchedFingerprint {
		return 0
	}
	if record.subjectDigest != "" && record.subjectDigest == entry.subjectDigest {
		score += 10
	}
	if record.predicateType != "" && record.predicateType == entry.predicateType {
		score += 10
	}
	if record.signer != "" && record.signer == entry.signer {
		score += 5
	}
	if record.issuer != "" && record.issuer == entry.issuer {
		score += 3
	}
	if timesEqual(record.timestamp, entry.timestamp) {
		score += 2
	}
	return score
}

func timesEqual(left *time.Time, right *time.Time) bool {
	if left == nil || right == nil {
		return false
	}
	return left.UTC().Truncate(time.Second).Equal(right.UTC().Truncate(time.Second))
}

func extractVerificationMetadata(entries []json.RawMessage) (string, string, *time.Time) {
	var signer string
	var issuer string
	var ts *time.Time
	bestSignerPriority := 0

	for _, entry := range entries {
		var decoded any
		if err := json.Unmarshal(entry, &decoded); err != nil {
			continue
		}
		walkJSON(decoded, func(path []string, value any) {
			if priority := signerPathPriority(path); priority > 0 {
				if text := stringValue(value); text != "" && !strings.Contains(strings.ToLower(text), "docker-reference") && priority > bestSignerPriority {
					signer = text
					bestSignerPriority = priority
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
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				item := typed[key]
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
	return signerPathPriority(path) > 0
}

func signerPathPriority(path []string) int {
	if len(path) == 0 {
		return 0
	}
	key := strings.ToLower(path[len(path)-1])
	switch key {
	case "email":
		return 3
	case "subject":
		return 2
	case "uri":
		return 1
	default:
		return 0
	}
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
