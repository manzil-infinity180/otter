package attestation

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type stubRegistry struct {
	resolved  ResolvedImage
	referrers []Referrer
	artifacts map[string]Artifact
	err       error
}

func (s stubRegistry) ResolveImage(context.Context, string) (ResolvedImage, error) {
	if s.err != nil {
		return ResolvedImage{}, s.err
	}
	return s.resolved, nil
}

func (s stubRegistry) ListReferrers(context.Context, string) ([]Referrer, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.referrers, nil
}

func (s stubRegistry) FetchArtifact(_ context.Context, referrer Referrer) (Artifact, error) {
	if s.err != nil {
		return Artifact{}, s.err
	}
	artifact, ok := s.artifacts[referrer.Descriptor.Digest.String()]
	if !ok {
		return Artifact{}, errors.New("artifact not found")
	}
	return artifact, nil
}

type stubRunner struct {
	stdout []byte
	stderr []byte
	err    error
}

func (s stubRunner) Run(context.Context, string, ...string) ([]byte, []byte, error) {
	return s.stdout, s.stderr, s.err
}

func TestDiscoverBuildsSignatureAndProvenanceRecords(t *testing.T) {
	t.Parallel()

	registry := stubRegistry{
		resolved: ResolvedImage{
			ImageRef:     "ghcr.io/example/demo:1.0",
			CanonicalRef: "ghcr.io/example/demo@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			ImageDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DigestRef:    "ghcr.io/example/demo@sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		referrers: []Referrer{
			{
				Repository: "ghcr.io/example/demo",
				Descriptor: v1.Descriptor{
					Digest:       mustHash(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
					MediaType:    types.OCIManifestSchema1,
					ArtifactType: cosignSimpleSigningMediaType,
				},
			},
			{
				Repository: "ghcr.io/example/demo",
				Descriptor: v1.Descriptor{
					Digest:       mustHash(t, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
					MediaType:    types.OCIManifestSchema1,
					ArtifactType: dsseEnvelopeMediaType,
				},
			},
		},
		artifacts: map[string]Artifact{
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
				Manifest: &v1.Manifest{
					Subject: &v1.Descriptor{Digest: mustHash(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111")},
				},
				Layers: []ArtifactLayer{
					{
						Descriptor: v1.Descriptor{MediaType: cosignSimpleSigningMediaType},
						Data: []byte(`{
  "critical": {
    "identity": {"docker-reference": "ghcr.io/example/demo"},
    "image": {"docker-manifest-digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
    "type": "cosign container image signature"
  }
}`),
					},
				},
			},
			"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
				Manifest: &v1.Manifest{
					Subject: &v1.Descriptor{Digest: mustHash(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111")},
				},
				Layers: []ArtifactLayer{
					{
						Descriptor: v1.Descriptor{MediaType: dsseEnvelopeMediaType},
						Data: []byte(`{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YwLjIiLCJzdWJqZWN0IjpbeyJuYW1lIjoiZ2hjci5pby9leGFtcGxlL2RlbW8iLCJkaWdlc3QiOnsic2hhMjU2IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSJ9fV0sInByZWRpY2F0ZSI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly9naXRodWIuY29tL2V4YW1wbGUvYnVpbGRlciJ9LCJidWlsZFR5cGUiOiJodHRwczovL2dpdGh1Yi5jb20vQXR0ZXN0YXRpb25zR0gvYnVpbGRAYzEiLCJtYXRlcmlhbHMiOlt7InVyaSI6ImdpdCtodHRwczovL2dpdGh1Yi5jb20vZXhhbXBsZS9yZXBvIiwgImRpZ2VzdCI6IHsic2hhMSI6ICJhYmNkZWYifX1dfX0=",
  "signatures": [{"keyid": "", "sig": "abc"}]
}`),
					},
				},
			},
		},
	}

	runner := stubRunner{
		stdout: []byte(`[{"subject":"signer@example.com","issuer":"https://token.actions.githubusercontent.com","integratedTime":1710000000}]`),
	}

	discoverer := &Discoverer{
		cfg: Config{
			CosignBinary:             "cosign",
			CertificateIdentityRegex: ".*",
			OIDCIssuerRegex:          ".*",
			CosignTimeout:            time.Minute,
		},
		registry: registry,
		runner:   runner,
	}

	result, err := discoverer.Discover(context.Background(), "ghcr.io/example/demo:1.0")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if got, want := result.Summary.Signatures, 1; got != want {
		t.Fatalf("Summary.Signatures = %d, want %d", got, want)
	}
	if got, want := result.Summary.Attestations, 1; got != want {
		t.Fatalf("Summary.Attestations = %d, want %d", got, want)
	}
	if got, want := result.Signatures[0].VerificationStatus, VerificationStatusValid; got != want {
		t.Fatalf("Signatures[0].VerificationStatus = %q, want %q", got, want)
	}
	if got, want := result.Signatures[0].Signer, "signer@example.com"; got != want {
		t.Fatalf("Signatures[0].Signer = %q, want %q", got, want)
	}
	if got, want := result.Attestations[0].PredicateType, "https://slsa.dev/provenance/v0.2"; got != want {
		t.Fatalf("Attestations[0].PredicateType = %q, want %q", got, want)
	}
	if result.Attestations[0].Provenance == nil {
		t.Fatal("expected provenance summary")
	}
	if got, want := result.Attestations[0].Provenance.BuilderID, "https://github.com/example/builder"; got != want {
		t.Fatalf("Provenance.BuilderID = %q, want %q", got, want)
	}
}

func TestDiscoverMarksArtifactsUnverifiedWithoutCosign(t *testing.T) {
	t.Parallel()

	discoverer := &Discoverer{
		cfg: Config{
			CosignBinary:             "cosign",
			CertificateIdentityRegex: ".*",
			OIDCIssuerRegex:          ".*",
		},
		registry: stubRegistry{
			resolved: ResolvedImage{
				ImageRef:     "alpine:latest",
				CanonicalRef: "index.docker.io/library/alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111",
				ImageDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				DigestRef:    "index.docker.io/library/alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			},
			referrers: []Referrer{
				{
					Repository: "index.docker.io/library/alpine",
					Descriptor: v1.Descriptor{
						Digest:       mustHash(t, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
						MediaType:    types.OCIManifestSchema1,
						ArtifactType: cosignSimpleSigningMediaType,
					},
				},
			},
			artifacts: map[string]Artifact{
				"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc": {
					Layers: []ArtifactLayer{
						{
							Descriptor: v1.Descriptor{MediaType: cosignSimpleSigningMediaType},
							Data:       []byte(`{"critical":{"image":{"docker-manifest-digest":"sha256:111"}}}`),
						},
					},
				},
			},
		},
		runner: stubRunner{err: exec.ErrNotFound},
	}

	result, err := discoverer.Discover(context.Background(), "alpine:latest")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got, want := result.Signatures[0].VerificationStatus, VerificationStatusUnverified; got != want {
		t.Fatalf("VerificationStatus = %q, want %q", got, want)
	}
}

func TestExecCommandRunnerRejectsDisallowedCommand(t *testing.T) {
	t.Parallel()

	_, _, err := (ExecCommandRunner{}).Run(context.Background(), "sh", "-c", "echo test")
	if err == nil {
		t.Fatal("expected disallowed command error")
	}
	if got, want := err.Error(), "disallowed command: sh"; got != want {
		t.Fatalf("Run() error = %q, want %q", got, want)
	}
}

func mustHash(t *testing.T, value string) v1.Hash {
	t.Helper()

	hash, err := v1.NewHash(value)
	if err != nil {
		t.Fatalf("NewHash(%q) error = %v", value, err)
	}
	return hash
}
