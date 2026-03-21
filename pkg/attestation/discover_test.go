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

type runnerResponse struct {
	stdout []byte
	stderr []byte
	err    error
}

type sequenceRunner struct {
	responses []runnerResponse
	calls     int
}

func (s *sequenceRunner) Run(context.Context, string, ...string) ([]byte, []byte, error) {
	if s.calls >= len(s.responses) {
		return nil, nil, errors.New("unexpected verification call")
	}
	response := s.responses[s.calls]
	s.calls++
	return response.stdout, response.stderr, response.err
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

	signaturePayload := []byte(`{
  "critical": {
    "identity": {"docker-reference": "ghcr.io/example/demo"},
    "image": {"docker-manifest-digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
    "type": "cosign container image signature"
  }
}`)
	attestationEnvelope := []byte(`{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YwLjIiLCJzdWJqZWN0IjpbeyJuYW1lIjoiZ2hjci5pby9leGFtcGxlL2RlbW8iLCJkaWdlc3QiOnsic2hhMjU2IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSJ9fV0sInByZWRpY2F0ZSI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly9naXRodWIuY29tL2V4YW1wbGUvYnVpbGRlciJ9LCJidWlsZFR5cGUiOiJodHRwczovL2dpdGh1Yi5jb20vQXR0ZXN0YXRpb25zR0gvYnVpbGRAMzEiLCJtYXRlcmlhbHMiOlt7InVyaSI6ImdpdCtodHRwczovL2dpdGh1Yi5jb20vZXhhbXBsZS9yZXBvIiwiZGlnZXN0Ijp7InNoYTEiOiJhYmNkZWYifX1dfX0=",
  "signatures": [{"keyid": "", "sig": "abc"}]
}`)
	runner := &sequenceRunner{
		responses: []runnerResponse{
			{stdout: append([]byte("["), append(signaturePayload, ']')...)},
			{stdout: append([]byte("["), append(attestationEnvelope, ']')...)},
		},
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

func TestDiscoverAssignsVerificationPerRecord(t *testing.T) {
	t.Parallel()

	signatureOne := []byte(`{
  "critical": {
    "identity": {"docker-reference": "ghcr.io/example/demo"},
    "image": {"docker-manifest-digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
    "type": "cosign container image signature"
  },
  "optional": {"timestamp": "2026-03-14T00:00:00Z"}
}`)
	signatureTwo := []byte(`{
  "critical": {
    "identity": {"docker-reference": "ghcr.io/example/demo"},
    "image": {"docker-manifest-digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
    "type": "cosign container image signature"
  },
  "optional": {"timestamp": "2026-03-15T00:00:00Z"}
}`)
	attestationOne := []byte(`{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YxIiwic3ViamVjdCI6W3sibmFtZSI6ImdoY3IuaW8vZXhhbXBsZS9kZW1vIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEifX1dLCJwcmVkaWNhdGUiOnsiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9leGFtcGxlL2J1aWxkZXIifX19",
  "signatures": [{"sig": "abc"}]
}`)
	attestationTwo := []byte(`{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9wcmVkaWNhdGUvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiZ2hjci5pby9leGFtcGxlL2RlbW8iLCJkaWdlc3QiOnsic2hhMjU2IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSJ9fV19",
  "signatures": [{"sig": "def"}]
}`)

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
					ArtifactType: cosignSimpleSigningMediaType,
				},
			},
			{
				Repository: "ghcr.io/example/demo",
				Descriptor: v1.Descriptor{
					Digest:       mustHash(t, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
					MediaType:    types.OCIManifestSchema1,
					ArtifactType: dsseEnvelopeMediaType,
				},
			},
			{
				Repository: "ghcr.io/example/demo",
				Descriptor: v1.Descriptor{
					Digest:       mustHash(t, "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
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
				Layers: []ArtifactLayer{{Descriptor: v1.Descriptor{MediaType: cosignSimpleSigningMediaType}, Data: signatureOne}},
			},
			"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {
				Manifest: &v1.Manifest{
					Subject: &v1.Descriptor{Digest: mustHash(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111")},
				},
				Layers: []ArtifactLayer{{Descriptor: v1.Descriptor{MediaType: cosignSimpleSigningMediaType}, Data: signatureTwo}},
			},
			"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc": {
				Manifest: &v1.Manifest{
					Subject: &v1.Descriptor{Digest: mustHash(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111")},
				},
				Layers: []ArtifactLayer{{Descriptor: v1.Descriptor{MediaType: dsseEnvelopeMediaType}, Data: attestationOne}},
			},
			"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd": {
				Manifest: &v1.Manifest{
					Subject: &v1.Descriptor{Digest: mustHash(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111")},
				},
				Layers: []ArtifactLayer{{Descriptor: v1.Descriptor{MediaType: dsseEnvelopeMediaType}, Data: attestationTwo}},
			},
		},
	}

	discoverer := &Discoverer{
		cfg: Config{
			CosignBinary:             "cosign",
			CertificateIdentityRegex: ".*",
			OIDCIssuerRegex:          ".*",
		},
		registry: registry,
		runner: &sequenceRunner{
			responses: []runnerResponse{
				{stdout: append([]byte("["), append(signatureOne, ']')...)},
				{stdout: append([]byte("["), append(attestationOne, ']')...)},
			},
		},
	}

	result, err := discoverer.Discover(context.Background(), "ghcr.io/example/demo:1.0")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if got, want := result.Signatures[0].VerificationStatus, VerificationStatusValid; got != want {
		t.Fatalf("Signatures[0].VerificationStatus = %q, want %q", got, want)
	}
	if got, want := result.Signatures[1].VerificationStatus, VerificationStatusInvalid; got != want {
		t.Fatalf("Signatures[1].VerificationStatus = %q, want %q", got, want)
	}
	if result.Signatures[1].VerificationMessage == "" {
		t.Fatal("expected invalid signature to include a verification message")
	}
	attestationStatus := map[string]string{}
	for _, record := range result.Attestations {
		attestationStatus[record.PredicateType] = record.VerificationStatus
	}
	if got, want := attestationStatus["https://slsa.dev/provenance/v1"], VerificationStatusValid; got != want {
		t.Fatalf("attestation status for SLSA predicate = %q, want %q", got, want)
	}
	if got, want := attestationStatus["https://example.com/predicate/v1"], VerificationStatusInvalid; got != want {
		t.Fatalf("attestation status for example predicate = %q, want %q", got, want)
	}
	if got, want := result.Summary.ByVerificationStatus[VerificationStatusValid], 2; got != want {
		t.Fatalf("Summary.ByVerificationStatus[valid] = %d, want %d", got, want)
	}
	if got, want := result.Summary.ByVerificationStatus[VerificationStatusInvalid], 2; got != want {
		t.Fatalf("Summary.ByVerificationStatus[invalid] = %d, want %d", got, want)
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

func TestExecCommandRunnerRejectsCommandPath(t *testing.T) {
	t.Parallel()

	_, _, err := (ExecCommandRunner{}).Run(context.Background(), "/tmp/cosign", "version")
	if err == nil {
		t.Fatal("expected disallowed command path error")
	}
	if got, want := err.Error(), "disallowed command path: /tmp/cosign"; got != want {
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
