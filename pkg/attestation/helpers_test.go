package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os/exec"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestEnrichRecordFromArtifactParsesSimpleSigningAndDSSEPayloads(t *testing.T) {
	t.Parallel()

	signature := Record{}
	enrichRecordFromArtifact(&signature, v1.Descriptor{
		MediaType: types.MediaType(cosignSimpleSigningMediaType),
	}, []byte(`{
		"critical": {
			"image": {"docker-manifest-digest": "sha256:1234"}
		},
		"optional": {"timestamp": "2026-03-14T00:00:00Z"}
	}`))
	if got, want := signature.Kind, KindSignature; got != want {
		t.Fatalf("signature.Kind = %q, want %q", got, want)
	}
	if got, want := signature.SubjectDigest, "sha256:1234"; got != want {
		t.Fatalf("signature.SubjectDigest = %q, want %q", got, want)
	}
	if signature.Timestamp == nil {
		t.Fatal("expected signature timestamp")
	}

	statement := `{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name":"ghcr.io/demo/app","digest":{"sha256":"abcd"}}],
		"predicate": {
			"builder": {"id":"https://github.com/demo/builder"},
			"buildType": "https://github.com/AttestationsGH/buildkit@v1",
			"invocation": {"id":"run-123"},
			"materials": [{"uri":"git+https://github.com/demo/repo","digest":{"sha1":"deadbeef"}}]
		}
	}`
	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString([]byte(statement)),
		"signatures":  []map[string]string{{"sig": "abc"}},
	}
	document, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	attestationRecord := Record{}
	enrichRecordFromArtifact(&attestationRecord, v1.Descriptor{
		MediaType: types.MediaType(dsseEnvelopeMediaType),
	}, document)
	if got, want := attestationRecord.Kind, KindAttestation; got != want {
		t.Fatalf("attestationRecord.Kind = %q, want %q", got, want)
	}
	if attestationRecord.Envelope == nil || attestationRecord.Envelope.Signatures != 1 {
		t.Fatalf("Envelope = %#v", attestationRecord.Envelope)
	}
	if attestationRecord.Provenance == nil || attestationRecord.Provenance.BuilderID == "" {
		t.Fatalf("Provenance = %#v", attestationRecord.Provenance)
	}
	if len(attestationRecord.Subjects) != 1 {
		t.Fatalf("Subjects = %#v", attestationRecord.Subjects)
	}
}

func TestAttestationUtilityHelpers(t *testing.T) {
	t.Parallel()

	ts := parseTimestampValue("integratedtime", float64(1710000000))
	if ts == nil {
		t.Fatal("expected parseTimestampValue() to return a timestamp")
	}
	if !looksLikeJSONMediaType("application/vnd.in-toto+json") {
		t.Fatal("expected looksLikeJSONMediaType() to detect +json media type")
	}
	if !isSimpleSigningPayload("", map[string]any{"critical": map[string]any{"image": map[string]any{"docker-manifest-digest": "sha256:1234"}}}) {
		t.Fatal("expected isSimpleSigningPayload() to detect a simple-signing payload")
	}
	if !isDSSEPayload("", map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": "abc"}) {
		t.Fatal("expected isDSSEPayload() to detect a DSSE payload")
	}
	if !isInTotoStatement("", map[string]any{"predicateType": "https://slsa.dev/provenance/v1"}) {
		t.Fatal("expected isInTotoStatement() to detect a statement payload")
	}
	if !isSLSAPredicate("https://slsa.dev/provenance/v1") {
		t.Fatal("expected isSLSAPredicate() to match SLSA predicate")
	}
	if got, want := stringValue(json.Number("42")), "42"; got != want {
		t.Fatalf("stringValue(json.Number) = %q, want %q", got, want)
	}
	if got, want := nestedString(map[string]any{"a": map[string]any{"b": "value"}}, "a", "b"), "value"; got != want {
		t.Fatalf("nestedString() = %q, want %q", got, want)
	}
	if got := stringMap(map[string]any{"sha256": "abcd", "empty": ""}); len(got) != 1 || got["sha256"] != "abcd" {
		t.Fatalf("stringMap() = %#v", got)
	}
	if got, want := firstNonEmpty("", " value "), "value"; got != want {
		t.Fatalf("firstNonEmpty() = %q, want %q", got, want)
	}
	if got := firstNonNilTime(nil, ts); got == nil || !got.Equal(*ts) {
		t.Fatalf("firstNonNilTime() = %#v, want %v", got, ts)
	}
}

func TestDiscovererVerificationAndClassificationHelpers(t *testing.T) {
	t.Parallel()

	discoverer := &Discoverer{
		cfg: Config{
			CosignBinary:             "cosign",
			CosignPublicKey:          "/tmp/cosign.pub",
			CertificateIdentityRegex: ".*",
			OIDCIssuerRegex:          ".*",
		},
		runner: stubRunner{
			stderr: []byte("verification failed"),
			err:    errors.New("exit status 1"),
		},
	}

	outcome := discoverer.verify(context.Background(), true, "ghcr.io/demo/app@sha256:1234")
	if got, want := outcome.Status, VerificationStatusInvalid; got != want {
		t.Fatalf("verify() status = %q, want %q", got, want)
	}
	if got, want := outcome.Message, "verification failed"; got != want {
		t.Fatalf("verify() message = %q, want %q", got, want)
	}

	unverified := (&Discoverer{
		cfg:    Config{CosignBinary: "cosign"},
		runner: stubRunner{err: exec.ErrNotFound},
	}).verify(context.Background(), false, "ghcr.io/demo/app@sha256:1234")
	if got, want := unverified.Status, VerificationStatusUnverified; got != want {
		t.Fatalf("verify() missing cosign status = %q, want %q", got, want)
	}

	records := []Record{{Kind: KindSignature}, {Kind: KindAttestation, Signer: "existing"}}
	now := time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC)
	applyVerification(records, verificationOutcome{
		Status:    VerificationStatusValid,
		Signer:    "signer@example.com",
		Issuer:    "issuer",
		Timestamp: &now,
	})
	if records[0].Signer != "signer@example.com" || records[1].Signer != "existing" {
		t.Fatalf("applyVerification() = %#v", records)
	}

	result := Result{
		Signatures: []Record{{VerificationStatus: VerificationStatusValid}},
		Attestations: []Record{{
			VerificationStatus: VerificationStatusUnverified,
			PredicateType:      "https://slsa.dev/provenance/v1",
		}},
	}
	summary := summarize(result)
	if summary.Total != 2 || summary.Provenance != 1 || summary.ByVerificationStatus[VerificationStatusValid] != 1 {
		t.Fatalf("summarize() = %#v", summary)
	}

	record := analyzeArtifact(Referrer{
		Descriptor: v1.Descriptor{
			Digest:       mustHash(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			MediaType:    types.OCIManifestSchema1,
			ArtifactType: dsseEnvelopeMediaType,
		},
	}, Artifact{
		Manifest: &v1.Manifest{
			Config:  v1.Descriptor{MediaType: types.MediaType("application/vnd.example.config.v1+json")},
			Subject: &v1.Descriptor{Digest: mustHash(t, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
		},
	})
	if got, want := record.Kind, KindAttestation; got != want {
		t.Fatalf("analyzeArtifact() kind = %q, want %q", got, want)
	}
	if got, want := classifyArtifact(Record{ArtifactType: "signature"}), KindSignature; got != want {
		t.Fatalf("classifyArtifact() = %q, want %q", got, want)
	}
	if got, want := inferredArtifactType(&v1.Manifest{Config: v1.Descriptor{MediaType: types.MediaType("application/vnd.example.config.v1+json")}}), "application/vnd.example.config.v1+json"; got != want {
		t.Fatalf("inferredArtifactType() = %q, want %q", got, want)
	}
}

func TestExtractVerificationMetadataFindsSignerIssuerAndTimestamp(t *testing.T) {
	t.Parallel()

	ts, _ := time.Parse(time.RFC3339, "2026-03-14T00:00:00Z")
	entries := []json.RawMessage{
		json.RawMessage(`{
			"subject":"docker-reference ignored",
			"issuer":"https://issuer.example.com"
		}`),
		json.RawMessage(`{
			"email":"signer@example.com",
			"integratedTime":1710374400,
			"nested":{"uri":"https://signer.example.com"}
		}`),
	}

	signer, issuer, got := extractVerificationMetadata(entries)
	if signer != "signer@example.com" {
		t.Fatalf("signer = %q, want signer@example.com", signer)
	}
	if issuer != "https://issuer.example.com" {
		t.Fatalf("issuer = %q, want https://issuer.example.com", issuer)
	}
	if got == nil || got.Equal(ts) == false && got.Unix() != 1710374400 {
		t.Fatalf("timestamp = %#v", got)
	}
}

func TestDiscovererConstructorAndRegistryFailurePaths(t *testing.T) {
	t.Parallel()

	discoverer := NewDiscoverer(Config{})
	if discoverer == nil || discoverer.registry == nil || discoverer.runner == nil {
		t.Fatalf("NewDiscoverer() = %#v", discoverer)
	}

	for _, tt := range []struct {
		name     string
		registry stubRegistry
	}{
		{name: "resolve", registry: stubRegistry{err: errors.New("resolve failed")}},
		{name: "list", registry: stubRegistry{resolved: ResolvedImage{ImageRef: "alpine:latest", CanonicalRef: "alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111", ImageDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", DigestRef: "alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111"}, err: errors.New("list failed")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := (&Discoverer{cfg: Config{}, registry: tt.registry, runner: stubRunner{}}).Discover(context.Background(), "alpine:latest")
			if err == nil {
				t.Fatalf("Discover() should fail for %s errors", tt.name)
			}
		})
	}
}

func TestDiscoveryHelperUtilities(t *testing.T) {
	t.Parallel()

	visited := make([]string, 0)
	walkJSON(map[string]any{
		"issuer": "https://issuer.example.com",
		"nested": map[string]any{"subject": "signer@example.com"},
	}, func(path []string, value any) {
		if text := stringValue(value); text != "" {
			visited = append(visited, text)
		}
	})
	if len(visited) < 2 {
		t.Fatalf("walkJSON() visited = %#v", visited)
	}
	if !isSignerPath([]string{"nested", "subject"}) {
		t.Fatal("expected isSignerPath() to detect subject fields")
	}
	if !isIssuerPath([]string{"issuer"}) {
		t.Fatal("expected isIssuerPath() to detect issuer fields")
	}
	if got := copyStringMap(map[string]string{"a": "b"}); got["a"] != "b" {
		t.Fatalf("copyStringMap() = %#v", got)
	}
	if got := copyStringMap(nil); got != nil {
		t.Fatalf("copyStringMap(nil) = %#v, want nil", got)
	}

	remote := newRemoteRegistry()
	if remote == nil {
		t.Fatal("expected newRemoteRegistry() to return a client")
	}

	if _, err := (&remoteRegistry{}).ResolveImage(context.Background(), "not a ref"); err == nil {
		t.Fatal("expected ResolveImage() to reject invalid references")
	}
	if _, err := (&remoteRegistry{}).ListReferrers(context.Background(), "not-a-digest"); err == nil {
		t.Fatal("expected ListReferrers() to reject invalid digests")
	}
	if _, err := (&remoteRegistry{}).FetchArtifact(context.Background(), Referrer{Repository: "bad repo", Descriptor: v1.Descriptor{Digest: mustHash(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}}); err == nil {
		t.Fatal("expected FetchArtifact() to reject invalid repositories")
	}
}
