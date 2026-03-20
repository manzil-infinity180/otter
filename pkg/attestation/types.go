package attestation

import (
	"context"
	"time"
)

const (
	KindSignature   = "signature"
	KindAttestation = "attestation"

	VerificationStatusValid      = "valid"
	VerificationStatusInvalid    = "invalid"
	VerificationStatusUnverified = "unverified"
)

type Fetcher interface {
	Discover(ctx context.Context, imageRef string) (Result, error)
}

type Result struct {
	ImageRef     string    `json:"image_ref"`
	CanonicalRef string    `json:"canonical_ref"`
	ImageDigest  string    `json:"image_digest"`
	Signatures   []Record  `json:"signatures"`
	Attestations []Record  `json:"attestations"`
	Summary      Summary   `json:"summary"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Summary struct {
	Total                int            `json:"total"`
	Signatures           int            `json:"signatures"`
	Attestations         int            `json:"attestations"`
	Provenance           int            `json:"provenance"`
	ByVerificationStatus map[string]int `json:"by_verification_status"`
}

type Record struct {
	Digest              string             `json:"digest"`
	MediaType           string             `json:"media_type,omitempty"`
	ArtifactType        string             `json:"artifact_type,omitempty"`
	Kind                string             `json:"kind"`
	Source              string             `json:"source"`
	SubjectDigest       string             `json:"subject_digest,omitempty"`
	VerificationStatus  string             `json:"verification_status"`
	VerificationMessage string             `json:"verification_message,omitempty"`
	Signer              string             `json:"signer,omitempty"`
	Issuer              string             `json:"issuer,omitempty"`
	Timestamp           *time.Time         `json:"timestamp,omitempty"`
	PredicateType       string             `json:"predicate_type,omitempty"`
	StatementType       string             `json:"statement_type,omitempty"`
	DSSEPayloadType     string             `json:"dsse_payload_type,omitempty"`
	Annotations         map[string]string  `json:"annotations,omitempty"`
	Subjects            []StatementSubject `json:"subjects,omitempty"`
	Envelope            *EnvelopeSummary   `json:"envelope,omitempty"`
	Provenance          *ProvenanceSummary `json:"provenance,omitempty"`
}

type StatementSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest,omitempty"`
}

type EnvelopeSummary struct {
	PayloadType string `json:"payload_type,omitempty"`
	Signatures  int    `json:"signatures"`
}

type ProvenanceSummary struct {
	BuilderID    string   `json:"builder_id,omitempty"`
	BuildType    string   `json:"build_type,omitempty"`
	InvocationID string   `json:"invocation_id,omitempty"`
	Materials    []string `json:"materials,omitempty"`
}
