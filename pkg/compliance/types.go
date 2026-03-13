package compliance

import (
	"context"
	"time"
)

const (
	StatusPass        = "pass"
	StatusPartial     = "partial"
	StatusFail        = "fail"
	StatusUnavailable = "unavailable"
)

type Repository struct {
	Host        string `json:"host"`
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Repository  string `json:"repository"`
	URL         string `json:"url"`
	DerivedFrom string `json:"derived_from"`
	Confidence  string `json:"confidence"`
}

type Input struct {
	ImageRef         string
	Vulnerabilities  *VulnerabilitySummary
	Attestations     *AttestationSummary
	AttestationError error
}

type VulnerabilitySummary struct {
	Total    int
	Critical int
	Fixable  int
}

type AttestationSummary struct {
	UpdatedAt    time.Time
	Total        int
	Signatures   int
	Attestations []ProvenanceRecord
	Verified     bool
}

type ProvenanceRecord struct {
	BuilderID           string
	BuildType           string
	InvocationID        string
	Materials           []string
	VerificationStatus  string
	PredicateType       string
	SourceRepositoryURL string
}

type Result struct {
	ImageRef         string            `json:"image_ref"`
	ScopeNote        string            `json:"scope_note"`
	SourceRepository *Repository       `json:"source_repository,omitempty"`
	SLSA             SLSAAssessment    `json:"slsa"`
	Scorecard        ScorecardSummary  `json:"scorecard"`
	Standards        []StandardSummary `json:"standards"`
	Summary          Summary           `json:"summary"`
	EvidenceErrors   []string          `json:"evidence_errors,omitempty"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

type SLSAAssessment struct {
	Level        int      `json:"level"`
	TargetLevel  int      `json:"target_level"`
	Status       string   `json:"status"`
	Verified     bool     `json:"verified"`
	BuilderID    string   `json:"builder_id,omitempty"`
	BuildType    string   `json:"build_type,omitempty"`
	InvocationID string   `json:"invocation_id,omitempty"`
	Materials    []string `json:"materials,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
	Missing      []string `json:"missing,omitempty"`
}

type ScorecardSummary struct {
	Enabled    bool             `json:"enabled"`
	Available  bool             `json:"available"`
	Status     string           `json:"status"`
	Repository string           `json:"repository,omitempty"`
	Score      float64          `json:"score,omitempty"`
	Date       time.Time        `json:"date,omitempty"`
	RiskLevel  string           `json:"risk_level,omitempty"`
	Checks     []ScorecardCheck `json:"checks,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type ScorecardCheck struct {
	Name             string  `json:"name"`
	Score            float64 `json:"score"`
	Reason           string  `json:"reason,omitempty"`
	DocumentationURL string  `json:"documentation_url,omitempty"`
}

type StandardSummary struct {
	Name    string          `json:"name"`
	Status  string          `json:"status"`
	Summary string          `json:"summary"`
	Checks  []StandardCheck `json:"checks"`
}

type StandardCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Summary struct {
	OverallStatus string `json:"overall_status"`
	Passed        int    `json:"passed"`
	Partial       int    `json:"partial"`
	Failed        int    `json:"failed"`
	Unavailable   int    `json:"unavailable"`
}

type ScorecardClient interface {
	Lookup(ctx context.Context, repository Repository) (ScorecardSummary, error)
}
