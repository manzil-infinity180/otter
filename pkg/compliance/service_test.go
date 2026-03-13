package compliance

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubScorecardClient struct {
	summary ScorecardSummary
	err     error
}

func (s stubScorecardClient) Lookup(context.Context, Repository) (ScorecardSummary, error) {
	return s.summary, s.err
}

func TestServiceAssessBuildsComplianceReport(t *testing.T) {
	t.Parallel()

	service := NewServiceWithClient(stubScorecardClient{
		summary: ScorecardSummary{
			Enabled:    true,
			Available:  true,
			Status:     StatusPass,
			Repository: "github.com/demo/project",
			Score:      8.7,
			RiskLevel:  "strong",
		},
	})

	result := service.Assess(context.Background(), Input{
		ImageRef: "ghcr.io/demo/project:1.0.0",
		Vulnerabilities: &VulnerabilitySummary{
			Total:    0,
			Critical: 0,
			Fixable:  0,
		},
		Attestations: &AttestationSummary{
			UpdatedAt: time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC),
			Total:     2,
			Verified:  true,
			Attestations: []ProvenanceRecord{
				{
					BuilderID:          "https://github.com/actions/runner",
					BuildType:          "https://slsa.dev/container-based-build/v1",
					InvocationID:       "workflow-run-123",
					Materials:          []string{"git+https://github.com/demo/project@refs/heads/main"},
					VerificationStatus: "valid",
				},
			},
		},
	})

	if result.SourceRepository == nil || result.SourceRepository.Repository != "github.com/demo/project" {
		t.Fatalf("unexpected source repository: %#v", result.SourceRepository)
	}
	if got, want := result.SLSA.Level, 3; got != want {
		t.Fatalf("SLSA.Level = %d, want %d", got, want)
	}
	if got, want := result.Scorecard.Available, true; got != want {
		t.Fatalf("Scorecard.Available = %t, want %t", got, want)
	}
	if got, want := result.Summary.OverallStatus, StatusPass; got != want {
		t.Fatalf("Summary.OverallStatus = %q, want %q", got, want)
	}
}

func TestServiceAssessDegradesWhenEvidenceIsUnavailable(t *testing.T) {
	t.Parallel()

	service := NewServiceWithClient(stubScorecardClient{err: errors.New("upstream unavailable")})

	result := service.Assess(context.Background(), Input{
		ImageRef:         "alpine:latest",
		AttestationError: errors.New("registry denied access"),
	})

	if result.SourceRepository != nil {
		t.Fatalf("expected no source repository, got %#v", result.SourceRepository)
	}
	if got, want := result.SLSA.Status, StatusFail; got != want {
		t.Fatalf("SLSA.Status = %q, want %q", got, want)
	}
	if got, want := result.Scorecard.Status, StatusUnavailable; got != want {
		t.Fatalf("Scorecard.Status = %q, want %q", got, want)
	}
	if len(result.EvidenceErrors) == 0 {
		t.Fatalf("expected evidence errors, got none")
	}
}
