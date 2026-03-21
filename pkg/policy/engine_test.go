package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/attestation"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestLoadBundleSupportsYAMLAndJSON(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	yamlPath := filepath.Join(tempDir, "bundle.yaml")
	jsonPath := filepath.Join(tempDir, "bundle.json")

	yamlBundle := []byte(`
name: defaults
version: 1
mode: enforce
policies:
  - id: no-critical
    max_severity: critical
    ignore_statuses: [not_affected]
`)
	jsonBundle := []byte(`{"name":"defaults","version":1,"policies":[{"id":"signed","min_verified_signatures":1}]}`)

	if err := os.WriteFile(yamlPath, yamlBundle, 0o600); err != nil {
		t.Fatalf("WriteFile(yaml) error = %v", err)
	}
	if err := os.WriteFile(jsonPath, jsonBundle, 0o600); err != nil {
		t.Fatalf("WriteFile(json) error = %v", err)
	}

	loadedYAML, err := LoadBundle(yamlPath)
	if err != nil {
		t.Fatalf("LoadBundle(yaml) error = %v", err)
	}
	if got, want := loadedYAML.Mode, ModeEnforce; got != want {
		t.Fatalf("yaml mode = %q, want %q", got, want)
	}
	if got, want := loadedYAML.Policies[0].MaxSeverity, "CRITICAL"; got != want {
		t.Fatalf("yaml max severity = %q, want %q", got, want)
	}

	loadedJSON, err := LoadBundle(jsonPath)
	if err != nil {
		t.Fatalf("LoadBundle(json) error = %v", err)
	}
	if got, want := loadedJSON.Policies[0].MinVerifiedSignatures, 1; got != want {
		t.Fatalf("json min verified signatures = %d, want %d", got, want)
	}
}

func TestEngineEvaluateAppliesVEXAwareSeverityAndScannerRules(t *testing.T) {
	t.Parallel()

	engine, err := NewEngineFromBundle(Bundle{
		Name: "default",
		Policies: []Policy{
			{
				ID:             "severity",
				MaxSeverity:    "CRITICAL",
				IgnoreStatuses: []string{vulnindex.StatusFixed, vulnindex.StatusNotAffected},
			},
			{
				ID:              "scanners",
				AllowedScanners: []string{"grype"},
			},
		},
	}, ModeReport)
	if err != nil {
		t.Fatalf("NewEngineFromBundle() error = %v", err)
	}

	evaluation := engine.Evaluate(Input{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "ghcr.io/example/demo:1.0",
		Vulnerabilities: vulnindex.Record{
			OrgID:     "demo-org",
			ImageID:   "demo-image",
			ImageName: "ghcr.io/example/demo:1.0",
			Summary: vulnindex.Summary{
				Total:      2,
				BySeverity: map[string]int{"CRITICAL": 2},
				ByScanner:  map[string]int{"grype": 1, "trivy": 1},
				ByStatus:   map[string]int{vulnindex.StatusAffected: 1, vulnindex.StatusFixed: 1},
			},
			Vulnerabilities: []vulnindex.VulnerabilityRecord{
				{
					ID:          "CVE-2024-0001",
					Severity:    "CRITICAL",
					PackageName: "openssl",
					Status:      vulnindex.StatusAffected,
					Scanners:    []string{"grype"},
				},
				{
					ID:          "CVE-2024-0002",
					Severity:    "CRITICAL",
					PackageName: "busybox",
					Status:      vulnindex.StatusFixed,
					Scanners:    []string{"trivy"},
				},
			},
		},
	})

	if got, want := evaluation.Status, StatusFail; got != want {
		t.Fatalf("evaluation.Status = %q, want %q", got, want)
	}
	if got, want := evaluation.Failed, 2; got != want {
		t.Fatalf("evaluation.Failed = %d, want %d", got, want)
	}
	if got, want := len(evaluation.Policies[0].Violations), 1; got != want {
		t.Fatalf("severity policy violations = %d, want %d", got, want)
	}
	if got, want := evaluation.Policies[1].Violations[0].Scanner, "trivy"; got != want {
		t.Fatalf("scanner violation scanner = %q, want %q", got, want)
	}
}

func TestEngineEvaluateChecksVerifiedSignaturesAndProvenance(t *testing.T) {
	t.Parallel()

	engine, err := NewEngineFromBundle(Bundle{
		Name: "signed",
		Policies: []Policy{{
			ID:                    "signed-provenance",
			MinVerifiedSignatures: 1,
			MinVerifiedProvenance: 1,
		}},
	}, ModeEnforce)
	if err != nil {
		t.Fatalf("NewEngineFromBundle() error = %v", err)
	}

	verified := attestation.VerificationStatusValid
	evaluation := engine.Evaluate(Input{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "ghcr.io/example/demo:1.0",
		Attestations: &attestation.Result{
			Signatures: []attestation.Record{{Kind: attestation.KindSignature, VerificationStatus: verified}},
			Attestations: []attestation.Record{{
				Kind:               attestation.KindAttestation,
				VerificationStatus: verified,
				PredicateType:      "https://slsa.dev/provenance/v1",
			}},
			UpdatedAt: time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC),
		},
	})

	if got, want := evaluation.Mode, ModeEnforce; got != want {
		t.Fatalf("evaluation.Mode = %q, want %q", got, want)
	}
	if got, want := evaluation.Status, StatusPass; got != want {
		t.Fatalf("evaluation.Status = %q, want %q", got, want)
	}
	if !evaluation.Allowed {
		t.Fatal("expected evaluation.Allowed to be true")
	}
}
