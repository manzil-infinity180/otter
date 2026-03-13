package vulnindex

import (
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/scan"
)

func TestBuildRecordFromReportAppliesVEXAndTrend(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, 3, 13, 18, 30, 0, 0, time.UTC)
	record, err := BuildRecordFromReport("demo-org", "demo-image", "alpine:latest", scan.CombinedVulnerabilityReport{
		GeneratedAt: observedAt,
		Vulnerabilities: []scan.VulnerabilityFinding{
			{
				ID:             "CVE-2024-0001",
				Severity:       "high",
				PackageName:    "openssl",
				PackageVersion: "3.0.0",
				FixVersion:     "3.0.2",
				Scanners:       []string{"grype", "trivy"},
			},
			{
				ID:             "CVE-2024-0002",
				Severity:       "medium",
				PackageName:    "busybox",
				PackageVersion: "1.36.0",
				Scanners:       []string{"trivy"},
			},
		},
	}, nil, BuildOptions{TrackTrend: true})
	if err != nil {
		t.Fatalf("BuildRecordFromReport() error = %v", err)
	}

	record, _, err = ApplyVEXDocument(record, []byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/demo",
  "author": "otter",
  "timestamp": "2026-03-13T18:45:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2024-0001"
      },
      "status": "fixed",
      "products": [
        {
          "@id": "pkg:oci/alpine@latest"
        }
      ]
    }
  ]
}`), "demo.vex.json", observedAt.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("ApplyVEXDocument() error = %v", err)
	}

	if got, want := record.Summary.ByStatus[StatusFixed], 1; got != want {
		t.Fatalf("Summary.ByStatus[fixed] = %d, want %d", got, want)
	}
	if got, want := len(record.Trend), 1; got != want {
		t.Fatalf("len(Trend) = %d, want %d", got, want)
	}
	if got, want := record.FixRecommendations[0].RecommendedVersion, "3.0.2"; got != want {
		t.Fatalf("RecommendedVersion = %s, want %s", got, want)
	}
	if got, want := record.Vulnerabilities[0].Status, StatusFixed; got != want {
		t.Fatalf("first vulnerability status = %s, want %s", got, want)
	}
}

func TestFilterRecordBySeverityAndStatus(t *testing.T) {
	t.Parallel()

	record := Record{
		Vulnerabilities: []VulnerabilityRecord{
			{ID: "CVE-1", Severity: "CRITICAL", Status: StatusAffected, Scanners: []string{"grype"}},
			{ID: "CVE-2", Severity: "LOW", Status: StatusFixed, Scanners: []string{"trivy"}},
		},
	}

	filtered, err := FilterRecord(record, FilterOptions{Severity: "critical", Status: "affected"})
	if err != nil {
		t.Fatalf("FilterRecord() error = %v", err)
	}
	if got, want := len(filtered.Vulnerabilities), 1; got != want {
		t.Fatalf("len(Vulnerabilities) = %d, want %d", got, want)
	}
	if got, want := filtered.Vulnerabilities[0].ID, "CVE-1"; got != want {
		t.Fatalf("first vulnerability ID = %s, want %s", got, want)
	}
}
