package vulnindex

import (
	"testing"
)

func TestBuildDisagreementReport(t *testing.T) {
	vulns := []VulnerabilityRecord{
		{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "openssl", Scanners: []string{"grype", "trivy"}},
		{ID: "CVE-2024-0002", Severity: "HIGH", PackageName: "curl", Scanners: []string{"grype"}},
		{ID: "CVE-2024-0003", Severity: "MEDIUM", PackageName: "zlib", Scanners: []string{"trivy"}},
	}

	report := BuildDisagreementReport(vulns, []string{"grype", "trivy"})

	if report.TotalVulnerabilities != 3 {
		t.Fatalf("expected 3 total, got %d", report.TotalVulnerabilities)
	}
	if report.AgreedCount != 1 {
		t.Fatalf("expected 1 agreed (CVE-2024-0001), got %d", report.AgreedCount)
	}
	if report.DisagreedCount != 2 {
		t.Fatalf("expected 2 disagreed, got %d", report.DisagreedCount)
	}
	if len(report.Disagreements) != 2 {
		t.Fatalf("expected 2 disagreement entries, got %d", len(report.Disagreements))
	}
	if report.DisagreementRate < 0.6 || report.DisagreementRate > 0.7 {
		t.Fatalf("expected ~66%% disagreement rate, got %.2f", report.DisagreementRate)
	}
}

func TestBuildDisagreementReportSingleScanner(t *testing.T) {
	vulns := []VulnerabilityRecord{
		{ID: "CVE-2024-0001", Scanners: []string{"grype"}},
	}
	report := BuildDisagreementReport(vulns, []string{"grype"})
	if report.DisagreedCount != 0 {
		t.Fatal("expected no disagreements with single scanner")
	}
}
