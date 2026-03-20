package scan

import "testing"

func TestBuildCombinedReportMergesScannerAttribution(t *testing.T) {
	t.Parallel()

	report, _, err := BuildCombinedReport("nginx:latest", []ScannerReport{
		{
			Scanner: "grype",
			Findings: []VulnerabilityFinding{
				{
					ID:             "CVE-2024-0001",
					Severity:       "high",
					PackageName:    "openssl",
					PackageVersion: "3.0.0",
					FixVersions:    []string{"3.0.1"},
					Scanners:       []string{"grype"},
				},
			},
		},
		{
			Scanner: "trivy",
			Findings: []VulnerabilityFinding{
				{
					ID:             "CVE-2024-0001",
					Severity:       "CRITICAL",
					PackageName:    "openssl",
					PackageVersion: "3.0.0",
					FixVersion:     "3.0.2",
					Scanners:       []string{"trivy"},
				},
				{
					ID:             "CVE-2024-0002",
					Severity:       "medium",
					PackageName:    "busybox",
					PackageVersion: "1.36.0",
					Scanners:       []string{"trivy"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildCombinedReport() error = %v", err)
	}

	if got, want := report.Summary.Total, 2; got != want {
		t.Fatalf("Summary.Total = %d, want %d", got, want)
	}
	if got, want := report.Summary.BySeverity["CRITICAL"], 1; got != want {
		t.Fatalf("Summary.BySeverity[CRITICAL] = %d, want %d", got, want)
	}
	if got, want := report.Summary.ByScanner["grype"], 1; got != want {
		t.Fatalf("Summary.ByScanner[grype] = %d, want %d", got, want)
	}
	if got, want := report.Summary.ByScanner["trivy"], 2; got != want {
		t.Fatalf("Summary.ByScanner[trivy] = %d, want %d", got, want)
	}
	if got, want := report.Summary.Fixable, 1; got != want {
		t.Fatalf("Summary.Fixable = %d, want %d", got, want)
	}

	first := report.Vulnerabilities[0]
	if got, want := first.ID, "CVE-2024-0001"; got != want {
		t.Fatalf("first vulnerability ID = %s, want %s", got, want)
	}
	if got, want := first.Severity, "CRITICAL"; got != want {
		t.Fatalf("first vulnerability severity = %s, want %s", got, want)
	}
	if got, want := len(first.Scanners), 2; got != want {
		t.Fatalf("first vulnerability scanners len = %d, want %d", got, want)
	}
	if got, want := first.FixVersion, "3.0.1"; got != want {
		t.Fatalf("first vulnerability fix version = %s, want %s", got, want)
	}
}
