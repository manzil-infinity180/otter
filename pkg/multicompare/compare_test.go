package multicompare

import (
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestBuildReportTwoImages(t *testing.T) {
	inputs := Inputs{
		SBOMs: []sbomindex.Record{
			{
				OrgID: "default", ImageID: "nginx-latest", ImageName: "nginx:latest",
				PackageCount: 150,
				Packages: []sbomindex.PackageRecord{
					{Name: "openssl", Version: "3.0.1", Type: "deb"},
					{Name: "curl", Version: "7.88.0", Type: "deb"},
					{Name: "zlib", Version: "1.2.13", Type: "deb"},
				},
				LicenseSummary: []sbomindex.LicenseSummaryEntry{{License: "MIT", Count: 80}},
				UpdatedAt:      time.Now(),
			},
			{
				OrgID: "default", ImageID: "chainguard-nginx", ImageName: "cgr.dev/chainguard/nginx:latest",
				PackageCount: 30,
				Packages: []sbomindex.PackageRecord{
					{Name: "openssl", Version: "3.1.0", Type: "apk"},
					{Name: "zlib", Version: "1.3.0", Type: "apk"},
				},
				LicenseSummary: []sbomindex.LicenseSummaryEntry{{License: "MIT", Count: 20}},
				UpdatedAt:      time.Now(),
			},
		},
		Vulnerabilities: []vulnindex.Record{
			{
				Summary: vulnindex.Summary{Total: 42, BySeverity: map[string]int{"CRITICAL": 5, "HIGH": 15, "MEDIUM": 12, "LOW": 10}, Fixable: 30, Unfixable: 12},
				Vulnerabilities: []vulnindex.VulnerabilityRecord{
					{ID: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "openssl"},
					{ID: "CVE-2024-0002", Severity: "HIGH", PackageName: "curl"},
				},
			},
			{
				Summary: vulnindex.Summary{Total: 3, BySeverity: map[string]int{"MEDIUM": 2, "LOW": 1}, Fixable: 3, Unfixable: 0},
				Vulnerabilities: []vulnindex.VulnerabilityRecord{
					{ID: "CVE-2024-0003", Severity: "MEDIUM", PackageName: "zlib"},
				},
			},
		},
	}

	report, err := BuildReport(inputs)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}

	if len(report.Images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(report.Images))
	}
	if report.Images[0].ImageName != "nginx:latest" {
		t.Fatalf("expected nginx:latest, got %s", report.Images[0].ImageName)
	}
	if report.Winner != 1 {
		t.Fatalf("expected winner=1 (chainguard with 3 vulns), got %d", report.Winner)
	}
	if len(report.PairwiseDiffs) != 1 {
		t.Fatalf("expected 1 pairwise diff, got %d", len(report.PairwiseDiffs))
	}
	if len(report.Charts.SeverityBreakdown) != 5 {
		t.Fatalf("expected 5 severity data points, got %d", len(report.Charts.SeverityBreakdown))
	}
	if report.Charts.SeverityBreakdown[0].Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL first, got %s", report.Charts.SeverityBreakdown[0].Severity)
	}
	if report.Charts.SeverityBreakdown[0].Counts[0] != 5 {
		t.Fatalf("expected 5 critical for image1, got %d", report.Charts.SeverityBreakdown[0].Counts[0])
	}
	if report.Charts.SeverityBreakdown[0].Counts[1] != 0 {
		t.Fatalf("expected 0 critical for image2, got %d", report.Charts.SeverityBreakdown[0].Counts[1])
	}
}

func TestBuildReportThreeImages(t *testing.T) {
	sbom := sbomindex.Record{
		OrgID: "default", ImageID: "img", ImageName: "img:latest",
		PackageCount: 10,
		Packages:     []sbomindex.PackageRecord{{Name: "pkg1", Version: "1.0"}},
		UpdatedAt:    time.Now(),
	}
	vuln := vulnindex.Record{
		Summary:         vulnindex.Summary{Total: 5, BySeverity: map[string]int{"HIGH": 5}},
		Vulnerabilities: []vulnindex.VulnerabilityRecord{{ID: "CVE-1", PackageName: "pkg1"}},
	}

	inputs := Inputs{
		SBOMs:           []sbomindex.Record{sbom, sbom, sbom},
		Vulnerabilities: []vulnindex.Record{vuln, vuln, vuln},
	}

	report, err := BuildReport(inputs)
	if err != nil {
		t.Fatalf("BuildReport 3-way: %v", err)
	}
	if len(report.Images) != 3 {
		t.Fatalf("expected 3 images, got %d", len(report.Images))
	}
	// 3 images → 3 pairwise diffs: (0,1), (0,2), (1,2)
	if len(report.PairwiseDiffs) != 3 {
		t.Fatalf("expected 3 pairwise diffs, got %d", len(report.PairwiseDiffs))
	}
	// Each severity count should have 3 entries
	for _, dp := range report.Charts.SeverityBreakdown {
		if len(dp.Counts) != 3 {
			t.Fatalf("expected 3 counts per severity, got %d for %s", len(dp.Counts), dp.Severity)
		}
	}
}

func TestBuildReportRejectsInvalidCount(t *testing.T) {
	_, err := BuildReport(Inputs{
		SBOMs:           []sbomindex.Record{{}},
		Vulnerabilities: []vulnindex.Record{{}},
	})
	if err == nil {
		t.Fatal("expected error for 1 image")
	}
}

func TestPresetsReturnsEntries(t *testing.T) {
	presets := Presets()
	if len(presets) < 5 {
		t.Fatalf("expected at least 5 presets, got %d", len(presets))
	}
	for _, p := range presets {
		if len(p.Images) < 2 {
			t.Fatalf("preset %q has fewer than 2 images", p.ID)
		}
	}
}
