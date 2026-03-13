package compare

import (
	"strings"
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestBuildReport(t *testing.T) {
	t.Parallel()

	report, err := BuildReport(Inputs{
		Image1: sbomindex.Record{
			OrgID:        "demo-org",
			ImageID:      "image-a",
			ImageName:    "alpine:3.19",
			PackageCount: 2,
			Packages: []sbomindex.PackageRecord{
				{Name: "busybox", Type: "apk", Version: "1.36.1", PURL: "pkg:apk/alpine/busybox@1.36.1"},
				{Name: "ssl", Type: "apk", Version: "1.0.0", PURL: "pkg:apk/alpine/ssl@1.0.0"},
			},
			DependencyRoots: []string{"pkg:oci/alpine@3.19"},
			UpdatedAt:       time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
		},
		Image2: sbomindex.Record{
			OrgID:        "demo-org",
			ImageID:      "image-b",
			ImageName:    "alpine:3.20",
			PackageCount: 2,
			Packages: []sbomindex.PackageRecord{
				{Name: "busybox", Type: "apk", Version: "1.37.0", PURL: "pkg:apk/alpine/busybox@1.37.0"},
				{Name: "curl", Type: "apk", Version: "8.0.0", PURL: "pkg:apk/alpine/curl@8.0.0"},
			},
			DependencyRoots: []string{"pkg:oci/alpine@3.20"},
			UpdatedAt:       time.Date(2026, 3, 13, 18, 30, 0, 0, time.UTC),
		},
		Vulnerabilities1: vulnindex.Record{
			Summary: vulnindex.Summary{Total: 2},
			Vulnerabilities: []vulnindex.VulnerabilityRecord{
				{ID: "CVE-1", Severity: "HIGH", PackageName: "busybox", PackageVersion: "1.36.1", Status: vulnindex.StatusAffected, Scanners: []string{"grype"}},
				{ID: "CVE-2", Severity: "LOW", PackageName: "ssl", PackageVersion: "1.0.0", Status: vulnindex.StatusAffected, Scanners: []string{"grype"}},
			},
			UpdatedAt: time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
		},
		Vulnerabilities2: vulnindex.Record{
			Summary: vulnindex.Summary{Total: 1},
			Vulnerabilities: []vulnindex.VulnerabilityRecord{
				{ID: "CVE-1", Severity: "MEDIUM", PackageName: "busybox", PackageVersion: "1.37.0", Status: vulnindex.StatusAffected, Scanners: []string{"grype", "trivy"}},
			},
			UpdatedAt: time.Date(2026, 3, 13, 18, 30, 0, 0, time.UTC),
		},
		CycloneDX1: []byte(`{
  "components": [
    {
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:layer-a"},
        {"name":"syft:metadata:size","value":"10"}
      ]
    },
    {
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:shared"},
        {"name":"syft:metadata:size","value":"20"}
      ]
    }
  ]
}`),
		CycloneDX2: []byte(`{
  "components": [
    {
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:layer-b"},
        {"name":"syft:metadata:size","value":"15"}
      ]
    },
    {
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:shared"},
        {"name":"syft:metadata:size","value":"20"}
      ]
    }
  ]
}`),
	})
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	if report.ID == "" {
		t.Fatal("expected comparison ID")
	}
	if got, want := len(report.PackageDiff.Added), 1; got != want {
		t.Fatalf("len(PackageDiff.Added) = %d, want %d", got, want)
	}
	if got, want := len(report.PackageDiff.Removed), 1; got != want {
		t.Fatalf("len(PackageDiff.Removed) = %d, want %d", got, want)
	}
	if got, want := len(report.PackageDiff.Changed), 1; got != want {
		t.Fatalf("len(PackageDiff.Changed) = %d, want %d", got, want)
	}
	if got, want := len(report.VulnerabilityDiff.Fixed), 2; got != want {
		t.Fatalf("len(VulnerabilityDiff.Fixed) = %d, want %d", got, want)
	}
	if got, want := len(report.VulnerabilityDiff.New), 1; got != want {
		t.Fatalf("len(VulnerabilityDiff.New) = %d, want %d", got, want)
	}
	if got, want := len(report.LayerDiff.OnlyInImage1), 1; got != want {
		t.Fatalf("len(LayerDiff.OnlyInImage1) = %d, want %d", got, want)
	}
	if !strings.Contains(report.Summary.Message, "Image B has 1 fewer vulns") {
		t.Fatalf("Summary.Message = %q", report.Summary.Message)
	}
}

func TestComparisonKey(t *testing.T) {
	t.Parallel()

	id := ComputeID("org-a", "image-a", "org-b", "image-b")
	key := ComparisonKey(id)
	if !strings.Contains(key, "/comparisons/") {
		t.Fatalf("ComparisonKey() = %q", key)
	}
}
