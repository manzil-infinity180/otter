package reportexport

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestMarshalVulnerabilitiesCSV(t *testing.T) {
	t.Parallel()

	record := testVulnerabilityRecord()
	document, err := MarshalVulnerabilitiesCSV(record)
	if err != nil {
		t.Fatalf("MarshalVulnerabilitiesCSV() error = %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(string(document))).ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll() error = %v", err)
	}
	if got, want := len(rows), 2; got != want {
		t.Fatalf("len(rows) = %d, want %d", got, want)
	}
	if got, want := rows[0][0], "id"; got != want {
		t.Fatalf("header id = %q, want %q", got, want)
	}
	if got, want := rows[1][0], "CVE-2024-0001"; got != want {
		t.Fatalf("row id = %q, want %q", got, want)
	}
	if got, want := rows[1][9], "1.36.2-r1|1.36.3-r0"; got != want {
		t.Fatalf("row fix_versions = %q, want %q", got, want)
	}
}

func TestMarshalVulnerabilitiesSARIF(t *testing.T) {
	t.Parallel()

	record := testVulnerabilityRecord()
	document, err := MarshalVulnerabilitiesSARIF(record)
	if err != nil {
		t.Fatalf("MarshalVulnerabilitiesSARIF() error = %v", err)
	}

	var payload struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(document, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := payload.Version, "2.1.0"; got != want {
		t.Fatalf("version = %q, want %q", got, want)
	}
	if got, want := payload.Runs[0].Tool.Driver.Name, "otter"; got != want {
		t.Fatalf("tool name = %q, want %q", got, want)
	}
	if got, want := payload.Runs[0].Results[0].RuleID, "CVE-2024-0001"; got != want {
		t.Fatalf("ruleId = %q, want %q", got, want)
	}
	if got, want := payload.Runs[0].Results[0].Level, "error"; got != want {
		t.Fatalf("level = %q, want %q", got, want)
	}
	if got := payload.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; !strings.Contains(got, "container-images/demo-org/demo-image/apk") {
		t.Fatalf("artifact uri = %q, want container image pseudo-path", got)
	}
	if payload.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] == "" {
		t.Fatal("expected primaryLocationLineHash fingerprint")
	}
}

func TestMarshalVulnerabilitiesJSON(t *testing.T) {
	t.Parallel()

	record := testVulnerabilityRecord()
	document, err := MarshalVulnerabilitiesJSON(record)
	if err != nil {
		t.Fatalf("MarshalVulnerabilitiesJSON() error = %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(document, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := payload["org_id"], "demo-org"; got != want {
		t.Fatalf("org_id = %v, want %q", got, want)
	}
	if got := payload["vulnerabilities"]; got == nil {
		t.Fatal("expected vulnerabilities array")
	}
}

func testVulnerabilityRecord() vulnindex.Record {
	now := time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC)
	return vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:3.20",
		Summary: vulnindex.Summary{
			Total:      1,
			BySeverity: map[string]int{"HIGH": 1},
			ByScanner:  map[string]int{"grype": 1},
			ByStatus:   map[string]int{vulnindex.StatusAffected: 1},
			Fixable:    1,
		},
		Vulnerabilities: []vulnindex.VulnerabilityRecord{
			{
				ID:             "CVE-2024-0001",
				Severity:       "HIGH",
				PackageName:    "busybox",
				PackageVersion: "1.36.1-r0",
				PackageType:    "apk",
				Namespace:      "alpine:3.20",
				Description:    "Busybox issue",
				PrimaryURL:     "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
				FixVersion:     "1.36.2-r1",
				FixVersions:    []string{"1.36.2-r1", "1.36.3-r0"},
				CVSS: []scan.CVSSScore{
					{Source: "nvd", Score: 8.7},
				},
				Scanners:     []string{"grype"},
				Status:       vulnindex.StatusAffected,
				StatusSource: vulnindex.StatusSourceScanner,
				Advisory: &vulnindex.Advisory{
					DocumentID:  "openvex-demo",
					StatusNotes: "Patched downstream",
				},
				FirstSeenAt: now.Add(-24 * time.Hour),
				LastSeenAt:  now,
			},
		},
		UpdatedAt: now,
	}
}
