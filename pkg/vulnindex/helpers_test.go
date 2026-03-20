package vulnindex

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/scan"
)

func TestVulnerabilityHelperFunctions(t *testing.T) {
	t.Parallel()

	importedAt := time.Date(2026, 3, 14, 1, 0, 0, 0, time.UTC)
	document, err := parseOpenVEXDocument([]byte(`{
		"@context":"https://openvex.dev/ns/v0.2.0",
		"author":"otter",
		"timestamp":"2026-03-14T00:00:00Z",
		"version":1,
		"statements":[
			{
				"vulnerability":{"name":"CVE-2024-0001"},
				"status":"fixed",
				"status_notes":"patched",
				"products":[{"@id":"pkg:oci/alpine@latest"}]
			}
		]
	}`), "demo.openvex.json", importedAt)
	if err != nil {
		t.Fatalf("parseOpenVEXDocument() error = %v", err)
	}
	if document.DocumentID == "" || len(document.Statements) != 1 {
		t.Fatalf("parsed VEX document = %#v", document)
	}

	overlay := latestVEXStatements([]VEXDocumentRecord{
		{
			DocumentID:  "old",
			LastUpdated: importedAt,
			Statements:  []VEXStatementRecord{{VulnerabilityID: "CVE-2024-0001", Status: StatusAffected}},
		},
		{
			DocumentID:  "new",
			LastUpdated: importedAt.Add(time.Minute),
			Statements:  []VEXStatementRecord{{VulnerabilityID: "CVE-2024-0001", Status: StatusFixed}},
		},
	})
	if got, want := overlay["CVE-2024-0001"].Statement.Status, StatusFixed; got != want {
		t.Fatalf("latestVEXStatements() status = %q, want %q", got, want)
	}
	if !overlay["CVE-2024-0001"].isNewerThan(vexOverlay{}) {
		t.Fatal("expected overlay to be newer than zero value")
	}

	if got, want := effectiveStatementTime(document, document.Statements[0]), document.Timestamp; !got.Equal(want) {
		t.Fatalf("effectiveStatementTime() = %v, want %v", got, want)
	}

	vulnerabilities := []VulnerabilityRecord{
		{
			ID:             "CVE-2024-0001",
			Severity:       "HIGH",
			PackageName:    "openssl",
			PackageVersion: "1.2.3",
			PackageType:    "apk",
			FixVersion:     "1.2.4",
			FixVersions:    []string{"1.2.4", "1.2.5"},
			Scanners:       []string{"grype"},
			Status:         StatusAffected,
		},
		{
			ID:             "CVE-2024-0002",
			Severity:       "CRITICAL",
			PackageName:    "openssl",
			PackageVersion: "1.2.3",
			PackageType:    "apk",
			FixVersions:    []string{"1.2.6"},
			Scanners:       []string{"trivy"},
			Status:         StatusAffected,
		},
	}
	summary := summarize(vulnerabilities)
	if summary.Total != 2 || summary.BySeverity["CRITICAL"] != 1 || summary.Fixable != 1 {
		t.Fatalf("summarize() = %#v", summary)
	}

	recommendations := buildFixRecommendations(vulnerabilities)
	if len(recommendations) != 1 || recommendations[0].RecommendedVersion != "1.2.6" {
		t.Fatalf("buildFixRecommendations() = %#v", recommendations)
	}
	if got, want := recommendedFixVersion(vulnerabilities[1]), "1.2.6"; got != want {
		t.Fatalf("recommendedFixVersion() = %q, want %q", got, want)
	}

	documents := upsertVEXDocument([]VEXDocumentRecord{{DocumentID: "doc-1", Version: 1}}, VEXDocumentRecord{DocumentID: "doc-1", Version: 2})
	if len(documents) != 1 || documents[0].Version != 2 {
		t.Fatalf("upsertVEXDocument() = %#v", documents)
	}

	normalized := normalizeFinding(scan.VulnerabilityFinding{
		ID:             " cve-2024-0001 ",
		Severity:       "critical",
		PackageName:    "openssl",
		PackageVersion: "1.2.3",
		FixVersion:     "1.2.4",
		Scanners:       []string{"trivy", "grype", "trivy"},
		CVSS:           []scan.CVSSScore{{Source: "nvd", Score: 9.8}, {Source: "nvd", Score: 9.8}},
	})
	if normalized.ID != "CVE-2024-0001" || normalized.Severity != "CRITICAL" || len(normalized.Scanners) != 2 {
		t.Fatalf("normalizeFinding() = %#v", normalized)
	}

	if got, want := normalizeSeverity("medium"), "MEDIUM"; got != want {
		t.Fatalf("normalizeSeverity() = %q, want %q", got, want)
	}
	if got, want := severityRank("CRITICAL"), 5; got != want {
		t.Fatalf("severityRank() = %d, want %d", got, want)
	}
	if got := vulnerabilityKey(VulnerabilityRecord{ID: "CVE-1", PackageName: "pkg", PackageVersion: "1"}); got == "" {
		t.Fatal("expected vulnerabilityKey() to return a stable key")
	}
	if got := cloneTrend([]TrendPoint{{ObservedAt: importedAt}}); len(got) != 1 || !got[0].ObservedAt.Equal(importedAt) {
		t.Fatalf("cloneTrend() = %#v", got)
	}
	if got := cloneVEXDocuments([]VEXDocumentRecord{document}); len(got) != 1 || got[0].DocumentID != document.DocumentID {
		t.Fatalf("cloneVEXDocuments() = %#v", got)
	}
	if got := uniqueSortedStrings([]string{"b", "a", "b", ""}); len(got) != 2 || got[0] != "a" {
		t.Fatalf("uniqueSortedStrings() = %#v", got)
	}
	if got := uniqueSortedCVSS([]scan.CVSSScore{{Source: "nvd", Score: 7.5}, {Source: "nvd", Score: 7.5}, {Source: "ghsa", Score: 8.0}}); len(got) != 2 {
		t.Fatalf("uniqueSortedCVSS() = %#v", got)
	}
	if got, want := firstNonEmpty("", " demo "), "demo"; got != want {
		t.Fatalf("firstNonEmpty() = %q, want %q", got, want)
	}
	if got := derefTime(nil, importedAt); !got.Equal(importedAt) {
		t.Fatalf("derefTime(nil) = %v, want %v", got, importedAt)
	}
}

func TestNormalizeStatusAndFilterErrors(t *testing.T) {
	t.Parallel()

	if _, err := NormalizeStatus("broken"); err == nil {
		t.Fatal("expected NormalizeStatus() to reject unsupported status")
	}
	if _, err := FilterRecord(Record{}, FilterOptions{Severity: "broken"}); err == nil {
		t.Fatal("expected FilterRecord() to reject unsupported severity")
	}
	if _, err := BuildRecordFromDocument("demo-org", "demo-image", "", []byte(`not-json`), nil, BuildOptions{}); err == nil {
		t.Fatal("expected BuildRecordFromDocument() to reject invalid JSON")
	}

	record := Record{OrgID: "demo-org", ImageID: "demo-image"}
	if _, _, err := ApplyVEXDocument(record, []byte(`{}`), "invalid.json", time.Now().UTC()); err == nil {
		t.Fatal("expected ApplyVEXDocument() to reject invalid OpenVEX payloads")
	}
}

func TestBuildRecordFromReportPreservesExistingFindingHistory(t *testing.T) {
	t.Parallel()

	firstSeen := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	previous := &Record{
		ImageName: "alpine:latest",
		Vulnerabilities: []VulnerabilityRecord{{
			ID:             "CVE-2024-0001",
			Severity:       "HIGH",
			PackageName:    "openssl",
			PackageVersion: "1.2.3",
			FirstSeenAt:    firstSeen,
			LastSeenAt:     firstSeen,
		}},
	}
	report := scan.CombinedVulnerabilityReport{
		GeneratedAt: time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC),
		Vulnerabilities: []scan.VulnerabilityFinding{{
			ID:             "CVE-2024-0001",
			Severity:       "HIGH",
			PackageName:    "openssl",
			PackageVersion: "1.2.3",
			Scanners:       []string{"grype"},
		}},
	}

	record, err := BuildRecordFromReport("demo-org", "demo-image", "", report, previous, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRecordFromReport() error = %v", err)
	}
	if got, want := record.ImageName, "alpine:latest"; got != want {
		t.Fatalf("record.ImageName = %q, want %q", got, want)
	}
	if got, want := record.Vulnerabilities[0].FirstSeenAt, firstSeen; !got.Equal(want) {
		t.Fatalf("FirstSeenAt = %v, want %v", got, want)
	}
}

func TestParseOpenVEXDocumentRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	if _, err := parseOpenVEXDocument([]byte(`not-json`), "invalid.json", time.Now().UTC()); err == nil {
		t.Fatal("expected parseOpenVEXDocument() to reject invalid JSON")
	}
}

func TestVulnerabilityRecordJSONRoundTrip(t *testing.T) {
	t.Parallel()

	record := Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:latest",
		Summary:   Summary{Total: 1},
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var decoded Record
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.ImageName != record.ImageName {
		t.Fatalf("decoded record = %#v", decoded)
	}
}
