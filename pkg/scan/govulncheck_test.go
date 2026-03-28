package scan

import (
	"testing"
)

func TestParseGovulncheckOutput(t *testing.T) {
	output := `{
		"vulns": [
			{
				"osv": "GO-2024-0001",
				"modules": [
					{
						"path": "golang.org/x/net",
						"fixed_in": "v0.20.0",
						"packages": [
							{"path": "golang.org/x/net/http2", "callstacks": [{"summary": "main calls http2.Transport.RoundTrip"}]}
						]
					}
				]
			},
			{
				"osv": "GO-2024-0002",
				"modules": [
					{
						"path": "golang.org/x/crypto",
						"fixed_in": "v0.18.0",
						"packages": [
							{"path": "golang.org/x/crypto/ssh"}
						]
					}
				]
			}
		]
	}`

	findings, err := parseGovulncheckOutput([]byte(output))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First vuln is reachable
	if findings[0].ID != "GO-2024-0001" {
		t.Fatalf("expected GO-2024-0001, got %s", findings[0].ID)
	}
	if findings[0].Severity != "HIGH" {
		t.Fatalf("expected HIGH for reachable vuln, got %s", findings[0].Severity)
	}
	if findings[0].FixVersion != "v0.20.0" {
		t.Fatalf("expected fix v0.20.0, got %s", findings[0].FixVersion)
	}

	// Second vuln is not reachable
	if findings[1].Severity != "MEDIUM" {
		t.Fatalf("expected MEDIUM for non-reachable vuln, got %s", findings[1].Severity)
	}
}

func TestParseGovulncheckEmptyOutput(t *testing.T) {
	findings, err := parseGovulncheckOutput([]byte(`{"vulns": null}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
