package scan

import (
	"context"
	"errors"
	"testing"
)

type mockCommandRunner struct {
	name   string
	args   []string
	stdout []byte
	stderr []byte
	err    error
}

func (m *mockCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	m.name = name
	m.args = append([]string(nil), args...)
	return m.stdout, m.stderr, m.err
}

func TestTrivyScannerScanParsesFindings(t *testing.T) {
	t.Parallel()

	runner := &mockCommandRunner{
		stdout: []byte(`{
  "Results": [
    {
      "Target": "alpine:3.20",
      "Class": "os-pkgs",
      "Type": "apk",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1234",
          "PkgName": "openssl",
          "InstalledVersion": "3.0.0-r0",
          "FixedVersion": "3.0.1-r0",
          "Title": "openssl issue",
          "Description": "details",
          "PrimaryURL": "https://example.com/CVE-2024-1234",
          "Severity": "HIGH",
          "References": ["https://example.com/ref"],
          "CVSS": {
            "nvd": {
              "V3Score": 7.5,
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
          }
        }
      ]
    }
  ]
}`),
	}

	scanner := &TrivyScanner{
		binaryPath: "trivy",
		serverURL:  "http://trivy:4954",
		scanners:   []string{"vuln"},
		runner:     runner,
	}

	report, err := scanner.Scan(context.Background(), "alpine:latest", nil)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if got, want := runner.name, "trivy"; got != want {
		t.Fatalf("runner name = %s, want %s", got, want)
	}
	if got, want := report.Scanner, "trivy"; got != want {
		t.Fatalf("report.Scanner = %s, want %s", got, want)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(report.Findings) = %d, want 1", len(report.Findings))
	}

	finding := report.Findings[0]
	if got, want := finding.ID, "CVE-2024-1234"; got != want {
		t.Fatalf("finding.ID = %s, want %s", got, want)
	}
	if got, want := finding.PackageType, "apk"; got != want {
		t.Fatalf("finding.PackageType = %s, want %s", got, want)
	}
	if got, want := finding.FixVersion, "3.0.1-r0"; got != want {
		t.Fatalf("finding.FixVersion = %s, want %s", got, want)
	}
	if got, want := len(finding.CVSS), 1; got != want {
		t.Fatalf("len(finding.CVSS) = %d, want %d", got, want)
	}
}

func TestTrivyScannerScanReturnsRunnerError(t *testing.T) {
	t.Parallel()

	scanner := &TrivyScanner{
		binaryPath: "trivy",
		serverURL:  "http://trivy:4954",
		runner: &mockCommandRunner{
			stderr: []byte("server unavailable"),
			err:    errors.New("exit status 1"),
		},
	}

	if _, err := scanner.Scan(context.Background(), "alpine:latest", nil); err == nil {
		t.Fatal("expected Scan() to fail")
	}
}
