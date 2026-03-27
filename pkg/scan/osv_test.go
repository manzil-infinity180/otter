package scan

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

func TestOSVScannerScanParsesFindings(t *testing.T) {
	t.Parallel()

	runner := &mockCommandRunner{
		stdout: []byte(`{
  "results": [
    {
      "source": { "path": "/tmp/sbom.json", "type": "lockfile" },
      "packages": [
        {
          "package": { "name": "lodash", "version": "4.17.20", "ecosystem": "npm" },
          "vulnerabilities": [
            {
              "id": "GHSA-xxxx-yyyy-zzzz",
              "summary": "Prototype Pollution in lodash",
              "detail": "Lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution.",
              "aliases": ["CVE-2021-23337"],
              "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
              "affected": [
                {
                  "package": { "ecosystem": "npm", "name": "lodash" },
                  "ranges": [{ "type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}] }]
                }
              ],
              "references": [{ "type": "WEB", "url": "https://github.com/lodash/lodash/issues/5261" }],
              "database_specific": { "severity": "HIGH" }
            }
          ],
          "groups": [{ "ids": ["GHSA-xxxx-yyyy-zzzz", "CVE-2021-23337"], "max_severity": "7.5" }]
        }
      ]
    }
  ]
}`),
	}

	scanner := &OSVScanner{
		binaryPath: "osv-scanner",
		runner:     runner,
	}

	report, err := scanner.Scan(context.Background(), "node:18-slim", nil)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if got, want := runner.name, "osv-scanner"; got != want {
		t.Fatalf("runner name = %s, want %s", got, want)
	}
	if got, want := report.Scanner, "osv"; got != want {
		t.Fatalf("report.Scanner = %s, want %s", got, want)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("len(report.Findings) = %d, want 1", len(report.Findings))
	}

	finding := report.Findings[0]
	if got, want := finding.ID, "CVE-2021-23337"; got != want {
		t.Fatalf("finding.ID = %s, want %s", got, want)
	}
	if got, want := finding.Severity, "HIGH"; got != want {
		t.Fatalf("finding.Severity = %s, want %s", got, want)
	}
	if got, want := finding.PackageName, "lodash"; got != want {
		t.Fatalf("finding.PackageName = %s, want %s", got, want)
	}
	if got, want := finding.PackageVersion, "4.17.20"; got != want {
		t.Fatalf("finding.PackageVersion = %s, want %s", got, want)
	}
	if got, want := finding.PackageType, "npm"; got != want {
		t.Fatalf("finding.PackageType = %s, want %s", got, want)
	}
	if got, want := finding.FixVersion, "4.17.21"; got != want {
		t.Fatalf("finding.FixVersion = %s, want %s", got, want)
	}
	if got, want := finding.Title, "Prototype Pollution in lodash"; got != want {
		t.Fatalf("finding.Title = %s, want %s", got, want)
	}
	if len(finding.References) != 1 {
		t.Fatalf("len(finding.References) = %d, want 1", len(finding.References))
	}
}

func TestOSVScannerScanReturnsRunnerError(t *testing.T) {
	t.Parallel()

	scanner := &OSVScanner{
		binaryPath: "osv-scanner",
		runner: &mockCommandRunner{
			stderr: []byte("command not found"),
			err:    exec.ErrNotFound,
		},
	}

	_, err := scanner.Scan(context.Background(), "alpine:latest", nil)
	if err == nil {
		t.Fatal("expected Scan() to fail")
	}
	if !IsScannerUnavailable(err) {
		t.Fatalf("expected ScannerUnavailableError, got %T: %v", err, err)
	}
}

func TestOSVScannerScanHandlesEmptyResults(t *testing.T) {
	t.Parallel()

	runner := &mockCommandRunner{
		stdout: []byte(`{"results": []}`),
	}

	scanner := &OSVScanner{
		binaryPath: "osv-scanner",
		runner:     runner,
	}

	report, err := scanner.Scan(context.Background(), "alpine:latest", nil)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got, want := len(report.Findings), 0; got != want {
		t.Fatalf("len(report.Findings) = %d, want %d", got, want)
	}
	if got, want := report.Scanner, "osv"; got != want {
		t.Fatalf("report.Scanner = %s, want %s", got, want)
	}
}

func TestOSVScannerScanReturnsGenericError(t *testing.T) {
	t.Parallel()

	scanner := &OSVScanner{
		binaryPath: "osv-scanner",
		runner: &mockCommandRunner{
			stderr: []byte("some error occurred"),
			err:    errors.New("exit status 1"),
		},
	}

	_, err := scanner.Scan(context.Background(), "alpine:latest", nil)
	if err == nil {
		t.Fatal("expected Scan() to fail")
	}
	if !IsScannerUnavailable(err) {
		t.Fatalf("expected ScannerUnavailableError, got %T: %v", err, err)
	}
}
