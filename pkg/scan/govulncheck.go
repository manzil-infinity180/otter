package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anchore/syft/syft/sbom"
)

// GovulncheckScanner runs govulncheck for Go-specific reachability analysis.
type GovulncheckScanner struct {
	binaryPath string
	timeout    time.Duration
	runner     CommandRunner
}

// NewGovulncheckScanner creates a scanner using the govulncheck binary.
func NewGovulncheckScanner(binaryPath string, timeout time.Duration, runner CommandRunner) *GovulncheckScanner {
	if binaryPath == "" {
		binaryPath = "govulncheck"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	return &GovulncheckScanner{
		binaryPath: binaryPath,
		timeout:    timeout,
		runner:     runner,
	}
}

func (s *GovulncheckScanner) Name() string { return "govulncheck" }

func (s *GovulncheckScanner) Scan(ctx context.Context, imageRef string, document *sbom.SBOM) (ScannerReport, error) {
	scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	args := []string{
		"-mode", "binary",
		"-format", "json",
		"-scan", imageRef,
	}

	stdout, stderr, err := s.runner.Run(scanCtx, s.binaryPath, args...)
	if err != nil {
		// govulncheck exits non-zero when vulnerabilities are found
		if len(stdout) == 0 {
			return ScannerReport{Scanner: s.Name(), Status: ScannerStatusUnavailable, Message: fmt.Sprintf("govulncheck execution failed: %v (stderr: %s)", err, strings.TrimSpace(string(stderr)))}, nil
		}
	}

	findings, err := parseGovulncheckOutput(stdout)
	if err != nil {
		return ScannerReport{Scanner: s.Name(), Status: ScannerStatusUnavailable, Message: fmt.Sprintf("parse govulncheck output: %v", err)}, nil
	}

	report := ScannerReport{
		Scanner:     s.Name(),
		Status:      ScannerStatusCompleted,
		ContentType: "application/json",
		Document:    stdout,
		Findings:    findings,
	}
	return report, nil
}

type govulncheckOutput struct {
	Vulns []govulncheckVuln `json:"vulns"`
}

type govulncheckVuln struct {
	OSV     string                `json:"osv"`
	Modules []govulncheckModule   `json:"modules"`
}

type govulncheckModule struct {
	Path     string               `json:"path"`
	Packages []govulncheckPackage `json:"packages"`
	FixedIn  string               `json:"fixed_in,omitempty"`
}

type govulncheckPackage struct {
	Path      string   `json:"path"`
	Callstacks []any   `json:"callstacks,omitempty"`
}

func parseGovulncheckOutput(data []byte) ([]VulnerabilityFinding, error) {
	var output govulncheckOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("unmarshal govulncheck: %w", err)
	}

	var findings []VulnerabilityFinding
	for _, vuln := range output.Vulns {
		for _, mod := range vuln.Modules {
			reachable := false
			for _, pkg := range mod.Packages {
				if len(pkg.Callstacks) > 0 {
					reachable = true
					break
				}
			}

			severity := "MEDIUM"
			if reachable {
				severity = "HIGH"
			}

			finding := VulnerabilityFinding{
				ID:          vuln.OSV,
				Severity:    severity,
				PackageName: mod.Path,
				FixVersion:  mod.FixedIn,
				Scanners:    []string{"govulncheck"},
			}
			if reachable {
				finding.Description = "Reachable vulnerability — call path exists to vulnerable code"
			} else {
				finding.Description = "Imported but not reachable via call graph analysis"
			}
			findings = append(findings, finding)
		}
	}
	return findings, nil
}
