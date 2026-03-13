package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/anchore/syft/syft/sbom"
)

type TrivyScanner struct {
	binaryPath string
	serverURL  string
	timeout    time.Duration
	scanners   []string
	runner     CommandRunner
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func NewTrivyScanner(cfg Config) *TrivyScanner {
	return &TrivyScanner{
		binaryPath: cfg.TrivyBinary,
		serverURL:  strings.TrimSpace(cfg.TrivyServerURL),
		timeout:    cfg.TrivyTimeout,
		scanners:   append([]string(nil), cfg.TrivyScanners...),
		runner:     ExecCommandRunner{},
	}
}

func (s *TrivyScanner) Name() string {
	return "trivy"
}

func (s *TrivyScanner) Scan(ctx context.Context, imageRef string, _ *sbom.SBOM) (ScannerReport, error) {
	if s.serverURL == "" {
		return ScannerReport{}, fmt.Errorf("trivy server URL is not configured")
	}

	scanCtx := ctx
	cancel := func() {}
	if s.timeout > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, s.timeout)
	}
	defer cancel()

	args := []string{
		"image",
		"--server", s.serverURL,
		"--format", "json",
		"--quiet",
	}
	if len(s.scanners) > 0 {
		args = append(args, "--scanners", strings.Join(s.scanners, ","))
	}
	args = append(args, imageRef)

	stdout, stderr, err := s.runner.Run(scanCtx, s.binaryPath, args...)
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if message == "" {
			message = strings.TrimSpace(string(stdout))
		}
		return ScannerReport{}, fmt.Errorf("run trivy client: %w: %s", err, message)
	}

	var report trivyScanReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		return ScannerReport{}, fmt.Errorf("decode trivy response: %w", err)
	}

	findings := make([]VulnerabilityFinding, 0)
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			findings = append(findings, findingFromTrivy(result, vulnerability))
		}
	}

	return ScannerReport{
		Scanner:     s.Name(),
		ContentType: "application/json",
		Document:    stdout,
		Findings:    findings,
	}, nil
}

type trivyScanReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string                   `json:"VulnerabilityID"`
	PkgName          string                   `json:"PkgName"`
	InstalledVersion string                   `json:"InstalledVersion"`
	FixedVersion     string                   `json:"FixedVersion"`
	Title            string                   `json:"Title"`
	Description      string                   `json:"Description"`
	PrimaryURL       string                   `json:"PrimaryURL"`
	Severity         string                   `json:"Severity"`
	References       []string                 `json:"References"`
	CVSS             map[string]trivyCVSSInfo `json:"CVSS"`
}

type trivyCVSSInfo struct {
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
}

func findingFromTrivy(result trivyResult, vulnerability trivyVulnerability) VulnerabilityFinding {
	finding := VulnerabilityFinding{
		ID:             vulnerability.VulnerabilityID,
		Severity:       vulnerability.Severity,
		PackageName:    vulnerability.PkgName,
		PackageVersion: vulnerability.InstalledVersion,
		PackageType:    firstNonEmpty(result.Type, result.Class),
		Title:          vulnerability.Title,
		Description:    vulnerability.Description,
		PrimaryURL:     vulnerability.PrimaryURL,
		References:     vulnerability.References,
		Scanners:       []string{"trivy"},
		CVSS:           trivyCVSS(vulnerability.CVSS),
	}
	if fixedVersion := strings.TrimSpace(vulnerability.FixedVersion); fixedVersion != "" {
		finding.FixVersion = fixedVersion
		finding.FixVersions = []string{fixedVersion}
	}
	return finding
}

func trivyCVSS(scores map[string]trivyCVSSInfo) []CVSSScore {
	if len(scores) == 0 {
		return nil
	}
	result := make([]CVSSScore, 0, len(scores)*2)
	for source, item := range scores {
		if item.V3Score > 0 {
			result = append(result, CVSSScore{
				Source:  source,
				Version: "3",
				Vector:  item.V3Vector,
				Score:   item.V3Score,
			})
		}
		if item.V2Score > 0 {
			result = append(result, CVSSScore{
				Source:  source,
				Version: "2",
				Vector:  item.V2Vector,
				Score:   item.V2Score,
			})
		}
	}
	return uniqueSortedCVSS(result)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
