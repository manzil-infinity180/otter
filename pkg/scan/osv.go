package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/syft/syft/sbom"
)

type OSVScanner struct {
	binaryPath string
	timeout    time.Duration
	runner     CommandRunner
}

func NewOSVScanner(cfg Config) *OSVScanner {
	return &OSVScanner{
		binaryPath: cfg.OSVBinary,
		timeout:    cfg.OSVTimeout,
		runner:     ExecCommandRunner{},
	}
}

func (s *OSVScanner) Name() string {
	return "osv"
}

func (s *OSVScanner) Scan(ctx context.Context, imageRef string, _ *sbom.SBOM) (ScannerReport, error) {
	scanCtx := ctx
	cancel := func() {}
	if s.timeout > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, s.timeout)
	}
	defer cancel()

	args := []string{
		"scan",
		"--docker", imageRef,
		"--format", "json",
	}

	stdout, stderr, err := s.runner.Run(scanCtx, s.binaryPath, args...)
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if message == "" {
			message = strings.TrimSpace(string(stdout))
		}
		if errors.Is(err, exec.ErrNotFound) {
			return ScannerReport{}, NewScannerUnavailableError(s.Name(), fmt.Sprintf("OSV scanner binary %q is not installed", s.binaryPath), err)
		}
		if message == "" {
			message = err.Error()
		}
		return ScannerReport{}, NewScannerUnavailableError(s.Name(), fmt.Sprintf("OSV scanner is unavailable: %s", message), err)
	}

	var report osvScanReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		return ScannerReport{}, fmt.Errorf("decode osv response: %w", err)
	}

	findings := make([]VulnerabilityFinding, 0)
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				findings = append(findings, findingFromOSV(pkg, vuln))
			}
		}
	}

	return ScannerReport{
		Scanner:     s.Name(),
		Status:      ScannerStatusCompleted,
		ContentType: "application/json",
		Document:    stdout,
		Findings:    findings,
	}, nil
}

// OSV JSON output types

type osvScanReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package         osvPackageInfo    `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	Groups          []osvGroup         `json:"groups"`
}

type osvPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID               string              `json:"id"`
	Summary          string              `json:"summary"`
	Detail           string              `json:"detail"`
	Aliases          []string            `json:"aliases"`
	Severity         []osvSeverity       `json:"severity"`
	Affected         []osvAffected       `json:"affected"`
	References       []osvReference      `json:"references"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackageInfo `json:"package"`
	Ranges  []osvRange     `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

type osvGroup struct {
	IDs         []string `json:"ids"`
	MaxSeverity string   `json:"max_severity"`
}

func findingFromOSV(pkg osvPackage, vuln osvVulnerability) VulnerabilityFinding {
	id := osvVulnID(vuln)
	severity := osvSeverityLevel(vuln)
	fixVersions := osvFixVersions(vuln, pkg.Package.Ecosystem)
	refs := osvReferenceURLs(vuln)

	finding := VulnerabilityFinding{
		ID:             id,
		Severity:       severity,
		PackageName:    pkg.Package.Name,
		PackageVersion: pkg.Package.Version,
		PackageType:    osvEcosystemToPackageType(pkg.Package.Ecosystem),
		Title:          vuln.Summary,
		Description:    vuln.Detail,
		References:     refs,
		Scanners:       []string{"osv"},
		CVSS:           osvCVSSScores(vuln.Severity),
	}

	if len(fixVersions) > 0 {
		finding.FixVersion = fixVersions[0]
		finding.FixVersions = fixVersions
	}

	if len(refs) > 0 {
		finding.PrimaryURL = refs[0]
	}

	return finding
}

// osvVulnID returns the CVE alias if available, otherwise the original vuln ID.
func osvVulnID(vuln osvVulnerability) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return vuln.ID
}

// osvSeverityLevel extracts severity from database_specific or CVSS score.
func osvSeverityLevel(vuln osvVulnerability) string {
	if s := strings.TrimSpace(vuln.DatabaseSpecific.Severity); s != "" {
		return strings.ToUpper(s)
	}
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := osvExtractCVSSScore(sev.Score)
			if score >= 9.0 {
				return "CRITICAL"
			} else if score >= 7.0 {
				return "HIGH"
			} else if score >= 4.0 {
				return "MEDIUM"
			} else if score > 0 {
				return "LOW"
			}
		}
	}
	return "UNKNOWN"
}

// osvExtractCVSSScore parses a numeric score from a CVSS vector string or plain number.
func osvExtractCVSSScore(vector string) float64 {
	// Try parsing as a plain number first.
	if score, err := strconv.ParseFloat(vector, 64); err == nil {
		return score
	}
	// Not a plain number; we can't easily extract a score from a vector string
	// without a CVSS library, so return 0.
	return 0
}

func osvFixVersions(vuln osvVulnerability, ecosystem string) []string {
	var versions []string
	for _, affected := range vuln.Affected {
		if !strings.EqualFold(affected.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if v := strings.TrimSpace(event.Fixed); v != "" {
					versions = append(versions, v)
				}
			}
		}
	}
	return uniqueSortedStrings(versions)
}

func osvReferenceURLs(vuln osvVulnerability) []string {
	urls := make([]string, 0, len(vuln.References))
	for _, ref := range vuln.References {
		if u := strings.TrimSpace(ref.URL); u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}

func osvCVSSScores(severities []osvSeverity) []CVSSScore {
	if len(severities) == 0 {
		return nil
	}
	result := make([]CVSSScore, 0, len(severities))
	for _, sev := range severities {
		if sev.Type == "CVSS_V3" {
			score := osvExtractCVSSScore(sev.Score)
			result = append(result, CVSSScore{
				Source:  "osv",
				Version: "3",
				Vector:  sev.Score,
				Score:   score,
			})
		}
	}
	return uniqueSortedCVSS(result)
}

func osvEcosystemToPackageType(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "pip"
	case "go":
		return "go"
	case "crates.io":
		return "cargo"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "rubygems":
		return "gem"
	case "packagist":
		return "composer"
	case "hex":
		return "hex"
	case "pub":
		return "pub"
	default:
		return strings.ToLower(ecosystem)
	}
}
