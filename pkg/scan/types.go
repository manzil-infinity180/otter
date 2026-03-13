package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/syft/sbom"
)

type ImageAnalyzer interface {
	Analyze(ctx context.Context, imageRef string) (AnalysisResult, error)
}

type SBOMGenerator interface {
	Generate(ctx context.Context, imageRef string) ([]byte, *sbom.SBOM, error)
}

type VulnerabilityScanner interface {
	Name() string
	Scan(ctx context.Context, imageRef string, document *sbom.SBOM) (ScannerReport, error)
}

type AnalysisResult struct {
	ImageRef                string
	SBOMDocument            []byte
	SBOMSPDXDocument        []byte
	SBOMData                *sbom.SBOM
	CombinedReport          CombinedVulnerabilityReport
	CombinedVulnerabilities []byte
	Summary                 VulnerabilitySummary
	ScannerReports          []ScannerReport
}

type ScannerReport struct {
	Scanner     string                 `json:"scanner"`
	ContentType string                 `json:"content_type"`
	Document    []byte                 `json:"-"`
	Findings    []VulnerabilityFinding `json:"findings"`
}

func (r ScannerReport) Filename() string {
	return fmt.Sprintf("%s-vulnerabilities.json", r.Scanner)
}

type CVSSScore struct {
	Source  string  `json:"source,omitempty"`
	Version string  `json:"version,omitempty"`
	Vector  string  `json:"vector,omitempty"`
	Score   float64 `json:"score"`
}

type VulnerabilityFinding struct {
	ID             string      `json:"id"`
	Severity       string      `json:"severity"`
	PackageName    string      `json:"package_name"`
	PackageVersion string      `json:"package_version,omitempty"`
	PackageType    string      `json:"package_type,omitempty"`
	Namespace      string      `json:"namespace,omitempty"`
	Title          string      `json:"title,omitempty"`
	Description    string      `json:"description,omitempty"`
	PrimaryURL     string      `json:"primary_url,omitempty"`
	References     []string    `json:"references,omitempty"`
	FixVersion     string      `json:"fix_version,omitempty"`
	FixVersions    []string    `json:"fix_versions,omitempty"`
	CVSS           []CVSSScore `json:"cvss,omitempty"`
	Scanners       []string    `json:"scanners"`
}

type VulnerabilitySummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByScanner  map[string]int `json:"by_scanner"`
	Fixable    int            `json:"fixable"`
	Unfixable  int            `json:"unfixable"`
}

type CombinedVulnerabilityReport struct {
	SchemaVersion   string                 `json:"schema_version"`
	ImageRef        string                 `json:"image_ref"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Summary         VulnerabilitySummary   `json:"summary"`
	Vulnerabilities []VulnerabilityFinding `json:"vulnerabilities"`
}

func BuildCombinedReport(imageRef string, reports []ScannerReport) (CombinedVulnerabilityReport, []byte, error) {
	now := time.Now().UTC()
	index := make(map[string]*VulnerabilityFinding)
	order := make([]string, 0)

	for _, report := range reports {
		for _, finding := range report.Findings {
			normalized := normalizeFinding(finding)
			key := vulnerabilityKey(normalized)
			existing, ok := index[key]
			if !ok {
				copyFinding := normalized
				index[key] = &copyFinding
				order = append(order, key)
				continue
			}
			mergeFinding(existing, normalized)
		}
	}

	vulnerabilities := make([]VulnerabilityFinding, 0, len(order))
	for _, key := range order {
		vulnerabilities = append(vulnerabilities, *index[key])
	}
	sort.Slice(vulnerabilities, func(i, j int) bool {
		a := vulnerabilities[i]
		b := vulnerabilities[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.PackageName != b.PackageName {
			return a.PackageName < b.PackageName
		}
		return a.PackageVersion < b.PackageVersion
	})

	summary := summarizeFindings(vulnerabilities)
	report := CombinedVulnerabilityReport{
		SchemaVersion:   "v1alpha1",
		ImageRef:        imageRef,
		GeneratedAt:     now,
		Summary:         summary,
		Vulnerabilities: vulnerabilities,
	}

	document, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return CombinedVulnerabilityReport{}, nil, fmt.Errorf("marshal combined vulnerability report: %w", err)
	}

	return report, document, nil
}

func summarizeFindings(findings []VulnerabilityFinding) VulnerabilitySummary {
	summary := VulnerabilitySummary{
		Total:      len(findings),
		BySeverity: make(map[string]int),
		ByScanner:  make(map[string]int),
	}

	for _, finding := range findings {
		severity := normalizeSeverity(finding.Severity)
		summary.BySeverity[severity]++
		if finding.FixVersion == "" {
			summary.Unfixable++
		} else {
			summary.Fixable++
		}
		for _, scanner := range finding.Scanners {
			summary.ByScanner[scanner]++
		}
	}

	return summary
}

func normalizeFinding(f VulnerabilityFinding) VulnerabilityFinding {
	f.ID = strings.TrimSpace(strings.ToUpper(f.ID))
	f.Severity = normalizeSeverity(f.Severity)
	f.PackageName = strings.TrimSpace(f.PackageName)
	f.PackageVersion = strings.TrimSpace(f.PackageVersion)
	f.PackageType = strings.TrimSpace(f.PackageType)
	f.Namespace = strings.TrimSpace(f.Namespace)
	f.Title = strings.TrimSpace(f.Title)
	f.Description = strings.TrimSpace(f.Description)
	f.PrimaryURL = strings.TrimSpace(f.PrimaryURL)
	f.References = uniqueSortedStrings(f.References)
	f.FixVersions = uniqueSortedStrings(f.FixVersions)
	if f.FixVersion == "" && len(f.FixVersions) > 0 {
		f.FixVersion = f.FixVersions[0]
	}
	f.Scanners = uniqueSortedStrings(f.Scanners)
	f.CVSS = uniqueSortedCVSS(f.CVSS)
	return f
}

func mergeFinding(dst *VulnerabilityFinding, src VulnerabilityFinding) {
	if severityRank(src.Severity) > severityRank(dst.Severity) {
		dst.Severity = src.Severity
	}
	if dst.PackageType == "" {
		dst.PackageType = src.PackageType
	}
	if dst.Namespace == "" {
		dst.Namespace = src.Namespace
	}
	if dst.Title == "" {
		dst.Title = src.Title
	}
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if dst.PrimaryURL == "" {
		dst.PrimaryURL = src.PrimaryURL
	}
	dst.References = uniqueSortedStrings(append(dst.References, src.References...))
	dst.FixVersions = uniqueSortedStrings(append(dst.FixVersions, src.FixVersions...))
	if dst.FixVersion == "" && src.FixVersion != "" {
		dst.FixVersion = src.FixVersion
	}
	if dst.FixVersion == "" && len(dst.FixVersions) > 0 {
		dst.FixVersion = dst.FixVersions[0]
	}
	dst.Scanners = uniqueSortedStrings(append(dst.Scanners, src.Scanners...))
	dst.CVSS = uniqueSortedCVSS(append(dst.CVSS, src.CVSS...))
}

func vulnerabilityKey(f VulnerabilityFinding) string {
	return strings.Join([]string{
		strings.ToUpper(f.ID),
		strings.ToLower(f.PackageName),
		f.PackageVersion,
		strings.ToLower(f.Namespace),
	}, "|")
}

func normalizeSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "NEGLIGIBLE":
		return "NEGLIGIBLE"
	default:
		return "UNKNOWN"
	}
}

func severityRank(severity string) int {
	switch normalizeSeverity(severity) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NEGLIGIBLE":
		return 1
	default:
		return 0
	}
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil
	}
	return result
}

func uniqueSortedCVSS(values []CVSSScore) []CVSSScore {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]CVSSScore, 0, len(values))
	for _, value := range values {
		key := fmt.Sprintf("%s|%s|%s|%.2f", value.Source, value.Version, value.Vector, value.Score)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		return result[i].Version < result[j].Version
	})
	return result
}
