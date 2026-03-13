package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
)

type GrypeVulnerabilityScanner struct {
	options Options
}

func NewGrypeVulnerabilityScanner(opts Options) *GrypeVulnerabilityScanner {
	return &GrypeVulnerabilityScanner{options: opts}
}

func (s *GrypeVulnerabilityScanner) Name() string {
	return "grype"
}

func (s *GrypeVulnerabilityScanner) Scan(ctx context.Context, _ string, document *sbom.SBOM) (ScannerReport, error) {
	scanner, err := NewScanner(s.options)
	if err != nil {
		return ScannerReport{}, fmt.Errorf("create grype scanner: %w", err)
	}

	syftPkgs := document.Artifacts.Packages.Sorted()
	grypePkgs := grypePkg.FromPackages(syftPkgs, grypePkg.SynthesisConfig{
		GenerateMissingCPEs: false,
	})

	grypeContext := grypePkg.Context{
		Source: &document.Source,
		Distro: distro.FromRelease(document.Artifacts.LinuxDistribution, nil),
	}

	matchesCollection, _, err := scanner.vulnerabilityMatcher.FindMatches(grypePkgs, grypeContext)
	if err != nil {
		return ScannerReport{}, fmt.Errorf("find vulnerabilities: %w", err)
	}

	matches := matchesCollection.Sorted()
	rawDocument, err := marshalIndented(matches)
	if err != nil {
		return ScannerReport{}, fmt.Errorf("encode vulnerabilities: %w", err)
	}

	findings := make([]VulnerabilityFinding, 0, len(matches))
	for _, matched := range matches {
		findings = append(findings, findingFromGrypeMatch(matched))
	}

	return ScannerReport{
		Scanner:     s.Name(),
		ContentType: "application/json",
		Document:    rawDocument,
		Findings:    findings,
	}, nil
}

func marshalIndented(value any) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func findingFromGrypeMatch(matched match.Match) VulnerabilityFinding {
	fixVersions := uniqueSortedStrings(matched.Vulnerability.Fix.Versions)
	finding := VulnerabilityFinding{
		ID:             matched.Vulnerability.ID,
		Severity:       grypeSeverity(matched.Vulnerability.Metadata),
		PackageName:    matched.Package.Name,
		PackageVersion: matched.Package.Version,
		PackageType:    strings.TrimSpace(string(matched.Package.Type)),
		Namespace:      matched.Vulnerability.Namespace,
		Description:    grypeDescription(matched.Vulnerability.Metadata),
		PrimaryURL:     grypePrimaryURL(matched.Vulnerability.Metadata),
		References:     grypeReferences(matched.Vulnerability.Metadata),
		FixVersions:    fixVersions,
		Scanners:       []string{"grype"},
		CVSS:           grypeCVSS(matched.Vulnerability.Metadata),
	}
	if len(fixVersions) > 0 {
		finding.FixVersion = fixVersions[0]
	}
	return finding
}

func grypeSeverity(metadata *vulnerability.Metadata) string {
	if metadata == nil {
		return "UNKNOWN"
	}
	return metadata.Severity
}

func grypeDescription(metadata *vulnerability.Metadata) string {
	if metadata == nil {
		return ""
	}
	return metadata.Description
}

func grypePrimaryURL(metadata *vulnerability.Metadata) string {
	if metadata == nil {
		return ""
	}
	return metadata.DataSource
}

func grypeReferences(metadata *vulnerability.Metadata) []string {
	if metadata == nil {
		return nil
	}
	references := append([]string(nil), metadata.URLs...)
	if metadata.DataSource != "" {
		references = append(references, metadata.DataSource)
	}
	return uniqueSortedStrings(references)
}

func grypeCVSS(metadata *vulnerability.Metadata) []CVSSScore {
	if metadata == nil {
		return nil
	}
	result := make([]CVSSScore, 0, len(metadata.Cvss))
	for _, item := range metadata.Cvss {
		score := item.Metrics.BaseScore
		if score <= 0 {
			continue
		}
		result = append(result, CVSSScore{
			Source:  item.Source,
			Version: item.Version,
			Vector:  item.Vector,
			Score:   score,
		})
	}
	return uniqueSortedCVSS(result)
}

func defaultGrypeOptions() Options {
	return Options{MaxAllowedBuildAge: 120 * time.Hour}
}
