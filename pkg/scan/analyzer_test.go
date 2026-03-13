package scan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
)

type stubSBOMGenerator struct {
	document []byte
	sbom     *syftsbom.SBOM
	err      error
}

func (s stubSBOMGenerator) Generate(context.Context, string) ([]byte, *syftsbom.SBOM, error) {
	return s.document, s.sbom, s.err
}

type stubVulnerabilityScanner struct {
	name   string
	report ScannerReport
	err    error
}

func (s stubVulnerabilityScanner) Name() string {
	return s.name
}

func (s stubVulnerabilityScanner) Scan(context.Context, string, *syftsbom.SBOM) (ScannerReport, error) {
	if s.err != nil {
		return ScannerReport{}, s.err
	}
	return s.report, nil
}

func TestAnalyzerAnalyzeBuildsCombinedResult(t *testing.T) {
	t.Parallel()

	document := []byte(`{"bomFormat":"CycloneDX"}`)
	sbomData := analyzerTestSBOM()

	analyzer := NewAnalyzer(
		stubSBOMGenerator{document: document, sbom: sbomData},
		stubVulnerabilityScanner{
			name: "grype",
			report: ScannerReport{
				Scanner: "grype",
				Findings: []VulnerabilityFinding{
					{
						ID:             "CVE-2024-0001",
						Severity:       "HIGH",
						PackageName:    "busybox",
						PackageVersion: "1.36.1",
						FixVersion:     "1.36.2",
						Scanners:       []string{"grype"},
					},
				},
			},
		},
		stubVulnerabilityScanner{
			name: "trivy",
			report: ScannerReport{
				Scanner: "trivy",
				Findings: []VulnerabilityFinding{
					{
						ID:             "CVE-2024-0001",
						Severity:       "CRITICAL",
						PackageName:    "busybox",
						PackageVersion: "1.36.1",
						Scanners:       []string{"trivy"},
					},
				},
			},
		},
	)

	result, err := analyzer.Analyze(context.Background(), "alpine:latest")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if !bytes.Equal(result.SBOMDocument, document) {
		t.Fatalf("result.SBOMDocument = %q, want %q", result.SBOMDocument, document)
	}
	if len(result.SBOMSPDXDocument) == 0 {
		t.Fatal("expected SPDX document to be generated")
	}
	if got, want := result.Summary.Total, 1; got != want {
		t.Fatalf("result.Summary.Total = %d, want %d", got, want)
	}
	if got, want := result.CombinedReport.Vulnerabilities[0].Severity, "CRITICAL"; got != want {
		t.Fatalf("combined severity = %q, want %q", got, want)
	}
	if got, want := len(result.ScannerReports), 2; got != want {
		t.Fatalf("len(result.ScannerReports) = %d, want %d", got, want)
	}
}

func TestAnalyzerAnalyzeReturnsScannerError(t *testing.T) {
	t.Parallel()

	analyzer := NewAnalyzer(
		stubSBOMGenerator{document: []byte(`{}`), sbom: analyzerTestSBOM()},
		stubVulnerabilityScanner{name: "grype", err: errors.New("database unavailable")},
	)

	if _, err := analyzer.Analyze(context.Background(), "alpine:latest"); err == nil || !strings.Contains(err.Error(), "grype scan") {
		t.Fatalf("Analyze() error = %v, want scanner context", err)
	}
}

func TestSchemaEncodersAndFileHelpers(t *testing.T) {
	t.Parallel()

	sbomData := analyzerTestSBOM()

	cycloneReader, err := ToCycloneDxSchema(sbomData)
	if err != nil {
		t.Fatalf("ToCycloneDxSchema() error = %v", err)
	}
	cycloneData := mustReadAll(t, cycloneReader)
	if !strings.Contains(string(cycloneData), `"bomFormat":"CycloneDX"`) {
		t.Fatalf("cyclonedx output = %s", cycloneData)
	}

	spdxDocument, err := GenerateSPDXDocument(sbomData)
	if err != nil {
		t.Fatalf("GenerateSPDXDocument() error = %v", err)
	}
	if !strings.Contains(string(spdxDocument), `"spdxVersion"`) {
		t.Fatalf("spdx output = %s", spdxDocument)
	}

	redactedReader, err := ToSyftJSONSchemaRedacted(sbomData)
	if err != nil {
		t.Fatalf("ToSyftJSONSchemaRedacted() error = %v", err)
	}
	redactedData := mustReadAll(t, redactedReader)
	if strings.Contains(string(redactedData), "schema-version") {
		t.Fatalf("expected redacted schema, got %s", redactedData)
	}

	outputPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := SaveSBOMToFile(sbomData, outputPath); err != nil {
		t.Fatalf("SaveSBOMToFile() error = %v", err)
	}
	if saved, err := os.ReadFile(outputPath); err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	} else if !strings.Contains(string(saved), `"bomFormat":"CycloneDX"`) {
		t.Fatalf("saved sbom = %s", saved)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("OTTER_TRIVY_ENABLED", "true")
	t.Setenv("OTTER_TRIVY_SERVER_URL", "http://trivy:4954")
	t.Setenv("OTTER_TRIVY_BINARY", "/usr/local/bin/trivy")
	t.Setenv("OTTER_TRIVY_TIMEOUT", "90s")
	t.Setenv("OTTER_TRIVY_SCANNERS", "vuln,secret")

	cfg := ConfigFromEnv()

	if !cfg.TrivyEnabled {
		t.Fatal("expected Trivy to be enabled")
	}
	if got, want := cfg.TrivyBinary, "/usr/local/bin/trivy"; got != want {
		t.Fatalf("TrivyBinary = %q, want %q", got, want)
	}
	if got, want := cfg.TrivyTimeout.String(), "1m30s"; got != want {
		t.Fatalf("TrivyTimeout = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.TrivyScanners, ","), "vuln,secret"; got != want {
		t.Fatalf("TrivyScanners = %q, want %q", got, want)
	}
}

func TestGenerateSPDXDocumentRequiresSBOM(t *testing.T) {
	t.Parallel()

	if _, err := GenerateSPDXDocument(nil); err == nil {
		t.Fatal("expected GenerateSPDXDocument(nil) to fail")
	}
}

func analyzerTestSBOM() *syftsbom.SBOM {
	root := syftpkg.Package{Name: "alpine", Version: "3.20.0", Type: syftpkg.Type("apk")}
	root.SetID()

	dependency := syftpkg.Package{Name: "busybox", Version: "1.36.1", Type: syftpkg.Type("apk")}
	dependency.SetID()

	return &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(root, dependency),
		},
		Relationships: []artifact.Relationship{
			{
				From: dependency,
				To:   root,
				Type: artifact.DependencyOfRelationship,
			},
		},
	}
}

func mustReadAll(t *testing.T, reader interface{ Read([]byte) (int, error) }) []byte {
	t.Helper()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	return data
}
