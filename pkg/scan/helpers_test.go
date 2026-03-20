package scan

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	grypematch "github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
)

func TestContextRegistryOptionsRoundTrip(t *testing.T) {
	t.Parallel()

	options := &stereoscopeimage.RegistryOptions{InsecureUseHTTP: true}
	ctx := ContextWithRegistryOptions(context.Background(), options)
	if got := RegistryOptionsFromContext(ctx); got != options {
		t.Fatalf("RegistryOptionsFromContext() = %#v, want %#v", got, options)
	}
	if got := RegistryOptionsFromContext(context.Background()); got != nil {
		t.Fatalf("RegistryOptionsFromContext(background) = %#v, want nil", got)
	}
}

func TestContextPlatformRoundTrip(t *testing.T) {
	t.Parallel()

	platform, err := stereoscopeimage.NewPlatform("linux/arm64")
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	ctx := ContextWithPlatform(context.Background(), platform)
	if got := PlatformFromContext(ctx); got != platform {
		t.Fatalf("PlatformFromContext() = %#v, want %#v", got, platform)
	}
	if got := PlatformFromContext(context.Background()); got != nil {
		t.Fatalf("PlatformFromContext(background) = %#v, want nil", got)
	}
}

func TestDirectorySBOMGenerationHelpers(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "package.json"), []byte(`{"name":"demo","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	src, err := GetSource(context.Background(), rootDir)
	if err != nil {
		t.Fatalf("GetSource() error = %v", err)
	}

	document, err := GetSBOM(context.Background(), src)
	if err != nil {
		t.Fatalf("GetSBOM() error = %v", err)
	}
	if document == nil {
		t.Fatal("expected SBOM document")
	}

	cyclone, sbomData, err := GenerateSBOMDocument(context.Background(), src)
	if err != nil {
		t.Fatalf("GenerateSBOMDocument() error = %v", err)
	}
	if len(cyclone) == 0 || sbomData == nil {
		t.Fatalf("unexpected GenerateSBOMDocument() result: %d bytes %#v", len(cyclone), sbomData)
	}

	if got, want := ImageReference("alpine:latest"), "alpine:latest"; got != want {
		t.Fatalf("ImageReference() = %q, want %q", got, want)
	}
}

func TestSBOMHelpersErrorPaths(t *testing.T) {
	t.Parallel()

	if _, err := GetSource(context.Background(), "::::"); err == nil {
		t.Fatal("expected GetSource() to reject invalid input")
	}

	rootDir := t.TempDir()
	sbomData := analyzerTestSBOM()
	if err := SaveSBOMToFile(sbomData, filepath.Join(rootDir, "missing", "sbom.json")); err == nil {
		t.Fatal("expected SaveSBOMToFile() to fail for missing parent directory")
	}

	if err := PrintToTerminal(failingReadSeeker{}); err == nil {
		t.Fatal("expected PrintToTerminal() to fail when the reader errors")
	}
}

func TestPrintToTerminalSuccess(t *testing.T) {
	t.Parallel()

	if err := PrintToTerminal(strings.NewReader("otter")); err != nil {
		t.Fatalf("PrintToTerminal() error = %v", err)
	}
}

func TestGrypeHelperFunctions(t *testing.T) {
	t.Parallel()

	scanner := NewGrypeVulnerabilityScanner(Options{UseCPEs: true})
	if got, want := scanner.Name(), "grype"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}

	matchers := createMatchers(true)
	if len(matchers) == 0 {
		t.Fatal("expected createMatchers() to return matchers")
	}

	wrapped := NewGrypeVulnerabilityMatcher(nil, true)
	if wrapped == nil || len(wrapped.Matchers) == 0 {
		t.Fatalf("NewGrypeVulnerabilityMatcher() = %#v", wrapped)
	}

	finding := findingFromGrypeMatch(grypematch.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-2024-0001",
				Namespace: "nvd:cpe",
			},
			Fix: vulnerability.Fix{Versions: []string{"1.2.4", "1.2.3"}},
			Metadata: &vulnerability.Metadata{
				Severity:    "HIGH",
				Description: "openssl issue",
				DataSource:  "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
				URLs:        []string{"https://example.com/advisory"},
				Cvss: []vulnerability.Cvss{
					{
						Source:  "nvd",
						Version: "3.1",
						Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Metrics: vulnerability.CvssMetrics{BaseScore: 7.5},
					},
				},
			},
		},
		Package: grypepkg.Package{
			Name:    "openssl",
			Version: "1.2.3",
			Type:    "apk",
		},
	})
	if got, want := finding.FixVersion, "1.2.3"; got != want {
		t.Fatalf("finding.FixVersion = %q, want %q", got, want)
	}
	if len(finding.CVSS) != 1 || len(finding.References) != 2 {
		t.Fatalf("finding = %#v", finding)
	}

	if got := grypeSeverity(nil); got != "UNKNOWN" {
		t.Fatalf("grypeSeverity(nil) = %q, want UNKNOWN", got)
	}
	if got := grypeDescription(nil); got != "" {
		t.Fatalf("grypeDescription(nil) = %q, want empty", got)
	}
	if got := grypePrimaryURL(nil); got != "" {
		t.Fatalf("grypePrimaryURL(nil) = %q, want empty", got)
	}
	if got := grypeReferences(nil); got != nil {
		t.Fatalf("grypeReferences(nil) = %#v, want nil", got)
	}
	if got := grypeCVSS(nil); got != nil {
		t.Fatalf("grypeCVSS(nil) = %#v, want nil", got)
	}

	data, err := marshalIndented(map[string]any{"ok": true})
	if err != nil {
		t.Fatalf("marshalIndented() error = %v", err)
	}
	var decoded map[string]bool
	if err := json.Unmarshal(data, &decoded); err != nil || !decoded["ok"] {
		t.Fatalf("marshalIndented() output = %s, err = %v", data, err)
	}

	if got, want := defaultGrypeOptions().MaxAllowedBuildAge, 120*time.Hour; got != want {
		t.Fatalf("defaultGrypeOptions().MaxAllowedBuildAge = %s, want %s", got, want)
	}
}

type failingReadSeeker struct{}

func (failingReadSeeker) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}

func (failingReadSeeker) Seek(int64, int) (int64, error) {
	return 0, nil
}

var _ io.ReadSeeker = failingReadSeeker{}
