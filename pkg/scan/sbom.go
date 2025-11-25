package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/anchore/grype/grype/distro"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const defaultImage = "manzilrahul/k8s-custom-controller:latest"

func ImageReference() string {
	// read an image string reference from the command line or use a default
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return defaultImage
}

func GetSource(input string) source.Source {
	src, err := syft.GetSource(context.Background(), input, nil)
	if err != nil {
		panic(err)
	}

	return src
}

func GetSBOM(src source.Source, defaultTags ...string) sbom.SBOM {
	// cfg := syft.DefaultCreateSBOMConfig().
	// 	WithCatalogerSelection(
	// 		// here you can sub-select, add, remove catalogers from the default selection...
	// 		// or replace the default selection entirely!
	// 		cataloging.NewSelectionRequest().
	// 			WithDefaults(defaultTags...),
	// 	)

	cfg := syft.DefaultCreateSBOMConfig()

	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		panic(err)
	}

	// r, err := ToSpdxSchema(s)
	r, err := ToCycloneDxSchema(s)
	if err != nil {
		panic(err)
	}

	filePath := "go-spdx.json"
	file, err := os.Create(filePath) // os.Create truncates if file exists
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		panic(err)
	}
	defer file.Close()

	_, err = io.Copy(file, r)
	if err != nil {
		fmt.Printf("Error copying content: %v\n", err)
		panic(err)
	}
	// Now scan for vulnerabilities using Grype
	var DefaultOptions = Options{
		MaxAllowedBuildAge: 120 * time.Hour,
	}
	scanner, err := NewScanner(DefaultOptions)
	if err != nil {
		panic(err)
	}
	fmt.Println("Database built at:", scanner.dbStatus.Built)
	fmt.Println("Database location:", scanner.dbStatus.Path)

	// Convert Syft packages to Grype packages
	syftPkgs := s.Artifacts.Packages.Sorted()
	grypePkgs := grypePkg.FromPackages(syftPkgs, grypePkg.SynthesisConfig{
		GenerateMissingCPEs: false,
	})

	fmt.Printf("Converted %d packages for vulnerability scanning\n", len(grypePkgs))

	// Create the context for Grype
	grypeContext := grypePkg.Context{
		Source: &s.Source,
		Distro: distro.FromRelease(s.Artifacts.LinuxDistribution, nil),
	}

	// Perform vulnerability matching
	matchesCollection, ignoredMatches, err := scanner.vulnerabilityMatcher.FindMatches(grypePkgs, grypeContext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Found %d vulnerabilities (%d ignored)\n", matchesCollection.Count(), len(ignoredMatches))

	// Get sorted matches
	matches := matchesCollection.Sorted()

	// Save vulnerability results
	vulnFilePath := "vulnerabilities.json"
	vulnFile, err := os.Create(vulnFilePath)
	if err != nil {
		panic(err)
	}
	defer vulnFile.Close()

	// Create structured output
	type VulnOutput struct {
		Matches      []interface{} `json:"matches"`
		MatchCount   int           `json:"matchCount"`
		IgnoredCount int           `json:"ignoredCount"`
	}

	vulnOutput := VulnOutput{
		Matches:      make([]interface{}, len(matches)),
		MatchCount:   len(matches),
		IgnoredCount: len(ignoredMatches),
	}

	for i, m := range matches {
		vulnOutput.Matches[i] = map[string]interface{}{
			"vulnerability": map[string]interface{}{
				"id":        m.Vulnerability.ID,
				"namespace": m.Vulnerability.Namespace,
				// "severity":  m.Vulnerability.
				"fix": m.Vulnerability.Fix,
			},
			"package": map[string]interface{}{
				"name":    m.Package.Name,
				"version": m.Package.Version,
				"type":    m.Package.Type,
				"purl":    m.Package.PURL,
			},
		}
	}

	enc := json.NewEncoder(vulnFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(matches); err != nil {
		panic(err)
	}

	fmt.Printf("SBOM saved to: %s\n", filePath)
	fmt.Printf("Vulnerabilities saved to: %s\n", vulnFilePath)
	return *s
}

func ToSyftJSONSchemaRedacted(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)
	m := syftjson.ToFormatModel(*s, syftjson.DefaultEncoderConfig())
	m.Schema = model.Schema{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func ToCycloneDxSchema(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)
	bom := cyclonedxhelpers.ToFormatModel(*s)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(bom)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}
func ToSpdxSchema(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)
	spdx := spdxhelpers.ToFormatModel(*s)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(spdx)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func PrintToTerminal(source io.ReadSeeker) error {
	// io.Copy efficiently copies data from a source (io.Reader) to a destination (io.Writer).
	// os.Stdout is an io.Writer that represents the terminal's standard output.
	_, err := io.Copy(os.Stdout, source)
	if err != nil {
		return fmt.Errorf("error copying to stdout: %w", err)
	}
	// Add a newline at the end for clean terminal output if desired
	fmt.Println()
	return nil
}
