package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

func ImageReference(name string) string {
	return name
}

func GetSource(ctx context.Context, input string) (source.Source, error) {
	cfg := syft.DefaultGetSourceConfig()
	if registryOptions := RegistryOptionsFromContext(ctx); registryOptions != nil {
		cfg = cfg.WithRegistryOptions(registryOptions)
	}

	src, err := syft.GetSource(ctx, input, cfg)
	if err != nil {
		return nil, fmt.Errorf("get syft source: %w", err)
	}
	return src, nil
}

func GetSBOM(ctx context.Context, src source.Source, defaultTags ...string) (*sbom.SBOM, error) {
	cfg := syft.DefaultCreateSBOMConfig()

	document, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("create sbom: %w", err)
	}

	return document, nil
}

func GenerateSBOMDocument(ctx context.Context, src source.Source) ([]byte, *sbom.SBOM, error) {
	document, err := GetSBOM(ctx, src)
	if err != nil {
		return nil, nil, err
	}

	reader, err := ToCycloneDxSchema(document)
	if err != nil {
		return nil, nil, fmt.Errorf("encode cyclonedx sbom: %w", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("read encoded sbom: %w", err)
	}

	return data, document, nil
}

func GenerateSPDXDocument(s *sbom.SBOM) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("sbom is required")
	}

	reader, err := ToSpdxSchema(s)
	if err != nil {
		return nil, fmt.Errorf("encode spdx sbom: %w", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read encoded spdx sbom: %w", err)
	}

	return data, nil
}

func GenerateVulnerabilityReport(s *sbom.SBOM) ([]byte, error) {
	scanner, err := NewScanner(Options{MaxAllowedBuildAge: 120 * time.Hour})
	if err != nil {
		return nil, fmt.Errorf("create grype scanner: %w", err)
	}
	fmt.Println("Database built at:", scanner.dbStatus.Built)
	fmt.Println("Database location:", scanner.dbStatus.Path)

	syftPkgs := s.Artifacts.Packages.Sorted()
	grypePkgs := grypePkg.FromPackages(syftPkgs, grypePkg.SynthesisConfig{
		GenerateMissingCPEs: false,
	})

	fmt.Printf("Converted %d packages for vulnerability scanning\n", len(grypePkgs))

	grypeContext := grypePkg.Context{
		Source: &s.Source,
		Distro: distro.FromRelease(s.Artifacts.LinuxDistribution, nil),
	}

	matchesCollection, ignoredMatches, err := scanner.vulnerabilityMatcher.FindMatches(grypePkgs, grypeContext)
	if err != nil {
		return nil, fmt.Errorf("find vulnerabilities: %w", err)
	}

	fmt.Printf("Found %d vulnerabilities (%d ignored)\n", matchesCollection.Count(), len(ignoredMatches))

	matches := matchesCollection.Sorted()
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(matches); err != nil {
		return nil, fmt.Errorf("encode vulnerabilities: %w", err)
	}

	return buffer.Bytes(), nil
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
	_, err := io.Copy(os.Stdout, source)
	if err != nil {
		return fmt.Errorf("error copying to stdout: %w", err)
	}
	fmt.Println()
	return nil
}

func SaveSBOMToFile(s *sbom.SBOM, filePath string) error {
	reader, err := ToCycloneDxSchema(s)
	if err != nil {
		return fmt.Errorf("convert sbom to cyclonedx: %w", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create sbom file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("failed to close sbom file: %v", err)
		}
	}()

	if _, err := io.Copy(file, reader); err != nil {
		_ = os.Remove(filePath)
		return fmt.Errorf("write sbom file: %w", err)
	}
	return nil
}
