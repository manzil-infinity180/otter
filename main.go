package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/hako/durafmt"
	"github.com/spf13/afero"
	// _ "modernc.org/sqlite" // required for rpmdb and other features
)

const defaultImage = "manzilrahul/k8s-custom-controller:latest"

func main() {
	// automagically get a source.Source for arbitrary string input
	src := getSource(imageReference())
	defer src.Close()

	// catalog the given source and return a SBOM
	// let's explicitly use catalogers that are:
	// - for installed software
	// - used in the directory scan
	_ = getSBOM(src, pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag)

	// Show a basic catalogers and input configuration used
	// enc := json.NewEncoder(os.Stdout)
	// enc.SetIndent("", "  ")
	// if err := enc.Encode(sbom.Descriptor.Configuration); err != nil {
	// 	panic(err)
	// }
}

func imageReference() string {
	// read an image string reference from the command line or use a default
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return defaultImage
}

func getSource(input string) source.Source {
	src, err := syft.GetSource(context.Background(), input, nil)
	if err != nil {
		panic(err)
	}

	return src
}

func getSBOM(src source.Source, defaultTags ...string) sbom.SBOM {
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

type Scanner struct {
	vulnProvider         vulnerability.Provider
	dbStatus             *vulnerability.ProviderStatus
	dbChecksum           string
	vulnerabilityMatcher *grype.VulnerabilityMatcher
	disableSBOMCache     bool
}

type Options struct {
	// PathOfDatabaseArchiveToImport, if set, is the path to a Grype vulnerability
	// database archive (.tar.gz file) from which a database will be loaded by
	// Grype.
	//
	// If empty, the default Grype database loading behavior will be used (e.g.
	// downloading the database from the Internet).
	PathOfDatabaseArchiveToImport string

	// PathOfDatabaseDestinationDirectory is the directory to which the Grype
	// database will be extracted, and where the database will be loaded from at
	// runtime. If empty, the value of DefaultGrypeDBDir will be used.
	PathOfDatabaseDestinationDirectory string

	// UseCPEs controls whether the scanner will use CPEs to match vulnerabilities
	// for matcher types that default to not using CPE matching. Most consumers will
	// probably want this set to false in order to avoid excessive noise from
	// matching.
	UseCPEs bool

	// DisableDatabaseAgeValidation controls whether the scanner will validate the
	// age of the vulnerability database before using it. If true, the scanner will
	// not validate the age of the database. This bool should always be set to false
	// except for testing purposes.
	DisableDatabaseAgeValidation bool

	// MaxAllowedBuildAge defines the maximum allowed age for the vulnerability database.
	// If the database is older than this duration, it will be considered invalid unless
	// DisableDatabaseAgeValidation is set to true. If not specified, the default value
	// of 48 hours will be used.
	MaxAllowedBuildAge time.Duration

	// DisableSBOMCache controls whether the scanner will cache SBOMs generated from
	// APKs. If true, the scanner will not cache SBOMs or use existing cached SBOMs.
	DisableSBOMCache bool
}

const (
	mavenSearchBaseURL = "https://search.maven.org/solrsearch/select"

	maxRecommendedBuildAge = 48 * time.Hour
)

var DefaultGrypeDBDir = path.Join(xdg.CacheHome, "otter", "grype", "db")

func NewScanner(opts Options) (*Scanner, error) {
	dbDestDir := opts.PathOfDatabaseDestinationDirectory
	if dbDestDir == "" {
		dbDestDir = DefaultGrypeDBDir
	}

	maxAllowedBuildAge := opts.MaxAllowedBuildAge
	if maxAllowedBuildAge == 0 {
		maxAllowedBuildAge = 120 * time.Hour
	}

	installCfg := installation.Config{
		DBRootDir:               dbDestDir,
		ValidateChecksum:        true,
		ValidateAge:             !opts.DisableDatabaseAgeValidation,
		MaxAllowedBuiltAge:      maxAllowedBuildAge,
		UpdateCheckMaxFrequency: 1 * time.Hour,
	}

	distCfg := distribution.DefaultConfig()

	distClient, err := distribution.NewClient(distCfg)
	if err != nil {
		return nil, fmt.Errorf("creating distribution client: %w", err)
	}

	updateDB := true
	var checksum string
	if dbArchivePath := opts.PathOfDatabaseArchiveToImport; dbArchivePath != "" {
		fmt.Fprintf(os.Stderr, "using local grype DB archive %q...\n", dbArchivePath)
		dbCurator, err := installation.NewCurator(installCfg, distClient)
		if err != nil {
			return nil, fmt.Errorf("unable to create the grype db import config: %w", err)
		}

		// Take the hash of the file at dbArchivePath
		h := sha256.New()
		f, err := os.Open(dbArchivePath)
		if err != nil {
			return nil, fmt.Errorf("opening vulnerability database archive for hashing: %w", err)
		}
		defer f.Close()
		if _, err := io.Copy(h, f); err != nil {
			return nil, fmt.Errorf("hashing vulnerability database archive: %w", err)
		}
		checksum = fmt.Sprintf("imported_db_archive_checksum=sha256:%x", h.Sum(nil))

		if err := dbCurator.Import(dbArchivePath); err != nil {
			return nil, fmt.Errorf("unable to import vulnerability database: %w", err)
		}

		updateDB = false
	}

	vulnProvider, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, updateDB)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	// built time is defined in UTC,
	// we should compare it against UTC
	now := time.Now().UTC()
	age := now.Sub(dbStatus.Built)
	if age > maxRecommendedBuildAge {
		fmt.Fprintf(os.Stdout, "WARNING: the vulnerability database was built %s ago (max allowed age is %s but the recommended value is %s)\n", durafmt.ParseShort(age), durafmt.ParseShort(maxAllowedBuildAge), durafmt.ParseShort(maxRecommendedBuildAge))
	}

	if checksum == "" {
		metadata, err := v6.ReadImportMetadata(afero.NewOsFs(), filepath.Dir(dbStatus.Path))
		if err != nil {
			return nil, fmt.Errorf("reading Grype DB import metadata: %w", err)
		}

		checksum = fmt.Sprintf("import_metadata_digest=%s", metadata.Digest)
	}

	vulnerabilityMatcher := NewGrypeVulnerabilityMatcher(vulnProvider, opts.UseCPEs)

	return &Scanner{
		vulnProvider:         vulnProvider,
		dbStatus:             dbStatus,
		dbChecksum:           checksum,
		vulnerabilityMatcher: vulnerabilityMatcher,
		disableSBOMCache:     opts.DisableSBOMCache,
	}, nil
}
func NewGrypeVulnerabilityMatcher(vulnProvider vulnerability.Provider, useCPEs bool) *grype.VulnerabilityMatcher {
	return &grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              createMatchers(useCPEs),
	}
}

func createMatchers(useCPEs bool) []match.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Dotnet: dotnet.MatcherConfig{UseCPEs: useCPEs},
			Golang: golang.MatcherConfig{
				UseCPEs:                                true, // note: disregarding --use-cpes flag value
				AlwaysUseCPEForStdlib:                  true,
				AllowMainModulePseudoVersionComparison: false,
			},
			Java: java.MatcherConfig{
				ExternalSearchConfig: java.ExternalSearchConfig{
					SearchMavenUpstream: false, // temporary disable of maven searches until we figure out the 403 rate limit issues
					MavenBaseURL:        mavenSearchBaseURL,
					MavenRateLimit:      400 * time.Millisecond, // increased from the default of 300ms to avoid rate limiting with extremely large set of java packages such as druid
				},
				UseCPEs: useCPEs,
			},
			Javascript: javascript.MatcherConfig{UseCPEs: useCPEs},
			Python:     python.MatcherConfig{UseCPEs: useCPEs},
			Ruby:       ruby.MatcherConfig{UseCPEs: useCPEs},
			Rust:       rust.MatcherConfig{UseCPEs: useCPEs},
			Stock:      stock.MatcherConfig{UseCPEs: true},
		},
	)
}
