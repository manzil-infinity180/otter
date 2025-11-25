package scan

import (
	"crypto/sha256"
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
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/hako/durafmt"
	"github.com/spf13/afero"
)

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
