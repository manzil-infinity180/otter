package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(securityHeaders())
	router.GET("/healthz", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusNoContent; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	for header, want := range map[string]string{
		"Content-Security-Policy": "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; img-src 'self' data: https:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Permissions-Policy":      "camera=(), geolocation=(), microphone=()",
	} {
		if got := resp.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestBuildLocalDependencies(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	t.Setenv("OTTER_STORAGE", storage.BackendLocal)
	t.Setenv("OTTER_DATA_DIR", dataDir)
	t.Setenv("HOME", t.TempDir())

	store, err := buildStore(ctx)
	if err != nil {
		t.Fatalf("buildStore() error = %v", err)
	}
	defer store.Close() //nolint:errcheck // test cleanup

	if got, want := store.Backend(), storage.BackendLocal; got != want {
		t.Fatalf("store.Backend() = %q, want %q", got, want)
	}

	key, err := storage.BuildArtifactKey("demo-org", "demo-image", "sbom.json")
	if err != nil {
		t.Fatalf("BuildArtifactKey() error = %v", err)
	}
	if _, err := store.Put(ctx, key, []byte(`{"bomFormat":"CycloneDX"}`), storage.PutOptions{}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}

	sbomRepo, err := buildSBOMRepository(ctx)
	if err != nil {
		t.Fatalf("buildSBOMRepository() error = %v", err)
	}
	defer sbomRepo.Close() //nolint:errcheck // test cleanup

	savedSBOM, err := sbomRepo.Save(ctx, sbomindex.Record{
		OrgID:        "demo-org",
		ImageID:      "demo-image",
		ImageName:    "alpine:latest",
		UpdatedAt:    time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC),
		PackageCount: 1,
	})
	if err != nil {
		t.Fatalf("sbomRepo.Save() error = %v", err)
	}
	if got, want := savedSBOM.ImageName, "alpine:latest"; got != want {
		t.Fatalf("saved sbom image name = %q, want %q", got, want)
	}

	vulnRepo, err := buildVulnerabilityRepository(ctx)
	if err != nil {
		t.Fatalf("buildVulnerabilityRepository() error = %v", err)
	}
	defer vulnRepo.Close() //nolint:errcheck // test cleanup

	savedVulns, err := vulnRepo.Save(ctx, vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:latest",
		Summary: vulnindex.Summary{
			Total:      1,
			BySeverity: map[string]int{"CRITICAL": 1},
			ByScanner:  map[string]int{"grype": 1},
			ByStatus:   map[string]int{"affected": 1},
			Fixable:    1,
		},
		UpdatedAt: time.Date(2026, 3, 14, 0, 5, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}
	if got, want := savedVulns.Summary.Total, 1; got != want {
		t.Fatalf("saved vulnerability total = %d, want %d", got, want)
	}

	manager, err := buildRegistryManager()
	if err != nil {
		t.Fatalf("buildRegistryManager() error = %v", err)
	}
	if manager == nil {
		t.Fatal("buildRegistryManager() returned nil")
	}

	if analyzer := buildAnalyzer(); analyzer == nil {
		t.Fatal("buildAnalyzer() returned nil")
	}
}

func TestBuildStoreRejectsUnsupportedBackend(t *testing.T) {
	t.Setenv("OTTER_STORAGE", "unsupported")

	if _, err := buildStore(context.Background()); err == nil {
		t.Fatal("expected buildStore() to fail for unsupported backend")
	}
}

func TestBuildIndexRepositoriesRejectUnsupportedBackend(t *testing.T) {
	t.Setenv("OTTER_STORAGE", "unsupported")

	if _, err := buildSBOMRepository(context.Background()); err == nil {
		t.Fatal("expected buildSBOMRepository() to fail for unsupported backend")
	}
	if _, err := buildVulnerabilityRepository(context.Background()); err == nil {
		t.Fatal("expected buildVulnerabilityRepository() to fail for unsupported backend")
	}
}

func TestBuildAnalyzerIncludesTrivyWhenEnabled(t *testing.T) {
	t.Setenv("OTTER_TRIVY_ENABLED", "true")
	t.Setenv("OTTER_TRIVY_SERVER_URL", "http://trivy:4954")

	if analyzer := buildAnalyzer(); analyzer == nil {
		t.Fatal("buildAnalyzer() returned nil")
	}
}

func TestBuildRepositoriesUseLocalIndexesForS3Mode(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("OTTER_STORAGE", storage.BackendS3)
	t.Setenv("OTTER_DATA_DIR", dataDir)

	sbomRepo, err := buildSBOMRepository(context.Background())
	if err != nil {
		t.Fatalf("buildSBOMRepository() error = %v", err)
	}
	defer sbomRepo.Close() //nolint:errcheck // test cleanup

	vulnRepo, err := buildVulnerabilityRepository(context.Background())
	if err != nil {
		t.Fatalf("buildVulnerabilityRepository() error = %v", err)
	}
	defer vulnRepo.Close() //nolint:errcheck // test cleanup
}

func TestBuildPostgresDependenciesReturnConnectionErrors(t *testing.T) {
	t.Setenv("OTTER_STORAGE", storage.BackendPostgres)
	t.Setenv("OTTER_POSTGRES_DSN", "postgres://otter:otter@127.0.0.1:1/otter?sslmode=disable")
	t.Setenv("OTTER_POSTGRES_MIGRATIONS", t.TempDir())

	if _, err := buildStore(context.Background()); err == nil {
		t.Fatal("expected buildStore() to fail for unreachable postgres")
	}
	if _, err := buildSBOMRepository(context.Background()); err == nil {
		t.Fatal("expected buildSBOMRepository() to fail for unreachable postgres")
	}
	if _, err := buildVulnerabilityRepository(context.Background()); err == nil {
		t.Fatal("expected buildVulnerabilityRepository() to fail for unreachable postgres")
	}
}

func TestBuildRegistryManagerReturnsFilesystemErrors(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("otter"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	t.Setenv("OTTER_DATA_DIR", filePath)
	if _, err := buildRegistryManager(); err == nil {
		t.Fatal("expected buildRegistryManager() to fail when OTTER_DATA_DIR is a file")
	}
}

func TestBuildStoreReturnsFilesystemErrorsForLocalMode(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("otter"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	t.Setenv("OTTER_STORAGE", storage.BackendLocal)
	t.Setenv("OTTER_DATA_DIR", filePath)
	if _, err := buildStore(context.Background()); err == nil {
		t.Fatal("expected buildStore() to fail when OTTER_DATA_DIR is a file")
	}
}
