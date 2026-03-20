package routes

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/api"
	"github.com/otterXf/otter/pkg/auth"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestSetupRoutesRegistersExpectedPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	SetupRoutes(router, testHandlers(t), auth.NewDisabledAuthenticator())

	paths := make([]string, 0, len(router.Routes()))
	for _, route := range router.Routes() {
		paths = append(paths, route.Method+" "+route.Path)
	}

	for _, want := range []string{
		"POST /api/v1/scans",
		"POST /api/v1/comparisons",
		"GET /api/v1/catalog",
		"GET /api/v1/images/:id/overview",
		"POST /api/v1/images/:id/indexes/repair",
		"GET /api/v1/compare",
		"GET /api/v1/aws/scans/:org_id/:image_id",
		"GET /browse",
		"GET /browse/images/:org_id/:id",
	} {
		if !slices.Contains(paths, want) {
			t.Fatalf("expected route %q to be registered; got %#v", want, paths)
		}
	}
}

func TestSetupFrontendRoutesFallbackRedirectsWithoutDist(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := chdir(t, t.TempDir())
	defer restore()

	router := gin.New()
	setupFrontendRoutes(router, testHandlers(t), auth.NewDisabledAuthenticator())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusTemporaryRedirect; got != want {
		t.Fatalf("GET / status = %d, want %d", got, want)
	}
	if got, want := resp.Header().Get("Location"), "/browse"; got != want {
		t.Fatalf("GET / location = %q, want %q", got, want)
	}

	req = httptest.NewRequest(http.MethodGet, "/images/demo-org/demo-image", nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Header().Get("Location"), "/browse/images/demo-org/demo-image"; got != want {
		t.Fatalf("GET /images redirect = %q, want %q", got, want)
	}
}

func TestSetupFrontendRoutesServeSPAAndNoRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	root := t.TempDir()
	restore := chdir(t, root)
	defer restore()

	distDir := filepath.Join(root, "frontend", "dist")
	assetsDir := filepath.Join(distDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "index.html"), []byte("<html><body>otter-ui</body></html>"), 0o644); err != nil {
		t.Fatalf("WriteFile(index) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "app.js"), []byte("console.log('otter');"), 0o644); err != nil {
		t.Fatalf("WriteFile(asset) error = %v", err)
	}

	router := gin.New()
	setupFrontendRoutes(router, testHandlers(t), auth.NewDisabledAuthenticator())

	for _, path := range []string{"/", "/images/demo-org/demo-image"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if got, want := resp.Code, http.StatusOK; got != want {
			t.Fatalf("GET %s status = %d, want %d", path, got, want)
		}
		if body := resp.Body.String(); body != "<html><body>otter-ui</body></html>" {
			t.Fatalf("GET %s body = %q", path, body)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("GET /assets/app.js status = %d, want %d", got, want)
	}

	req = httptest.NewRequest(http.MethodGet, "/not-found", nil)
	req.Header.Set("Accept", "text/html")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("GET /not-found status = %d, want %d", got, want)
	}
	if body := resp.Body.String(); body != "<html><body>otter-ui</body></html>" {
		t.Fatalf("GET /not-found body = %q", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/unknown", nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusNotFound; got != want {
		t.Fatalf("GET /api/unknown status = %d, want %d", got, want)
	}

	req = httptest.NewRequest(http.MethodPost, "/not-found", nil)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusNotFound; got != want {
		t.Fatalf("POST /not-found status = %d, want %d", got, want)
	}
}

func testHandlers(t *testing.T) *Handlers {
	t.Helper()

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository(sbom) error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository(vuln) error = %v", err)
	}

	return &Handlers{
		ScanHandler: api.NewScanHandler(store, sbomRepo, vulnRepo, scan.NewAnalyzer(nil)),
	}
}

func chdir(t *testing.T, dir string) func() {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%q) error = %v", dir, err)
	}
	return func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd error = %v", err)
		}
	}
}
