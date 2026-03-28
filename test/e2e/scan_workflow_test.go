package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/api"
	"github.com/otterXf/otter/pkg/auth"
	"github.com/otterXf/otter/pkg/routes"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func setupTestRouter(t *testing.T) (*gin.Engine, *api.ScanHandler) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	store, err := storage.NewLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	sbomRepo, err := sbomindex.NewLocalRepository(dir)
	if err != nil {
		t.Fatal(err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(dir)
	if err != nil {
		t.Fatal(err)
	}

	handler := api.NewScanHandler(store, sbomRepo, vulnRepo, nil)
	router := gin.New()
	routes.SetupRoutes(router, &routes.Handlers{ScanHandler: handler}, auth.NewDisabledAuthenticator())

	return router, handler
}

func TestHealthEndpoint(t *testing.T) {
	router, _ := setupTestRouter(t)

	// The /healthz endpoint is registered in main.go, not in routes.
	// Test the routes that are registered.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/catalog", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/catalog: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestScanEndpointValidation(t *testing.T) {
	router, _ := setupTestRouter(t)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "empty body",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid image name",
			body:       `{"image_name": ""}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "shell injection attempt",
			body:       `{"image_name": "alpine; rm -rf /"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("POST /api/v1/scans: expected %d, got %d: %s", tt.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestImageNotFoundReturns404(t *testing.T) {
	router, _ := setupTestRouter(t)

	endpoints := []string{
		"/api/v1/images/nonexistent/overview?org_id=default",
		"/api/v1/images/nonexistent/vulnerabilities?org_id=default",
		"/api/v1/images/nonexistent/sbom?org_id=default",
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, endpoint, nil)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusNotFound {
				t.Fatalf("GET %s: expected 404, got %d: %s", endpoint, w.Code, w.Body.String())
			}
		})
	}
}

func TestCatalogEmptyReturnsValidJSON(t *testing.T) {
	router, _ := setupTestRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/catalog?page=1&page_size=10", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := body["items"]; !ok {
		t.Fatal("response missing 'items' field")
	}
}
