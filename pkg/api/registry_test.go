package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/registry"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

type stubRegistryService struct {
	configureResult registry.ConfigureResult
	configureErr    error
	listResult      []registry.Summary
	listErr         error
	access          registry.ImageAccess
	accessErr       error
}

func (s stubRegistryService) Configure(context.Context, registry.ConfigureRequest) (registry.ConfigureResult, error) {
	return s.configureResult, s.configureErr
}

func (s stubRegistryService) List(context.Context) ([]registry.Summary, error) {
	return s.listResult, s.listErr
}

func (s stubRegistryService) PrepareImage(context.Context, string) (registry.ImageAccess, error) {
	return s.access, s.accessErr
}

type contextCheckingAnalyzer struct {
	t *testing.T
}

func (a contextCheckingAnalyzer) Analyze(ctx context.Context, imageRef string) (scan.AnalysisResult, error) {
	a.t.Helper()
	options := scan.RegistryOptionsFromContext(ctx)
	if options == nil || len(options.Credentials) != 1 || options.Credentials[0].Authority != "ghcr.io" {
		a.t.Fatalf("expected registry options in analyze context, got %#v", options)
	}
	return stubAnalyzer{
		result: scan.AnalysisResult{
			ImageRef:                imageRef,
			SBOMDocument:            []byte(testCycloneDXDocument),
			SBOMSPDXDocument:        []byte(testSPDXDocument),
			SBOMData:                testSyftSBOM(),
			CombinedVulnerabilities: []byte(`{"schema_version":"v1alpha1"}`),
			CombinedReport:          scan.CombinedVulnerabilityReport{ImageRef: imageRef},
		},
	}.Analyze(ctx, imageRef)
}

func TestConfigureRegistryEndpoint(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := NewScanHandlerWithRegistry(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{}, stubRegistryService{
		configureResult: registry.ConfigureResult{
			Summary: registry.Summary{
				Registry:       "ghcr.io",
				AuthMode:       registry.AuthModeExplicit,
				HasCredentials: true,
			},
			AuthSource: "explicit-token",
		},
	})
	router := gin.New()
	router.POST("/api/v1/registries", handler.ConfigureRegistry)

	body := []byte(`{"registry":"ghcr.io","auth_mode":"explicit","token":"secret"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registries", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

func TestListRegistriesEndpoint(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := NewScanHandlerWithRegistry(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{}, stubRegistryService{
		listResult: []registry.Summary{{Registry: "ghcr.io", AuthMode: registry.AuthModeDockerConfig}},
	})
	router := gin.New()
	router.GET("/api/v1/registries", handler.ListRegistries)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/registries", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
	if !bytes.Contains(resp.Body.Bytes(), []byte(`"ghcr.io"`)) {
		t.Fatalf("expected registry listing in response, body=%s", resp.Body.String())
	}
}

func TestRegistryEndpointsReturnErrors(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := NewScanHandlerWithRegistry(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{}, stubRegistryService{
		configureErr: errors.New("invalid credentials"),
		listErr:      errors.New("storage unavailable"),
	})
	router := gin.New()
	router.POST("/api/v1/registries", handler.ConfigureRegistry)
	router.GET("/api/v1/registries", handler.ListRegistries)

	badJSON := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registries", bytes.NewReader([]byte(`{`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(badJSON, req)
	if got, want := badJSON.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, badJSON.Body.String())
	}

	configureErr := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/registries", bytes.NewReader([]byte(`{"registry":"ghcr.io","auth_mode":"explicit","token":"secret"}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(configureErr, req)
	if got, want := configureErr.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, configureErr.Body.String())
	}

	listErr := httptest.NewRecorder()
	router.ServeHTTP(listErr, httptest.NewRequest(http.MethodGet, "/api/v1/registries", nil))
	if got, want := listErr.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, listErr.Body.String())
	}
}

func TestGenerateScanUsesRegistryPreflightOptions(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := NewScanHandlerWithRegistry(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), contextCheckingAnalyzer{t: t}, stubRegistryService{
		access: registry.ImageAccess{
			Registry:   "ghcr.io",
			AuthSource: "explicit-token",
			RegistryOptions: &stereoscopeimage.RegistryOptions{
				Credentials: []stereoscopeimage.RegistryCredentials{{Authority: "ghcr.io", Token: "secret"}},
			},
		},
	})
	router := gin.New()
	router.POST("/api/v1/scans", handler.GenerateScanSbomVul)

	body, err := json.Marshal(ImageGeneratePayload{
		ImageName: "ghcr.io/demo/app:latest",
		Registry:  "ghcr.io",
		OrgID:     "demo",
		ImageID:   "app",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
	if !bytes.Contains(resp.Body.Bytes(), []byte(`"registry_auth":"explicit-token"`)) {
		t.Fatalf("expected registry auth metadata in response, body=%s", resp.Body.String())
	}
}

func mustLocalStore(t *testing.T) storage.Store {
	t.Helper()
	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	return store
}

func mustLocalSBOMRepo(t *testing.T) sbomindex.Repository {
	t.Helper()
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	return repo
}

func mustLocalVulnRepo(t *testing.T) vulnindex.Repository {
	t.Helper()
	repo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	return repo
}
