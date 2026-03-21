package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/api"
	"github.com/otterXf/otter/pkg/auth"
	"github.com/otterXf/otter/pkg/compare"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestProtectedAPIRequiresAuthentication(t *testing.T) {
	t.Parallel()

	router, _ := newAuthTestRouter(t, auth.Config{
		Enabled: true,
		Tokens: []auth.TokenRecord{
			{Token: "team-a-token", Subject: "team-a", Orgs: []string{"team-a"}},
		},
	})

	body, err := json.Marshal(api.ImageGeneratePayload{
		ImageName: "alpine:latest",
		OrgID:     "team-a",
		ImageID:   "image-a",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

func TestOrgScopedRoutesRejectCrossOrgAccess(t *testing.T) {
	t.Parallel()

	router, _ := newAuthTestRouter(t, auth.Config{
		Enabled: true,
		Tokens: []auth.TokenRecord{
			{Token: "team-a-token", Subject: "team-a", Orgs: []string{"team-a"}},
		},
	})

	body, err := json.Marshal(api.ImageGeneratePayload{
		ImageName: "alpine:latest",
		OrgID:     "team-b",
		ImageID:   "image-b",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer team-a-token")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusForbidden; got != want {
		t.Fatalf("POST /api/v1/scans status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/images/image-b/overview?org_id=team-b", nil)
	req.Header.Set("Authorization", "Bearer team-a-token")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusForbidden; got != want {
		t.Fatalf("GET overview status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

func TestRegistryRoutesRequireAdminAccess(t *testing.T) {
	t.Parallel()

	router, _ := newAuthTestRouter(t, auth.Config{
		Enabled: true,
		Tokens: []auth.TokenRecord{
			{Token: "member-token", Subject: "member", Orgs: []string{"team-a"}},
			{Token: "admin-token", Subject: "admin", Admin: true},
		},
	})

	memberReq := httptest.NewRequest(http.MethodGet, "/api/v1/registries", nil)
	memberReq.Header.Set("Authorization", "Bearer member-token")
	memberResp := httptest.NewRecorder()
	router.ServeHTTP(memberResp, memberReq)

	if got, want := memberResp.Code, http.StatusForbidden; got != want {
		t.Fatalf("member status = %d, want %d, body=%s", got, want, memberResp.Body.String())
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/api/v1/registries", nil)
	adminReq.Header.Set("Authorization", "Bearer admin-token")
	adminResp := httptest.NewRecorder()
	router.ServeHTTP(adminResp, adminReq)

	if got, want := adminResp.Code, http.StatusOK; got != want {
		t.Fatalf("admin status = %d, want %d, body=%s", got, want, adminResp.Body.String())
	}
}

func TestStoredComparisonRejectsUnauthorizedOrgAccess(t *testing.T) {
	t.Parallel()

	router, deps := newAuthTestRouter(t, auth.Config{
		Enabled: true,
		Tokens: []auth.TokenRecord{
			{Token: "team-a-token", Subject: "team-a", Orgs: []string{"team-a"}},
		},
	})

	report := compare.Report{
		ID:          compare.ComputeID("team-b", "image-b", "team-c", "image-c"),
		GeneratedAt: time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC),
		Image1:      compare.ImageDescriptor{OrgID: "team-b", ImageID: "image-b", ImageName: "alpine:3.20"},
		Image2:      compare.ImageDescriptor{OrgID: "team-c", ImageID: "image-c", ImageName: "alpine:3.19"},
	}
	document, err := compare.MarshalReport(report)
	if err != nil {
		t.Fatalf("compare.MarshalReport() error = %v", err)
	}
	key, err := api.BuildComparisonKey(report.ID)
	if err != nil {
		t.Fatalf("api.BuildComparisonKey() error = %v", err)
	}
	if _, err := deps.store.Put(context.Background(), key, document, storage.PutOptions{ContentType: "application/json"}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/comparisons/"+report.ID, nil)
	req.Header.Set("Authorization", "Bearer team-a-token")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

type authTestDependencies struct {
	handlers *Handlers
	store    storage.Store
}

func newAuthTestRouter(t *testing.T, cfg auth.Config) (*gin.Engine, authTestDependencies) {
	t.Helper()

	gin.SetMode(gin.TestMode)

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
	authenticator, err := auth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("auth.NewAuthenticator() error = %v", err)
	}

	router := gin.New()
	handlers := &Handlers{
		ScanHandler: api.NewScanHandler(store, sbomRepo, vulnRepo, scan.NewAnalyzer(nil)),
	}
	SetupRoutes(router, handlers, authenticator)

	return router, authTestDependencies{
		handlers: handlers,
		store:    store,
	}
}
