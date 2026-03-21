package api

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/audit"
	"github.com/otterXf/otter/pkg/auth"
	"github.com/otterXf/otter/pkg/catalogscan"
	"github.com/otterXf/otter/pkg/registry"
	"github.com/otterXf/otter/pkg/scan"
)

type capturingJobQueue struct {
	job      catalogscan.Job
	requests []catalogscan.Request
}

func (q *capturingJobQueue) Enqueue(req catalogscan.Request) (catalogscan.Job, error) {
	q.requests = append(q.requests, req)
	return q.job, nil
}

func (q *capturingJobQueue) Get(jobID string) (catalogscan.Job, bool) {
	if q.job.ID != jobID {
		return catalogscan.Job{}, false
	}
	return q.job, true
}

func (q *capturingJobQueue) Stats() catalogscan.QueueStats {
	return catalogscan.QueueStats{}
}

func TestGenerateScanAsyncEmitsAuditEventAndPropagatesActor(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := NewScanHandler(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{})
	var buffer bytes.Buffer
	recorder, err := audit.NewWriterRecorder(&buffer)
	if err != nil {
		t.Fatalf("NewWriterRecorder() error = %v", err)
	}
	handler.SetAuditRecorder(recorder)
	queue := &capturingJobQueue{
		job: catalogscan.Job{
			ID:        "scanjob-1234",
			Status:    catalogscan.StatusPending,
			Request:   catalogscan.Request{OrgID: "catalog", ImageID: "alpine-job", ImageName: "alpine:latest"},
			CreatedAt: time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC),
		},
	}
	handler.SetJobQueue(queue)

	router := authenticatedRouter(t, false)
	router.POST("/api/v1/scans", handler.GenerateScanSbomVul)

	body, err := json.Marshal(ImageGeneratePayload{
		ImageName: "alpine:latest",
		OrgID:     "catalog",
		ImageID:   "alpine-job",
		Async:     true,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer audit-token")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusAccepted; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
	if got, want := len(queue.requests), 1; got != want {
		t.Fatalf("len(queue.requests) = %d, want %d", got, want)
	}
	if got, want := queue.requests[0].Actor, "auditor"; got != want {
		t.Fatalf("queue.requests[0].Actor = %q, want %q", got, want)
	}

	events := decodeAuditEvents(t, buffer.Bytes())
	if got, want := len(events), 1; got != want {
		t.Fatalf("len(events) = %d, want %d", got, want)
	}
	if got, want := events[0].Action, "scan.enqueued"; got != want {
		t.Fatalf("events[0].Action = %q, want %q", got, want)
	}
	if got, want := events[0].Actor, "auditor"; got != want {
		t.Fatalf("events[0].Actor = %q, want %q", got, want)
	}
	if got, want := events[0].OrgID, "catalog"; got != want {
		t.Fatalf("events[0].OrgID = %q, want %q", got, want)
	}
	if got, want := events[0].Target, "catalog/alpine-job"; got != want {
		t.Fatalf("events[0].Target = %q, want %q", got, want)
	}
	if events[0].Timestamp.IsZero() {
		t.Fatal("expected non-zero event timestamp")
	}
}

func TestExecuteCatalogScanEmitsCompletionAuditEvent(t *testing.T) {
	t.Parallel()

	handler := NewScanHandlerWithRegistry(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{
		result: scan.AnalysisResult{
			ImageRef:                "alpine:latest",
			SBOMDocument:            []byte(testCycloneDXDocument),
			SBOMSPDXDocument:        []byte(testSPDXDocument),
			SBOMData:                testSyftSBOM(),
			CombinedVulnerabilities: []byte(`{"matches":[]}`),
			CombinedReport:          testCombinedVulnerabilityReport(),
			Summary:                 scan.VulnerabilitySummary{Total: 1, Fixable: 1},
			ScannerReports:          []scan.ScannerReport{{Scanner: "grype", ContentType: "application/json", Document: []byte(`[]`)}},
		},
	}, stubRegistryService{
		access: registry.ImageAccess{Registry: "index.docker.io", AuthSource: "anonymous"},
	})
	var buffer bytes.Buffer
	recorder, err := audit.NewWriterRecorder(&buffer)
	if err != nil {
		t.Fatalf("NewWriterRecorder() error = %v", err)
	}
	handler.SetAuditRecorder(recorder)

	if _, err := handler.ExecuteCatalogScan(context.Background(), catalogscan.Request{
		OrgID:     "catalog",
		ImageID:   "alpine-latest",
		ImageName: "alpine:latest",
		Source:    catalogscan.SourceAPI,
		Trigger:   catalogscan.TriggerManual,
		Actor:     "auditor",
		ActorType: "user",
	}); err != nil {
		t.Fatalf("ExecuteCatalogScan() error = %v", err)
	}

	events := decodeAuditEvents(t, buffer.Bytes())
	if got, want := len(events), 1; got != want {
		t.Fatalf("len(events) = %d, want %d", got, want)
	}
	if got, want := events[0].Action, "scan.completed"; got != want {
		t.Fatalf("events[0].Action = %q, want %q", got, want)
	}
	if got, want := events[0].Outcome, "succeeded"; got != want {
		t.Fatalf("events[0].Outcome = %q, want %q", got, want)
	}
	if got, want := events[0].Actor, "auditor"; got != want {
		t.Fatalf("events[0].Actor = %q, want %q", got, want)
	}
}

func TestImportAndDeleteEmitAuditEvents(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := NewScanHandler(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{})
	var buffer bytes.Buffer
	recorder, err := audit.NewWriterRecorder(&buffer)
	if err != nil {
		t.Fatalf("NewWriterRecorder() error = %v", err)
	}
	handler.SetAuditRecorder(recorder)

	router := authenticatedRouter(t, false)
	router.POST("/api/v1/images/:id/sbom", handler.ImportImageSBOM)
	router.POST("/api/v1/images/:id/vex", handler.ImportImageVEX)
	router.DELETE("/api/v1/scans/:org_id/:image_id", handler.DeleteImageScansHandler)

	importSBOMBody, importSBOMType := buildMultipartBody(t, "file", "demo.cdx.json", testCycloneDXDocument, map[string]string{
		"image_name": "alpine:latest",
		"format":     "cyclonedx",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/images/demo-image/sbom?org_id=demo-org", importSBOMBody)
	req.Header.Set("Authorization", "Bearer audit-token")
	req.Header.Set("Content-Type", importSBOMType)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("SBOM status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	importVEXBody, importVEXType := buildMultipartBody(t, "file", "demo.vex.json", `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/demo",
  "author": "Otter",
  "timestamp": "2026-03-20T12:00:00Z",
  "statements": [
    {
      "vulnerability": { "name": "CVE-2024-0001" },
      "products": [{ "@id": "pkg:oci/alpine@latest" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_present"
    }
  ]
}`, nil)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/images/demo-image/vex?org_id=demo-org", importVEXBody)
	req.Header.Set("Authorization", "Bearer audit-token")
	req.Header.Set("Content-Type", importVEXType)
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("VEX status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/scans/demo-org/demo-image", nil)
	req.Header.Set("Authorization", "Bearer audit-token")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("delete status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	events := decodeAuditEvents(t, buffer.Bytes())
	if got, want := len(events), 3; got != want {
		t.Fatalf("len(events) = %d, want %d", got, want)
	}
	if got, want := events[0].Action, "sbom.imported"; got != want {
		t.Fatalf("events[0].Action = %q, want %q", got, want)
	}
	if got, want := events[1].Action, "vex.imported"; got != want {
		t.Fatalf("events[1].Action = %q, want %q", got, want)
	}
	if got, want := events[2].Action, "scan.deleted"; got != want {
		t.Fatalf("events[2].Action = %q, want %q", got, want)
	}
}

func TestConfigureRegistryEmitsAuditEvent(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	handler := NewScanHandlerWithRegistry(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{}, stubRegistryService{
		listResult: []registry.Summary{{Registry: "docker.io"}},
		configureResult: registry.ConfigureResult{
			Summary: registry.Summary{
				Registry:       "ghcr.io",
				AuthMode:       registry.AuthModeExplicit,
				HasCredentials: true,
			},
			AuthSource: "explicit-token",
		},
	})
	var buffer bytes.Buffer
	recorder, err := audit.NewWriterRecorder(&buffer)
	if err != nil {
		t.Fatalf("NewWriterRecorder() error = %v", err)
	}
	handler.SetAuditRecorder(recorder)

	router := authenticatedRouter(t, true)
	router.POST("/api/v1/registries", handler.ConfigureRegistry)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/registries", bytes.NewReader([]byte(`{"registry":"ghcr.io","auth_mode":"explicit","token":"secret"}`)))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	events := decodeAuditEvents(t, buffer.Bytes())
	if got, want := len(events), 1; got != want {
		t.Fatalf("len(events) = %d, want %d", got, want)
	}
	if got, want := events[0].Action, "registry.created"; got != want {
		t.Fatalf("events[0].Action = %q, want %q", got, want)
	}
	if got, want := events[0].OrgID, "global"; got != want {
		t.Fatalf("events[0].OrgID = %q, want %q", got, want)
	}
	if got, want := events[0].Target, "ghcr.io"; got != want {
		t.Fatalf("events[0].Target = %q, want %q", got, want)
	}
}

func authenticatedRouter(t *testing.T, requireAdmin bool) *gin.Engine {
	t.Helper()

	authenticator, err := auth.NewAuthenticator(auth.Config{
		Enabled: true,
		Tokens: []auth.TokenRecord{
			{Token: "audit-token", Subject: "auditor", Orgs: []string{"demo-org", "catalog"}},
			{Token: "admin-token", Subject: "admin", Admin: true},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	router := gin.New()
	router.Use(authenticator.Middleware())
	if requireAdmin {
		router.Use(authenticator.RequireAdmin())
	} else {
		router.Use(authenticator.RequireAuthentication())
	}
	return router
}

func buildMultipartBody(t *testing.T, fieldName, filename, document string, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write([]byte(document)); err != nil {
		t.Fatalf("part.Write() error = %v", err)
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("WriteField(%q) error = %v", key, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() error = %v", err)
	}
	return &body, writer.FormDataContentType()
}

func decodeAuditEvents(t *testing.T, payload []byte) []audit.Event {
	t.Helper()

	lines := bytes.Split(bytes.TrimSpace(payload), []byte("\n"))
	events := make([]audit.Event, 0, len(lines))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event audit.Event
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		events = append(events, event)
	}
	return events
}
