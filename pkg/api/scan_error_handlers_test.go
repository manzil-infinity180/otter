package api

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/catalogscan"
	"github.com/otterXf/otter/pkg/compare"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestScanHandlerErrorClassificationAndQueueErrors(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	handler := NewScanHandler(mustLocalStore(t), mustLocalSBOMRepo(t), mustLocalVulnRepo(t), stubAnalyzer{})

	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "deadline", err: context.DeadlineExceeded, wantStatus: http.StatusGatewayTimeout},
		{name: "registry", err: io.EOF, wantStatus: http.StatusInternalServerError},
		{name: "prepare", err: assertError("prepare image pull: upstream failed"), wantStatus: http.StatusBadGateway},
		{name: "bad-request", err: assertError("invalid image_name"), wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			handler.renderScanExecutionError(c, tt.err)
			if got, want := recorder.Code, tt.wantStatus; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
		})
	}

	router := gin.New()
	router.GET("/api/v1/scan-jobs/:id", handler.GetScanJob)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/job-1", nil))
	if got, want := resp.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	handler.SetJobQueue(&stubJobQueue{job: catalogscanJob("job-1")})
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/missing", nil))
	if got, want := resp.Code, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

func TestImportImageSBOMAndReadValidationErrors(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := mustLocalStore(t)
	sbomRepo := mustLocalSBOMRepo(t)
	vulnRepo := mustLocalVulnRepo(t)
	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})

	router := gin.New()
	router.POST("/api/v1/images/:id/sbom", handler.ImportImageSBOM)
	router.GET("/api/v1/images/:id/sbom", handler.GetImageSBOM)

	body, contentType := multipartBody(t, "file", "sbom.json", []byte(testCycloneDXDocument), map[string]string{
		"image_name": "alpine:latest",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/images/demo-image/sbom?org_id=demo-org", body)
	req.Header.Set("Content-Type", contentType)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	badFormat := httptest.NewRecorder()
	router.ServeHTTP(badFormat, httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/sbom?org_id=demo-org&format=yaml", nil))
	if got, want := badFormat.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, badFormat.Body.String())
	}

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/v1/images/missing/sbom?org_id=demo-org", nil))
	if got, want := missing.Code, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, missing.Body.String())
	}
}

func TestImportImageVEXAndVulnerabilityErrorPaths(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := mustLocalStore(t)
	sbomRepo := mustLocalSBOMRepo(t)
	vulnRepo := mustLocalVulnRepo(t)
	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})

	record, err := vulnRepo.Save(context.Background(), vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:latest",
		Vulnerabilities: []vulnindex.VulnerabilityRecord{
			{
				ID:             "CVE-2024-0001",
				Severity:       "HIGH",
				PackageName:    "busybox",
				PackageVersion: "1.36.1",
				Status:         vulnindex.StatusAffected,
				StatusSource:   vulnindex.StatusSourceScanner,
				Scanners:       []string{"grype"},
			},
		},
		Summary:   vulnindex.Summary{Total: 1, BySeverity: map[string]int{"HIGH": 1}, ByStatus: map[string]int{vulnindex.StatusAffected: 1}, ByScanner: map[string]int{"grype": 1}},
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}
	if record.ImageID == "" {
		t.Fatal("expected vulnerability record to be saved")
	}

	router := gin.New()
	router.POST("/api/v1/images/:id/vex", handler.ImportImageVEX)
	router.GET("/api/v1/images/:id/vulnerabilities", handler.GetImageVulnerabilities)

	body, contentType := multipartBody(t, "file", "advisory.json", []byte(`{
		"@context":"https://openvex.dev/ns/v0.2.0",
		"@id":"https://example.com/vex/demo",
		"author":"otter",
		"timestamp":"2026-03-14T00:00:00Z",
		"version":1,
		"statements":[{"vulnerability":{"name":"CVE-2024-0001"},"status":"fixed","products":[{"@id":"pkg:oci/alpine@latest"}]}]
	}`), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/images/demo-image/vex?org_id=demo-org", body)
	req.Header.Set("Content-Type", contentType)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	badSeverity := httptest.NewRecorder()
	router.ServeHTTP(badSeverity, httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/vulnerabilities?org_id=demo-org&severity=impossible", nil))
	if got, want := badSeverity.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, badSeverity.Body.String())
	}

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/v1/images/missing/vulnerabilities?org_id=demo-org", nil))
	if got, want := missing.Code, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, missing.Body.String())
	}
}

func TestAttestationAndStoredComparisonErrorPaths(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := mustLocalStore(t)
	sbomRepo := mustLocalSBOMRepo(t)
	vulnRepo := mustLocalVulnRepo(t)
	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	handler.attestor = stubAttestationFetcher{err: assertError("registry unavailable")}

	router := gin.New()
	router.GET("/api/v1/images/:id/attestations", handler.GetImageAttestations)
	router.GET("/api/v1/comparisons/:id", handler.GetStoredComparison)

	notFound := httptest.NewRecorder()
	router.ServeHTTP(notFound, httptest.NewRequest(http.MethodGet, "/api/v1/images/missing/attestations?org_id=demo-org", nil))
	if got, want := notFound.Code, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, notFound.Body.String())
	}

	sbomRecord, err := sbomRepo.Save(context.Background(), sbomindex.Record{
		OrgID:        "demo-org",
		ImageID:      "demo-image",
		ImageName:    "alpine:latest",
		SourceFormat: sbomindex.FormatCycloneDX,
		UpdatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("sbomRepo.Save() error = %v", err)
	}
	if sbomRecord.ImageID == "" {
		t.Fatal("expected SBOM record to be saved")
	}

	badGateway := httptest.NewRecorder()
	router.ServeHTTP(badGateway, httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/attestations?org_id=demo-org", nil))
	if got, want := badGateway.Code, http.StatusBadGateway; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, badGateway.Body.String())
	}

	comparisonID := compare.ComputeID("org1", "img1", "org2", "img2")
	key, err := BuildComparisonKey(comparisonID)
	if err != nil {
		t.Fatalf("BuildComparisonKey() error = %v", err)
	}
	if _, err := store.Put(context.Background(), key, []byte(`not-json`), storage.PutOptions{ContentType: "application/json"}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}

	invalid := httptest.NewRecorder()
	router.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/api/v1/comparisons/"+comparisonID, nil))
	if got, want := invalid.Code, http.StatusInternalServerError; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, invalid.Body.String())
	}
}

func TestScanListingDownloadExportCompareAndDeleteErrorPaths(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	store := mustLocalStore(t)
	sbomRepo := mustLocalSBOMRepo(t)
	vulnRepo := mustLocalVulnRepo(t)
	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})

	router := gin.New()
	router.GET("/api/v1/scans/:org_id/:image_id", handler.GetImageScans)
	router.GET("/api/v1/scans/:org_id/:image_id/files/:filename", handler.DownloadScanFile)
	router.GET("/api/v1/images/:id/export", handler.ExportImage)
	router.GET("/api/v1/comparisons/:id/export", handler.ExportComparison)
	router.GET("/api/v1/compare", handler.CompareImages)
	router.DELETE("/api/v1/scans/:org_id/:image_id", handler.DeleteImageScansHandler)

	badIDs := httptest.NewRecorder()
	router.ServeHTTP(badIDs, httptest.NewRequest(http.MethodGet, "/api/v1/scans/bad!/demo-image", nil))
	if got, want := badIDs.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, badIDs.Body.String())
	}

	missingFile := httptest.NewRecorder()
	router.ServeHTTP(missingFile, httptest.NewRequest(http.MethodGet, "/api/v1/scans/demo-org/demo-image/files/sbom.json", nil))
	if got, want := missingFile.Code, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, missingFile.Body.String())
	}

	badExport := httptest.NewRecorder()
	router.ServeHTTP(badExport, httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/export?org_id=demo-org&format=yaml", nil))
	if got, want := badExport.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, badExport.Body.String())
	}

	missingComparison := httptest.NewRecorder()
	router.ServeHTTP(missingComparison, httptest.NewRequest(http.MethodGet, "/api/v1/comparisons/missing/export", nil))
	if got, want := missingComparison.Code, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, missingComparison.Body.String())
	}

	missingCompareParams := httptest.NewRecorder()
	router.ServeHTTP(missingCompareParams, httptest.NewRequest(http.MethodGet, "/api/v1/compare?image1=alpine:latest", nil))
	if got, want := missingCompareParams.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, missingCompareParams.Body.String())
	}

	sbomKey, err := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}.BuildSBOMKey()
	if err != nil {
		t.Fatalf("BuildSBOMKey() error = %v", err)
	}
	if _, err := store.Put(context.Background(), sbomKey, []byte(testCycloneDXDocument), storage.PutOptions{ContentType: "application/vnd.cyclonedx+json"}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}
	if _, err := sbomRepo.Save(context.Background(), sbomindex.Record{OrgID: "demo-org", ImageID: "demo-image", ImageName: "alpine:latest", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("sbomRepo.Save() error = %v", err)
	}
	if _, err := vulnRepo.Save(context.Background(), vulnindex.Record{OrgID: "demo-org", ImageID: "demo-image", ImageName: "alpine:latest", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}

	deleteResp := httptest.NewRecorder()
	router.ServeHTTP(deleteResp, httptest.NewRequest(http.MethodDelete, "/api/v1/scans/demo-org/demo-image", nil))
	if got, want := deleteResp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, deleteResp.Body.String())
	}
}

func multipartBody(t *testing.T, field, filename string, content []byte, extra map[string]string) (*bytes.Buffer, string) {
	t.Helper()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("part.Write() error = %v", err)
	}
	for key, value := range extra {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("WriteField() error = %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return body, writer.FormDataContentType()
}

func catalogscanJob(id string) catalogscan.Job {
	return catalogscan.Job{
		ID:        id,
		Status:    catalogscan.StatusPending,
		Request:   catalogscan.Request{OrgID: "demo-org", ImageID: "demo-image", ImageName: "alpine:latest"},
		CreatedAt: time.Now().UTC(),
	}
}

type assertError string

func (e assertError) Error() string { return string(e) }
