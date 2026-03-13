package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
)

type stubAnalyzer struct {
	result scan.AnalysisResult
	err    error
}

func (s stubAnalyzer) Analyze(context.Context, string) (scan.AnalysisResult, error) {
	return s.result, s.err
}

func TestGenerateScanSbomVulStoresCombinedAndScannerArtifacts(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}

	handler := NewScanHandler(store, stubAnalyzer{
		result: scan.AnalysisResult{
			ImageRef:                "alpine:latest",
			SBOMDocument:            []byte(`{"bomFormat":"CycloneDX"}`),
			CombinedVulnerabilities: []byte(`{"schema_version":"v1alpha1"}`),
			Summary:                 scan.VulnerabilitySummary{Total: 2},
			ScannerReports: []scan.ScannerReport{
				{
					Scanner:     "grype",
					ContentType: "application/json",
					Document:    []byte(`[{"id":"CVE-2024-0001"}]`),
				},
				{
					Scanner:     "trivy",
					ContentType: "application/json",
					Document:    []byte(`{"Results":[]}`),
				},
			},
		},
	})

	router := gin.New()
	router.POST("/api/v1/scans", handler.GenerateScanSbomVul)

	body, err := json.Marshal(ImageGeneratePayload{
		ImageName: "alpine:latest",
		OrgID:     "demo-org",
		ImageID:   "demo-image",
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

	prefix, err := storage.BuildImagePrefix("demo-org", "demo-image")
	if err != nil {
		t.Fatalf("BuildImagePrefix() error = %v", err)
	}
	objects, err := store.List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(objects), 4; got != want {
		t.Fatalf("len(objects) = %d, want %d", got, want)
	}
}
