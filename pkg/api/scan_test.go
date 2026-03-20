package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	syftsource "github.com/anchore/syft/syft/source"
	"github.com/otterXf/otter/pkg/attestation"
	"github.com/otterXf/otter/pkg/catalogscan"
	"github.com/otterXf/otter/pkg/compliance"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

type stubAnalyzer struct {
	result scan.AnalysisResult
	err    error
}

func (s stubAnalyzer) Analyze(context.Context, string) (scan.AnalysisResult, error) {
	return s.result, s.err
}

type stubAttestationFetcher struct {
	result attestation.Result
	err    error
}

func (s stubAttestationFetcher) Discover(context.Context, string) (attestation.Result, error) {
	return s.result, s.err
}

type stubComplianceScorecardClient struct {
	summary compliance.ScorecardSummary
	err     error
}

func (s stubComplianceScorecardClient) Lookup(context.Context, compliance.Repository) (compliance.ScorecardSummary, error) {
	return s.summary, s.err
}

type stubJobQueue struct {
	job      catalogscan.Job
	requests []catalogscan.Request
}

func (s *stubJobQueue) Enqueue(req catalogscan.Request) (catalogscan.Job, error) {
	s.requests = append(s.requests, req)
	return s.job, nil
}

func (s *stubJobQueue) Get(jobID string) (catalogscan.Job, bool) {
	if s.job.ID != jobID {
		return catalogscan.Job{}, false
	}
	return s.job, true
}

func TestGenerateScanSbomVulStoresCombinedAndStructuredSBOMArtifacts(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{
		result: scan.AnalysisResult{
			ImageRef:         "alpine:latest",
			SBOMDocument:     []byte(testCycloneDXDocument),
			SBOMSPDXDocument: []byte(testSPDXDocument),
			SBOMData:         testSyftSBOM(),
			CombinedReport: scan.CombinedVulnerabilityReport{
				ImageRef:    "alpine:latest",
				GeneratedAt: time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
				Summary:     scan.VulnerabilitySummary{Total: 1, Fixable: 1},
				Vulnerabilities: []scan.VulnerabilityFinding{
					{
						ID:             "CVE-2024-0001",
						Severity:       "HIGH",
						PackageName:    "busybox",
						PackageVersion: "1.36.1",
						FixVersion:     "1.36.2",
						Scanners:       []string{"grype"},
					},
				},
			},
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
	if got, want := len(objects), 6; got != want {
		t.Fatalf("len(objects) = %d, want %d", got, want)
	}
	for _, object := range objects {
		if got, want := object.Metadata["platform"], "linux/amd64"; got != want {
			t.Fatalf("object %q platform metadata = %q, want %q", object.Key, got, want)
		}
	}

	record, err := repo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("repo.Get() error = %v", err)
	}
	if got, want := record.PackageCount, 2; got != want {
		t.Fatalf("record.PackageCount = %d, want %d", got, want)
	}
	if got, want := record.Platform, "linux/amd64"; got != want {
		t.Fatalf("record.Platform = %q, want %q", got, want)
	}

	vulnerabilities, err := vulnRepo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("vulnRepo.Get() error = %v", err)
	}
	if got, want := vulnerabilities.Summary.Total, 1; got != want {
		t.Fatalf("vulnerabilities.Summary.Total = %d, want %d", got, want)
	}
	if got, want := vulnerabilities.Platform, "linux/amd64"; got != want {
		t.Fatalf("vulnerabilities.Platform = %q, want %q", got, want)
	}
	if !bytes.Contains(resp.Body.Bytes(), []byte(`"platform":"linux/amd64"`)) {
		t.Fatalf("expected platform in response body, body=%s", resp.Body.String())
	}
}

func TestGenerateScanSbomVulQueuesAsyncJobs(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{})
	queue := &stubJobQueue{
		job: catalogscan.Job{
			ID:        "scanjob-1234",
			Status:    catalogscan.StatusPending,
			Request:   catalogscan.Request{OrgID: "catalog", ImageID: "alpine-job", ImageName: "alpine:latest"},
			CreatedAt: time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
		},
	}
	handler.SetJobQueue(queue)

	router := gin.New()
	router.POST("/api/v1/scans", handler.GenerateScanSbomVul)

	body, err := json.Marshal(ImageGeneratePayload{
		ImageName: "alpine:latest",
		OrgID:     "catalog",
		ImageID:   "alpine-job",
		Arch:      "arm64",
		Async:     true,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusAccepted; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload struct {
		StatusURL string `json:"status_url"`
		Job       struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"job"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Job.ID != "scanjob-1234" || payload.Job.Status != catalogscan.StatusPending {
		t.Fatalf("payload.Job = %#v", payload.Job)
	}
	if payload.StatusURL != "/api/v1/scan-jobs/scanjob-1234" {
		t.Fatalf("payload.StatusURL = %q", payload.StatusURL)
	}
	if got, want := len(queue.requests), 1; got != want {
		t.Fatalf("len(queue.requests) = %d, want %d", got, want)
	}
	if got, want := queue.requests[0].Platform, "linux/arm64"; got != want {
		t.Fatalf("queue.requests[0].Platform = %q, want %q", got, want)
	}
}

func TestGetScanJobReturnsQueuedJob(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{})
	handler.SetJobQueue(&stubJobQueue{
		job: catalogscan.Job{
			ID:        "scanjob-queued",
			Status:    catalogscan.StatusRunning,
			Request:   catalogscan.Request{OrgID: "catalog", ImageID: "nginx-job", ImageName: "nginx:latest"},
			CreatedAt: time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
		},
	})

	router := gin.New()
	router.GET("/api/v1/scan-jobs/:id", handler.GetScanJob)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-jobs/scanjob-queued", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload struct {
		Job struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"job"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Job.ID != "scanjob-queued" || payload.Job.Status != catalogscan.StatusRunning {
		t.Fatalf("payload.Job = %#v", payload.Job)
	}
}

func TestGetImageSBOMReturnsStructuredDocument(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	record, err := sbomindex.BuildRecordFromDocument("demo-org", "demo-image", "alpine:latest", sbomindex.FormatSPDX, []byte(testSPDXDocument))
	if err != nil {
		t.Fatalf("BuildRecordFromDocument() error = %v", err)
	}
	if _, err := repo.Save(context.Background(), record); err != nil {
		t.Fatalf("repo.Save() error = %v", err)
	}

	key, err := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}.BuildSBOMKeyForFormat(sbomindex.FormatSPDX)
	if err != nil {
		t.Fatalf("BuildSBOMKeyForFormat() error = %v", err)
	}
	if _, err := store.Put(context.Background(), key, []byte(testSPDXDocument), storage.PutOptions{ContentType: "application/spdx+json"}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/images/:id/sbom", handler.GetImageSBOM)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/sbom?org_id=demo-org&format=spdx", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload struct {
		Format       string `json:"format"`
		PackageCount int    `json:"package_count"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Format != sbomindex.FormatSPDX || payload.PackageCount != 2 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestReadOnlyGETsDoNotPersistMissingIndexes(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}
	sbomKey, err := keyBuilder.BuildSBOMKeyForFormat(sbomindex.FormatCycloneDX)
	if err != nil {
		t.Fatalf("BuildSBOMKeyForFormat() error = %v", err)
	}
	if _, err := store.Put(context.Background(), sbomKey, []byte(testCycloneDXDocument), storage.PutOptions{
		ContentType: "application/vnd.cyclonedx+json",
		Metadata:    map[string]string{"image_name": "alpine:latest", "platform": "linux/amd64"},
	}); err != nil {
		t.Fatalf("store.Put(sbom) error = %v", err)
	}

	vulnerabilityDocument, err := json.Marshal(testCombinedVulnerabilityReport())
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	vulnerabilityKey, err := keyBuilder.BuildVulnerabilityKey()
	if err != nil {
		t.Fatalf("BuildVulnerabilityKey() error = %v", err)
	}
	if _, err := store.Put(context.Background(), vulnerabilityKey, vulnerabilityDocument, storage.PutOptions{
		ContentType: "application/json",
		Metadata:    map[string]string{"image_name": "alpine:latest", "platform": "linux/amd64"},
	}); err != nil {
		t.Fatalf("store.Put(vulnerabilities) error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/images/:id/sbom", handler.GetImageSBOM)
	router.GET("/api/v1/images/:id/vulnerabilities", handler.GetImageVulnerabilities)

	sbomReq := httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/sbom?org_id=demo-org", nil)
	sbomResp := httptest.NewRecorder()
	router.ServeHTTP(sbomResp, sbomReq)
	if got, want := sbomResp.Code, http.StatusOK; got != want {
		t.Fatalf("sbom status = %d, want %d, body=%s", got, want, sbomResp.Body.String())
	}
	if _, err := sbomRepo.Get(context.Background(), "demo-org", "demo-image"); !errors.Is(err, sbomindex.ErrNotFound) {
		t.Fatalf("sbomRepo.Get() error = %v, want ErrNotFound", err)
	}

	vulnReq := httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/vulnerabilities?org_id=demo-org", nil)
	vulnResp := httptest.NewRecorder()
	router.ServeHTTP(vulnResp, vulnReq)
	if got, want := vulnResp.Code, http.StatusOK; got != want {
		t.Fatalf("vulnerability status = %d, want %d, body=%s", got, want, vulnResp.Body.String())
	}
	if _, err := vulnRepo.Get(context.Background(), "demo-org", "demo-image"); !errors.Is(err, vulnindex.ErrNotFound) {
		t.Fatalf("vulnRepo.Get() error = %v, want ErrNotFound", err)
	}
}

func TestRepairImageIndexesPersistsMissingIndexesFromArtifacts(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}
	sbomKey, err := keyBuilder.BuildSBOMKeyForFormat(sbomindex.FormatCycloneDX)
	if err != nil {
		t.Fatalf("BuildSBOMKeyForFormat() error = %v", err)
	}
	if _, err := store.Put(context.Background(), sbomKey, []byte(testCycloneDXDocument), storage.PutOptions{
		ContentType: "application/vnd.cyclonedx+json",
		Metadata:    map[string]string{"image_name": "alpine:latest", "platform": "linux/amd64"},
	}); err != nil {
		t.Fatalf("store.Put(sbom) error = %v", err)
	}

	vulnerabilityDocument, err := json.Marshal(testCombinedVulnerabilityReport())
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	vulnerabilityKey, err := keyBuilder.BuildVulnerabilityKey()
	if err != nil {
		t.Fatalf("BuildVulnerabilityKey() error = %v", err)
	}
	if _, err := store.Put(context.Background(), vulnerabilityKey, vulnerabilityDocument, storage.PutOptions{
		ContentType: "application/json",
		Metadata:    map[string]string{"image_name": "alpine:latest", "platform": "linux/amd64"},
	}); err != nil {
		t.Fatalf("store.Put(vulnerabilities) error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.POST("/api/v1/images/:id/indexes/repair", handler.RepairImageIndexes)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/images/demo-image/indexes/repair?org_id=demo-org", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
	if !bytes.Contains(resp.Body.Bytes(), []byte(`"status":"repaired"`)) {
		t.Fatalf("expected repaired statuses in response, body=%s", resp.Body.String())
	}

	if _, err := sbomRepo.Get(context.Background(), "demo-org", "demo-image"); err != nil {
		t.Fatalf("sbomRepo.Get() error = %v", err)
	}
	if _, err := vulnRepo.Get(context.Background(), "demo-org", "demo-image"); err != nil {
		t.Fatalf("vulnRepo.Get() error = %v", err)
	}
}

func TestGetImageComplianceReturnsStructuredAssessment(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	if _, err := repo.Save(context.Background(), sbomindex.Record{
		OrgID:        "demo-org",
		ImageID:      "demo-image",
		ImageName:    "ghcr.io/demo/project:1.0.0",
		SourceFormat: sbomindex.FormatCycloneDX,
		UpdatedAt:    time.Date(2026, 3, 14, 1, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("repo.Save() error = %v", err)
	}
	if _, err := vulnRepo.Save(context.Background(), vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "ghcr.io/demo/project:1.0.0",
		Summary: vulnindex.Summary{
			BySeverity: map[string]int{},
		},
		UpdatedAt: time.Date(2026, 3, 14, 1, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{})
	handler.attestor = stubAttestationFetcher{
		result: attestation.Result{
			ImageRef: "ghcr.io/demo/project:1.0.0",
			Summary:  attestation.Summary{Total: 1, Signatures: 1, Attestations: 1, Provenance: 1},
			Attestations: []attestation.Record{
				{
					Digest:             "sha256:abc123",
					Kind:               attestation.KindAttestation,
					VerificationStatus: attestation.VerificationStatusValid,
					PredicateType:      "https://slsa.dev/provenance/v1",
					Provenance: &attestation.ProvenanceSummary{
						BuilderID:    "https://github.com/actions/runner",
						BuildType:    "https://slsa.dev/container-based-build/v1",
						InvocationID: "run-123",
						Materials:    []string{"git+https://github.com/demo/project@refs/heads/main"},
					},
				},
			},
			UpdatedAt: time.Date(2026, 3, 14, 1, 5, 0, 0, time.UTC),
		},
	}
	handler.compliance = compliance.NewServiceWithClient(stubComplianceScorecardClient{
		summary: compliance.ScorecardSummary{
			Enabled:    true,
			Available:  true,
			Status:     compliance.StatusPass,
			Repository: "github.com/demo/project",
			Score:      9.1,
			RiskLevel:  "strong",
		},
	})

	router := gin.New()
	router.GET("/api/v1/images/:id/compliance", handler.GetImageCompliance)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/compliance?org_id=demo-org", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
	if !bytes.Contains(resp.Body.Bytes(), []byte(`"repository":"github.com/demo/project"`)) {
		t.Fatalf("expected source repository in response, body=%s", resp.Body.String())
	}
	if !bytes.Contains(resp.Body.Bytes(), []byte(`"level":3`)) {
		t.Fatalf("expected slsa level 3 in response, body=%s", resp.Body.String())
	}
}

func TestImportImageSBOMStoresDocumentAndIndex(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.POST("/api/v1/images/:id/sbom", handler.ImportImageSBOM)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "demo.cdx.json")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write([]byte(testCycloneDXDocument)); err != nil {
		t.Fatalf("part.Write() error = %v", err)
	}
	if err := writer.WriteField("image_name", "alpine:latest"); err != nil {
		t.Fatalf("WriteField(image_name) error = %v", err)
	}
	if err := writer.WriteField("format", sbomindex.FormatCycloneDX); err != nil {
		t.Fatalf("WriteField(format) error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/images/demo-image/sbom?org_id=demo-org", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	record, err := repo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("repo.Get() error = %v", err)
	}
	if got, want := record.PackageCount, 2; got != want {
		t.Fatalf("record.PackageCount = %d, want %d", got, want)
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}
	for _, format := range []string{"sbom.json", "sbom-cyclonedx.json"} {
		key, err := keyBuilder.BuildKey(format)
		if err != nil {
			t.Fatalf("BuildKey(%q) error = %v", format, err)
		}
		if _, err := store.Get(context.Background(), key); err != nil {
			t.Fatalf("store.Get(%q) error = %v", key, err)
		}
	}
}

func TestListCatalogReturnsEntriesAndFilters(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	for _, record := range []sbomindex.Record{
		{
			OrgID:        "demo-org",
			ImageID:      "image-a",
			ImageName:    "alpine:3.19",
			SourceFormat: sbomindex.FormatCycloneDX,
			PackageCount: 2,
			UpdatedAt:    time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
		},
		{
			OrgID:        "demo-org",
			ImageID:      "image-b",
			ImageName:    "nginx:latest",
			SourceFormat: sbomindex.FormatCycloneDX,
			PackageCount: 3,
			UpdatedAt:    time.Date(2026, 3, 13, 17, 0, 0, 0, time.UTC),
		},
	} {
		if _, err := repo.Save(context.Background(), record); err != nil {
			t.Fatalf("repo.Save() error = %v", err)
		}
	}

	for _, record := range []vulnindex.Record{
		{
			OrgID:     "demo-org",
			ImageID:   "image-a",
			ImageName: "alpine:3.19",
			Summary: vulnindex.Summary{
				Total:      2,
				BySeverity: map[string]int{"CRITICAL": 1, "HIGH": 1},
				ByScanner:  map[string]int{"grype": 2},
			},
			UpdatedAt: time.Date(2026, 3, 13, 18, 30, 0, 0, time.UTC),
		},
		{
			OrgID:     "demo-org",
			ImageID:   "image-b",
			ImageName: "nginx:latest",
			Summary: vulnindex.Summary{
				Total:      1,
				BySeverity: map[string]int{"LOW": 1},
				ByScanner:  map[string]int{"trivy": 1},
			},
			UpdatedAt: time.Date(2026, 3, 13, 17, 30, 0, 0, time.UTC),
		},
	} {
		if _, err := vulnRepo.Save(context.Background(), record); err != nil {
			t.Fatalf("vulnRepo.Save() error = %v", err)
		}
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/catalog", handler.ListCatalog)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/catalog?severity=critical", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload struct {
		Count int                 `json:"count"`
		Items []ImageCatalogEntry `json:"items"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := payload.Count, 1; got != want {
		t.Fatalf("payload.Count = %d, want %d", got, want)
	}
	if got, want := payload.Items[0].Repository, "index.docker.io/library/alpine"; got != want {
		t.Fatalf("payload.Items[0].Repository = %q, want %q", got, want)
	}
}

func TestGetImageOverviewReturnsTagsAndFiles(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	repo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	for _, record := range []sbomindex.Record{
		{
			OrgID:           "demo-org",
			ImageID:         "image-a",
			ImageName:       "alpine:3.19",
			Platform:        "linux/amd64",
			SourceFormat:    sbomindex.FormatCycloneDX,
			PackageCount:    2,
			DependencyRoots: []string{"pkg:apk/alpine/busybox@1.0.0"},
			UpdatedAt:       time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
		},
		{
			OrgID:        "demo-org",
			ImageID:      "image-b",
			ImageName:    "alpine:3.20",
			Platform:     "linux/arm64",
			SourceFormat: sbomindex.FormatCycloneDX,
			PackageCount: 3,
			UpdatedAt:    time.Date(2026, 3, 13, 19, 0, 0, 0, time.UTC),
		},
	} {
		if _, err := repo.Save(context.Background(), record); err != nil {
			t.Fatalf("repo.Save() error = %v", err)
		}
	}

	if _, err := vulnRepo.Save(context.Background(), vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "image-a",
		ImageName: "alpine:3.19",
		Summary: vulnindex.Summary{
			Total:      1,
			BySeverity: map[string]int{"HIGH": 1},
			ByScanner:  map[string]int{"grype": 1},
		},
		UpdatedAt: time.Date(2026, 3, 13, 18, 30, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}
	if _, err := vulnRepo.Save(context.Background(), vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "image-b",
		ImageName: "alpine:3.20",
		Summary: vulnindex.Summary{
			Total:      2,
			BySeverity: map[string]int{"CRITICAL": 1, "HIGH": 1},
			ByScanner:  map[string]int{"trivy": 2},
		},
		UpdatedAt: time.Date(2026, 3, 13, 19, 30, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}

	key, err := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "image-a"}.BuildSBOMKey()
	if err != nil {
		t.Fatalf("BuildSBOMKey() error = %v", err)
	}
	if _, err := store.Put(context.Background(), key, []byte(`{"bomFormat":"CycloneDX"}`), storage.PutOptions{
		ContentType: "application/vnd.cyclonedx+json",
	}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}

	handler := NewScanHandler(store, repo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/images/:id/overview", handler.GetImageOverview)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/image-a/overview?org_id=demo-org", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload ImageOverview
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := len(payload.Tags), 1; got != want {
		t.Fatalf("len(payload.Tags) = %d, want %d", got, want)
	}
	if got, want := len(payload.Files), 1; got != want {
		t.Fatalf("len(payload.Files) = %d, want %d", got, want)
	}
	if got, want := payload.Platform, "linux/amd64"; got != want {
		t.Fatalf("payload.Platform = %q, want %q", got, want)
	}
	if got, want := payload.Tags[0].Tag, "3.20"; got != want {
		t.Fatalf("payload.Tags[0].Tag = %q, want %q", got, want)
	}
	if got, want := payload.Tags[0].Platform, "linux/arm64"; got != want {
		t.Fatalf("payload.Tags[0].Platform = %q, want %q", got, want)
	}
}

func TestGetImageVulnerabilitiesFiltersSeverity(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	record := vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:latest",
		Summary: vulnindex.Summary{
			Total:      2,
			BySeverity: map[string]int{"CRITICAL": 1, "LOW": 1},
			ByScanner:  map[string]int{"grype": 2},
			ByStatus:   map[string]int{vulnindex.StatusAffected: 2},
			Fixable:    1,
			Unfixable:  1,
		},
		Vulnerabilities: []vulnindex.VulnerabilityRecord{
			{
				ID:          "CVE-2024-0001",
				Severity:    "CRITICAL",
				PackageName: "openssl",
				Status:      vulnindex.StatusAffected,
				Scanners:    []string{"grype"},
			},
			{
				ID:          "CVE-2024-0002",
				Severity:    "LOW",
				PackageName: "busybox",
				Status:      vulnindex.StatusAffected,
				Scanners:    []string{"grype"},
			},
		},
	}
	if _, err := vulnRepo.Save(context.Background(), record); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/images/:id/vulnerabilities", handler.GetImageVulnerabilities)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/vulnerabilities?org_id=demo-org&severity=critical", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload struct {
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
		SummaryAll struct {
			Total int `json:"total"`
		} `json:"summary_all"`
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Summary.Total != 1 || payload.SummaryAll.Total != 2 || payload.Vulnerabilities[0].ID != "CVE-2024-0001" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestExportImageSupportsSBOMAndVulnerabilityFormats(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	if _, err := sbomRepo.Save(context.Background(), sbomindex.Record{
		OrgID:        "demo-org",
		ImageID:      "demo-image",
		ImageName:    "alpine:3.20",
		SourceFormat: sbomindex.FormatCycloneDX,
		PackageCount: 1,
		Packages: []sbomindex.PackageRecord{
			{Name: "busybox", Version: "1.36.1-r0", Type: "apk"},
		},
	}); err != nil {
		t.Fatalf("sbomRepo.Save() error = %v", err)
	}

	for _, fixture := range []struct {
		filename    string
		contentType string
		document    string
	}{
		{filename: "sbom-cyclonedx.json", contentType: "application/vnd.cyclonedx+json", document: testCycloneDXDocument},
		{filename: "sbom-spdx.json", contentType: "application/spdx+json", document: testSPDXDocument},
	} {
		key, err := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}.BuildKey(fixture.filename)
		if err != nil {
			t.Fatalf("BuildKey() error = %v", err)
		}
		if _, err := store.Put(context.Background(), key, []byte(fixture.document), storage.PutOptions{ContentType: fixture.contentType}); err != nil {
			t.Fatalf("store.Put() error = %v", err)
		}
	}

	if _, err := vulnRepo.Save(context.Background(), vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:3.20",
		Summary: vulnindex.Summary{
			Total:      1,
			BySeverity: map[string]int{"HIGH": 1},
			ByScanner:  map[string]int{"grype": 1},
			ByStatus:   map[string]int{vulnindex.StatusAffected: 1},
			Fixable:    1,
		},
		Vulnerabilities: []vulnindex.VulnerabilityRecord{
			{
				ID:             "CVE-2024-0001",
				Severity:       "HIGH",
				PackageName:    "busybox",
				PackageVersion: "1.36.1-r0",
				PackageType:    "apk",
				Status:         vulnindex.StatusAffected,
				StatusSource:   vulnindex.StatusSourceScanner,
				FixVersion:     "1.36.2-r1",
				Scanners:       []string{"grype"},
				FirstSeenAt:    time.Date(2026, 3, 13, 18, 0, 0, 0, time.UTC),
				LastSeenAt:     time.Date(2026, 3, 14, 18, 0, 0, 0, time.UTC),
			},
		},
		UpdatedAt: time.Date(2026, 3, 14, 18, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/images/:id/export", handler.ExportImage)

	testCases := []struct {
		name                string
		path                string
		wantContentType     string
		wantDispositionPart string
		wantBodyPart        string
	}{
		{
			name:                "cyclonedx",
			path:                "/api/v1/images/demo-image/export?org_id=demo-org&format=cyclonedx",
			wantContentType:     "application/vnd.cyclonedx+json",
			wantDispositionPart: "demo-org-demo-image-sbom-cyclonedx.json",
			wantBodyPart:        "\"bomFormat\": \"CycloneDX\"",
		},
		{
			name:                "spdx",
			path:                "/api/v1/images/demo-image/export?org_id=demo-org&format=spdx",
			wantContentType:     "application/spdx+json",
			wantDispositionPart: "demo-org-demo-image-sbom-spdx.json",
			wantBodyPart:        "\"spdxVersion\": \"SPDX-2.3\"",
		},
		{
			name:                "csv",
			path:                "/api/v1/images/demo-image/export?org_id=demo-org&format=csv",
			wantContentType:     "text/csv; charset=utf-8",
			wantDispositionPart: "demo-org-demo-image-vulnerabilities.csv",
			wantBodyPart:        "CVE-2024-0001",
		},
		{
			name:                "json",
			path:                "/api/v1/images/demo-image/export?org_id=demo-org&format=json",
			wantContentType:     "application/json",
			wantDispositionPart: "demo-org-demo-image-vulnerabilities.json",
			wantBodyPart:        "\"vulnerabilities\":",
		},
		{
			name:                "sarif",
			path:                "/api/v1/images/demo-image/export?org_id=demo-org&format=sarif",
			wantContentType:     "application/sarif+json",
			wantDispositionPart: "demo-org-demo-image-vulnerabilities.sarif",
			wantBodyPart:        "\"version\": \"2.1.0\"",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, req)

			if got, want := resp.Code, http.StatusOK; got != want {
				t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
			}
			if got := resp.Header().Get("Content-Type"); !strings.Contains(got, tc.wantContentType) {
				t.Fatalf("Content-Type = %q, want substring %q", got, tc.wantContentType)
			}
			if got := resp.Header().Get("Content-Disposition"); !strings.Contains(got, tc.wantDispositionPart) {
				t.Fatalf("Content-Disposition = %q, want substring %q", got, tc.wantDispositionPart)
			}
			if got := resp.Body.String(); !strings.Contains(got, tc.wantBodyPart) {
				t.Fatalf("body = %q, want substring %q", got, tc.wantBodyPart)
			}
		})
	}
}

func TestExportImageRejectsUnsupportedFormat(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/images/:id/export", handler.ExportImage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/export?org_id=demo-org&format=pdf", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

func TestGetImageAttestationsReturnsRegistryData(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	if _, err := sbomRepo.Save(context.Background(), sbomindex.Record{
		OrgID:        "demo-org",
		ImageID:      "demo-image",
		ImageName:    "ghcr.io/example/demo:1.0",
		SourceFormat: sbomindex.FormatCycloneDX,
		PackageCount: 1,
	}); err != nil {
		t.Fatalf("sbomRepo.Save() error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	handler.attestor = stubAttestationFetcher{
		result: attestation.Result{
			CanonicalRef: "ghcr.io/example/demo@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			ImageDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Signatures: []attestation.Record{
				{
					Digest:             "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Kind:               attestation.KindSignature,
					VerificationStatus: attestation.VerificationStatusValid,
					Signer:             "signer@example.com",
				},
			},
			Attestations: []attestation.Record{
				{
					Digest:             "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Kind:               attestation.KindAttestation,
					VerificationStatus: attestation.VerificationStatusValid,
					PredicateType:      "https://slsa.dev/provenance/v0.2",
				},
			},
			Summary: attestation.Summary{
				Total:        2,
				Signatures:   1,
				Attestations: 1,
				Provenance:   1,
				ByVerificationStatus: map[string]int{
					attestation.VerificationStatusValid: 2,
				},
			},
			UpdatedAt: time.Date(2026, 3, 13, 19, 0, 0, 0, time.UTC),
		},
	}

	router := gin.New()
	router.GET("/api/v1/images/:id/attestations", handler.GetImageAttestations)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/demo-image/attestations?org_id=demo-org", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload struct {
		ImageName string `json:"image_name"`
		Summary   struct {
			Provenance int `json:"provenance"`
		} `json:"summary"`
		Signatures []struct {
			Signer string `json:"signer"`
		} `json:"signatures"`
		Attestations []struct {
			PredicateType string `json:"predicate_type"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := payload.ImageName, "ghcr.io/example/demo:1.0"; got != want {
		t.Fatalf("ImageName = %q, want %q", got, want)
	}
	if got, want := payload.Signatures[0].Signer, "signer@example.com"; got != want {
		t.Fatalf("Signatures[0].Signer = %q, want %q", got, want)
	}
	if got, want := payload.Attestations[0].PredicateType, "https://slsa.dev/provenance/v0.2"; got != want {
		t.Fatalf("Attestations[0].PredicateType = %q, want %q", got, want)
	}
	if got, want := payload.Summary.Provenance, 1; got != want {
		t.Fatalf("Summary.Provenance = %d, want %d", got, want)
	}
}

func TestImportImageVEXUpdatesAdvisoryStatus(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	record := vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:latest",
		Summary: vulnindex.Summary{
			Total:      1,
			BySeverity: map[string]int{"HIGH": 1},
			ByScanner:  map[string]int{"grype": 1},
			ByStatus:   map[string]int{vulnindex.StatusAffected: 1},
			Fixable:    1,
		},
		Vulnerabilities: []vulnindex.VulnerabilityRecord{
			{
				ID:           "CVE-2024-0001",
				Severity:     "HIGH",
				PackageName:  "openssl",
				FixVersion:   "3.0.2",
				Status:       vulnindex.StatusAffected,
				StatusSource: vulnindex.StatusSourceScanner,
				Scanners:     []string{"grype"},
				FirstSeenAt:  time.Now().UTC(),
				LastSeenAt:   time.Now().UTC(),
			},
		},
	}
	if _, err := vulnRepo.Save(context.Background(), record); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.POST("/api/v1/images/:id/vex", handler.ImportImageVEX)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "demo.vex.json")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write([]byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/demo",
  "author": "otter",
  "timestamp": "2026-03-13T18:45:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2024-0001"
      },
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "products": [
        {
          "@id": "pkg:oci/alpine@latest"
        }
      ]
    }
  ]
}`)); err != nil {
		t.Fatalf("part.Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/images/demo-image/vex?org_id=demo-org", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusCreated; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	updated, err := vulnRepo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("vulnRepo.Get() error = %v", err)
	}
	if got, want := updated.Vulnerabilities[0].Status, vulnindex.StatusNotAffected; got != want {
		t.Fatalf("status = %s, want %s", got, want)
	}
	if len(updated.VEXDocuments) != 1 {
		t.Fatalf("len(VEXDocuments) = %d, want 1", len(updated.VEXDocuments))
	}
}

func TestCompareImagesBuildsReadOnlyReportAndCreateComparisonStoresIt(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	for _, record := range []sbomindex.Record{
		{
			OrgID:        "demo-org",
			ImageID:      "alpine-319",
			ImageName:    "alpine:3.19",
			SourceFormat: sbomindex.FormatCycloneDX,
			PackageCount: 2,
			Packages: []sbomindex.PackageRecord{
				{Name: "busybox", Type: "apk", Version: "1.36.1-r0", PURL: "pkg:apk/alpine/busybox@1.36.1-r0"},
				{Name: "ssl", Type: "apk", Version: "1.0.0-r0", PURL: "pkg:apk/alpine/ssl@1.0.0-r0"},
			},
			DependencyRoots: []string{"pkg:oci/alpine@3.19"},
		},
		{
			OrgID:        "demo-org",
			ImageID:      "alpine-320",
			ImageName:    "alpine:3.20",
			SourceFormat: sbomindex.FormatCycloneDX,
			PackageCount: 2,
			Packages: []sbomindex.PackageRecord{
				{Name: "busybox", Type: "apk", Version: "1.37.0-r30", PURL: "pkg:apk/alpine/busybox@1.37.0-r30"},
				{Name: "curl", Type: "apk", Version: "8.0.0-r0", PURL: "pkg:apk/alpine/curl@8.0.0-r0"},
			},
			DependencyRoots: []string{"pkg:oci/alpine@3.20"},
		},
	} {
		if _, err := sbomRepo.Save(context.Background(), record); err != nil {
			t.Fatalf("sbomRepo.Save() error = %v", err)
		}
	}

	for _, record := range []vulnindex.Record{
		{
			OrgID:     "demo-org",
			ImageID:   "alpine-319",
			ImageName: "alpine:3.19",
			Summary: vulnindex.Summary{
				Total:      2,
				BySeverity: map[string]int{"HIGH": 1, "LOW": 1},
				ByScanner:  map[string]int{"grype": 2},
				ByStatus:   map[string]int{vulnindex.StatusAffected: 2},
			},
			Vulnerabilities: []vulnindex.VulnerabilityRecord{
				{ID: "CVE-1", Severity: "HIGH", PackageName: "busybox", PackageVersion: "1.36.1-r0", Status: vulnindex.StatusAffected, Scanners: []string{"grype"}},
				{ID: "CVE-2", Severity: "LOW", PackageName: "ssl", PackageVersion: "1.0.0-r0", Status: vulnindex.StatusAffected, Scanners: []string{"grype"}},
			},
		},
		{
			OrgID:     "demo-org",
			ImageID:   "alpine-320",
			ImageName: "alpine:3.20",
			Summary: vulnindex.Summary{
				Total:      1,
				BySeverity: map[string]int{"MEDIUM": 1},
				ByScanner:  map[string]int{"grype": 1},
				ByStatus:   map[string]int{vulnindex.StatusAffected: 1},
			},
			Vulnerabilities: []vulnindex.VulnerabilityRecord{
				{ID: "CVE-1", Severity: "MEDIUM", PackageName: "busybox", PackageVersion: "1.37.0-r30", Status: vulnindex.StatusAffected, Scanners: []string{"grype"}},
			},
		},
	} {
		if _, err := vulnRepo.Save(context.Background(), record); err != nil {
			t.Fatalf("vulnRepo.Save() error = %v", err)
		}
	}

	for _, fixture := range []struct {
		orgID   string
		imageID string
		doc     string
	}{
		{orgID: "demo-org", imageID: "alpine-319", doc: testCycloneDXDocumentWithLayersA},
		{orgID: "demo-org", imageID: "alpine-320", doc: testCycloneDXDocumentWithLayersB},
	} {
		key, err := ArtifactKeyBuilder{OrgID: fixture.orgID, ImageID: fixture.imageID}.BuildSBOMKeyForFormat(sbomindex.FormatCycloneDX)
		if err != nil {
			t.Fatalf("BuildSBOMKeyForFormat() error = %v", err)
		}
		if _, err := store.Put(context.Background(), key, []byte(fixture.doc), storage.PutOptions{ContentType: "application/vnd.cyclonedx+json"}); err != nil {
			t.Fatalf("store.Put() error = %v", err)
		}
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/compare", handler.CompareImages)
	router.POST("/api/v1/comparisons", handler.CreateComparison)
	router.GET("/api/v1/comparisons/:id", handler.GetStoredComparison)
	router.GET("/api/v1/comparisons/:id/export", handler.ExportComparison)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compare?image1=alpine:3.19&image2=alpine:3.20&org1=demo-org&org2=demo-org", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload struct {
		ComparisonID string `json:"comparison_id"`
		Comparison   struct {
			Summary struct {
				Message string `json:"message"`
			} `json:"summary"`
			PackageDiff struct {
				Added []struct {
					Name string `json:"name"`
				} `json:"added"`
			} `json:"package_diff"`
		} `json:"comparison"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.ComparisonID == "" {
		t.Fatal("expected comparison_id")
	}
	if got, want := payload.Comparison.PackageDiff.Added[0].Name, "curl"; got != want {
		t.Fatalf("PackageDiff.Added[0].Name = %q, want %q", got, want)
	}

	comparisonKey, err := BuildComparisonKey(payload.ComparisonID)
	if err != nil {
		t.Fatalf("BuildComparisonKey() error = %v", err)
	}
	if _, err := store.Get(context.Background(), comparisonKey); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("store.Get(comparison) error = %v, want ErrNotFound", err)
	}

	createBody, err := json.Marshal(ComparisonPayload{
		Image1: "alpine:3.19",
		Image2: "alpine:3.20",
		Org1:   "demo-org",
		Org2:   "demo-org",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/comparisons", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createResp := httptest.NewRecorder()
	router.ServeHTTP(createResp, createReq)

	if got, want := createResp.Code, http.StatusOK; got != want {
		t.Fatalf("create status = %d, want %d, body=%s", got, want, createResp.Body.String())
	}

	storedReq := httptest.NewRequest(http.MethodGet, "/api/v1/comparisons/"+payload.ComparisonID, nil)
	storedResp := httptest.NewRecorder()
	router.ServeHTTP(storedResp, storedReq)

	if got, want := storedResp.Code, http.StatusOK; got != want {
		t.Fatalf("stored status = %d, want %d, body=%s", got, want, storedResp.Body.String())
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/api/v1/comparisons/"+payload.ComparisonID+"/export", nil)
	exportResp := httptest.NewRecorder()
	router.ServeHTTP(exportResp, exportReq)

	if got, want := exportResp.Code, http.StatusOK; got != want {
		t.Fatalf("export status = %d, want %d, body=%s", got, want, exportResp.Body.String())
	}
	if got := exportResp.Header().Get("Content-Disposition"); !strings.Contains(got, "comparison-"+payload.ComparisonID+".json") {
		t.Fatalf("Content-Disposition = %q, want comparison export filename", got)
	}
}

func TestCompareImagesRejectsAmbiguousImageName(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	for _, record := range []sbomindex.Record{
		{OrgID: "demo-org", ImageID: "image-a", ImageName: "alpine:latest", SourceFormat: sbomindex.FormatCycloneDX, PackageCount: 1},
		{OrgID: "demo-two", ImageID: "image-b", ImageName: "alpine:latest", SourceFormat: sbomindex.FormatCycloneDX, PackageCount: 1},
	} {
		if _, err := sbomRepo.Save(context.Background(), record); err != nil {
			t.Fatalf("sbomRepo.Save() error = %v", err)
		}
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	router := gin.New()
	router.GET("/api/v1/compare", handler.CompareImages)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compare?image1=alpine:latest&image2=alpine:latest", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusConflict; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

func testSyftSBOM() *syftsbom.SBOM {
	return testSyftSBOMForPlatform("linux/amd64")
}

func testSyftSBOMForPlatform(platform string) *syftsbom.SBOM {
	root := syftpkg.Package{
		Name:    "alpine",
		Version: "3.20.0",
		Type:    syftpkg.Type("apk"),
		Licenses: func() syftpkg.LicenseSet {
			set := syftpkg.NewLicenseSet(syftpkg.NewLicense("Apache-2.0"))
			return set
		}(),
	}
	root.SetID()

	dependency := syftpkg.Package{
		Name:    "busybox",
		Version: "1.36.1",
		Type:    syftpkg.Type("apk"),
		Licenses: func() syftpkg.LicenseSet {
			set := syftpkg.NewLicenseSet(syftpkg.NewLicense("MIT"))
			return set
		}(),
	}
	dependency.SetID()

	return &syftsbom.SBOM{
		Source: syftsource.Description{
			Metadata: mustImageMetadataForPlatform(platform),
		},
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(root, dependency),
		},
		Relationships: []artifact.Relationship{
			{
				From: dependency,
				To:   root,
				Type: artifact.DependencyOfRelationship,
			},
		},
	}
}

func mustImageMetadataForPlatform(platform string) syftsource.ImageMetadata {
	normalized, err := normalizeRequestedPlatform("", platform)
	if err != nil {
		panic(err)
	}
	if normalized == nil {
		return syftsource.ImageMetadata{}
	}
	return syftsource.ImageMetadata{
		OS:           normalized.OS,
		Architecture: normalized.Architecture,
		Variant:      normalized.Variant,
	}
}

const testCycloneDXDocument = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "bom-ref": "pkg:oci/alpine@latest",
      "name": "alpine",
      "version": "latest",
      "type": "container"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:apk/alpine/busybox@1.36.1-r0",
      "name": "busybox",
      "version": "1.36.1-r0",
      "type": "library",
      "purl": "pkg:apk/alpine/busybox@1.36.1-r0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:oci/alpine@latest",
      "dependsOn": [
        "pkg:apk/alpine/busybox@1.36.1-r0"
      ]
    }
  ]
}`

const testCycloneDXDocumentWithLayersA = `{
  "bomFormat": "CycloneDX",
  "metadata": {
    "component": {
      "bom-ref": "pkg:oci/alpine@3.19",
      "name": "alpine",
      "version": "3.19",
      "type": "container"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:apk/alpine/busybox@1.36.1-r0",
      "name": "busybox",
      "version": "1.36.1-r0",
      "type": "library",
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:layer-a"},
        {"name":"syft:metadata:size","value":"10"}
      ]
    },
    {
      "bom-ref": "pkg:apk/alpine/ssl@1.0.0-r0",
      "name": "ssl",
      "version": "1.0.0-r0",
      "type": "library",
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:shared"},
        {"name":"syft:metadata:size","value":"20"}
      ]
    }
  ]
}`

const testCycloneDXDocumentWithLayersB = `{
  "bomFormat": "CycloneDX",
  "metadata": {
    "component": {
      "bom-ref": "pkg:oci/alpine@3.20",
      "name": "alpine",
      "version": "3.20",
      "type": "container"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:apk/alpine/busybox@1.37.0-r30",
      "name": "busybox",
      "version": "1.37.0-r30",
      "type": "library",
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:layer-b"},
        {"name":"syft:metadata:size","value":"15"}
      ]
    },
    {
      "bom-ref": "pkg:apk/alpine/curl@8.0.0-r0",
      "name": "curl",
      "version": "8.0.0-r0",
      "type": "library",
      "properties": [
        {"name":"syft:location:0:layerID","value":"sha256:shared"},
        {"name":"syft:metadata:size","value":"20"}
      ]
    }
  ]
}`

const testSPDXDocument = `{
  "spdxVersion": "SPDX-2.3",
  "documentDescribes": [
    "SPDXRef-alpine"
  ],
  "packages": [
    {
      "SPDXID": "SPDXRef-alpine",
      "name": "alpine",
      "versionInfo": "latest",
      "licenseDeclared": "Apache-2.0"
    },
    {
      "SPDXID": "SPDXRef-busybox",
      "name": "busybox",
      "versionInfo": "1.36.1-r0",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/busybox@1.36.1-r0"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-alpine",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-busybox"
    }
  ]
}`
