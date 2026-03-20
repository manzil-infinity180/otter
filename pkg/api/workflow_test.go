package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/otterXf/otter/pkg/attestation"
	"github.com/otterXf/otter/pkg/compliance"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

type workflowAnalyzer struct {
	results map[string]scan.AnalysisResult
}

func (a workflowAnalyzer) Analyze(_ context.Context, imageRef string) (scan.AnalysisResult, error) {
	result, ok := a.results[imageRef]
	if !ok {
		return scan.AnalysisResult{}, fmt.Errorf("unexpected image %q", imageRef)
	}
	return result, nil
}

type stubComplianceAssessor struct {
	result compliance.Result
}

func (s stubComplianceAssessor) Assess(context.Context, compliance.Input) compliance.Result {
	return s.result
}

func TestWorkflowScanViewCompareExport(t *testing.T) {
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

	handler := NewScanHandler(store, sbomRepo, vulnRepo, workflowAnalyzer{
		results: map[string]scan.AnalysisResult{
			"alpine:3.20": buildWorkflowAnalysisResult(t, "alpine:3.20", testCycloneDXDocumentWithLayersA, workflowSBOM(true), "CVE-2024-0001", "CRITICAL", "1.36.2"),
			"alpine:3.19": buildWorkflowAnalysisResult(t, "alpine:3.19", testCycloneDXDocumentWithLayersB, workflowSBOM(false), "CVE-2024-0002", "HIGH", ""),
		},
	})
	handler.attestor = stubAttestationFetcher{
		result: attestation.Result{
			ImageRef:     "alpine:3.20",
			CanonicalRef: "alpine@sha256:1234",
			ImageDigest:  "sha256:1234",
			Summary: attestation.Summary{
				Total:                1,
				Signatures:           1,
				Attestations:         0,
				Provenance:           0,
				ByVerificationStatus: map[string]int{attestation.VerificationStatusValid: 1},
			},
			Signatures: []attestation.Record{
				{
					Digest:             "sha256:signature",
					Kind:               attestation.KindSignature,
					Source:             "cosign",
					VerificationStatus: attestation.VerificationStatusValid,
					Signer:             "builder@example.com",
				},
			},
			UpdatedAt: time.Date(2026, 3, 14, 1, 0, 0, 0, time.UTC),
		},
	}
	handler.compliance = stubComplianceAssessor{
		result: compliance.Result{
			ImageRef:  "alpine:3.20",
			ScopeNote: "Best-effort standards tracking.",
			SLSA: compliance.SLSAAssessment{
				Level:       3,
				TargetLevel: 3,
				Status:      compliance.StatusPass,
				Verified:    true,
				BuilderID:   "https://github.com/actions/runner",
			},
			Scorecard: compliance.ScorecardSummary{
				Enabled:    true,
				Available:  true,
				Status:     compliance.StatusPass,
				Repository: "github.com/demo/project",
				Score:      9.1,
			},
			Standards: []compliance.StandardSummary{
				{
					Name:    "SLSA",
					Status:  compliance.StatusPass,
					Summary: "SLSA Level 3 evidence is present.",
					Checks: []compliance.StandardCheck{
						{ID: "slsa-provenance", Title: "Provenance", Status: compliance.StatusPass, Detail: "Detected."},
					},
				},
			},
			Summary: compliance.Summary{
				OverallStatus: compliance.StatusPass,
				Passed:        1,
			},
			UpdatedAt: time.Date(2026, 3, 14, 1, 5, 0, 0, time.UTC),
		},
	}

	router := gin.New()
	registerWorkflowRoutes(router, handler)

	mustStatus(t, performJSONRequest(router, http.MethodPost, "/api/v1/scans", ImageGeneratePayload{
		ImageName: "alpine:3.20",
		OrgID:     "demo-org",
		ImageID:   "image-a",
	}), http.StatusOK)
	mustStatus(t, performJSONRequest(router, http.MethodPost, "/api/v1/scans", ImageGeneratePayload{
		ImageName: "alpine:3.19",
		OrgID:     "demo-org",
		ImageID:   "image-b",
	}), http.StatusOK)

	catalogResp := performRequest(router, http.MethodGet, "/api/v1/catalog?query=alpine&severity=critical&sort=critical", nil, nil)
	mustStatus(t, catalogResp, http.StatusOK)
	var catalog struct {
		Count int                 `json:"count"`
		Items []ImageCatalogEntry `json:"items"`
	}
	decodeJSON(t, catalogResp, &catalog)
	if got, want := catalog.Count, 1; got != want {
		t.Fatalf("catalog count = %d, want %d", got, want)
	}

	overviewResp := performRequest(router, http.MethodGet, "/api/v1/images/image-a/overview?org_id=demo-org", nil, nil)
	mustStatus(t, overviewResp, http.StatusOK)
	var overview ImageOverview
	decodeJSON(t, overviewResp, &overview)
	if got, want := overview.ImageName, "alpine:3.20"; got != want {
		t.Fatalf("overview image name = %q, want %q", got, want)
	}
	if len(overview.Files) == 0 || len(overview.Tags) == 0 {
		t.Fatalf("overview = %#v, want files and tags", overview)
	}

	scansResp := performRequest(router, http.MethodGet, "/api/v1/scans/demo-org/image-a", nil, nil)
	mustStatus(t, scansResp, http.StatusOK)
	var scans struct {
		Count int      `json:"count"`
		Files []string `json:"files"`
	}
	decodeJSON(t, scansResp, &scans)
	if got, want := scans.Count, 5; got != want {
		t.Fatalf("scan count = %d, want %d", got, want)
	}

	downloadResp := performRequest(router, http.MethodGet, "/api/v1/scans/demo-org/image-a/files/sbom-cyclonedx.json", nil, nil)
	mustStatus(t, downloadResp, http.StatusOK)
	if got := downloadResp.Header().Get("Content-Disposition"); !strings.Contains(got, "sbom-cyclonedx.json") {
		t.Fatalf("download Content-Disposition = %q", got)
	}

	sbomResp := performRequest(router, http.MethodGet, "/api/v1/images/image-a/sbom?org_id=demo-org&format=cyclonedx", nil, nil)
	mustStatus(t, sbomResp, http.StatusOK)
	var sbomPayload struct {
		Format       string `json:"format"`
		PackageCount int    `json:"package_count"`
	}
	decodeJSON(t, sbomResp, &sbomPayload)
	if got, want := sbomPayload.PackageCount, 2; got != want {
		t.Fatalf("sbom package count = %d, want %d", got, want)
	}

	vulnResp := performRequest(router, http.MethodGet, "/api/v1/images/image-a/vulnerabilities?org_id=demo-org&severity=critical", nil, nil)
	mustStatus(t, vulnResp, http.StatusOK)
	var vulnPayload struct {
		SummaryAll      vulnindex.Summary               `json:"summary_all"`
		Vulnerabilities []vulnindex.VulnerabilityRecord `json:"vulnerabilities"`
	}
	decodeJSON(t, vulnResp, &vulnPayload)
	if got, want := len(vulnPayload.Vulnerabilities), 1; got != want {
		t.Fatalf("filtered vulnerabilities len = %d, want %d", got, want)
	}
	if got, want := vulnPayload.SummaryAll.Total, 1; got != want {
		t.Fatalf("summary_all.total = %d, want %d", got, want)
	}

	attestationResp := performRequest(router, http.MethodGet, "/api/v1/images/image-a/attestations?org_id=demo-org", nil, nil)
	mustStatus(t, attestationResp, http.StatusOK)
	if body := attestationResp.Body.String(); !strings.Contains(body, "builder@example.com") {
		t.Fatalf("attestation body missing signer: %s", body)
	}

	complianceResp := performRequest(router, http.MethodGet, "/api/v1/images/image-a/compliance?org_id=demo-org", nil, nil)
	mustStatus(t, complianceResp, http.StatusOK)
	if body := complianceResp.Body.String(); !strings.Contains(body, `"overall_status":"pass"`) {
		t.Fatalf("compliance body = %s", body)
	}

	browseCatalogResp := performRequest(router, http.MethodGet, "/browse?query=alpine", nil, map[string]string{"Accept": "text/html"})
	mustStatus(t, browseCatalogResp, http.StatusOK)
	if body := browseCatalogResp.Body.String(); !strings.Contains(body, "alpine:3.20") {
		t.Fatalf("browse catalog body = %s", body)
	}

	browseImageResp := performRequest(router, http.MethodGet, "/browse/images/demo-org/image-a", nil, map[string]string{"Accept": "text/html"})
	mustStatus(t, browseImageResp, http.StatusOK)
	if body := browseImageResp.Body.String(); !strings.Contains(body, "SLSA Level 3 evidence is present.") || !strings.Contains(body, "CVE-2024-0001") {
		t.Fatalf("browse image body = %s", body)
	}

	compareResp := performRequest(router, http.MethodGet, "/api/v1/compare?image1=alpine:3.20&org1=demo-org&image2=alpine:3.19&org2=demo-org", nil, nil)
	mustStatus(t, compareResp, http.StatusOK)
	var comparison struct {
		ComparisonID string `json:"comparison_id"`
	}
	decodeJSON(t, compareResp, &comparison)
	if comparison.ComparisonID == "" {
		t.Fatal("comparison_id should not be empty")
	}

	storedCompareResp := performRequest(router, http.MethodGet, "/api/v1/comparisons/"+comparison.ComparisonID, nil, nil)
	mustStatus(t, storedCompareResp, http.StatusNotFound)

	createCompareResp := performJSONRequest(router, http.MethodPost, "/api/v1/comparisons", ComparisonPayload{
		Image1: "alpine:3.20",
		Image2: "alpine:3.19",
		Org1:   "demo-org",
		Org2:   "demo-org",
	})
	mustStatus(t, createCompareResp, http.StatusOK)

	storedCompareResp = performRequest(router, http.MethodGet, "/api/v1/comparisons/"+comparison.ComparisonID, nil, nil)
	mustStatus(t, storedCompareResp, http.StatusOK)

	exportCompareResp := performRequest(router, http.MethodGet, "/api/v1/comparisons/"+comparison.ComparisonID+"/export", nil, nil)
	mustStatus(t, exportCompareResp, http.StatusOK)
	if got := exportCompareResp.Header().Get("Content-Disposition"); !strings.Contains(got, comparison.ComparisonID) {
		t.Fatalf("comparison export Content-Disposition = %q", got)
	}

	exportImageResp := performRequest(router, http.MethodGet, "/api/v1/images/image-a/export?org_id=demo-org&format=sarif", nil, nil)
	mustStatus(t, exportImageResp, http.StatusOK)
	if got := exportImageResp.Header().Get("Content-Disposition"); !strings.Contains(got, "vulnerabilities.sarif") {
		t.Fatalf("image export Content-Disposition = %q", got)
	}

	deleteResp := performRequest(router, http.MethodDelete, "/api/v1/scans/demo-org/image-a", nil, nil)
	mustStatus(t, deleteResp, http.StatusOK)

	postDeleteResp := performRequest(router, http.MethodGet, "/api/v1/scans/demo-org/image-a", nil, nil)
	mustStatus(t, postDeleteResp, http.StatusOK)
	if body := postDeleteResp.Body.String(); !strings.Contains(body, `"count":0`) {
		t.Fatalf("post-delete scans body = %s", body)
	}
}

func registerWorkflowRoutes(router *gin.Engine, handler *ScanHandler) {
	router.POST("/api/v1/scans", handler.GenerateScanSbomVul)
	router.GET("/api/v1/scans/:org_id/:image_id", handler.GetImageScans)
	router.DELETE("/api/v1/scans/:org_id/:image_id", handler.DeleteImageScansHandler)
	router.GET("/api/v1/scans/:org_id/:image_id/files/:filename", handler.DownloadScanFile)
	router.GET("/api/v1/catalog", handler.ListCatalog)
	router.GET("/api/v1/images/:id/overview", handler.GetImageOverview)
	router.GET("/api/v1/images/:id/sbom", handler.GetImageSBOM)
	router.GET("/api/v1/images/:id/vulnerabilities", handler.GetImageVulnerabilities)
	router.GET("/api/v1/images/:id/attestations", handler.GetImageAttestations)
	router.GET("/api/v1/images/:id/compliance", handler.GetImageCompliance)
	router.GET("/api/v1/images/:id/export", handler.ExportImage)
	router.GET("/api/v1/compare", handler.CompareImages)
	router.POST("/api/v1/comparisons", handler.CreateComparison)
	router.GET("/api/v1/comparisons/:id", handler.GetStoredComparison)
	router.GET("/api/v1/comparisons/:id/export", handler.ExportComparison)
	router.GET("/browse", handler.BrowseCatalog)
	router.GET("/browse/images/:org_id/:id", handler.BrowseImage)
}

func buildWorkflowAnalysisResult(t *testing.T, imageRef, cyclonedx string, sbomData *syftsbom.SBOM, vulnID, severity, fixVersion string) scan.AnalysisResult {
	t.Helper()

	reports := []scan.ScannerReport{
		{
			Scanner:     "grype",
			ContentType: "application/json",
			Document:    []byte(`[{"matches":1}]`),
			Findings: []scan.VulnerabilityFinding{
				{
					ID:             vulnID,
					Severity:       severity,
					PackageName:    "busybox",
					PackageVersion: "1.36.1",
					FixVersion:     fixVersion,
					Scanners:       []string{"grype"},
				},
			},
		},
	}

	combined, combinedDocument, err := scan.BuildCombinedReport(imageRef, reports)
	if err != nil {
		t.Fatalf("BuildCombinedReport() error = %v", err)
	}

	return scan.AnalysisResult{
		ImageRef:                imageRef,
		SBOMDocument:            []byte(cyclonedx),
		SBOMSPDXDocument:        []byte(testSPDXDocument),
		SBOMData:                sbomData,
		CombinedReport:          combined,
		CombinedVulnerabilities: combinedDocument,
		Summary:                 combined.Summary,
		ScannerReports:          reports,
	}
}

func workflowSBOM(includeDependency bool) *syftsbom.SBOM {
	root := syftpkg.Package{
		Name:    "alpine",
		Version: "3.20.0",
		Type:    syftpkg.Type("apk"),
	}
	root.SetID()

	artifacts := syftsbom.Artifacts{
		Packages: syftpkg.NewCollection(root),
	}
	relationships := []artifact.Relationship{}

	if includeDependency {
		dependency := syftpkg.Package{
			Name:    "busybox",
			Version: "1.36.1",
			Type:    syftpkg.Type("apk"),
		}
		dependency.SetID()
		artifacts.Packages.Add(dependency)
		relationships = append(relationships, artifact.Relationship{
			From: dependency,
			To:   root,
			Type: artifact.DependencyOfRelationship,
		})
	}

	return &syftsbom.SBOM{
		Artifacts:     artifacts,
		Relationships: relationships,
	}
}

func performJSONRequest(router *gin.Engine, method, target string, payload any) *httptest.ResponseRecorder {
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return performRequest(router, method, target, data, map[string]string{"Content-Type": "application/json"})
}

func performRequest(router *gin.Engine, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}

	req := httptest.NewRequest(method, target, reader)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func mustStatus(t *testing.T, resp *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got := resp.Code; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}
}

func decodeJSON(t *testing.T, resp *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(resp.Body.Bytes(), target); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, resp.Body.String())
	}
}
