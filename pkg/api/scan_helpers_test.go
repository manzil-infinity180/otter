package api

import (
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/catalogscan"
	"github.com/otterXf/otter/pkg/compare"
	"github.com/otterXf/otter/pkg/registry"
	reportexport "github.com/otterXf/otter/pkg/reportexport"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

type metadataStore struct {
	object storage.Object
}

func (m metadataStore) Backend() string {
	return storage.BackendLocal
}

func (m metadataStore) Put(context.Context, string, []byte, storage.PutOptions) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, nil
}

func (m metadataStore) Get(context.Context, string) (storage.Object, error) {
	return m.object, nil
}

func (m metadataStore) List(context.Context, string) ([]storage.ObjectInfo, error) {
	return []storage.ObjectInfo{m.object.Info}, nil
}

func (m metadataStore) Delete(context.Context, string) error {
	return nil
}

func (m metadataStore) Close() error {
	return nil
}

func TestExecuteCatalogScanAndHelperFallbacks(t *testing.T) {
	t.Parallel()

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = sbomRepo.Close() })

	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = vulnRepo.Close() })

	handler := NewScanHandlerWithRegistry(store, sbomRepo, vulnRepo, stubAnalyzer{
		result: scan.AnalysisResult{
			ImageRef:                "alpine:latest",
			SBOMDocument:            []byte(testCycloneDXDocument),
			SBOMSPDXDocument:        []byte(testSPDXDocument),
			SBOMData:                testSyftSBOMForPlatform("linux/arm64"),
			CombinedVulnerabilities: []byte(`{"matches":[]}`),
			CombinedReport:          testCombinedVulnerabilityReport(),
			Summary:                 scan.VulnerabilitySummary{Total: 1, Fixable: 1},
			ScannerReports:          []scan.ScannerReport{{Scanner: "grype", ContentType: "application/json", Document: []byte(`[]`)}},
		},
	}, stubRegistryService{
		access: registry.ImageAccess{Registry: "index.docker.io", AuthSource: "anonymous"},
	})

	result, err := handler.ExecuteCatalogScan(context.Background(), catalogscan.Request{
		OrgID:     "catalog",
		ImageID:   "alpine-latest",
		ImageName: "alpine:latest",
	})
	if err != nil {
		t.Fatalf("ExecuteCatalogScan() error = %v", err)
	}

	if got, want := result.ImageName, "alpine:latest"; got != want {
		t.Fatalf("ImageName = %q, want %q", got, want)
	}
	if got, want := len(result.Scanners), 1; got != want {
		t.Fatalf("len(Scanners) = %d, want %d", got, want)
	}
	if got, want := result.Platform, "linux/arm64"; got != want {
		t.Fatalf("Platform = %q, want %q", got, want)
	}

	legacyKey, err := ArtifactKeyBuilder{OrgID: "catalog", ImageID: "legacy-image"}.BuildSBOMKey()
	if err != nil {
		t.Fatalf("BuildSBOMKey() error = %v", err)
	}
	if _, err := store.Put(context.Background(), legacyKey, []byte(testCycloneDXDocument), storage.PutOptions{ContentType: "application/vnd.cyclonedx+json"}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}

	object, err := handler.getSBOMArtifact(context.Background(), ArtifactKeyBuilder{OrgID: "catalog", ImageID: "legacy-image"}, sbomindex.FormatCycloneDX)
	if err != nil {
		t.Fatalf("getSBOMArtifact() error = %v", err)
	}
	if string(object.Data) != testCycloneDXDocument {
		t.Fatalf("getSBOMArtifact() data = %s", object.Data)
	}
}

func TestGetOrCreateIndexRecordsResolveStoredImageReferenceAndComparisonTarget(t *testing.T) {
	t.Parallel()

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = sbomRepo.Close() })

	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = vulnRepo.Close() })

	handler := NewScanHandlerWithRegistry(store, sbomRepo, vulnRepo, stubAnalyzer{}, stubRegistryService{})

	sbomRecord, err := handler.getOrCreateSBOMRecord(context.Background(), "demo-org", "demo-image", sbomindex.FormatCycloneDX, []byte(testCycloneDXDocument))
	if err != nil {
		t.Fatalf("getOrCreateSBOMRecord() error = %v", err)
	}
	sbomKey, err := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}.BuildSBOMKeyForFormat(sbomindex.FormatCycloneDX)
	if err != nil {
		t.Fatalf("BuildSBOMKeyForFormat() error = %v", err)
	}
	if _, err := store.Put(context.Background(), sbomKey, []byte(testCycloneDXDocument), storage.PutOptions{ContentType: "application/vnd.cyclonedx+json"}); err != nil {
		t.Fatalf("store.Put(sbom) error = %v", err)
	}
	sbomRecord.ImageName = "alpine:latest"
	if _, err := sbomRepo.Save(context.Background(), sbomRecord); err != nil {
		t.Fatalf("sbomRepo.Save() error = %v", err)
	}
	if got, want := sbomRecord.PackageCount, 2; got != want {
		t.Fatalf("sbom package count = %d, want %d", got, want)
	}

	vulnKey, err := ArtifactKeyBuilder{OrgID: "demo-org", ImageID: "demo-image"}.BuildVulnerabilityKey()
	if err != nil {
		t.Fatalf("BuildVulnerabilityKey() error = %v", err)
	}
	reportDocument, err := json.Marshal(testCombinedVulnerabilityReport())
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := store.Put(context.Background(), vulnKey, reportDocument, storage.PutOptions{ContentType: "application/json"}); err != nil {
		t.Fatalf("store.Put(vulnerabilities) error = %v", err)
	}

	vulnRecord, err := handler.getOrCreateVulnerabilityRecord(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("getOrCreateVulnerabilityRecord() error = %v", err)
	}
	if got, want := vulnRecord.Summary.Total, 1; got != want {
		t.Fatalf("vulnerability total = %d, want %d", got, want)
	}

	imageRef, err := handler.resolveStoredImageReference(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("resolveStoredImageReference() error = %v", err)
	}
	if got, want := imageRef, "alpine:latest"; got != want {
		t.Fatalf("imageRef = %q, want %q", got, want)
	}

	secondRecord := sbomindex.Record{
		OrgID:           "other-org",
		ImageID:         "demo-image",
		ImageName:       "alpine:latest",
		SourceFormat:    sbomindex.FormatCycloneDX,
		PackageCount:    1,
		Packages:        []sbomindex.PackageRecord{{ID: "pkg", Name: "pkg", Version: "1.0.0"}},
		DependencyTree:  []sbomindex.DependencyNode{{ID: "pkg", Name: "pkg", Version: "1.0.0"}},
		DependencyRoots: []string{"pkg"},
		UpdatedAt:       time.Now().UTC(),
	}
	if _, err := sbomRepo.Save(context.Background(), secondRecord); err != nil {
		t.Fatalf("sbomRepo.Save(secondRecord) error = %v", err)
	}
	if _, err := handler.resolveComparisonTarget(context.Background(), "alpine:latest", "", nil); !errors.Is(err, errComparisonTargetAmbiguous) {
		t.Fatalf("resolveComparisonTarget() error = %v, want ambiguous", err)
	}

	comparisonTarget, err := handler.resolveComparisonTarget(context.Background(), "alpine:latest", "demo-org", nil)
	if err != nil {
		t.Fatalf("resolveComparisonTarget(org-scoped) error = %v", err)
	}
	if got, want := comparisonTarget.SBOM.OrgID, "demo-org"; got != want {
		t.Fatalf("comparison target org = %q, want %q", got, want)
	}
	if got, want := comparisonTarget.Vulnerabilities.Summary.Total, 1; got != want {
		t.Fatalf("comparison vulnerability total = %d, want %d", got, want)
	}
}

func TestResolveStoredImageReferenceFallsBackToArtifactMetadata(t *testing.T) {
	t.Parallel()

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = sbomRepo.Close() })

	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = vulnRepo.Close() })

	key, err := ArtifactKeyBuilder{OrgID: "fallback-org", ImageID: "fallback-image"}.BuildSBOMKey()
	if err != nil {
		t.Fatalf("BuildSBOMKey() error = %v", err)
	}
	handler := NewScanHandler(metadataStore{
		object: storage.Object{
			Info: storage.ObjectInfo{
				Key:      key,
				Backend:  storage.BackendLocal,
				Metadata: map[string]string{"image_name": "nginx:latest"},
			},
			Data: []byte(testCycloneDXDocument),
		},
	}, sbomRepo, vulnRepo, stubAnalyzer{})

	imageRef, err := handler.resolveStoredImageReference(context.Background(), "fallback-org", "fallback-image")
	if err != nil {
		t.Fatalf("resolveStoredImageReference() error = %v", err)
	}
	if got, want := imageRef, "nginx:latest"; got != want {
		t.Fatalf("imageRef = %q, want %q", got, want)
	}
}

func TestResolveStoredImageReferenceFallsBackToPersistedArtifactMetadata(t *testing.T) {
	t.Parallel()

	store, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sbomRepo, err := sbomindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = sbomRepo.Close() })

	vulnRepo, err := vulnindex.NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	t.Cleanup(func() { _ = vulnRepo.Close() })

	key, err := ArtifactKeyBuilder{OrgID: "fallback-org", ImageID: "fallback-image"}.BuildSBOMKey()
	if err != nil {
		t.Fatalf("BuildSBOMKey() error = %v", err)
	}
	if _, err := store.Put(context.Background(), key, []byte(testCycloneDXDocument), storage.PutOptions{
		ContentType: "application/vnd.cyclonedx+json",
		Metadata: map[string]string{
			"image_name":           "nginx:latest",
			"availability_message": "scanner unavailable",
		},
	}); err != nil {
		t.Fatalf("store.Put() error = %v", err)
	}

	handler := NewScanHandler(store, sbomRepo, vulnRepo, stubAnalyzer{})
	imageRef, err := handler.resolveStoredImageReference(context.Background(), "fallback-org", "fallback-image")
	if err != nil {
		t.Fatalf("resolveStoredImageReference() error = %v", err)
	}
	if got, want := imageRef, "nginx:latest"; got != want {
		t.Fatalf("imageRef = %q, want %q", got, want)
	}
}

func TestRenderComparisonLookupErrorAndFilenameHelpers(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "not-found", err: errComparisonTargetNotFound, wantStatus: http.StatusNotFound},
		{name: "ambiguous", err: errComparisonTargetAmbiguous, wantStatus: http.StatusConflict},
		{name: "bad-request", err: errors.New("invalid image_name"), wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			NewScanHandler(nil, nil, nil, nil).renderComparisonLookupError(c, "image1", tt.err)
			if got, want := recorder.Code, tt.wantStatus; got != want {
				t.Fatalf("status = %d, want %d, body=%s", got, want, recorder.Body.String())
			}
		})
	}

	if got, want := scannerResponseKey("trivy-server"), "trivy_server_vulnerabilities"; got != want {
		t.Fatalf("scannerResponseKey() = %q, want %q", got, want)
	}
	if _, err := normalizeImageExportFormat("yaml"); err == nil {
		t.Fatal("expected normalizeImageExportFormat() to reject unsupported formats")
	}
	if got, err := normalizeImageExportFormat(reportexport.FormatSARIF); err != nil || got != reportexport.FormatSARIF {
		t.Fatalf("normalizeImageExportFormat() = %q, %v", got, err)
	}
	if got, err := buildImageExportFilename("demo-org", "demo-image", "sbom", sbomindex.FormatCycloneDX); err != nil || got != "demo-org-demo-image-sbom-cyclonedx.json" {
		t.Fatalf("buildImageExportFilename(sbom) = %q, %v", got, err)
	}
	if got, err := buildImageExportFilename("demo-org", "demo-image", "vulnerabilities", reportexport.FormatCSV); err != nil || got != "demo-org-demo-image-vulnerabilities.csv" {
		t.Fatalf("buildImageExportFilename(csv) = %q, %v", got, err)
	}
	if got, err := buildComparisonExportFilename(compare.ComputeID("org1", "img1", "org2", "img2")); err != nil || got == "" {
		t.Fatalf("buildComparisonExportFilename() = %q, %v", got, err)
	}
	if got, err := buildVEXFilename(&multipart.FileHeader{Filename: "advisory.txt"}, time.Unix(100, 1)); err != nil || got == "" {
		t.Fatalf("buildVEXFilename() = %q, %v", got, err)
	}

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	writeAttachment(c, "demo.json", "application/json", []byte(`{"ok":true}`))
	if got, want := recorder.Header().Get("Content-Disposition"), `attachment; filename="demo.json"`; got != want {
		t.Fatalf("Content-Disposition = %q, want %q", got, want)
	}
}

func TestRenderScanExecutionErrorTreatsPolicyBlocksAsBadRequest(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)

	NewScanHandler(nil, nil, nil, nil).renderScanExecutionError(c, &registry.PolicyError{
		Registry: "127.0.0.1:5000",
		Reason:   "host IP 127.0.0.1 is a loopback address",
	})

	if got, want := recorder.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, recorder.Body.String())
	}
}

func testCombinedVulnerabilityReport() scan.CombinedVulnerabilityReport {
	return scan.CombinedVulnerabilityReport{
		ImageRef:    "alpine:latest",
		GeneratedAt: time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC),
		Summary:     scan.VulnerabilitySummary{Total: 1, Fixable: 1},
		Vulnerabilities: []scan.VulnerabilityFinding{
			{
				ID:             "CVE-2024-0001",
				Severity:       "HIGH",
				PackageName:    "busybox",
				PackageVersion: "1.36.1-r0",
				FixVersion:     "1.36.2-r0",
				Scanners:       []string{"grype"},
			},
		},
	}
}
