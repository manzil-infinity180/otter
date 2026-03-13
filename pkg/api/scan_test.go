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

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
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

	record, err := repo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("repo.Get() error = %v", err)
	}
	if got, want := record.PackageCount, 2; got != want {
		t.Fatalf("record.PackageCount = %d, want %d", got, want)
	}

	vulnerabilities, err := vulnRepo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("vulnRepo.Get() error = %v", err)
	}
	if got, want := vulnerabilities.Summary.Total, 1; got != want {
		t.Fatalf("vulnerabilities.Summary.Total = %d, want %d", got, want)
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

func testSyftSBOM() *syftsbom.SBOM {
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
