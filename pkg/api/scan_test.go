package api

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/otterXf/otter/pkg/sbomindex"
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

	handler := NewScanHandler(store, repo, stubAnalyzer{
		result: scan.AnalysisResult{
			ImageRef:                "alpine:latest",
			SBOMDocument:            []byte(testCycloneDXDocument),
			SBOMSPDXDocument:        []byte(testSPDXDocument),
			SBOMData:                testSyftSBOM(),
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

	handler := NewScanHandler(store, repo, stubAnalyzer{})
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

	handler := NewScanHandler(store, repo, stubAnalyzer{})
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
