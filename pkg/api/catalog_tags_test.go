package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/registry"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestGetImageTagsMergesStoredAndRemoteResultsWithPagination(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store := mustLocalStore(t)
	sbomRepo := mustLocalSBOMRepo(t)
	vulnRepo := mustLocalVulnRepo(t)

	for _, record := range []sbomindex.Record{
		{
			OrgID:        "demo-org",
			ImageID:      "image-a",
			ImageName:    "alpine:3.19",
			Platform:     "linux/amd64",
			SourceFormat: sbomindex.FormatCycloneDX,
			PackageCount: 12,
			UpdatedAt:    time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC),
		},
		{
			OrgID:        "demo-org",
			ImageID:      "image-b",
			ImageName:    "alpine:3.18",
			Platform:     "linux/arm64",
			SourceFormat: sbomindex.FormatCycloneDX,
			PackageCount: 10,
			UpdatedAt:    time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC),
		},
	} {
		if _, err := sbomRepo.Save(context.Background(), record); err != nil {
			t.Fatalf("sbomRepo.Save() error = %v", err)
		}
	}

	for _, record := range []vulnindex.Record{
		{
			OrgID:     "demo-org",
			ImageID:   "image-a",
			ImageName: "alpine:3.19",
			Summary: vulnindex.Summary{
				Total:      2,
				BySeverity: map[string]int{"HIGH": 1, "MEDIUM": 1},
				ByScanner:  map[string]int{"grype": 2},
			},
			UpdatedAt: time.Date(2026, 3, 21, 9, 30, 0, 0, time.UTC),
		},
		{
			OrgID:     "demo-org",
			ImageID:   "image-b",
			ImageName: "alpine:3.18",
			Summary: vulnindex.Summary{
				Total:      1,
				BySeverity: map[string]int{"LOW": 1},
				ByScanner:  map[string]int{"grype": 1},
			},
			UpdatedAt: time.Date(2026, 3, 20, 9, 30, 0, 0, time.UTC),
		},
	} {
		if _, err := vulnRepo.Save(context.Background(), record); err != nil {
			t.Fatalf("vulnRepo.Save() error = %v", err)
		}
	}

	handler := NewScanHandlerWithRegistry(store, sbomRepo, vulnRepo, stubAnalyzer{}, stubRegistryService{
		repositoryTagsResult: registry.RepositoryTagsResult{
			Repository:     "index.docker.io/library/alpine",
			Tags:           []string{"3.19", "3.18", "3.17", "latest"},
			Cached:         true,
			CacheExpiresAt: time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC),
		},
	})
	router := gin.New()
	router.GET("/api/v1/images/:id/tags", handler.GetImageTags)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/image-a/tags?org_id=demo-org&query=3.&page=2&page_size=2", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload ImageTagsResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := payload.Total, 3; got != want {
		t.Fatalf("payload.Total = %d, want %d", got, want)
	}
	if got, want := payload.Count, 1; got != want {
		t.Fatalf("payload.Count = %d, want %d", got, want)
	}
	if got, want := payload.Page, 2; got != want {
		t.Fatalf("payload.Page = %d, want %d", got, want)
	}
	if got, want := payload.PageSize, 2; got != want {
		t.Fatalf("payload.PageSize = %d, want %d", got, want)
	}
	if payload.HasMore {
		t.Fatal("expected second page to be terminal")
	}
	if !payload.RemoteCached {
		t.Fatal("expected remote tag response to expose cache hit metadata")
	}
	if len(payload.Items) != 1 {
		t.Fatalf("len(payload.Items) = %d, want 1", len(payload.Items))
	}
	if got, want := payload.Items[0].Tag, "3.17"; got != want {
		t.Fatalf("payload.Items[0].Tag = %q, want %q", got, want)
	}
	if payload.Items[0].Scanned {
		t.Fatal("expected remote-only tag to be unscanned")
	}
	if got, want := payload.Items[0].Source, "remote"; got != want {
		t.Fatalf("payload.Items[0].Source = %q, want %q", got, want)
	}
}

func TestGetImageTagsKeepsStoredResultsWhenRemoteListingFails(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	store := mustLocalStore(t)
	sbomRepo := mustLocalSBOMRepo(t)
	vulnRepo := mustLocalVulnRepo(t)

	if _, err := sbomRepo.Save(context.Background(), sbomindex.Record{
		OrgID:        "demo-org",
		ImageID:      "image-a",
		ImageName:    "alpine:3.19",
		SourceFormat: sbomindex.FormatCycloneDX,
		PackageCount: 4,
		UpdatedAt:    time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("sbomRepo.Save() error = %v", err)
	}

	handler := NewScanHandlerWithRegistry(store, sbomRepo, vulnRepo, stubAnalyzer{}, stubRegistryService{
		repositoryTagsErr: errors.New("registry unavailable"),
	})
	router := gin.New()
	router.GET("/api/v1/images/:id/tags", handler.GetImageTags)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/images/image-a/tags?org_id=demo-org", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d, body=%s", got, want, resp.Body.String())
	}

	var payload ImageTagsResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.RemoteTagError == "" {
		t.Fatal("expected remote tag error to be reported")
	}
	if len(payload.Items) != 1 {
		t.Fatalf("len(payload.Items) = %d, want 1", len(payload.Items))
	}
	if got, want := payload.Items[0].Tag, "3.19"; got != want {
		t.Fatalf("payload.Items[0].Tag = %q, want %q", got, want)
	}
	if !payload.Items[0].Current || !payload.Items[0].Scanned {
		t.Fatalf("payload.Items[0] = %#v, want current scanned tag", payload.Items[0])
	}
}
