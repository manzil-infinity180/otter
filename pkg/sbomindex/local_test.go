package sbomindex

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/vulnindex"
)

func TestLocalRepositorySaveGetDelete(t *testing.T) {
	t.Parallel()

	repo, err := NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	record := Record{
		OrgID:        "demo-org",
		ImageID:      "demo-image",
		ImageName:    "alpine:latest",
		SourceFormat: FormatCycloneDX,
		PackageCount: 1,
		Packages: []PackageRecord{
			{ID: "pkg:apk/alpine/busybox@1.0.0", Name: "busybox", Version: "1.0.0", Licenses: []string{"MIT"}},
		},
		LicenseSummary: []LicenseSummaryEntry{{License: "MIT", Count: 1}},
	}

	if _, err := repo.Save(context.Background(), record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := repo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.PackageCount != 1 || got.Packages[0].Name != "busybox" {
		t.Fatalf("Get() = %#v", got)
	}

	if err := repo.Delete(context.Background(), "demo-org", "demo-image"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repo.Get(context.Background(), "demo-org", "demo-image"); err == nil {
		t.Fatal("expected Get() after Delete() to fail")
	}
}

func TestLocalRepositoryFindByImageName(t *testing.T) {
	t.Parallel()

	repo, err := NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	for _, record := range []Record{
		{
			OrgID:        "demo-org",
			ImageID:      "image-a",
			ImageName:    "alpine:latest",
			SourceFormat: FormatCycloneDX,
			PackageCount: 1,
		},
		{
			OrgID:        "demo-org",
			ImageID:      "image-b",
			ImageName:    "nginx:latest",
			SourceFormat: FormatCycloneDX,
			PackageCount: 1,
		},
		{
			OrgID:        "demo-two",
			ImageID:      "image-c",
			ImageName:    "alpine:latest",
			SourceFormat: FormatCycloneDX,
			PackageCount: 2,
		},
	} {
		if _, err := repo.Save(context.Background(), record); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	matches, err := repo.FindByImageName(context.Background(), "alpine:latest")
	if err != nil {
		t.Fatalf("FindByImageName() error = %v", err)
	}
	if got, want := len(matches), 2; got != want {
		t.Fatalf("len(matches) = %d, want %d", got, want)
	}
}

func TestLocalRepositoryList(t *testing.T) {
	t.Parallel()

	repo, err := NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	for _, record := range []Record{
		{
			OrgID:        "demo-org",
			ImageID:      "image-a",
			ImageName:    "alpine:3.19",
			SourceFormat: FormatCycloneDX,
		},
		{
			OrgID:        "demo-org",
			ImageID:      "image-b",
			ImageName:    "alpine:3.20",
			SourceFormat: FormatCycloneDX,
		},
	} {
		if _, err := repo.Save(context.Background(), record); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(records), 2; got != want {
		t.Fatalf("len(records) = %d, want %d", got, want)
	}
	if records[0].UpdatedAt.IsZero() {
		t.Fatalf("records[0].UpdatedAt = %v", records[0].UpdatedAt)
	}
}

func TestLocalRepositoryQueryCatalogPagination(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	repo, err := NewLocalRepository(filepath.Join(baseDir, "_sbom_index"))
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}
	vulnRepo, err := vulnindex.NewLocalRepository(filepath.Join(baseDir, "_vulnerability_index"))
	if err != nil {
		t.Fatalf("NewLocalRepository(vuln) error = %v", err)
	}

	for _, record := range []Record{
		{OrgID: "demo-org", ImageID: "image-a", ImageName: "alpine:3.21", SourceFormat: FormatCycloneDX, PackageCount: 4, UpdatedAt: time.Date(2026, 3, 20, 18, 0, 0, 0, time.UTC)},
		{OrgID: "demo-org", ImageID: "image-b", ImageName: "alpine:3.20", SourceFormat: FormatCycloneDX, PackageCount: 3, UpdatedAt: time.Date(2026, 3, 20, 17, 0, 0, 0, time.UTC)},
		{OrgID: "demo-org", ImageID: "image-c", ImageName: "nginx:1.0", SourceFormat: FormatCycloneDX, PackageCount: 2, UpdatedAt: time.Date(2026, 3, 20, 16, 0, 0, 0, time.UTC)},
	} {
		if _, err := repo.Save(context.Background(), record); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	if _, err := vulnRepo.Save(context.Background(), vulnindex.Record{
		OrgID:     "demo-org",
		ImageID:   "image-b",
		ImageName: "alpine:3.20",
		Summary: vulnindex.Summary{
			Total:      2,
			BySeverity: map[string]int{"CRITICAL": 2},
		},
		UpdatedAt: time.Date(2026, 3, 20, 17, 30, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("vulnRepo.Save() error = %v", err)
	}

	page, err := repo.QueryCatalog(context.Background(), CatalogQuery{
		Query:    "alpine",
		SortBy:   "recent",
		Page:     2,
		PageSize: 1,
	})
	if err != nil {
		t.Fatalf("QueryCatalog() error = %v", err)
	}
	if got, want := page.Total, 2; got != want {
		t.Fatalf("page.Total = %d, want %d", got, want)
	}
	if got, want := len(page.Items), 1; got != want {
		t.Fatalf("len(page.Items) = %d, want %d", got, want)
	}
	if got, want := page.Items[0].ImageID, "image-b"; got != want {
		t.Fatalf("page.Items[0].ImageID = %q, want %q", got, want)
	}

	severityPage, err := repo.QueryCatalog(context.Background(), CatalogQuery{
		Severity: "CRITICAL",
		SortBy:   "critical",
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("QueryCatalog(severity) error = %v", err)
	}
	if got, want := severityPage.Total, 1; got != want {
		t.Fatalf("severityPage.Total = %d, want %d", got, want)
	}
	if got, want := severityPage.Items[0].VulnerabilitySummary.BySeverity["CRITICAL"], 2; got != want {
		t.Fatalf("critical count = %d, want %d", got, want)
	}
}

func TestLocalRepositoryListRepositoryTags(t *testing.T) {
	t.Parallel()

	repo, err := NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	for _, record := range []Record{
		{OrgID: "demo-org", ImageID: "image-a", ImageName: "alpine:3.21", SourceFormat: FormatCycloneDX, UpdatedAt: time.Date(2026, 3, 20, 18, 0, 0, 0, time.UTC)},
		{OrgID: "demo-org", ImageID: "image-b", ImageName: "alpine:3.20", SourceFormat: FormatCycloneDX, UpdatedAt: time.Date(2026, 3, 20, 17, 0, 0, 0, time.UTC)},
		{OrgID: "demo-org", ImageID: "image-c", ImageName: "nginx:1.0", SourceFormat: FormatCycloneDX, UpdatedAt: time.Date(2026, 3, 20, 16, 0, 0, 0, time.UTC)},
	} {
		if _, err := repo.Save(context.Background(), record); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	records, err := repo.ListRepositoryTags(context.Background(), RepositoryTagQuery{
		OrgID:          "demo-org",
		RepositoryKey:  normalizeRepositoryKey("alpine:latest"),
		ExcludeImageID: "image-a",
	})
	if err != nil {
		t.Fatalf("ListRepositoryTags() error = %v", err)
	}
	if got, want := len(records), 1; got != want {
		t.Fatalf("len(records) = %d, want %d", got, want)
	}
	if got, want := records[0].ImageID, "image-b"; got != want {
		t.Fatalf("records[0].ImageID = %q, want %q", got, want)
	}
}
