package sbomindex

import (
	"context"
	"testing"
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
