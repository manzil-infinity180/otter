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
