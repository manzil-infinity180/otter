package vulnindex

import (
	"context"
	"testing"
	"time"
)

func TestLocalRepositorySaveGetDelete(t *testing.T) {
	t.Parallel()

	repo, err := NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	record := Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:latest",
		Summary: Summary{
			Total:      1,
			BySeverity: map[string]int{"HIGH": 1},
			ByScanner:  map[string]int{"grype": 1},
			ByStatus:   map[string]int{StatusAffected: 1},
			Fixable:    1,
		},
		Vulnerabilities: []VulnerabilityRecord{
			{
				ID:          "CVE-2024-0001",
				Severity:    "HIGH",
				PackageName: "openssl",
				Status:      StatusAffected,
				Scanners:    []string{"grype"},
				FirstSeenAt: time.Now().UTC(),
				LastSeenAt:  time.Now().UTC(),
			},
		},
	}

	if _, err := repo.Save(context.Background(), record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := repo.Get(context.Background(), "demo-org", "demo-image")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ImageName != "alpine:latest" || got.Summary.Total != 1 {
		t.Fatalf("Get() = %#v", got)
	}

	if err := repo.Delete(context.Background(), "demo-org", "demo-image"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repo.Get(context.Background(), "demo-org", "demo-image"); err == nil {
		t.Fatal("expected Get() after Delete() to fail")
	}
}
