package catalogscan

import (
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("OTTER_CATALOG_SCANNER_ENABLED", "false")
	t.Setenv("OTTER_CATALOG_SCANNER_INTERVAL", "30m")
	t.Setenv("OTTER_CATALOG_SCANNER_TIMEOUT", "2m")
	t.Setenv("OTTER_CATALOG_SCANNER_WORKERS", "4")
	t.Setenv("OTTER_CATALOG_SCANNER_QUEUE_SIZE", "12")
	t.Setenv("OTTER_CATALOG_SCANNER_JOB_HISTORY_LIMIT", "99")
	t.Setenv("OTTER_CATALOG_SCANNER_STATE_DIR", "/tmp/otter-jobs")
	t.Setenv("OTTER_CATALOG_SCANNER_RETRY_LIMIT", "4")
	t.Setenv("OTTER_CATALOG_SCANNER_RETRY_BACKOFF", "7s")
	t.Setenv("OTTER_CATALOG_SCANNER_RETRY_BACKOFF_MAX", "45s")
	t.Setenv("OTTER_CATALOG_SCANNER_ORG_ID", "preseed")
	t.Setenv("OTTER_CATALOG_SCANNER_IMAGES", "alpine:latest, nginx:latest, alpine:latest")

	cfg := ConfigFromEnv()

	if cfg.Enabled {
		t.Fatal("expected catalog scanner to be disabled")
	}
	if got, want := cfg.Interval, 30*time.Minute; got != want {
		t.Fatalf("Interval = %v, want %v", got, want)
	}
	if got, want := cfg.Timeout, 2*time.Minute; got != want {
		t.Fatalf("Timeout = %v, want %v", got, want)
	}
	if got, want := len(cfg.ImageRefs), 2; got != want {
		t.Fatalf("len(ImageRefs) = %d, want %d", got, want)
	}
	if got, want := cfg.StateDir, "/tmp/otter-jobs"; got != want {
		t.Fatalf("StateDir = %q, want %q", got, want)
	}
	if got, want := cfg.RetryLimit, 4; got != want {
		t.Fatalf("RetryLimit = %d, want %d", got, want)
	}
	if got, want := cfg.RetryBackoff, 7*time.Second; got != want {
		t.Fatalf("RetryBackoff = %v, want %v", got, want)
	}
	if got, want := cfg.RetryBackoffMax, 45*time.Second; got != want {
		t.Fatalf("RetryBackoffMax = %v, want %v", got, want)
	}
	if got, want := cfg.OrgID, "preseed"; got != want {
		t.Fatalf("OrgID = %q, want %q", got, want)
	}
}
