package storage

import (
	"path/filepath"
	"testing"
)

func TestConfigFromEnvDefaultsAndOverrides(t *testing.T) {
	t.Setenv("OTTER_STORAGE", BackendPostgres)
	t.Setenv("OTTER_DATA_DIR", "/tmp/otter-data")
	t.Setenv("OTTER_POSTGRES_DSN", "postgres://otter:test@localhost:5432/otter?sslmode=disable")
	t.Setenv("OTTER_POSTGRES_MIGRATIONS", "/tmp/migrations")
	t.Setenv("S3_BUCKET_NAME", "custom-bucket")
	t.Setenv("AWS_REGION", "eu-west-1")

	cfg := ConfigFromEnv()

	if got, want := cfg.Backend, BackendPostgres; got != want {
		t.Fatalf("Backend = %q, want %q", got, want)
	}
	if got, want := cfg.LocalDataDir, "/tmp/otter-data"; got != want {
		t.Fatalf("LocalDataDir = %q, want %q", got, want)
	}
	if got, want := cfg.S3Bucket, "custom-bucket"; got != want {
		t.Fatalf("S3Bucket = %q, want %q", got, want)
	}
	if got, want := cfg.S3Region, "eu-west-1"; got != want {
		t.Fatalf("S3Region = %q, want %q", got, want)
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	cfg := ConfigFromEnv()

	if got, want := cfg.Backend, BackendLocal; got != want {
		t.Fatalf("Backend = %q, want %q", got, want)
	}
	if got, want := filepath.Base(cfg.PostgresMigrations), "migrations"; got != want {
		t.Fatalf("PostgresMigrations base = %q, want %q", got, want)
	}
}

func TestDefaultContentTypeForKey(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"scans/demo/image/sbom.json":           "application/vnd.cyclonedx+json",
		"scans/demo/image/sbom-cyclonedx.json": "application/vnd.cyclonedx+json",
		"scans/demo/image/sbom-spdx.json":      "application/spdx+json",
		"scans/demo/image/report.json":         "application/json",
		"scans/demo/image/report.bin":          "application/octet-stream",
	}

	for key, want := range tests {
		if got := defaultContentTypeForKey(key); got != want {
			t.Fatalf("defaultContentTypeForKey(%q) = %q, want %q", key, got, want)
		}
	}
}
