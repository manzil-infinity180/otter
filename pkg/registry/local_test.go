package registry

import (
	"context"
	"testing"
	"time"
)

func TestLocalRepositoryLifecycle(t *testing.T) {
	t.Parallel()

	repo, err := NewLocalRepository(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	createdAt := time.Date(2026, 3, 14, 1, 0, 0, 0, time.UTC)
	record, err := repo.Save(context.Background(), Record{
		Registry:        "ghcr.io",
		AuthMode:        AuthModeExplicit,
		Username:        "robot",
		Password:        "secret",
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
		InsecureUseHTTP: true,
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	updated, err := repo.Save(context.Background(), Record{
		Registry:  "ghcr.io",
		AuthMode:  AuthModeDockerConfig,
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: createdAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("second Save() error = %v", err)
	}
	if got, want := updated.CreatedAt, record.CreatedAt; !got.Equal(want) {
		t.Fatalf("updated.CreatedAt = %v, want %v", got, want)
	}

	got, err := repo.Get(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.AuthMode != AuthModeDockerConfig {
		t.Fatalf("Get().AuthMode = %q, want %q", got.AuthMode, AuthModeDockerConfig)
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(records), 1; got != want {
		t.Fatalf("len(List()) = %d, want %d", got, want)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("HOME", "/Users/tester")
	t.Setenv("OTTER_DOCKER_CONFIG_PATH", "/tmp/config.json")
	t.Setenv("OTTER_REGISTRY_HEALTHCHECK_TIMEOUT", "5s")
	t.Setenv("OTTER_REGISTRY_PULLS_PER_SECOND", "4")

	cfg := ConfigFromEnv("/tmp/otter")

	if got, want := cfg.DataDir, "/tmp/otter/_registry"; got != want {
		t.Fatalf("DataDir = %q, want %q", got, want)
	}
	if got, want := cfg.DefaultDockerConfig, "/tmp/config.json"; got != want {
		t.Fatalf("DefaultDockerConfig = %q, want %q", got, want)
	}
	if got, want := cfg.HealthcheckTimeout.String(), "5s"; got != want {
		t.Fatalf("HealthcheckTimeout = %q, want %q", got, want)
	}
	if got, want := cfg.MinPullInterval.String(), "250ms"; got != want {
		t.Fatalf("MinPullInterval = %q, want %q", got, want)
	}
}
