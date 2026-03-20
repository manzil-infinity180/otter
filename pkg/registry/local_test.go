package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalRepositoryLifecycle(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	repo, err := NewLocalRepository(dataDir)
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
	if got.Password != "" || got.Token != "" || got.Username != "" {
		t.Fatalf("Get() should not retain explicit credentials after docker config switch, got %#v", got)
	}

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(records), 1; got != want {
		t.Fatalf("len(List()) = %d, want %d", got, want)
	}

	metadata, err := os.ReadFile(filepath.Join(dataDir, "registries.json"))
	if err != nil {
		t.Fatalf("ReadFile(registries.json) error = %v", err)
	}
	if strings.Contains(string(metadata), "secret") || strings.Contains(string(metadata), "robot") {
		t.Fatalf("registries.json should not contain plaintext credentials: %s", metadata)
	}
	if _, err := os.Stat(repo.secrets.secretPathForRegistry("ghcr.io")); !os.IsNotExist(err) {
		t.Fatalf("expected registry secret file to be removed after switching to docker config, err=%v", err)
	}
}

func TestLocalRepositoryEncryptsAndSeparatesRegistrySecrets(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	repo, err := NewLocalRepository(dataDir)
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	now := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)
	first, err := repo.Save(context.Background(), Record{
		Registry:  "ghcr.io",
		AuthMode:  AuthModeExplicit,
		Token:     "ghcr-token",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	if _, err := repo.Save(context.Background(), Record{
		Registry:  "registry.example.com",
		AuthMode:  AuthModeExplicit,
		Username:  "builder",
		Password:  "builder-secret",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}

	metadata, err := os.ReadFile(filepath.Join(dataDir, "registries.json"))
	if err != nil {
		t.Fatalf("ReadFile(registries.json) error = %v", err)
	}
	for _, secret := range []string{"ghcr-token", "builder", "builder-secret"} {
		if strings.Contains(string(metadata), secret) {
			t.Fatalf("registries.json contains plaintext secret %q: %s", secret, metadata)
		}
	}

	ghcrSecretPath := repo.secrets.secretPathForRegistry(first.Registry)
	ghcrCiphertext, err := os.ReadFile(ghcrSecretPath)
	if err != nil {
		t.Fatalf("ReadFile(ghcr secret) error = %v", err)
	}
	if strings.Contains(string(ghcrCiphertext), "ghcr-token") {
		t.Fatalf("encrypted secret file should not contain plaintext token: %s", ghcrCiphertext)
	}

	otherSecretPath := repo.secrets.secretPathForRegistry("registry.example.com")
	otherCiphertext, err := os.ReadFile(otherSecretPath)
	if err != nil {
		t.Fatalf("ReadFile(other secret) error = %v", err)
	}

	if _, err := repo.Save(context.Background(), Record{
		Registry:  "ghcr.io",
		AuthMode:  AuthModeExplicit,
		Token:     "rotated-token",
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save(rotation) error = %v", err)
	}

	rotatedCiphertext, err := os.ReadFile(ghcrSecretPath)
	if err != nil {
		t.Fatalf("ReadFile(rotated secret) error = %v", err)
	}
	if string(rotatedCiphertext) == string(ghcrCiphertext) {
		t.Fatalf("expected rotated registry secret ciphertext to change")
	}
	unchangedCiphertext, err := os.ReadFile(otherSecretPath)
	if err != nil {
		t.Fatalf("ReadFile(unchanged secret) error = %v", err)
	}
	if string(unchangedCiphertext) != string(otherCiphertext) {
		t.Fatalf("expected unrelated registry secret file to remain unchanged")
	}

	record, err := repo.Get(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got, want := record.Token, "rotated-token"; got != want {
		t.Fatalf("Get().Token = %q, want %q", got, want)
	}
}

func TestLocalRepositoryMigratesLegacyPlaintextCredentials(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	repo, err := NewLocalRepository(dataDir)
	if err != nil {
		t.Fatalf("NewLocalRepository() error = %v", err)
	}

	legacy := []byte(`{
  "registries": [
    {
      "registry": "ghcr.io",
      "auth_mode": "explicit",
      "username": "robot",
      "password": "legacy-secret",
      "created_at": "2026-03-14T01:00:00Z",
      "updated_at": "2026-03-14T01:00:00Z"
    }
  ]
}`)
	if err := os.WriteFile(filepath.Join(dataDir, "registries.json"), legacy, 0o600); err != nil {
		t.Fatalf("WriteFile(legacy registries.json) error = %v", err)
	}

	record, err := repo.Get(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got, want := record.Password, "legacy-secret"; got != want {
		t.Fatalf("Get().Password = %q, want %q", got, want)
	}
	if got, want := record.Username, "robot"; got != want {
		t.Fatalf("Get().Username = %q, want %q", got, want)
	}

	metadata, err := os.ReadFile(filepath.Join(dataDir, "registries.json"))
	if err != nil {
		t.Fatalf("ReadFile(registries.json) error = %v", err)
	}
	if strings.Contains(string(metadata), "legacy-secret") || strings.Contains(string(metadata), `"password"`) {
		t.Fatalf("legacy registries.json should be rewritten without plaintext credentials: %s", metadata)
	}

	secretData, err := os.ReadFile(repo.secrets.secretPathForRegistry("ghcr.io"))
	if err != nil {
		t.Fatalf("ReadFile(secret) error = %v", err)
	}
	if strings.Contains(string(secretData), "legacy-secret") {
		t.Fatalf("migrated secret file should be encrypted: %s", secretData)
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
