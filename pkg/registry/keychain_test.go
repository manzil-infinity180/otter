package registry

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func TestDockerConfigKeychainResolveContext(t *testing.T) {
	t.Parallel()

	configPath := writeDockerConfig(t, authn.DefaultAuthKey, "reader", "secret")
	keychain := keychainFromDockerConfig(configPath)

	authenticator, err := keychain.Resolve(mustRepository(t, "index.docker.io/library/alpine"))
	if err != nil {
		t.Fatalf("ResolveContext() error = %v", err)
	}

	authConfig, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization() error = %v", err)
	}
	if got, want := authConfig.Username, "reader"; got != want {
		t.Fatalf("auth username = %q, want %q", got, want)
	}
	if got, want := authConfig.Password, "secret"; got != want {
		t.Fatalf("auth password = %q, want %q", got, want)
	}
}

func TestDockerConfigKeychainResolveContextFallsBackToAnonymous(t *testing.T) {
	t.Parallel()

	configPath := writeDockerConfig(t, "ghcr.io", "reader", "secret")
	authenticator, err := keychainFromDockerConfig(configPath).Resolve(mustRepository(t, "registry.example.com/demo/app"))
	if err != nil {
		t.Fatalf("ResolveContext() error = %v", err)
	}
	if got, want := authenticator, authn.Anonymous; got != want {
		t.Fatalf("authenticator = %#v, want anonymous", got)
	}
}

func TestLoadDockerConfigSupportsDirectoryAndRejectsMissingFile(t *testing.T) {
	t.Parallel()

	configPath := writeDockerConfig(t, "ghcr.io", "reader", "secret")
	if _, err := loadDockerConfig(configPath); err != nil {
		t.Fatalf("loadDockerConfig(file) error = %v", err)
	}
	if _, err := loadDockerConfig(t.TempDir()); err != nil {
		t.Fatalf("loadDockerConfig(dir) error = %v", err)
	}
	if _, err := loadDockerConfig(configPath + ".missing"); err == nil {
		t.Fatal("expected loadDockerConfig() to fail for missing path")
	}
}

func mustRepository(t *testing.T, raw string) name.Repository {
	t.Helper()

	repo, err := name.NewRepository(raw)
	if err != nil {
		t.Fatalf("NewRepository(%q) error = %v", raw, err)
	}
	return repo
}
