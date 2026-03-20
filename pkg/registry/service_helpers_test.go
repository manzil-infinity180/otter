package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/name"
)

type stubRegistryRepo struct {
	record  Record
	getErr  error
	list    []Record
	listErr error
}

func (s stubRegistryRepo) Save(context.Context, Record) (Record, error) {
	return s.record, nil
}

func (s stubRegistryRepo) Get(context.Context, string) (Record, error) {
	if s.getErr != nil {
		return Record{}, s.getErr
	}
	return s.record, nil
}

func (s stubRegistryRepo) List(context.Context) ([]Record, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.list, nil
}

func TestRegistryValidationAndHelpers(t *testing.T) {
	t.Parallel()

	configPath := writeDockerConfig(t, "ghcr.io", "reader", "secret")
	record, err := validateConfigureRequest(ConfigureRequest{
		Registry:         "GHCR.IO",
		AuthMode:         AuthModeDockerConfig,
		DockerConfigPath: configPath,
	}, "")
	if err != nil {
		t.Fatalf("validateConfigureRequest() error = %v", err)
	}
	if got, want := record.Registry, "ghcr.io"; got != want {
		t.Fatalf("record.Registry = %q, want %q", got, want)
	}

	explicit, err := validateConfigureRequest(ConfigureRequest{
		Registry: "index.docker.io",
		Username: "robot",
		Password: "secret",
	}, "")
	if err != nil {
		t.Fatalf("validateConfigureRequest(explicit inference) error = %v", err)
	}
	if got, want := explicit.AuthMode, AuthModeExplicit; got != want {
		t.Fatalf("AuthMode = %q, want %q", got, want)
	}

	if _, err := validateConfigureRequest(ConfigureRequest{
		Registry: "ghcr.io",
		AuthMode: AuthModeExplicit,
		Token:    "token",
		Username: "robot",
	}, ""); err == nil {
		t.Fatal("expected validateConfigureRequest() to reject mixed explicit auth")
	}

	if _, err := validateRegistryName("https://ghcr.io/demo/app"); err == nil {
		t.Fatal("expected validateRegistryName() to reject URLs")
	}
	if got, want := canonicalRegistry("Docker.io"), "index.docker.io"; got != want {
		t.Fatalf("canonicalRegistry() = %q, want %q", got, want)
	}
	if got, want := firstNonEmpty("", " demo ", "other"), "demo"; got != want {
		t.Fatalf("firstNonEmpty() = %q, want %q", got, want)
	}

	registry, scheme, err := parseRegistry("ghcr.io", true)
	if err != nil {
		t.Fatalf("parseRegistry() error = %v", err)
	}
	if scheme != "http" || registry.RegistryStr() != "ghcr.io" {
		t.Fatalf("parseRegistry() = %#v %q", registry, scheme)
	}

	ref, err := name.ParseReference("ghcr.io/demo/app:latest", name.Insecure)
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	options, err := remoteOptions(context.Background(), ref, &stereoscopeimage.RegistryOptions{InsecureUseHTTP: true})
	if err != nil {
		t.Fatalf("remoteOptions() error = %v", err)
	}
	if len(options) == 0 {
		t.Fatal("expected remoteOptions() to return options")
	}
}

func TestManagerRecordForRegistryRegistryOptionsAndList(t *testing.T) {
	t.Parallel()

	manager := NewManager(stubRegistryRepo{getErr: ErrNotFound}, Config{DefaultDockerConfig: "/tmp/config.json"})
	record, err := manager.recordForRegistry(context.Background(), "docker.io")
	if err != nil {
		t.Fatalf("recordForRegistry() error = %v", err)
	}
	if got, want := record.Registry, "index.docker.io"; got != want {
		t.Fatalf("record.Registry = %q, want %q", got, want)
	}

	explicitOptions, authSource, err := manager.registryOptions(Record{
		Registry: "ghcr.io",
		AuthMode: AuthModeExplicit,
		Token:    "secret",
	})
	if err != nil {
		t.Fatalf("registryOptions(explicit) error = %v", err)
	}
	if authSource != "explicit-token" || len(explicitOptions.Credentials) != 1 {
		t.Fatalf("registryOptions(explicit) = %#v, %q", explicitOptions, authSource)
	}

	keychainOptions, authSource, err := manager.registryOptions(Record{
		Registry:         "ghcr.io",
		AuthMode:         AuthModeDockerConfig,
		DockerConfigPath: "/tmp/config.json",
	})
	if err != nil {
		t.Fatalf("registryOptions(docker config) error = %v", err)
	}
	if authSource != "docker-config-path" || keychainOptions.Keychain == nil {
		t.Fatalf("registryOptions(docker config) = %#v, %q", keychainOptions, authSource)
	}
	if _, _, err := manager.registryOptions(Record{Registry: "ghcr.io", AuthMode: "invalid"}); err == nil {
		t.Fatal("expected registryOptions() to reject invalid auth modes")
	}

	listed, err := NewManager(stubRegistryRepo{
		list: []Record{
			{Registry: "ghcr.io", AuthMode: AuthModeExplicit},
			{Registry: "docker.io", AuthMode: AuthModeDockerConfig},
		},
	}, Config{}).List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed) != 2 || listed[0].Registry != "docker.io" {
		t.Fatalf("List() = %#v", listed)
	}
}

func TestResolveAuthenticatorAndLimiter(t *testing.T) {
	t.Parallel()

	registryName, err := name.NewRegistry("ghcr.io")
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	authenticator, hasAuth, err := resolveAuthenticator(context.Background(), registryName, &stereoscopeimage.RegistryOptions{
		Credentials: []stereoscopeimage.RegistryCredentials{{
			Authority: "ghcr.io",
			Token:     "secret",
		}},
	})
	if err != nil {
		t.Fatalf("resolveAuthenticator() error = %v", err)
	}
	if authenticator == nil || !hasAuth {
		t.Fatalf("resolveAuthenticator() = %#v, %t", authenticator, hasAuth)
	}

	limiter := newPullLimiter(5 * time.Millisecond)
	if err := limiter.Wait(context.Background(), "ghcr.io"); err != nil {
		t.Fatalf("Wait(first) error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := limiter.Wait(ctx, "ghcr.io"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait(cancelled) error = %v, want deadline exceeded", err)
	}
	if err := (*pullLimiter)(nil).Wait(context.Background(), "ghcr.io"); err != nil {
		t.Fatalf("nil limiter Wait() error = %v", err)
	}
}

func TestSummarizeRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC)
	summary := summarize(Record{
		Registry:         "ghcr.io",
		AuthMode:         AuthModeExplicit,
		Username:         "robot",
		CreatedAt:        now,
		UpdatedAt:        now,
		DockerConfigPath: "/tmp/config.json",
	})
	if !summary.HasCredentials || !summary.HasDockerConfigPath || summary.Registry != "ghcr.io" {
		t.Fatalf("summarize() = %#v", summary)
	}
}
