package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerConfigureAndPrepareImageWithExplicitCredentials(t *testing.T) {
	t.Parallel()

	server := newBasicAuthRegistry(t, "robot", "secret")
	t.Cleanup(server.Close)

	host := strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://")
	manager := NewManager(NewMemoryRepository(), Config{
		AllowPrivateNetworks:    true,
		AllowInsecureRegistries: true,
	})

	result, err := manager.Configure(context.Background(), ConfigureRequest{
		Registry:        host,
		AuthMode:        AuthModeExplicit,
		Username:        "robot",
		Password:        "secret",
		InsecureUseHTTP: true,
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if got, want := result.Summary.Registry, host; got != want {
		t.Fatalf("summary registry = %q, want %q", got, want)
	}
	if got, want := result.AuthSource, "explicit-basic"; got != want {
		t.Fatalf("auth source = %q, want %q", got, want)
	}

	access, err := manager.PrepareImage(context.Background(), host+"/demo:latest")
	if err != nil {
		t.Fatalf("PrepareImage() error = %v", err)
	}
	if got, want := access.Registry, host; got != want {
		t.Fatalf("prepared registry = %q, want %q", got, want)
	}
	if got, want := access.AuthSource, "explicit-basic"; got != want {
		t.Fatalf("prepared auth source = %q, want %q", got, want)
	}
	if access.RegistryOptions == nil || len(access.RegistryOptions.Credentials) != 1 {
		t.Fatalf("expected explicit registry credentials, got %#v", access.RegistryOptions)
	}
}

func TestManagerConfigureDockerConfigRegistry(t *testing.T) {
	t.Parallel()

	server := newBasicAuthRegistry(t, "reader", "tokenpass")
	t.Cleanup(server.Close)

	host := strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://")
	configPath := writeDockerConfig(t, host, "reader", "tokenpass")
	manager := NewManager(NewMemoryRepository(), Config{
		AllowPrivateNetworks:    true,
		AllowInsecureRegistries: true,
	})

	result, err := manager.Configure(context.Background(), ConfigureRequest{
		Registry:         host,
		AuthMode:         AuthModeDockerConfig,
		DockerConfigPath: configPath,
		InsecureUseHTTP:  true,
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if !result.Summary.HasDockerConfigPath {
		t.Fatalf("expected docker config summary, got %#v", result.Summary)
	}

	access, err := manager.PrepareImage(context.Background(), host+"/demo:latest")
	if err != nil {
		t.Fatalf("PrepareImage() error = %v", err)
	}
	if got, want := access.AuthSource, "docker-config-path"; got != want {
		t.Fatalf("prepared auth source = %q, want %q", got, want)
	}
	if access.RegistryOptions == nil || access.RegistryOptions.Keychain == nil {
		t.Fatalf("expected docker config keychain, got %#v", access.RegistryOptions)
	}
}

func newBasicAuthRegistry(t *testing.T, username, password string) *httptest.Server {
	t.Helper()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, ok := r.BasicAuth()
		if !ok || gotUser != username || gotPass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v2/demo/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", "sha256:1111111111111111111111111111111111111111111111111111111111111111")
			w.Header().Set("Content-Length", "2")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte("{}"))
			}
		default:
			http.NotFound(w, r)
		}
	})

	return httptest.NewServer(handler)
}

func writeDockerConfig(t *testing.T, registryHost, username, password string) string {
	t.Helper()

	rawAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	payload := map[string]any{
		"auths": map[string]any{
			registryHost: map[string]any{
				"auth": rawAuth,
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
