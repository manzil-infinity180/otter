package registry

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestManagerConfigureRejectsPrivateRegistryByDefault(t *testing.T) {
	t.Parallel()

	manager := NewManager(NewMemoryRepository(), Config{})
	err := manager.enforcePolicy(context.Background(), "configure", Record{
		Registry: "127.0.0.1:5000",
		AuthMode: AuthModeDockerConfig,
	})
	if err == nil {
		t.Fatal("expected private registry to be rejected")
	}
	if !strings.Contains(err.Error(), "blocked by egress policy") || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := err.(*PolicyError); !ok {
		t.Fatalf("expected PolicyError, got %T", err)
	}
}

func TestManagerConfigureRejectsInsecureRegistryByDefault(t *testing.T) {
	t.Parallel()

	manager := NewManager(NewMemoryRepository(), Config{})
	err := manager.enforcePolicy(context.Background(), "configure", Record{
		Registry:        "ghcr.io",
		AuthMode:        AuthModeDockerConfig,
		InsecureUseHTTP: true,
	})
	if err == nil {
		t.Fatal("expected insecure registry access to be rejected")
	}
	if !strings.Contains(err.Error(), "OTTER_REGISTRY_ALLOW_INSECURE=true") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerPolicyAllowlistAndDenylist(t *testing.T) {
	t.Parallel()

	manager := NewManager(NewMemoryRepository(), Config{
		AllowedRegistries: []string{"ghcr.io", "*.docker.io"},
		DeniedRegistries:  []string{"index.docker.io"},
	})

	if err := manager.enforcePolicy(context.Background(), "prepare-image", Record{Registry: "ghcr.io"}); err != nil {
		t.Fatalf("expected ghcr.io to be allowed, got %v", err)
	}
	if err := manager.enforcePolicy(context.Background(), "prepare-image", Record{Registry: "index.docker.io"}); err == nil {
		t.Fatal("expected denylist match to be rejected")
	}
	if err := manager.enforcePolicy(context.Background(), "prepare-image", Record{Registry: "quay.io"}); err == nil {
		t.Fatal("expected non-allowlisted registry to be rejected")
	}
}

func TestManagerPolicyAllowsPrivateAndInsecureWhenOperatorEnablesThem(t *testing.T) {
	t.Parallel()

	manager := NewManager(NewMemoryRepository(), Config{
		AllowPrivateNetworks:    true,
		AllowInsecureRegistries: true,
	})

	if err := manager.enforcePolicy(context.Background(), "prepare-image", Record{
		Registry:              "127.0.0.1:5000",
		AuthMode:              AuthModeDockerConfig,
		InsecureSkipTLSVerify: true,
	}); err != nil {
		t.Fatalf("expected explicit operator opt-in to allow private/insecure registry, got %v", err)
	}
}

func TestInternalRegistryTargetReasonRejectsBlockedSuffixAndResolvedPrivateAddress(t *testing.T) {
	t.Parallel()

	originalLookup := registryLookupIPAddr
	registryLookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.8")}}, nil
	}
	t.Cleanup(func() {
		registryLookupIPAddr = originalLookup
	})

	if reason, ok := internalRegistryTargetReason(context.Background(), "registry.svc.cluster.local"); !ok || !strings.Contains(reason, ".cluster.local") {
		t.Fatalf("expected blocked cluster-local hostname, got ok=%t reason=%q", ok, reason)
	}
	if reason, ok := internalRegistryTargetReason(context.Background(), "registry.example.test"); !ok || !strings.Contains(reason, "10.0.0.8") {
		t.Fatalf("expected private DNS resolution to be blocked, got ok=%t reason=%q", ok, reason)
	}
}
