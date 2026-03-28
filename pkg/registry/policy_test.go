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

func TestSSRFCloudMetadataEndpointsBlocked(t *testing.T) {
	t.Parallel()

	cloudMetadataIPs := []struct {
		name string
		ip   string
	}{
		{name: "AWS metadata", ip: "169.254.169.254"},
		{name: "Azure metadata", ip: "169.254.169.254"},
		{name: "GCP metadata", ip: "169.254.169.254"},
		{name: "link-local base", ip: "169.254.0.1"},
		{name: "link-local end", ip: "169.254.255.254"},
	}

	for _, tc := range cloudMetadataIPs {
		t.Run(tc.name, func(t *testing.T) {
			reason, blocked := internalRegistryTargetReason(context.Background(), tc.ip)
			if !blocked {
				t.Fatalf("expected cloud metadata IP %s to be blocked", tc.ip)
			}
			if !strings.Contains(reason, "link-local") {
				t.Fatalf("expected link-local reason for %s, got: %s", tc.ip, reason)
			}
		})
	}
}

func TestSSRFPrivateNetworkCIDRsBlocked(t *testing.T) {
	t.Parallel()

	privateIPs := []struct {
		name string
		ip   string
		want string
	}{
		{name: "10.0.0.0/8", ip: "10.0.0.1", want: "RFC1918"},
		{name: "10.255.255.255", ip: "10.255.255.255", want: "RFC1918"},
		{name: "172.16.0.0/12", ip: "172.16.0.1", want: "RFC1918"},
		{name: "172.31.255.255", ip: "172.31.255.255", want: "RFC1918"},
		{name: "192.168.0.0/16", ip: "192.168.1.1", want: "RFC1918"},
		{name: "loopback", ip: "127.0.0.1", want: "loopback"},
		{name: "carrier-grade NAT", ip: "100.64.0.1", want: "carrier-grade"},
		{name: "current-network", ip: "0.0.0.1", want: "current-network"},
	}

	for _, tc := range privateIPs {
		t.Run(tc.name, func(t *testing.T) {
			reason, blocked := internalRegistryTargetReason(context.Background(), tc.ip)
			if !blocked {
				t.Fatalf("expected IP %s to be blocked", tc.ip)
			}
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("expected reason containing %q for %s, got: %s", tc.want, tc.ip, reason)
			}
		})
	}
}

func TestSSRFDNSRebindingBlocked(t *testing.T) {
	t.Parallel()

	originalLookup := registryLookupIPAddr
	t.Cleanup(func() { registryLookupIPAddr = originalLookup })

	registryLookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}

	manager := NewManager(NewMemoryRepository(), Config{})
	err := manager.enforcePolicy(context.Background(), "prepare-image", Record{
		Registry: "attacker-rebind.example.com",
	})
	if err == nil {
		t.Fatal("expected DNS rebinding to cloud metadata IP to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked by egress policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSSRFIPv6PrivateAddressesBlocked(t *testing.T) {
	t.Parallel()

	ipv6Addrs := []struct {
		name string
		ip   string
		want string
	}{
		{name: "IPv6 loopback", ip: "::1", want: "loopback"},
		{name: "IPv6 unique-local", ip: "fd00::1", want: "unique-local"},
		{name: "IPv6 link-local", ip: "fe80::1", want: "link-local"},
	}

	for _, tc := range ipv6Addrs {
		t.Run(tc.name, func(t *testing.T) {
			reason, blocked := internalRegistryTargetReason(context.Background(), tc.ip)
			if !blocked {
				t.Fatalf("expected IPv6 address %s to be blocked", tc.ip)
			}
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("expected reason containing %q for %s, got: %s", tc.want, tc.ip, reason)
			}
		})
	}
}

func TestSSRFBlockedHostnames(t *testing.T) {
	t.Parallel()

	blockedHosts := []struct {
		name string
		host string
	}{
		{name: "localhost", host: "localhost"},
		{name: "docker internal", host: "host.docker.internal"},
		{name: "kubernetes default", host: "kubernetes.default"},
		{name: "cluster local suffix", host: "my-service.default.svc.cluster.local"},
		{name: "local suffix", host: "registry.local"},
	}

	for _, tc := range blockedHosts {
		t.Run(tc.name, func(t *testing.T) {
			reason, blocked := internalRegistryTargetReason(context.Background(), tc.host)
			if !blocked {
				t.Fatalf("expected hostname %q to be blocked", tc.host)
			}
			if reason == "" {
				t.Fatalf("expected non-empty reason for blocked host %q", tc.host)
			}
		})
	}
}
