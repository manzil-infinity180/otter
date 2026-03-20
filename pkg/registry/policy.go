package registry

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

var (
	registryLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}

	blockedRegistryCIDRs = []blockedRegistryCIDR{
		mustBlockedRegistryCIDR("0.0.0.0/8", "current-network address"),
		mustBlockedRegistryCIDR("10.0.0.0/8", "RFC1918 private address"),
		mustBlockedRegistryCIDR("100.64.0.0/10", "carrier-grade NAT address"),
		mustBlockedRegistryCIDR("127.0.0.0/8", "loopback address"),
		mustBlockedRegistryCIDR("169.254.0.0/16", "link-local address"),
		mustBlockedRegistryCIDR("172.16.0.0/12", "RFC1918 private address"),
		mustBlockedRegistryCIDR("192.168.0.0/16", "RFC1918 private address"),
		mustBlockedRegistryCIDR("198.18.0.0/15", "benchmarking address"),
		mustBlockedRegistryCIDR("::/128", "unspecified address"),
		mustBlockedRegistryCIDR("::1/128", "loopback address"),
		mustBlockedRegistryCIDR("fc00::/7", "unique-local address"),
		mustBlockedRegistryCIDR("fe80::/10", "link-local address"),
	}

	blockedRegistryHosts = map[string]string{
		"localhost":                            "localhost target",
		"docker.internal":                      "docker-internal target",
		"host.docker.internal":                 "docker-internal target",
		"kubernetes":                           "cluster-internal target",
		"kubernetes.default":                   "cluster-internal target",
		"kubernetes.default.svc":               "cluster-internal target",
		"kubernetes.default.svc.cluster.local": "cluster-internal target",
	}

	blockedRegistrySuffixes = []string{
		".localhost",
		".local",
		".internal",
		".svc",
		".cluster.local",
		".svc.cluster.local",
	}
)

type blockedRegistryCIDR struct {
	network *net.IPNet
	reason  string
}

type PolicyError struct {
	Registry string
	Reason   string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("registry %q blocked by egress policy: %s", e.Registry, e.Reason)
}

func mustBlockedRegistryCIDR(cidr, reason string) blockedRegistryCIDR {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return blockedRegistryCIDR{network: network, reason: reason}
}

func (m *Manager) enforcePolicy(ctx context.Context, action string, record Record) error {
	registryName := canonicalRegistry(record.Registry)
	host := registryHost(registryName)

	if matched, pattern := matchesRegistryPolicy(m.cfg.DeniedRegistries, registryName, host); matched {
		err := &PolicyError{
			Registry: registryName,
			Reason:   fmt.Sprintf("matched denylist entry %q", pattern),
		}
		logRegistryPolicy("deny", action, registryName, host, err.Reason)
		return err
	}

	if len(m.cfg.AllowedRegistries) > 0 {
		if matched, pattern := matchesRegistryPolicy(m.cfg.AllowedRegistries, registryName, host); matched {
			logRegistryPolicy("allow", action, registryName, host, fmt.Sprintf("matched allowlist entry %q", pattern))
		} else {
			err := &PolicyError{
				Registry: registryName,
				Reason:   "registry is not present in OTTER_REGISTRY_ALLOWLIST",
			}
			logRegistryPolicy("deny", action, registryName, host, err.Reason)
			return err
		}
	}

	if (record.InsecureUseHTTP || record.InsecureSkipTLSVerify) && !m.cfg.AllowInsecureRegistries {
		err := &PolicyError{
			Registry: registryName,
			Reason:   "insecure HTTP or TLS bypass requires OTTER_REGISTRY_ALLOW_INSECURE=true",
		}
		logRegistryPolicy("deny", action, registryName, host, err.Reason)
		return err
	}
	if record.InsecureUseHTTP || record.InsecureSkipTLSVerify {
		logRegistryPolicy("allow", action, registryName, host, "insecure registry access explicitly enabled by operator")
	}

	if m.cfg.AllowPrivateNetworks {
		if reason, ok := internalRegistryTargetReason(ctx, host); ok {
			logRegistryPolicy("allow", action, registryName, host, reason+" allowed by OTTER_REGISTRY_ALLOW_PRIVATE_NETWORKS=true")
		}
		return nil
	}

	if reason, ok := internalRegistryTargetReason(ctx, host); ok {
		err := &PolicyError{
			Registry: registryName,
			Reason:   reason,
		}
		logRegistryPolicy("deny", action, registryName, host, err.Reason)
		return err
	}

	return nil
}

func registryHost(registryName string) string {
	parsed, err := url.Parse("https://" + strings.TrimSpace(registryName))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(registryName))
	}
	return strings.ToLower(parsed.Hostname())
}

func matchesRegistryPolicy(items []string, registryName, host string) (bool, string) {
	for _, item := range items {
		if matchRegistryPolicy(item, registryName, host) {
			return true, item
		}
	}
	return false, ""
}

func matchRegistryPolicy(pattern, registryName, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if pattern == registryName || pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix)
	}
	return false
}

func internalRegistryTargetReason(ctx context.Context, host string) (string, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "registry host is empty", true
	}
	if reason, ok := blockedRegistryHosts[host]; ok {
		return reason, true
	}
	for _, suffix := range blockedRegistrySuffixes {
		if strings.HasSuffix(host, suffix) {
			return fmt.Sprintf("hostname %q uses blocked internal suffix %q", host, suffix), true
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		if reason, ok := blockedRegistryIPReason(ip); ok {
			return fmt.Sprintf("host IP %s is a %s", ip.String(), reason), true
		}
		return "", false
	}

	addresses, err := registryLookupIPAddr(ctx, host)
	if err != nil {
		return "", false
	}
	for _, address := range addresses {
		if reason, ok := blockedRegistryIPReason(address.IP); ok {
			return fmt.Sprintf("hostname %q resolved to %s (%s)", host, address.IP.String(), reason), true
		}
	}
	return "", false
}

func blockedRegistryIPReason(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	if ip.IsMulticast() {
		return "multicast address", true
	}
	for _, blocked := range blockedRegistryCIDRs {
		if blocked.network.Contains(ip) {
			return blocked.reason, true
		}
	}
	return "", false
}

func logRegistryPolicy(outcome, action, registryName, host, reason string) {
	log.Printf("registry policy %s action=%s registry=%s host=%s reason=%q", outcome, action, registryName, host, reason)
}
