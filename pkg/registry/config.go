package registry

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir                 string
	DefaultDockerConfig     string
	HealthcheckTimeout      time.Duration
	MinPullInterval         time.Duration
	AllowedRegistries       []string
	DeniedRegistries        []string
	AllowPrivateNetworks    bool
	AllowInsecureRegistries bool
}

func ConfigFromEnv(dataDir string) Config {
	defaultDockerConfig := strings.TrimSpace(os.Getenv("OTTER_DOCKER_CONFIG_PATH"))
	if defaultDockerConfig == "" {
		defaultDockerConfig = filepath.Join(os.Getenv("HOME"), ".docker", "config.json")
	}

	healthTimeout := 15 * time.Second
	if raw := strings.TrimSpace(os.Getenv("OTTER_REGISTRY_HEALTHCHECK_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			healthTimeout = parsed
		}
	}

	minPullInterval := 750 * time.Millisecond
	if raw := strings.TrimSpace(os.Getenv("OTTER_REGISTRY_PULL_INTERVAL")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed >= 0 {
			minPullInterval = parsed
		}
	} else if raw := strings.TrimSpace(os.Getenv("OTTER_REGISTRY_PULLS_PER_SECOND")); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 {
			minPullInterval = time.Duration(float64(time.Second) / parsed)
		}
	}

	allowPrivateNetworks := false
	if raw := strings.TrimSpace(os.Getenv("OTTER_REGISTRY_ALLOW_PRIVATE_NETWORKS")); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			allowPrivateNetworks = parsed
		}
	}

	allowInsecureRegistries := false
	if raw := strings.TrimSpace(os.Getenv("OTTER_REGISTRY_ALLOW_INSECURE")); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			allowInsecureRegistries = parsed
		}
	}

	return Config{
		DataDir:                 filepath.Join(dataDir, "_registry"),
		DefaultDockerConfig:     defaultDockerConfig,
		HealthcheckTimeout:      healthTimeout,
		MinPullInterval:         minPullInterval,
		AllowedRegistries:       parseRegistryPolicyList(os.Getenv("OTTER_REGISTRY_ALLOWLIST")),
		DeniedRegistries:        parseRegistryPolicyList(os.Getenv("OTTER_REGISTRY_DENYLIST")),
		AllowPrivateNetworks:    allowPrivateNetworks,
		AllowInsecureRegistries: allowInsecureRegistries,
	}
}

func parseRegistryPolicyList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	items := make([]string, 0, len(fields))
	for _, field := range fields {
		value := strings.ToLower(strings.TrimSpace(field))
		if value == "" {
			continue
		}
		items = append(items, value)
	}
	if len(items) == 0 {
		return nil
	}
	return items
}
