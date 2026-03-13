package registry

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir             string
	DefaultDockerConfig string
	HealthcheckTimeout  time.Duration
	MinPullInterval     time.Duration
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

	return Config{
		DataDir:             filepath.Join(dataDir, "_registry"),
		DefaultDockerConfig: defaultDockerConfig,
		HealthcheckTimeout:  healthTimeout,
		MinPullInterval:     minPullInterval,
	}
}
