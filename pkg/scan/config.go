package scan

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	TrivyEnabled   bool
	TrivyBinary    string
	TrivyServerURL string
	TrivyTimeout   time.Duration
	TrivyScanners  []string
}

func ConfigFromEnv() Config {
	enabled := false
	if raw := strings.TrimSpace(os.Getenv("OTTER_TRIVY_ENABLED")); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			enabled = parsed
		}
	}

	serverURL := strings.TrimSpace(os.Getenv("OTTER_TRIVY_SERVER_URL"))
	if serverURL == "" {
		serverURL = "http://localhost:4954"
	}
	if !enabled && os.Getenv("OTTER_TRIVY_ENABLED") == "" && os.Getenv("OTTER_TRIVY_SERVER_URL") != "" {
		enabled = true
	}

	binary := strings.TrimSpace(os.Getenv("OTTER_TRIVY_BINARY"))
	if binary == "" {
		binary = "trivy"
	}

	timeout := 5 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("OTTER_TRIVY_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	scanners := []string{"vuln"}
	if raw := strings.TrimSpace(os.Getenv("OTTER_TRIVY_SCANNERS")); raw != "" {
		scanners = splitCSV(raw)
	}

	return Config{
		TrivyEnabled:   enabled,
		TrivyBinary:    binary,
		TrivyServerURL: serverURL,
		TrivyTimeout:   timeout,
		TrivyScanners:  scanners,
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
