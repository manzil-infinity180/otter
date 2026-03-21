package catalogscan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultOrgID = "catalog"

var defaultImageRefs = []string{
	"alpine:latest",
	"alpine:3.19",
	"debian:latest",
	"debian:12-slim",
	"ubuntu:latest",
	"ubuntu:24.04",
	"nginx:latest",
	"nginx:1.27",
	"python:latest",
	"python:3.12",
	"golang:latest",
	"golang:1.24",
	"cgr.dev/chainguard/static:latest",
}

type Config struct {
	Enabled         bool
	Interval        time.Duration
	Timeout         time.Duration
	WorkerCount     int
	QueueSize       int
	JobHistoryLimit int
	StateDir        string
	RetryLimit      int
	RetryBackoff    time.Duration
	RetryBackoffMax time.Duration
	OrgID           string
	ImageRefs       []string
}

func ConfigFromEnv() Config {
	workingDir, err := os.Getwd()
	if err != nil {
		workingDir = "."
	}
	dataDir := strings.TrimSpace(os.Getenv("OTTER_DATA_DIR"))
	if dataDir == "" {
		dataDir = filepath.Join(workingDir, "data")
	}
	cfg := Config{
		Enabled:         envBool("OTTER_CATALOG_SCANNER_ENABLED", true),
		Interval:        envDuration("OTTER_CATALOG_SCANNER_INTERVAL", 6*time.Hour),
		Timeout:         envDuration("OTTER_CATALOG_SCANNER_TIMEOUT", 15*time.Minute),
		WorkerCount:     envInt("OTTER_CATALOG_SCANNER_WORKERS", 2),
		QueueSize:       envInt("OTTER_CATALOG_SCANNER_QUEUE_SIZE", 32),
		JobHistoryLimit: envInt("OTTER_CATALOG_SCANNER_JOB_HISTORY_LIMIT", 200),
		StateDir:        strings.TrimSpace(os.Getenv("OTTER_CATALOG_SCANNER_STATE_DIR")),
		RetryLimit:      envInt("OTTER_CATALOG_SCANNER_RETRY_LIMIT", 2),
		RetryBackoff:    envDuration("OTTER_CATALOG_SCANNER_RETRY_BACKOFF", 5*time.Second),
		RetryBackoffMax: envDuration("OTTER_CATALOG_SCANNER_RETRY_BACKOFF_MAX", time.Minute),
		OrgID:           strings.TrimSpace(os.Getenv("OTTER_CATALOG_SCANNER_ORG_ID")),
		ImageRefs:       parseImageRefs(os.Getenv("OTTER_CATALOG_SCANNER_IMAGES")),
	}
	if cfg.OrgID == "" {
		cfg.OrgID = DefaultOrgID
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 6 * time.Hour
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Minute
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 32
	}
	if cfg.JobHistoryLimit <= 0 {
		cfg.JobHistoryLimit = 200
	}
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(dataDir, "_catalog_scan_jobs")
	}
	if cfg.RetryLimit < 0 {
		cfg.RetryLimit = 0
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 5 * time.Second
	}
	if cfg.RetryBackoffMax <= 0 {
		cfg.RetryBackoffMax = time.Minute
	}
	if cfg.RetryBackoffMax < cfg.RetryBackoff {
		cfg.RetryBackoffMax = cfg.RetryBackoff
	}
	if len(cfg.ImageRefs) == 0 {
		cfg.ImageRefs = DefaultImageRefs()
	}
	return cfg
}

func DefaultImageRefs() []string {
	refs := make([]string, len(defaultImageRefs))
	copy(refs, defaultImageRefs)
	return refs
}

func DefaultRequests(cfg Config) []Request {
	imageRefs := cfg.ImageRefs
	if len(imageRefs) == 0 {
		imageRefs = DefaultImageRefs()
	}

	requests := make([]Request, 0, len(imageRefs))
	for _, imageRef := range imageRefs {
		request, err := NewRequest(cfg.OrgID, "", imageRef, "", SourceCatalog, TriggerScheduler)
		if err != nil {
			continue
		}
		request.Actor = "catalog-scheduler"
		request.ActorType = "system"
		requests = append(requests, request)
	}
	return requests
}

func parseImageRefs(value string) []string {
	parts := strings.Split(value, ",")
	seen := make(map[string]struct{}, len(parts))
	refs := make([]string, 0, len(parts))
	for _, part := range parts {
		ref := strings.TrimSpace(part)
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
