package storage

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	BackendLocal    = "local"
	BackendPostgres = "postgres"
	BackendS3       = "s3"
)

var ErrNotFound = errors.New("storage object not found")

type PutOptions struct {
	ContentType string
	Metadata    map[string]string
}

type ObjectInfo struct {
	Key         string            `json:"key"`
	Size        int64             `json:"size"`
	ContentType string            `json:"content_type"`
	CreatedAt   time.Time         `json:"created_at"`
	Backend     string            `json:"backend"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	DownloadURL string            `json:"download_url,omitempty"`
}

type Object struct {
	Info ObjectInfo
	Data []byte
}

type Store interface {
	Backend() string
	Put(ctx context.Context, key string, data []byte, opts PutOptions) (ObjectInfo, error)
	Get(ctx context.Context, key string) (Object, error)
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
	Delete(ctx context.Context, key string) error
	Close() error
}

func defaultContentTypeForKey(key string) string {
	switch {
	case strings.HasSuffix(key, "/sbom.json"):
		return "application/vnd.cyclonedx+json"
	case strings.HasSuffix(key, ".json"):
		return "application/json"
	default:
		return "application/octet-stream"
	}
}
