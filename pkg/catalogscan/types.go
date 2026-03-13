package catalogscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
)

const (
	SourceAPI     = "api"
	SourceCatalog = "catalog"

	TriggerManual    = "manual"
	TriggerScheduler = "scheduler"

	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

type Request struct {
	OrgID     string `json:"org_id"`
	ImageID   string `json:"image_id"`
	ImageName string `json:"image_name"`
	Registry  string `json:"registry,omitempty"`
	Source    string `json:"source"`
	Trigger   string `json:"trigger"`
}

type Result struct {
	OrgID       string                    `json:"org_id"`
	ImageID     string                    `json:"image_id"`
	ImageName   string                    `json:"image_name"`
	Registry    string                    `json:"registry,omitempty"`
	Scanners    []string                  `json:"scanners,omitempty"`
	Summary     scan.VulnerabilitySummary `json:"summary"`
	CompletedAt time.Time                 `json:"completed_at"`
}

type Job struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	Request     Request    `json:"request"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	Result      *Result    `json:"result,omitempty"`
}

type Executor interface {
	ExecuteCatalogScan(context.Context, Request) (Result, error)
}

func NewRequest(orgID, imageID, imageName, registry, source, trigger string) (Request, error) {
	imageName = strings.TrimSpace(imageName)
	if imageName == "" {
		return Request{}, fmt.Errorf("image_name is required")
	}
	if _, err := name.ParseReference(imageName); err != nil {
		return Request{}, fmt.Errorf("invalid image_name %q: %w", imageName, err)
	}

	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		orgID = DefaultOrgID
	}
	if err := storage.ValidateSegment("org_id", orgID); err != nil {
		return Request{}, err
	}

	imageID = strings.TrimSpace(imageID)
	if imageID == "" {
		imageID = BuildImageID(imageName)
	}
	if err := storage.ValidateSegment("image_id", imageID); err != nil {
		return Request{}, err
	}

	source = strings.TrimSpace(source)
	if source == "" {
		source = SourceAPI
	}
	trigger = strings.TrimSpace(trigger)
	if trigger == "" {
		trigger = TriggerManual
	}

	return Request{
		OrgID:     orgID,
		ImageID:   imageID,
		ImageName: imageName,
		Registry:  strings.TrimSpace(registry),
		Source:    source,
		Trigger:   trigger,
	}, nil
}

func BuildImageID(imageName string) string {
	sanitized := strings.NewReplacer(
		"/", "-",
		":", "-",
		"@", "-",
		"+", "-",
	).Replace(strings.ToLower(strings.TrimSpace(imageName)))
	sanitized = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == '-':
			return r
		default:
			return '-'
		}
	}, sanitized)
	sanitized = strings.Trim(sanitized, "-.")
	if sanitized == "" {
		sanitized = "image"
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(imageName)))
	suffix := hex.EncodeToString(sum[:])[:12]
	maxPrefixLength := 128 - 1 - len(suffix)
	if len(sanitized) > maxPrefixLength {
		sanitized = sanitized[:maxPrefixLength]
		sanitized = strings.TrimRight(sanitized, "-.")
		if sanitized == "" {
			sanitized = "image"
		}
	}
	return sanitized + "-" + suffix
}

func (r Request) TargetKey() string {
	return r.OrgID + "/" + r.ImageID
}
