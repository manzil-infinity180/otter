package sbomindex

import (
	"context"
	"errors"
	"time"
)

const (
	FormatCycloneDX = "cyclonedx"
	FormatSPDX      = "spdx"
)

var ErrNotFound = errors.New("sbom index record not found")

type PackageRecord struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Type     string   `json:"type,omitempty"`
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
}

type DependencyNode struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
}

type LicenseSummaryEntry struct {
	License string `json:"license"`
	Count   int    `json:"count"`
}

type Record struct {
	OrgID           string                `json:"org_id"`
	ImageID         string                `json:"image_id"`
	ImageName       string                `json:"image_name,omitempty"`
	SourceFormat    string                `json:"source_format"`
	PackageCount    int                   `json:"package_count"`
	Packages        []PackageRecord       `json:"packages"`
	DependencyTree  []DependencyNode      `json:"dependency_tree"`
	DependencyRoots []string              `json:"dependency_roots,omitempty"`
	LicenseSummary  []LicenseSummaryEntry `json:"license_summary"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

type Repository interface {
	Save(ctx context.Context, record Record) (Record, error)
	Get(ctx context.Context, orgID, imageID string) (Record, error)
	Delete(ctx context.Context, orgID, imageID string) error
	Close() error
}
