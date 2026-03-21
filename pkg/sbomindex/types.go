package sbomindex

import (
	"context"
	"errors"
	"time"

	"github.com/otterXf/otter/pkg/vulnindex"
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
	RepositoryKey   string                `json:"repository_key,omitempty"`
	Platform        string                `json:"platform,omitempty"`
	SourceFormat    string                `json:"source_format"`
	PackageCount    int                   `json:"package_count"`
	Packages        []PackageRecord       `json:"packages"`
	DependencyTree  []DependencyNode      `json:"dependency_tree"`
	DependencyRoots []string              `json:"dependency_roots,omitempty"`
	LicenseSummary  []LicenseSummaryEntry `json:"license_summary"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

type CatalogRecord struct {
	OrgID                string                `json:"org_id"`
	ImageID              string                `json:"image_id"`
	ImageName            string                `json:"image_name,omitempty"`
	RepositoryKey        string                `json:"repository_key,omitempty"`
	Platform             string                `json:"platform,omitempty"`
	SourceFormat         string                `json:"source_format"`
	PackageCount         int                   `json:"package_count"`
	LicenseSummary       []LicenseSummaryEntry `json:"license_summary,omitempty"`
	VulnerabilitySummary vulnindex.Summary     `json:"vulnerability_summary"`
	UpdatedAt            time.Time             `json:"updated_at"`
}

type CatalogQuery struct {
	OrgID       string
	AllowedOrgs []string
	Query       string
	Severity    string
	SortBy      string
	Page        int
	PageSize    int
}

type CatalogPage struct {
	Items []CatalogRecord
	Total int
}

type RepositoryTagQuery struct {
	OrgID          string
	RepositoryKey  string
	ExcludeImageID string
}

type Repository interface {
	Save(ctx context.Context, record Record) (Record, error)
	Get(ctx context.Context, orgID, imageID string) (Record, error)
	List(ctx context.Context) ([]Record, error)
	QueryCatalog(ctx context.Context, query CatalogQuery) (CatalogPage, error)
	ListRepositoryTags(ctx context.Context, query RepositoryTagQuery) ([]CatalogRecord, error)
	FindByImageName(ctx context.Context, imageName string) ([]Record, error)
	Delete(ctx context.Context, orgID, imageID string) error
	Close() error
}
