package vulnindex

import (
	"context"
	"errors"
	"time"

	"github.com/otterXf/otter/pkg/scan"
)

const (
	StatusAffected           = "affected"
	StatusNotAffected        = "not_affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"

	StatusSourceScanner = "scanner"
	StatusSourceVEX     = "vex"
)

var ErrNotFound = errors.New("vulnerability index record not found")

type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByScanner  map[string]int `json:"by_scanner"`
	ByStatus   map[string]int `json:"by_status"`
	Fixable    int            `json:"fixable"`
	Unfixable  int            `json:"unfixable"`
}

type Advisory struct {
	DocumentID      string    `json:"document_id"`
	Filename        string    `json:"filename,omitempty"`
	StatementID     string    `json:"statement_id,omitempty"`
	Author          string    `json:"author,omitempty"`
	StatusNotes     string    `json:"status_notes,omitempty"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impact_statement,omitempty"`
	ActionStatement string    `json:"action_statement,omitempty"`
	Timestamp       time.Time `json:"timestamp,omitempty"`
}

type VulnerabilityRecord struct {
	ID             string           `json:"id"`
	Severity       string           `json:"severity"`
	PackageName    string           `json:"package_name"`
	PackageVersion string           `json:"package_version,omitempty"`
	PackageType    string           `json:"package_type,omitempty"`
	Namespace      string           `json:"namespace,omitempty"`
	Title          string           `json:"title,omitempty"`
	Description    string           `json:"description,omitempty"`
	PrimaryURL     string           `json:"primary_url,omitempty"`
	References     []string         `json:"references,omitempty"`
	FixVersion     string           `json:"fix_version,omitempty"`
	FixVersions    []string         `json:"fix_versions,omitempty"`
	CVSS           []scan.CVSSScore `json:"cvss,omitempty"`
	Scanners       []string         `json:"scanners"`
	Status         string           `json:"status"`
	StatusSource   string           `json:"status_source"`
	Advisory       *Advisory        `json:"advisory,omitempty"`
	FirstSeenAt    time.Time        `json:"first_seen_at"`
	LastSeenAt     time.Time        `json:"last_seen_at"`
}

type FixRecommendation struct {
	PackageName        string   `json:"package_name"`
	PackageVersion     string   `json:"package_version,omitempty"`
	PackageType        string   `json:"package_type,omitempty"`
	Namespace          string   `json:"namespace,omitempty"`
	RecommendedVersion string   `json:"recommended_version"`
	VulnerabilityIDs   []string `json:"vulnerability_ids"`
	VulnerabilityCount int      `json:"vulnerability_count"`
}

type TrendPoint struct {
	ObservedAt time.Time `json:"observed_at"`
	Summary    Summary   `json:"summary"`
}

type VEXStatementRecord struct {
	StatementID     string    `json:"statement_id,omitempty"`
	VulnerabilityID string    `json:"vulnerability_id"`
	Status          string    `json:"status"`
	StatusNotes     string    `json:"status_notes,omitempty"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impact_statement,omitempty"`
	ActionStatement string    `json:"action_statement,omitempty"`
	ProductIDs      []string  `json:"product_ids,omitempty"`
	SubcomponentIDs []string  `json:"subcomponent_ids,omitempty"`
	Timestamp       time.Time `json:"timestamp,omitempty"`
	LastUpdated     time.Time `json:"last_updated,omitempty"`
}

type VEXDocumentRecord struct {
	DocumentID  string               `json:"document_id"`
	Author      string               `json:"author,omitempty"`
	AuthorRole  string               `json:"author_role,omitempty"`
	Timestamp   time.Time            `json:"timestamp,omitempty"`
	LastUpdated time.Time            `json:"last_updated,omitempty"`
	Version     int                  `json:"version"`
	ImportedAt  time.Time            `json:"imported_at"`
	Filename    string               `json:"filename,omitempty"`
	Statements  []VEXStatementRecord `json:"statements"`
}

type Record struct {
	OrgID              string                `json:"org_id"`
	ImageID            string                `json:"image_id"`
	ImageName          string                `json:"image_name,omitempty"`
	Summary            Summary               `json:"summary"`
	Vulnerabilities    []VulnerabilityRecord `json:"vulnerabilities"`
	FixRecommendations []FixRecommendation   `json:"fix_recommendations"`
	Trend              []TrendPoint          `json:"trend"`
	VEXDocuments       []VEXDocumentRecord   `json:"vex_documents"`
	UpdatedAt          time.Time             `json:"updated_at"`
}

type BuildOptions struct {
	TrackTrend bool
}

type FilterOptions struct {
	Severity string
	Status   string
}

type Repository interface {
	Save(ctx context.Context, record Record) (Record, error)
	Get(ctx context.Context, orgID, imageID string) (Record, error)
	Delete(ctx context.Context, orgID, imageID string) error
	Close() error
}
