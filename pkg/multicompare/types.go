// Package multicompare provides multi-image comparison analysis.
// Designed as a self-contained package for potential future extraction.
package multicompare

import (
	"time"
)

// ImageTarget identifies an image to include in the comparison.
type ImageTarget struct {
	Name  string `json:"name"`
	OrgID string `json:"org_id,omitempty"`
}

// Request is the input for a multi-image comparison.
type Request struct {
	Images []ImageTarget `json:"images"` // 2-3 images
}

// ImageSnapshot captures all relevant data for a single image in the comparison.
type ImageSnapshot struct {
	OrgID         string                `json:"org_id"`
	ImageID       string                `json:"image_id"`
	ImageName     string                `json:"image_name"`
	PackageCount  int                   `json:"package_count"`
	VulnSummary   VulnSummary           `json:"vulnerability_summary"`
	LicenseSummary []LicenseSummaryEntry `json:"license_summary,omitempty"`
	Compliance    *ComplianceSnapshot   `json:"compliance,omitempty"`
	Trend         []TrendPoint          `json:"trend,omitempty"`
	Scanners      []string              `json:"scanners,omitempty"`
	UpdatedAt     time.Time             `json:"updated_at"`
	Color         string                `json:"color"` // assigned chart color
}

// VulnSummary is a portable vulnerability summary.
type VulnSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	Fixable    int            `json:"fixable"`
	Unfixable  int            `json:"unfixable"`
}

// LicenseSummaryEntry is a license count pair.
type LicenseSummaryEntry struct {
	License string `json:"license"`
	Count   int    `json:"count"`
}

// ComplianceSnapshot captures supply chain posture.
type ComplianceSnapshot struct {
	SLSALevel      string  `json:"slsa_level,omitempty"`
	ScorecardScore float64 `json:"scorecard_score,omitempty"`
	HasSBOM        bool    `json:"has_sbom"`
	HasSignature   bool    `json:"has_signature"`
	HasAttestation bool    `json:"has_attestation"`
}

// TrendPoint is a time-series vulnerability observation.
type TrendPoint struct {
	ObservedAt time.Time `json:"observed_at"`
	Total      int       `json:"total"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
}

// PairwiseDiff summarizes the diff between two images.
type PairwiseDiff struct {
	Image1Index int `json:"image1_index"`
	Image2Index int `json:"image2_index"`

	PackagesAdded   int `json:"packages_added"`
	PackagesRemoved int `json:"packages_removed"`
	PackagesChanged int `json:"packages_changed"`

	VulnsNew       int `json:"vulns_new"`
	VulnsFixed     int `json:"vulns_fixed"`
	VulnsUnchanged int `json:"vulns_unchanged"`
}

// PackageEntry is a package with its image membership.
type PackageEntry struct {
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`
	Versions []string `json:"versions"` // one per image, "" if absent
	InImages []int    `json:"in_images"` // indices of images containing this package
}

// SeverityDataPoint is one bar in the grouped severity chart.
type SeverityDataPoint struct {
	Severity string `json:"severity"`
	Counts   []int  `json:"counts"` // one per image
}

// ChartData holds pre-computed data for frontend charts.
type ChartData struct {
	SeverityBreakdown []SeverityDataPoint `json:"severity_breakdown"`
	PackageOverlap    []PackageEntry      `json:"package_overlap"`
}

// Report is the full multi-image comparison result.
type Report struct {
	ID            string         `json:"id"`
	GeneratedAt   time.Time      `json:"generated_at"`
	Images        []ImageSnapshot `json:"images"`
	PairwiseDiffs []PairwiseDiff `json:"pairwise_diffs"`
	Charts        ChartData      `json:"chart_data"`
	Winner        int            `json:"winner"` // index of image with fewest vulns
}

// PresetComparison is a quick-start comparison template.
type PresetComparison struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Images      []ImageTarget `json:"images"`
}
