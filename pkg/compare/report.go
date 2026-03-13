package compare

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/vulnindex"
)

const (
	changeAdded   = "added"
	changeRemoved = "removed"
	changeChanged = "changed"
)

type ImageDescriptor struct {
	OrgID              string                          `json:"org_id"`
	ImageID            string                          `json:"image_id"`
	ImageName          string                          `json:"image_name"`
	PackageCount       int                             `json:"package_count"`
	VulnerabilityTotal int                             `json:"vulnerability_total"`
	UpdatedAt          time.Time                       `json:"updated_at"`
	LicenseSummary     []sbomindex.LicenseSummaryEntry `json:"license_summary,omitempty"`
}

type Summary struct {
	Message                    string `json:"message"`
	PackageDelta               int    `json:"package_delta"`
	VulnerabilityDelta         int    `json:"vulnerability_delta"`
	ChangedLayerDelta          int    `json:"changed_layer_delta"`
	Image2FewerPackages        int    `json:"image2_fewer_packages"`
	Image2FewerVulnerabilities int    `json:"image2_fewer_vulnerabilities"`
}

type PackageChange struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	PURL        string `json:"purl,omitempty"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
	Change      string `json:"change"`
}

type PackageDiff struct {
	Added   []PackageChange `json:"added"`
	Removed []PackageChange `json:"removed"`
	Changed []PackageChange `json:"changed"`
}

type VulnerabilityChange struct {
	ID          string   `json:"id"`
	PackageName string   `json:"package_name"`
	PackageType string   `json:"package_type,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	Severity    string   `json:"severity"`
	FixVersion  string   `json:"fix_version,omitempty"`
	FromStatus  string   `json:"from_status,omitempty"`
	ToStatus    string   `json:"to_status,omitempty"`
	Change      string   `json:"change"`
	Scanners    []string `json:"scanners,omitempty"`
	Description string   `json:"description,omitempty"`
	PrimaryURL  string   `json:"primary_url,omitempty"`
}

type VulnerabilityDiff struct {
	New       []VulnerabilityChange `json:"new"`
	Fixed     []VulnerabilityChange `json:"fixed"`
	Unchanged []VulnerabilityChange `json:"unchanged"`
}

type LayerRecord struct {
	Digest               string `json:"digest"`
	PackageCount         int    `json:"package_count"`
	EstimatedContentSize int64  `json:"estimated_content_size"`
}

type LayerSizeComparison struct {
	Image1EstimatedContentSize int64 `json:"image1_estimated_content_size"`
	Image2EstimatedContentSize int64 `json:"image2_estimated_content_size"`
	DeltaEstimatedContentSize  int64 `json:"delta_estimated_content_size"`
}

type LayerDiff struct {
	Image1Count    int                 `json:"image1_count"`
	Image2Count    int                 `json:"image2_count"`
	OnlyInImage1   []LayerRecord       `json:"only_in_image1"`
	OnlyInImage2   []LayerRecord       `json:"only_in_image2"`
	Shared         []LayerRecord       `json:"shared"`
	SizeComparison LayerSizeComparison `json:"size_comparison"`
}

type SBOMDiff struct {
	ComponentsAdded        int      `json:"components_added"`
	ComponentsRemoved      int      `json:"components_removed"`
	ComponentsChanged      int      `json:"components_changed"`
	DependencyRootsAdded   []string `json:"dependency_roots_added,omitempty"`
	DependencyRootsRemoved []string `json:"dependency_roots_removed,omitempty"`
}

type Report struct {
	ID                string            `json:"id"`
	GeneratedAt       time.Time         `json:"generated_at"`
	Image1            ImageDescriptor   `json:"image1"`
	Image2            ImageDescriptor   `json:"image2"`
	Summary           Summary           `json:"summary"`
	PackageDiff       PackageDiff       `json:"package_diff"`
	VulnerabilityDiff VulnerabilityDiff `json:"vulnerability_diff"`
	LayerDiff         LayerDiff         `json:"layer_diff"`
	SBOMDiff          SBOMDiff          `json:"sbom_diff"`
}

type Inputs struct {
	Image1           sbomindex.Record
	Image2           sbomindex.Record
	Vulnerabilities1 vulnindex.Record
	Vulnerabilities2 vulnindex.Record
	CycloneDX1       []byte
	CycloneDX2       []byte
}

type cyclonedxDocument struct {
	Components []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	Properties []cycloneDXProperty `json:"properties"`
}

type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type packageState struct {
	Name    string
	Type    string
	PURL    string
	Version string
}

type vulnerabilityState struct {
	ID          string
	PackageName string
	PackageType string
	Namespace   string
	Severity    string
	FixVersion  string
	Status      string
	Scanners    []string
	Description string
	PrimaryURL  string
}

func BuildReport(input Inputs) (Report, error) {
	layer1, err := extractLayers(input.CycloneDX1)
	if err != nil {
		return Report{}, fmt.Errorf("extract image1 layers: %w", err)
	}
	layer2, err := extractLayers(input.CycloneDX2)
	if err != nil {
		return Report{}, fmt.Errorf("extract image2 layers: %w", err)
	}

	packageDiff := diffPackages(input.Image1.Packages, input.Image2.Packages)
	vulnerabilityDiff := diffVulnerabilities(input.Vulnerabilities1.Vulnerabilities, input.Vulnerabilities2.Vulnerabilities)
	layerDiff := diffLayers(layer1, layer2)
	sbomDiff := buildSBOMDiff(input.Image1, input.Image2, packageDiff)

	report := Report{
		ID:          ComputeID(input.Image1.OrgID, input.Image1.ImageID, input.Image2.OrgID, input.Image2.ImageID),
		GeneratedAt: time.Now().UTC(),
		Image1: ImageDescriptor{
			OrgID:              input.Image1.OrgID,
			ImageID:            input.Image1.ImageID,
			ImageName:          input.Image1.ImageName,
			PackageCount:       input.Image1.PackageCount,
			VulnerabilityTotal: input.Vulnerabilities1.Summary.Total,
			UpdatedAt:          latestUpdatedAt(input.Image1.UpdatedAt, input.Vulnerabilities1.UpdatedAt),
			LicenseSummary:     input.Image1.LicenseSummary,
		},
		Image2: ImageDescriptor{
			OrgID:              input.Image2.OrgID,
			ImageID:            input.Image2.ImageID,
			ImageName:          input.Image2.ImageName,
			PackageCount:       input.Image2.PackageCount,
			VulnerabilityTotal: input.Vulnerabilities2.Summary.Total,
			UpdatedAt:          latestUpdatedAt(input.Image2.UpdatedAt, input.Vulnerabilities2.UpdatedAt),
			LicenseSummary:     input.Image2.LicenseSummary,
		},
		PackageDiff:       packageDiff,
		VulnerabilityDiff: vulnerabilityDiff,
		LayerDiff:         layerDiff,
		SBOMDiff:          sbomDiff,
	}
	report.Summary = buildSummary(report)
	return report, nil
}

func ComputeID(org1, imageID1, org2, imageID2 string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{org1, imageID1, org2, imageID2}, "|")))
	return hex.EncodeToString(sum[:])
}

func MarshalReport(report Report) ([]byte, error) {
	document, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal comparison report: %w", err)
	}
	return document, nil
}

func ComparisonKey(comparisonID string) string {
	return fmt.Sprintf("otterxf/comparisons/%s/comparison.json", comparisonID)
}

func diffPackages(image1, image2 []sbomindex.PackageRecord) PackageDiff {
	left := make(map[string]packageState, len(image1))
	right := make(map[string]packageState, len(image2))
	for _, pkg := range image1 {
		left[packageKey(pkg)] = packageState{Name: pkg.Name, Type: pkg.Type, PURL: pkg.PURL, Version: pkg.Version}
	}
	for _, pkg := range image2 {
		right[packageKey(pkg)] = packageState{Name: pkg.Name, Type: pkg.Type, PURL: pkg.PURL, Version: pkg.Version}
	}

	diff := PackageDiff{
		Added:   make([]PackageChange, 0),
		Removed: make([]PackageChange, 0),
		Changed: make([]PackageChange, 0),
	}

	for key, leftPkg := range left {
		rightPkg, ok := right[key]
		if !ok {
			diff.Removed = append(diff.Removed, PackageChange{
				Name:        leftPkg.Name,
				Type:        leftPkg.Type,
				PURL:        leftPkg.PURL,
				FromVersion: leftPkg.Version,
				Change:      changeRemoved,
			})
			continue
		}
		if leftPkg.Version != rightPkg.Version {
			diff.Changed = append(diff.Changed, PackageChange{
				Name:        leftPkg.Name,
				Type:        leftPkg.Type,
				PURL:        chooseString(rightPkg.PURL, leftPkg.PURL),
				FromVersion: leftPkg.Version,
				ToVersion:   rightPkg.Version,
				Change:      changeChanged,
			})
		}
		delete(right, key)
	}
	for _, pkg := range right {
		diff.Added = append(diff.Added, PackageChange{
			Name:      pkg.Name,
			Type:      pkg.Type,
			PURL:      pkg.PURL,
			ToVersion: pkg.Version,
			Change:    changeAdded,
		})
	}

	sortPackageChanges(diff.Added)
	sortPackageChanges(diff.Removed)
	sortPackageChanges(diff.Changed)
	return diff
}

func diffVulnerabilities(image1, image2 []vulnindex.VulnerabilityRecord) VulnerabilityDiff {
	left := make(map[string]vulnerabilityState, len(image1))
	right := make(map[string]vulnerabilityState, len(image2))
	for _, finding := range image1 {
		left[vulnerabilityKey(finding)] = vulnerabilityState{
			ID:          finding.ID,
			PackageName: finding.PackageName,
			PackageType: finding.PackageType,
			Namespace:   finding.Namespace,
			Severity:    finding.Severity,
			FixVersion:  finding.FixVersion,
			Status:      finding.Status,
			Scanners:    finding.Scanners,
			Description: finding.Description,
			PrimaryURL:  finding.PrimaryURL,
		}
	}
	for _, finding := range image2 {
		right[vulnerabilityKey(finding)] = vulnerabilityState{
			ID:          finding.ID,
			PackageName: finding.PackageName,
			PackageType: finding.PackageType,
			Namespace:   finding.Namespace,
			Severity:    finding.Severity,
			FixVersion:  finding.FixVersion,
			Status:      finding.Status,
			Scanners:    finding.Scanners,
			Description: finding.Description,
			PrimaryURL:  finding.PrimaryURL,
		}
	}

	diff := VulnerabilityDiff{
		New:       make([]VulnerabilityChange, 0),
		Fixed:     make([]VulnerabilityChange, 0),
		Unchanged: make([]VulnerabilityChange, 0),
	}

	for key, leftFinding := range left {
		rightFinding, ok := right[key]
		if !ok {
			diff.Fixed = append(diff.Fixed, VulnerabilityChange{
				ID:          leftFinding.ID,
				PackageName: leftFinding.PackageName,
				PackageType: leftFinding.PackageType,
				Namespace:   leftFinding.Namespace,
				Severity:    leftFinding.Severity,
				FixVersion:  leftFinding.FixVersion,
				FromStatus:  leftFinding.Status,
				Change:      "fixed",
				Scanners:    leftFinding.Scanners,
				Description: leftFinding.Description,
				PrimaryURL:  leftFinding.PrimaryURL,
			})
			continue
		}
		diff.Unchanged = append(diff.Unchanged, VulnerabilityChange{
			ID:          rightFinding.ID,
			PackageName: rightFinding.PackageName,
			PackageType: rightFinding.PackageType,
			Namespace:   rightFinding.Namespace,
			Severity:    rightFinding.Severity,
			FixVersion:  chooseString(rightFinding.FixVersion, leftFinding.FixVersion),
			FromStatus:  leftFinding.Status,
			ToStatus:    rightFinding.Status,
			Change:      "unchanged",
			Scanners:    uniqueSortedStrings(append(leftFinding.Scanners, rightFinding.Scanners...)),
			Description: chooseString(rightFinding.Description, leftFinding.Description),
			PrimaryURL:  chooseString(rightFinding.PrimaryURL, leftFinding.PrimaryURL),
		})
		delete(right, key)
	}
	for _, finding := range right {
		diff.New = append(diff.New, VulnerabilityChange{
			ID:          finding.ID,
			PackageName: finding.PackageName,
			PackageType: finding.PackageType,
			Namespace:   finding.Namespace,
			Severity:    finding.Severity,
			FixVersion:  finding.FixVersion,
			ToStatus:    finding.Status,
			Change:      "new",
			Scanners:    finding.Scanners,
			Description: finding.Description,
			PrimaryURL:  finding.PrimaryURL,
		})
	}

	sortVulnerabilityChanges(diff.New)
	sortVulnerabilityChanges(diff.Fixed)
	sortVulnerabilityChanges(diff.Unchanged)
	return diff
}

func buildSBOMDiff(image1, image2 sbomindex.Record, packageDiff PackageDiff) SBOMDiff {
	addedRoots, removedRoots := diffStringSets(image1.DependencyRoots, image2.DependencyRoots)
	sort.Strings(addedRoots)
	sort.Strings(removedRoots)

	return SBOMDiff{
		ComponentsAdded:        len(packageDiff.Added),
		ComponentsRemoved:      len(packageDiff.Removed),
		ComponentsChanged:      len(packageDiff.Changed),
		DependencyRootsAdded:   addedRoots,
		DependencyRootsRemoved: removedRoots,
	}
}

func extractLayers(document []byte) (map[string]LayerRecord, error) {
	if len(document) == 0 {
		return map[string]LayerRecord{}, nil
	}

	var decoded cyclonedxDocument
	if err := json.Unmarshal(document, &decoded); err != nil {
		return nil, fmt.Errorf("decode cyclonedx document: %w", err)
	}

	layers := make(map[string]LayerRecord)
	for _, component := range decoded.Components {
		layerID := ""
		var size int64
		for _, property := range component.Properties {
			switch {
			case strings.Contains(property.Name, "layerID"):
				layerID = strings.TrimSpace(property.Value)
			case strings.HasSuffix(property.Name, ":size"):
				if parsed, err := strconv.ParseInt(strings.TrimSpace(property.Value), 10, 64); err == nil {
					size = parsed
				}
			}
		}
		if layerID == "" {
			continue
		}
		layer := layers[layerID]
		layer.Digest = layerID
		layer.PackageCount++
		layer.EstimatedContentSize += size
		layers[layerID] = layer
	}

	return layers, nil
}

func diffLayers(image1, image2 map[string]LayerRecord) LayerDiff {
	diff := LayerDiff{
		Image1Count:  len(image1),
		Image2Count:  len(image2),
		OnlyInImage1: make([]LayerRecord, 0),
		OnlyInImage2: make([]LayerRecord, 0),
		Shared:       make([]LayerRecord, 0),
	}

	for digest, layer1 := range image1 {
		layer2, ok := image2[digest]
		if !ok {
			diff.OnlyInImage1 = append(diff.OnlyInImage1, layer1)
			diff.SizeComparison.Image1EstimatedContentSize += layer1.EstimatedContentSize
			continue
		}
		diff.Shared = append(diff.Shared, LayerRecord{
			Digest:               digest,
			PackageCount:         maxInt(layer1.PackageCount, layer2.PackageCount),
			EstimatedContentSize: maxInt64(layer1.EstimatedContentSize, layer2.EstimatedContentSize),
		})
		diff.SizeComparison.Image1EstimatedContentSize += layer1.EstimatedContentSize
		diff.SizeComparison.Image2EstimatedContentSize += layer2.EstimatedContentSize
		delete(image2, digest)
	}
	for _, layer2 := range image2 {
		diff.OnlyInImage2 = append(diff.OnlyInImage2, layer2)
		diff.SizeComparison.Image2EstimatedContentSize += layer2.EstimatedContentSize
	}
	diff.SizeComparison.DeltaEstimatedContentSize = diff.SizeComparison.Image2EstimatedContentSize - diff.SizeComparison.Image1EstimatedContentSize

	sortLayers(diff.OnlyInImage1)
	sortLayers(diff.OnlyInImage2)
	sortLayers(diff.Shared)
	return diff
}

func buildSummary(report Report) Summary {
	image2FewerPackages := report.Image1.PackageCount - report.Image2.PackageCount
	image2FewerVulnerabilities := report.Image1.VulnerabilityTotal - report.Image2.VulnerabilityTotal
	changedLayers := len(report.LayerDiff.OnlyInImage1) + len(report.LayerDiff.OnlyInImage2)

	return Summary{
		Message:                    fmt.Sprintf("Image B has %d fewer vulns and %d fewer packages", image2FewerVulnerabilities, image2FewerPackages),
		PackageDelta:               len(report.PackageDiff.Added) - len(report.PackageDiff.Removed),
		VulnerabilityDelta:         len(report.VulnerabilityDiff.New) - len(report.VulnerabilityDiff.Fixed),
		ChangedLayerDelta:          changedLayers,
		Image2FewerPackages:        image2FewerPackages,
		Image2FewerVulnerabilities: image2FewerVulnerabilities,
	}
}

func packageKey(pkg sbomindex.PackageRecord) string {
	name := strings.ToLower(strings.TrimSpace(pkg.Name))
	pkgType := strings.ToLower(strings.TrimSpace(pkg.Type))
	if name != "" {
		return name + "|" + pkgType
	}
	purl := strings.TrimSpace(pkg.PURL)
	if purl != "" {
		base := purl
		if idx := strings.Index(base, "@"); idx >= 0 {
			base = base[:idx]
		}
		return strings.ToLower(base)
	}
	return strings.ToLower(strings.Join([]string{pkg.Name, pkg.Type}, "|"))
}

func vulnerabilityKey(vulnerability vulnindex.VulnerabilityRecord) string {
	return strings.ToUpper(strings.Join([]string{
		strings.TrimSpace(vulnerability.ID),
		strings.ToLower(strings.TrimSpace(vulnerability.PackageName)),
		strings.TrimSpace(vulnerability.PackageVersion),
		strings.ToLower(strings.TrimSpace(vulnerability.Namespace)),
	}, "|"))
}

func diffStringSets(image1, image2 []string) ([]string, []string) {
	left := make(map[string]struct{}, len(image1))
	right := make(map[string]struct{}, len(image2))
	for _, value := range image1 {
		left[value] = struct{}{}
	}
	for _, value := range image2 {
		right[value] = struct{}{}
	}

	added := make([]string, 0)
	removed := make([]string, 0)
	for value := range left {
		if _, ok := right[value]; !ok {
			removed = append(removed, value)
		}
	}
	for value := range right {
		if _, ok := left[value]; !ok {
			added = append(added, value)
		}
	}
	return added, removed
}

func latestUpdatedAt(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func chooseString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func sortPackageChanges(changes []PackageChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		if changes[i].Type != changes[j].Type {
			return changes[i].Type < changes[j].Type
		}
		return changes[i].ToVersion < changes[j].ToVersion
	})
}

func sortVulnerabilityChanges(changes []VulnerabilityChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Severity != changes[j].Severity {
			return changes[i].Severity > changes[j].Severity
		}
		if changes[i].ID != changes[j].ID {
			return changes[i].ID < changes[j].ID
		}
		return changes[i].PackageName < changes[j].PackageName
	})
}

func sortLayers(layers []LayerRecord) {
	sort.Slice(layers, func(i, j int) bool {
		return layers[i].Digest < layers[j].Digest
	})
}

func maxInt(a, b int) int {
	if b > a {
		return b
	}
	return a
}

func maxInt64(a, b int64) int64 {
	if b > a {
		return b
	}
	return a
}
