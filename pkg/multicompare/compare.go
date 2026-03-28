package multicompare

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

// imageColors are assigned to images in order.
var imageColors = []string{"#0ea5e9", "#f59e0b", "#10b981"} // sky, amber, emerald

// Inputs holds the raw data needed to build a multi-image comparison.
type Inputs struct {
	SBOMs           []sbomindex.Record
	Vulnerabilities []vulnindex.Record
	CycloneDXDocs   [][]byte // optional, for image size extraction
}

// BuildReport generates a multi-image comparison report from the inputs.
func BuildReport(inputs Inputs) (Report, error) {
	n := len(inputs.SBOMs)
	if n < 2 || n > 3 {
		return Report{}, fmt.Errorf("multi-compare requires 2-3 images, got %d", n)
	}
	if len(inputs.Vulnerabilities) != n {
		return Report{}, fmt.Errorf("vulnerability records count (%d) must match SBOM count (%d)", len(inputs.Vulnerabilities), n)
	}

	report := Report{
		ID:          computeMultiID(inputs.SBOMs),
		GeneratedAt: time.Now().UTC(),
		Images:      make([]ImageSnapshot, n),
	}

	// Build image snapshots
	for i := 0; i < n; i++ {
		var cdxDoc []byte
		if i < len(inputs.CycloneDXDocs) {
			cdxDoc = inputs.CycloneDXDocs[i]
		}
		report.Images[i] = buildSnapshot(inputs.SBOMs[i], inputs.Vulnerabilities[i], imageColors[i], cdxDoc)
	}

	// Determine winner (fewest total vulns)
	minVulns := report.Images[0].VulnSummary.Total
	report.Winner = 0
	for i := 1; i < n; i++ {
		if report.Images[i].VulnSummary.Total < minVulns {
			minVulns = report.Images[i].VulnSummary.Total
			report.Winner = i
		}
	}

	// Build pairwise diffs
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			diff := buildPairwiseDiff(i, j, inputs.SBOMs[i], inputs.SBOMs[j], inputs.Vulnerabilities[i], inputs.Vulnerabilities[j])
			report.PairwiseDiffs = append(report.PairwiseDiffs, diff)
		}
	}

	// Build chart data
	report.Charts = buildChartData(report.Images, inputs.SBOMs, inputs.Vulnerabilities)

	return report, nil
}

func buildSnapshot(sbom sbomindex.Record, vulns vulnindex.Record, color string, cdxDoc []byte) ImageSnapshot {
	snap := ImageSnapshot{
		OrgID:        sbom.OrgID,
		ImageID:      sbom.ImageID,
		ImageName:    sbom.ImageName,
		PackageCount: sbom.PackageCount,
		Color:        color,
		UpdatedAt:    sbom.UpdatedAt,
	}

	// Estimate image size from CycloneDX layer properties
	snap.EstimatedSize = estimateImageSize(cdxDoc)

	// Convert license summary
	for _, lic := range sbom.LicenseSummary {
		snap.LicenseSummary = append(snap.LicenseSummary, LicenseSummaryEntry{
			License: lic.License,
			Count:   lic.Count,
		})
	}

	// Convert vulnerability summary
	snap.VulnSummary = VulnSummary{
		Total:      vulns.Summary.Total,
		BySeverity: cloneMapIntSafe(vulns.Summary.BySeverity),
		Fixable:    vulns.Summary.Fixable,
		Unfixable:  vulns.Summary.Unfixable,
	}

	// Convert trend data
	for _, tp := range vulns.Trend {
		snap.Trend = append(snap.Trend, TrendPoint{
			ObservedAt: tp.ObservedAt,
			Total:      tp.Summary.Total,
			Critical:   tp.Summary.BySeverity["CRITICAL"],
			High:       tp.Summary.BySeverity["HIGH"],
		})
	}

	return snap
}

func buildPairwiseDiff(i, j int, sbom1, sbom2 sbomindex.Record, vuln1, vuln2 vulnindex.Record) PairwiseDiff {
	diff := PairwiseDiff{
		Image1Index: i,
		Image2Index: j,
	}

	// Package diff
	pkgs1 := packageSet(sbom1.Packages)
	pkgs2 := packageSet(sbom2.Packages)
	for name := range pkgs2 {
		if _, ok := pkgs1[name]; !ok {
			diff.PackagesAdded++
		}
	}
	for name, v1 := range pkgs1 {
		if v2, ok := pkgs2[name]; !ok {
			diff.PackagesRemoved++
		} else if v1 != v2 {
			diff.PackagesChanged++
		}
	}

	// Vulnerability diff
	vulnSet1 := vulnIDSet(vuln1.Vulnerabilities)
	vulnSet2 := vulnIDSet(vuln2.Vulnerabilities)
	for id := range vulnSet2 {
		if _, ok := vulnSet1[id]; !ok {
			diff.VulnsNew++
		} else {
			diff.VulnsUnchanged++
		}
	}
	for id := range vulnSet1 {
		if _, ok := vulnSet2[id]; !ok {
			diff.VulnsFixed++
		}
	}

	return diff
}

func buildChartData(images []ImageSnapshot, sboms []sbomindex.Record, vulnRecords []vulnindex.Record) ChartData {
	data := ChartData{}

	// Severity breakdown
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"}
	for _, sev := range severities {
		dp := SeverityDataPoint{Severity: sev}
		for _, img := range images {
			dp.Counts = append(dp.Counts, img.VulnSummary.BySeverity[sev])
		}
		data.SeverityBreakdown = append(data.SeverityBreakdown, dp)
	}

	// Package overlap
	type pkgInfo struct {
		name     string
		typ      string
		versions []string
		inImages []int
	}
	pkgMap := make(map[string]*pkgInfo)
	for i, sbom := range sboms {
		for _, pkg := range sbom.Packages {
			key := pkg.Name
			info, ok := pkgMap[key]
			if !ok {
				info = &pkgInfo{
					name:     pkg.Name,
					typ:      pkg.Type,
					versions: make([]string, len(sboms)),
				}
				pkgMap[key] = info
			}
			info.versions[i] = pkg.Version
			info.inImages = append(info.inImages, i)
		}
	}

	// Sort by name and limit to top 200 for performance
	entries := make([]PackageEntry, 0, len(pkgMap))
	for _, info := range pkgMap {
		entries = append(entries, PackageEntry{
			Name:     info.name,
			Type:     info.typ,
			Versions: info.versions,
			InImages: uniqueInts(info.inImages),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	if len(entries) > 200 {
		entries = entries[:200]
	}
	data.PackageOverlap = entries

	// Vulnerability overlap
	data.VulnOverlap = buildVulnOverlap(images, vulnRecords)

	// License breakdown
	data.LicenseBreakdown = buildLicenseBreakdown(images)

	return data
}

func buildVulnOverlap(images []ImageSnapshot, vulnRecords []vulnindex.Record) []VulnOverlapEntry {
	type vulnInfo struct {
		severity    string
		packageName string
		inImages    []int
		imageNames  []string
	}
	vulnMap := make(map[string]*vulnInfo)
	for i, vr := range vulnRecords {
		for _, v := range vr.Vulnerabilities {
			info, ok := vulnMap[v.ID]
			if !ok {
				info = &vulnInfo{severity: v.Severity, packageName: v.PackageName}
				vulnMap[v.ID] = info
			}
			info.inImages = append(info.inImages, i)
			info.imageNames = append(info.imageNames, images[i].ImageName)
		}
	}

	entries := make([]VulnOverlapEntry, 0, len(vulnMap))
	for id, info := range vulnMap {
		entries = append(entries, VulnOverlapEntry{
			ID:          id,
			Severity:    info.severity,
			PackageName: info.packageName,
			InImages:    uniqueInts(info.inImages),
			ImageNames:  info.imageNames,
		})
	}
	// Sort: unique CVEs first (in fewer images), then by severity
	severityOrder := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NEGLIGIBLE": 1}
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].InImages) != len(entries[j].InImages) {
			return len(entries[i].InImages) < len(entries[j].InImages)
		}
		return severityOrder[entries[i].Severity] > severityOrder[entries[j].Severity]
	})
	if len(entries) > 300 {
		entries = entries[:300]
	}
	return entries
}

var copyleftLicenses = map[string]bool{
	"GPL-2.0": true, "GPL-2.0-only": true, "GPL-2.0-or-later": true,
	"GPL-3.0": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true,
	"AGPL-3.0": true, "AGPL-3.0-only": true, "AGPL-3.0-or-later": true,
	"LGPL-2.1": true, "LGPL-2.1-only": true, "LGPL-2.1-or-later": true,
	"LGPL-3.0": true, "LGPL-3.0-only": true, "LGPL-3.0-or-later": true,
	"MPL-2.0": true, "SSPL-1.0": true,
}

func buildLicenseBreakdown(images []ImageSnapshot) []LicenseDataPoint {
	licMap := make(map[string]*LicenseDataPoint)
	for i, img := range images {
		for _, lic := range img.LicenseSummary {
			dp, ok := licMap[lic.License]
			if !ok {
				dp = &LicenseDataPoint{
					License:    lic.License,
					Counts:     make([]int, len(images)),
					IsCopyleft: copyleftLicenses[lic.License],
				}
				licMap[lic.License] = dp
			}
			dp.Counts[i] = lic.Count
		}
	}
	entries := make([]LicenseDataPoint, 0, len(licMap))
	for _, dp := range licMap {
		entries = append(entries, *dp)
	}
	sort.Slice(entries, func(i, j int) bool {
		// Copyleft first, then by total count descending
		if entries[i].IsCopyleft != entries[j].IsCopyleft {
			return entries[i].IsCopyleft
		}
		totalI, totalJ := 0, 0
		for _, c := range entries[i].Counts {
			totalI += c
		}
		for _, c := range entries[j].Counts {
			totalJ += c
		}
		return totalI > totalJ
	})
	if len(entries) > 30 {
		entries = entries[:30]
	}
	return entries
}

func estimateImageSize(cdxDoc []byte) int64 {
	if len(cdxDoc) == 0 {
		return 0
	}
	// Quick parse: look for "oci:image:layerSize" or "size" properties
	// This is a best-effort estimate from CycloneDX layer metadata
	var doc struct {
		Components []struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cdxDoc, &doc); err != nil {
		return 0
	}
	var totalSize int64
	for _, comp := range doc.Components {
		for _, prop := range comp.Properties {
			if strings.HasSuffix(prop.Name, ":size") || strings.HasSuffix(prop.Name, ":layerSize") {
				if size, err := strconv.ParseInt(prop.Value, 10, 64); err == nil {
					totalSize += size
				}
			}
		}
	}
	return totalSize
}

func computeMultiID(sboms []sbomindex.Record) string {
	parts := make([]string, len(sboms))
	for i, s := range sboms {
		parts[i] = s.OrgID + "/" + s.ImageID
	}
	sort.Strings(parts)
	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(hash[:16])
}

func packageSet(pkgs []sbomindex.PackageRecord) map[string]string {
	m := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		m[p.Name] = p.Version
	}
	return m
}

func vulnIDSet(vulns []vulnindex.VulnerabilityRecord) map[string]struct{} {
	m := make(map[string]struct{}, len(vulns))
	for _, v := range vulns {
		m[v.ID] = struct{}{}
	}
	return m
}

func cloneMapIntSafe(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	c := make(map[string]int, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func uniqueInts(s []int) []int {
	seen := make(map[int]struct{})
	result := make([]int, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
