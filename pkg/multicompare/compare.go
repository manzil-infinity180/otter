package multicompare

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
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
		report.Images[i] = buildSnapshot(inputs.SBOMs[i], inputs.Vulnerabilities[i], imageColors[i])
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
	report.Charts = buildChartData(report.Images, inputs.SBOMs)

	return report, nil
}

func buildSnapshot(sbom sbomindex.Record, vulns vulnindex.Record, color string) ImageSnapshot {
	snap := ImageSnapshot{
		OrgID:        sbom.OrgID,
		ImageID:      sbom.ImageID,
		ImageName:    sbom.ImageName,
		PackageCount: sbom.PackageCount,
		Color:        color,
		UpdatedAt:    sbom.UpdatedAt,
	}

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

func buildChartData(images []ImageSnapshot, sboms []sbomindex.Record) ChartData {
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

	return data
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
