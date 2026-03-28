package api

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/sbomindex"
)

type DashboardSummary struct {
	TotalImages          int                    `json:"total_images"`
	TotalVulnerabilities int                    `json:"total_vulnerabilities"`
	TotalPackages        int                    `json:"total_packages"`
	SeverityBreakdown    map[string]int         `json:"severity_breakdown"`
	TopVulnerableImages  []ImageExposure        `json:"top_vulnerable_images"`
	TopRiskyPackages     []PackageRisk          `json:"top_risky_packages"`
}

type ImageExposure struct {
	ImageID   string `json:"image_id"`
	ImageName string `json:"image_name"`
	Total     int    `json:"total_vulnerabilities"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
}

type PackageRisk struct {
	Name       string `json:"name"`
	ImageCount int    `json:"image_count"`
}

func (h *ScanHandler) GetDashboard(c *gin.Context) {
	orgID := c.Query("org_id")
	if orgID == "" {
		orgID = "default"
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	catalog, err := h.sbomIndex.QueryCatalog(c.Request.Context(), sbomindex.CatalogQuery{
		OrgID:    orgID,
		PageSize: 1000,
		Page:     1,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load catalog"})
		return
	}

	summary := DashboardSummary{
		SeverityBreakdown: make(map[string]int),
	}

	exposures := make([]ImageExposure, 0, len(catalog.Items))
	packageImageCount := make(map[string]int)

	for _, item := range catalog.Items {
		summary.TotalImages++
		summary.TotalPackages += item.PackageCount

		vulnTotal := item.VulnerabilitySummary.Total
		summary.TotalVulnerabilities += vulnTotal

		for sev, count := range item.VulnerabilitySummary.BySeverity {
			summary.SeverityBreakdown[sev] += count
		}

		exposure := ImageExposure{
			ImageID:   item.ImageID,
			ImageName: item.ImageName,
			Total:     vulnTotal,
			Critical:  item.VulnerabilitySummary.BySeverity["CRITICAL"],
			High:      item.VulnerabilitySummary.BySeverity["HIGH"],
		}
		exposures = append(exposures, exposure)

		// Count packages across images (use license summary as proxy for top packages)
		for _, lic := range item.LicenseSummary {
			packageImageCount[lic.License]++
		}
	}

	// Sort by total vulnerabilities descending
	sort.Slice(exposures, func(i, j int) bool {
		return exposures[i].Total > exposures[j].Total
	})
	if len(exposures) > 10 {
		exposures = exposures[:10]
	}
	summary.TopVulnerableImages = exposures

	// Top risky packages
	type pkgCount struct {
		name  string
		count int
	}
	pkgCounts := make([]pkgCount, 0, len(packageImageCount))
	for name, count := range packageImageCount {
		pkgCounts = append(pkgCounts, pkgCount{name, count})
	}
	sort.Slice(pkgCounts, func(i, j int) bool {
		return pkgCounts[i].count > pkgCounts[j].count
	})
	topPackages := make([]PackageRisk, 0, 10)
	for i := 0; i < len(pkgCounts) && i < 10; i++ {
		topPackages = append(topPackages, PackageRisk{
			Name:       pkgCounts[i].name,
			ImageCount: pkgCounts[i].count,
		})
	}
	summary.TopRiskyPackages = topPackages

	c.JSON(http.StatusOK, summary)
}
