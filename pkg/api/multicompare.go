package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/multicompare"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/vulnindex"
)

// MultiCompare handles POST /api/v1/multi-compare
func (h *ScanHandler) MultiCompare(c *gin.Context) {
	var req multicompare.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Images) < 2 || len(req.Images) > 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide 2-3 images for comparison"})
		return
	}

	allowedOrgs := authorizedOrgSet(c)
	sboms := make([]sbomindex.Record, len(req.Images))
	vulns := make([]vulnindex.Record, len(req.Images))

	for i, img := range req.Images {
		img.Name = strings.TrimSpace(img.Name)
		if img.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("image %d: name is required", i+1)})
			return
		}
		orgID := strings.TrimSpace(img.OrgID)
		if orgID == "" {
			orgID = "default"
		}

		target, err := h.resolveComparisonTarget(c.Request.Context(), img.Name, orgID, allowedOrgs)
		if err != nil {
			if errors.Is(err, sbomindex.ErrNotFound) || errors.Is(err, vulnindex.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{
					"error":       fmt.Sprintf("image %d (%s) not found in catalog", i+1, img.Name),
					"remediation": "Scan the image first via POST /api/v1/scans before comparing.",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("image %d: %v", i+1, err)})
			return
		}

		sboms[i] = target.SBOM
		vulns[i] = target.Vulnerabilities
	}

	report, err := multicompare.BuildReport(multicompare.Inputs{
		SBOMs:           sboms,
		Vulnerabilities: vulns,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("build comparison: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"report":          report,
		"storage_backend": h.store.Backend(),
	})
}

// GetMultiComparePresets handles GET /api/v1/multi-compare/presets
func (h *ScanHandler) GetMultiComparePresets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"presets": multicompare.Presets(),
	})
}
