package api

import (
	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/auth"
	"github.com/otterXf/otter/pkg/compare"
)

func authorizeOrgRequest(c *gin.Context, orgID string) bool {
	if err := auth.RequireOrgAccess(c, orgID); err != nil {
		auth.AbortWithError(c, err)
		return false
	}
	return true
}

func authorizeCatalogFilters(c *gin.Context, filters *catalogFilters) bool {
	if !auth.Enabled(c) {
		return true
	}
	if filters.OrgID != "" {
		return authorizeOrgRequest(c, filters.OrgID)
	}

	identity, ok := auth.IdentityFromContext(c)
	if !ok {
		auth.AbortWithError(c, auth.UnauthenticatedError(c))
		return false
	}
	if identity.Admin {
		return true
	}

	filters.AllowedOrgs = make(map[string]struct{}, len(identity.Orgs))
	for _, orgID := range identity.Orgs {
		filters.AllowedOrgs[orgID] = struct{}{}
	}
	return true
}

func authorizedOrgSet(c *gin.Context) map[string]struct{} {
	if !auth.Enabled(c) {
		return nil
	}

	identity, ok := auth.IdentityFromContext(c)
	if !ok || identity.Admin {
		return nil
	}

	allowed := make(map[string]struct{}, len(identity.Orgs))
	for _, orgID := range identity.Orgs {
		allowed[orgID] = struct{}{}
	}
	return allowed
}

func authorizeComparisonReport(c *gin.Context, report compare.Report) bool {
	if !authorizeOrgRequest(c, report.Image1.OrgID) {
		return false
	}
	if !authorizeOrgRequest(c, report.Image2.OrgID) {
		return false
	}
	return true
}
