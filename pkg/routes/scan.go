package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/auth"
)

func setupScanRoutes(router *gin.Engine, handlers *Handlers, authenticator *auth.Authenticator) {
	api := router.Group("/api/v1")
	api.Use(authenticator.RequireAuthentication())
	{
		api.POST("/scans", handlers.ScanHandler.GenerateScanSbomVul)
		api.GET("/scan-jobs/:id", handlers.ScanHandler.GetScanJob)
		api.GET("/scans/:org_id/:image_id", handlers.ScanHandler.GetImageScans)
		api.DELETE("/scans/:org_id/:image_id", handlers.ScanHandler.DeleteImageScansHandler)
		api.GET("/scans/:org_id/:image_id/files/:filename", handlers.ScanHandler.DownloadScanFile)
		api.GET("/compare", handlers.ScanHandler.CompareImages)
		api.POST("/comparisons", handlers.ScanHandler.CreateComparison)
		api.GET("/comparisons/:id", handlers.ScanHandler.GetStoredComparison)
		api.GET("/comparisons/:id/export", handlers.ScanHandler.ExportComparison)
		api.GET("/catalog", handlers.ScanHandler.ListCatalog)
		api.GET("/security-feed", handlers.ScanHandler.GetSecurityFeed)
		api.GET("/images/:id/overview", handlers.ScanHandler.GetImageOverview)
		api.GET("/images/:id/tags", handlers.ScanHandler.GetImageTags)
		api.GET("/images/:id/compliance", handlers.ScanHandler.GetImageCompliance)
		api.GET("/images/:id/export", handlers.ScanHandler.ExportImage)
		api.GET("/images/:id/sbom", handlers.ScanHandler.GetImageSBOM)
		api.POST("/images/:id/indexes/repair", handlers.ScanHandler.RepairImageIndexes)
		api.POST("/images/:id/sbom", handlers.ScanHandler.ImportImageSBOM)
		api.GET("/images/:id/vulnerabilities", handlers.ScanHandler.GetImageVulnerabilities)
		api.GET("/images/:id/attestations", handlers.ScanHandler.GetImageAttestations)
		api.POST("/images/:id/vex", handlers.ScanHandler.ImportImageVEX)
		api.POST("/images/:id/vulnerabilities/vex", handlers.ScanHandler.ImportImageVEX)
	}

	admin := api.Group("/")
	admin.Use(authenticator.RequireAdmin())
	{
		admin.GET("/registries", handlers.ScanHandler.ListRegistries)
		admin.POST("/registries", handlers.ScanHandler.ConfigureRegistry)
	}
}
