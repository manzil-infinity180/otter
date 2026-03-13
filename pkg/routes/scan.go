package routes

import (
	"github.com/gin-gonic/gin"
)

func setupScanRoutes(router *gin.Engine, handlers *Handlers) {
	router.GET("/api/v1/registries", handlers.ScanHandler.ListRegistries)
	router.POST("/api/v1/registries", handlers.ScanHandler.ConfigureRegistry)
	router.POST("/api/v1/scans", handlers.ScanHandler.GenerateScanSbomVul)
	router.GET("/api/v1/scan-jobs/:id", handlers.ScanHandler.GetScanJob)
	router.GET("/api/v1/scans/:org_id/:image_id", handlers.ScanHandler.GetImageScans)
	router.DELETE("/api/v1/scans/:org_id/:image_id", handlers.ScanHandler.DeleteImageScansHandler)
	router.GET("/api/v1/scans/:org_id/:image_id/files/:filename", handlers.ScanHandler.DownloadScanFile)
	router.GET("/api/v1/compare", handlers.ScanHandler.CompareImages)
	router.GET("/api/v1/comparisons/:id", handlers.ScanHandler.GetStoredComparison)
	router.GET("/api/v1/comparisons/:id/export", handlers.ScanHandler.ExportComparison)
	router.GET("/api/v1/catalog", handlers.ScanHandler.ListCatalog)
	router.GET("/api/v1/images/:id/overview", handlers.ScanHandler.GetImageOverview)
	router.GET("/api/v1/images/:id/export", handlers.ScanHandler.ExportImage)
	router.GET("/api/v1/images/:id/sbom", handlers.ScanHandler.GetImageSBOM)
	router.POST("/api/v1/images/:id/sbom", handlers.ScanHandler.ImportImageSBOM)
	router.GET("/api/v1/images/:id/vulnerabilities", handlers.ScanHandler.GetImageVulnerabilities)
	router.GET("/api/v1/images/:id/attestations", handlers.ScanHandler.GetImageAttestations)
	router.POST("/api/v1/images/:id/vex", handlers.ScanHandler.ImportImageVEX)
	router.POST("/api/v1/images/:id/vulnerabilities/vex", handlers.ScanHandler.ImportImageVEX)
}
