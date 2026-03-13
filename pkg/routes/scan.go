package routes

import (
	"github.com/gin-gonic/gin"
)

func setupScanRoutes(router *gin.Engine, handlers *Handlers) {
	router.POST("/api/v1/scans", handlers.ScanHandler.GenerateScanSbomVul)
	router.GET("/api/v1/scans/:org_id/:image_id", handlers.ScanHandler.GetImageScans)
	router.DELETE("/api/v1/scans/:org_id/:image_id", handlers.ScanHandler.DeleteImageScansHandler)
	router.GET("/api/v1/scans/:org_id/:image_id/files/:filename", handlers.ScanHandler.DownloadScanFile)
	router.GET("/api/v1/images/:id/sbom", handlers.ScanHandler.GetImageSBOM)
	router.POST("/api/v1/images/:id/sbom", handlers.ScanHandler.ImportImageSBOM)
}
