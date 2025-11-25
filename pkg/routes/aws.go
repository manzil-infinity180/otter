package routes

import "github.com/gin-gonic/gin"

func setupAWSRoutes(router *gin.Engine, handlers *Handlers) {
	// S3/AWS related routes
	aws := router.Group("/api/v1/aws")
	{
		// List all scan files for an image
		aws.GET("/scans/:org_id/:image_id", handlers.ScanHandler.GetImageScans)

		// Delete all scan files for an image
		aws.DELETE("/scans/:org_id/:image_id", handlers.ScanHandler.DeleteImageScansHandler)

		// Download a specific scan file
		aws.GET("/scans/:org_id/:image_id/:filename", handlers.ScanHandler.DownloadScanFile)
	}
}
