package routes

import "github.com/gin-gonic/gin"

func setupAWSRoutes(router *gin.Engine, handlers *Handlers) {
	aws := router.Group("/api/v1/aws")
	{
		aws.GET("/scans/:org_id/:image_id", handlers.ScanHandler.GetImageScans)
		aws.DELETE("/scans/:org_id/:image_id", handlers.ScanHandler.DeleteImageScansHandler)
		aws.GET("/scans/:org_id/:image_id/:filename", handlers.ScanHandler.DownloadScanFile)
	}
}
