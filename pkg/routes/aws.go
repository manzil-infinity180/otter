package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/auth"
)

func setupAWSRoutes(router *gin.Engine, handlers *Handlers, authenticator *auth.Authenticator) {
	aws := router.Group("/api/v1/aws")
	aws.Use(authenticator.RequireAuthentication())
	{
		aws.GET("/scans/:org_id/:image_id", handlers.ScanHandler.GetImageScans)
		aws.DELETE("/scans/:org_id/:image_id", handlers.ScanHandler.DeleteImageScansHandler)
		aws.GET("/scans/:org_id/:image_id/:filename", handlers.ScanHandler.DownloadScanFile)
	}
}
