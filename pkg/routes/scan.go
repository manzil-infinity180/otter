package routes

import (
	"github.com/gin-gonic/gin"
)

func setupScanRoutes(router *gin.Engine, handlers *Handlers) {
	router.GET("/test/scan", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})
	router.POST("/api/v1/scans", handlers.ScanHandler.GenerateScanSbomVul)
}
