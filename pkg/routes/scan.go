package routes

import (
	"github.com/gin-gonic/gin"
)

func setupScanRoutes(router *gin.Engine, handlers *Handlers) {
	router.POST("/api/v1/scans", handlers.ScanHandler.GenerateScanSbomVul)
}
