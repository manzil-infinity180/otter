//package routes
//
//import "github.com/gin-gonic/gin"
//
//func SetupRoutes(router *gin.Engine) {
//	setupScanRoutes(router)
//	setupAWSRoutes(router)
//}

package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/api"
)

// Handlers holds all handler dependencies
type Handlers struct {
	ScanHandler *api.ScanHandler
	// Add more handlers here as you expand
	// UserHandler *api.UserHandler
	// OrgHandler  *api.OrgHandler
}

func SetupRoutes(router *gin.Engine, handlers *Handlers) {
	setupScanRoutes(router, handlers)
	setupAWSRoutes(router, handlers)
}
