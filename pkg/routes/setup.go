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
	"github.com/otterXf/otter/pkg/auth"
)

// Handlers holds all handler dependencies
type Handlers struct {
	ScanHandler *api.ScanHandler
	// Add more handlers here as you expand
	// UserHandler *api.UserHandler
	// OrgHandler  *api.OrgHandler
}

func SetupRoutes(router *gin.Engine, handlers *Handlers, authenticator *auth.Authenticator) {
	if authenticator == nil {
		authenticator = auth.NewDisabledAuthenticator()
	}

	router.Use(authenticator.Middleware())
	setupScanRoutes(router, handlers, authenticator)
	setupAWSRoutes(router, handlers, authenticator)
	setupFrontendRoutes(router, handlers, authenticator)
}
