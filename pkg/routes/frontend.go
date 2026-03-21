package routes

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/auth"
)

func setupFrontendRoutes(router *gin.Engine, handlers *Handlers, authenticator *auth.Authenticator) {
	browse := router.Group("/")
	browse.Use(authenticator.RequireAuthentication())
	browse.GET("/browse", handlers.ScanHandler.BrowseCatalog)
	browse.GET("/browse/images/:org_id/:id", handlers.ScanHandler.BrowseImage)

	distDir := filepath.Join("frontend", "dist")
	indexPath := filepath.Join(distDir, "index.html")
	info, err := os.Stat(indexPath)
	if err != nil || info.IsDir() {
		router.GET("/", func(c *gin.Context) {
			c.Redirect(http.StatusTemporaryRedirect, "/browse")
		})
		router.GET("/images/:org_id/:id", func(c *gin.Context) {
			c.Redirect(http.StatusTemporaryRedirect, "/browse/images/"+c.Param("org_id")+"/"+c.Param("id"))
		})
		return
	}

	assetsDir := filepath.Join(distDir, "assets")
	if assetInfo, err := os.Stat(assetsDir); err == nil && assetInfo.IsDir() {
		router.StaticFS("/assets", gin.Dir(assetsDir, false))
	}

	serveIndex := func(c *gin.Context) {
		c.File(indexPath)
	}

	router.GET("/", serveIndex)
	router.GET("/images/:org_id/:id", serveIndex)

	router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		if c.Request.Method != http.MethodGet {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		accept := c.GetHeader("Accept")
		if accept != "" && !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.File(indexPath)
	})
}
