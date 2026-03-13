package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/registry"
)

func (h *ScanHandler) ConfigureRegistry(c *gin.Context) {
	var payload registry.ConfigureRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.registry.Configure(c.Request.Context(), payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("configure registry: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, result)
}

func (h *ScanHandler) ListRegistries(c *gin.Context) {
	items, err := h.registry.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("list registries: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"count":      len(items),
		"registries": items,
	})
}
