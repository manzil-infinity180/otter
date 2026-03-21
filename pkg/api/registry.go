package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/audit"
	"github.com/otterXf/otter/pkg/registry"
)

func (h *ScanHandler) ConfigureRegistry(c *gin.Context) {
	var payload registry.ConfigureRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	action := "registry.configured"
	existing, err := h.registry.List(c.Request.Context())
	if err == nil {
		action = "registry.created"
		for _, item := range existing {
			if strings.EqualFold(item.Registry, strings.TrimSpace(payload.Registry)) {
				action = "registry.updated"
				break
			}
		}
	}

	result, err := h.registry.Configure(c.Request.Context(), payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("configure registry: %v", err)})
		return
	}

	actor := auditActorFromContext(c)
	h.recordAuditEvent(c.Request.Context(), audit.Event{
		Action:     action,
		Outcome:    "succeeded",
		Actor:      actor.ID,
		ActorType:  actor.Type,
		OrgID:      auditGlobalOrgID,
		Target:     result.Summary.Registry,
		TargetType: "registry",
		Metadata: map[string]any{
			"auth_mode":                result.Summary.AuthMode,
			"auth_source":              result.AuthSource,
			"has_credentials":          result.Summary.HasCredentials,
			"has_docker_config_path":   result.Summary.HasDockerConfigPath,
			"insecure_skip_tls_verify": result.Summary.InsecureSkipTLSVerify,
			"insecure_use_http":        result.Summary.InsecureUseHTTP,
			"registry_api":             result.RegistryAPI,
		},
	})
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
