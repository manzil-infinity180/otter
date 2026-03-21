package api

import (
	"context"
	"log"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/audit"
	"github.com/otterXf/otter/pkg/auth"
	"github.com/otterXf/otter/pkg/catalogscan"
)

const auditGlobalOrgID = "global"

type auditActor struct {
	ID   string
	Type string
}

func (h *ScanHandler) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		recorder = audit.NewNopRecorder()
	}
	h.auditor = recorder
}

func (h *ScanHandler) recordAuditEvent(ctx context.Context, event audit.Event) {
	if h == nil || h.auditor == nil {
		return
	}
	if err := h.auditor.Record(ctx, event); err != nil {
		log.Printf("record audit event %s: %v", event.Action, err)
	}
}

func auditActorFromContext(c *gin.Context) auditActor {
	if identity, ok := auth.IdentityFromContext(c); ok {
		return auditActor{ID: identity.Subject, Type: "user"}
	}
	if auth.Enabled(c) {
		return auditActor{ID: "unauthenticated", Type: "unknown"}
	}
	return auditActor{ID: "anonymous", Type: "anonymous"}
}

func auditActorFromRequest(req catalogscan.Request) auditActor {
	if actor := strings.TrimSpace(req.Actor); actor != "" {
		actorType := strings.TrimSpace(req.ActorType)
		if actorType == "" {
			actorType = "user"
		}
		return auditActor{ID: actor, Type: actorType}
	}
	if req.Trigger == catalogscan.TriggerScheduler {
		return auditActor{ID: "catalog-scheduler", Type: "system"}
	}
	return auditActor{ID: "catalog-worker", Type: "system"}
}

func imageAuditTarget(orgID, imageID string) string {
	return strings.TrimSpace(orgID) + "/" + strings.TrimSpace(imageID)
}
