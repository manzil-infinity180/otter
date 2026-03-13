package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
)

const scanTimeout = 10 * time.Minute

type ImageGeneratePayload struct {
	Arch      string `json:"arch"`
	ImageName string `json:"image_name"`
	Registry  string `json:"registry"`
	OrgID     string `json:"org_id"`
	ImageID   string `json:"image_id"`
}

type ScanHandler struct {
	store storage.Store
}

func NewScanHandler(store storage.Store) *ScanHandler {
	return &ScanHandler{store: store}
}

func (h *ScanHandler) GenerateScanSbomVul(c *gin.Context) {
	var payload ImageGeneratePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateImageReference(payload.ImageName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	orgID, imageID, err := normalizeArtifactIDs(payload.OrgID, payload.ImageID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), scanTimeout)
	defer cancel()

	src, err := scan.GetSource(ctx, scan.ImageReference(payload.ImageName))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load image source: %v", err)})
		return
	}
	defer src.Close()

	sbomDocument, sbomData, err := scan.GenerateSBOMDocument(ctx, src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("generate sbom: %v", err)})
		return
	}

	vulnerabilityDocument, err := scan.GenerateVulnerabilityReport(sbomData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("generate vulnerabilities: %v", err)})
		return
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}
	sbomKey, err := keyBuilder.BuildSBOMKey()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	vulnerabilityKey, err := keyBuilder.BuildVulnerabilityKey()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var (
		sbomInfo ObjectResponse
		vulnInfo ObjectResponse
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		info, err := h.store.Put(groupCtx, sbomKey, sbomDocument, storage.PutOptions{
			ContentType: "application/vnd.cyclonedx+json",
			Metadata: map[string]string{
				"artifact":   "sbom",
				"image_name": payload.ImageName,
			},
		})
		if err != nil {
			return err
		}
		sbomInfo = toObjectResponse(info)
		return nil
	})
	group.Go(func() error {
		info, err := h.store.Put(groupCtx, vulnerabilityKey, vulnerabilityDocument, storage.PutOptions{
			ContentType: "application/json",
			Metadata: map[string]string{
				"artifact":   "vulnerabilities",
				"image_name": payload.ImageName,
			},
		})
		if err != nil {
			return err
		}
		vulnInfo = toObjectResponse(info)
		return nil
	})
	if err := group.Wait(); err != nil {
		_ = h.store.Delete(context.Background(), sbomKey)
		_ = h.store.Delete(context.Background(), vulnerabilityKey)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store scan artifacts: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "SBOM and vulnerabilities generated successfully",
		"org_id":          orgID,
		"image_id":        imageID,
		"image_name":      payload.ImageName,
		"storage_backend": h.store.Backend(),
		"files": gin.H{
			"sbom":            sbomInfo,
			"vulnerabilities": vulnInfo,
		},
	})
}

func (h *ScanHandler) GetImageScans(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Param("org_id"), c.Param("image_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	prefix, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildImagePrefix()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	objects, err := h.store.List(c.Request.Context(), prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("list scans: %v", err)})
		return
	}

	keys := make([]string, 0, len(objects))
	responses := make([]ObjectResponse, 0, len(objects))
	for _, object := range objects {
		keys = append(keys, object.Key)
		responses = append(responses, toObjectResponse(object))
	}

	c.JSON(http.StatusOK, gin.H{
		"org_id":          orgID,
		"image_id":        imageID,
		"storage_backend": h.store.Backend(),
		"files":           keys,
		"objects":         responses,
		"count":           len(keys),
	})
}

func (h *ScanHandler) DeleteImageScansHandler(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Param("org_id"), c.Param("image_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	prefix, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildImagePrefix()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	objects, err := h.store.List(c.Request.Context(), prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("list scans for delete: %v", err)})
		return
	}

	for _, object := range objects {
		if err := h.store.Delete(c.Request.Context(), object.Key); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("delete scan %s: %v", object.Key, err)})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "Scans deleted successfully",
		"org_id":          orgID,
		"image_id":        imageID,
		"storage_backend": h.store.Backend(),
		"deleted":         len(objects),
	})
}

func (h *ScanHandler) DownloadScanFile(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Param("org_id"), c.Param("image_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filename := c.Param("filename")
	if err := validateDownloadFilename(filename); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildKey(filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	object, err := h.store.Get(c.Request.Context(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan file not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("download scan file: %v", err)})
		return
	}

	contentType := object.Info.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Data(http.StatusOK, contentType, object.Data)
}

type ObjectResponse struct {
	Key         string            `json:"key"`
	Size        int64             `json:"size"`
	ContentType string            `json:"content_type"`
	CreatedAt   time.Time         `json:"created_at"`
	Backend     string            `json:"backend"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	DownloadURL string            `json:"download_url,omitempty"`
}

func toObjectResponse(info storage.ObjectInfo) ObjectResponse {
	return ObjectResponse{
		Key:         info.Key,
		Size:        info.Size,
		ContentType: info.ContentType,
		CreatedAt:   info.CreatedAt,
		Backend:     info.Backend,
		Metadata:    info.Metadata,
		DownloadURL: info.DownloadURL,
	}
}
