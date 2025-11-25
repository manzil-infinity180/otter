package api

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/aws"
	"github.com/otterXf/otter/pkg/scan"
)

type ImageGeneratePayload struct {
	Arch      string `json:"arch"`
	ImageName string `json:"image_name"`
	Registry  string `json:"registry"`
	OrgID     string `json:"org_id"`   // Optional for now
	ImageID   string `json:"image_id"` // Optional for now
}

// ScanHandler handles scan-related HTTP requests
type ScanHandler struct {
	S3Client   aws.BucketBasics
	BucketName string
}

// NewScanHandler creates a new ScanHandler with dependencies
func NewScanHandler(s3Client aws.BucketBasics, bucketName string) *ScanHandler {
	return &ScanHandler{
		S3Client:   s3Client,
		BucketName: bucketName,
	}
}

// GenerateScanSbomVul generates SBOM and uploads to S3
func (h *ScanHandler) GenerateScanSbomVul(c *gin.Context) {
	var payload ImageGeneratePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use default org/image IDs if not provided
	orgID := payload.OrgID
	if orgID == "" {
		orgID = "default_org"
	}
	imageID := payload.ImageID
	if imageID == "" {
		imageID = "default_image"
	}

	// Get the source and generate SBOM
	src := scan.GetSource(scan.ImageReference(payload.ImageName))
	defer func() {
		if err := src.Close(); err != nil {
			log.Printf("failed to close source: %v", err)
		}
	}()

	sbom := scan.GetSBOM(src)
	cyclonedxFormatSbom, err := scan.ToCycloneDxSchema(sbom)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("failed to convert the sbom to cyclonedx-json format: %v", err),
		})
		return
	}

	// Create temporary file for SBOM
	filePath := "sbom.json"
	file, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Error creating file: %v", err),
		})
		return
	}

	// Copy SBOM content to file
	_, err = io.Copy(file, cyclonedxFormatSbom)
	if err != nil {
		file.Close()
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Error copying content: %v", err),
		})
		return
	}
	file.Close()

	// Upload to S3
	// S3 key structure: otterxf/<org_id>/<image_id>/sbom.json
	s3Key := fmt.Sprintf("otterxf/%s/%s/sbom.json", orgID, imageID)

	ctx := context.Background()
	err = h.S3Client.UploadFile(ctx, h.BucketName, s3Key, filePath)
	if err != nil {
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to upload to S3: %v", err),
		})
		return
	}

	// Clean up local file after successful upload
	err = os.Remove(filePath)
	if err != nil {
		log.Printf("Warning: failed to delete local file %s: %v", filePath, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "SBOM generated and uploaded successfully",
		"s3_key":     s3Key,
		"bucket":     h.BucketName,
		"org_id":     orgID,
		"image_id":   imageID,
		"image_name": payload.ImageName,
	})
}

// GetImageScans lists all scan files for a specific image
func (h *ScanHandler) GetImageScans(c *gin.Context) {
	orgID := c.Param("org_id")
	imageID := c.Param("image_id")

	if orgID == "" || imageID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "org_id and image_id are required",
		})
		return
	}

	ctx := context.Background()
	files, err := h.ListImageScans(ctx, orgID, imageID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to list scans: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"org_id":   orgID,
		"image_id": imageID,
		"files":    files,
		"count":    len(files),
	})
}

// DeleteImageScansHandler deletes all scan files for a specific image
func (h *ScanHandler) DeleteImageScansHandler(c *gin.Context) {
	orgID := c.Param("org_id")
	imageID := c.Param("image_id")

	if orgID == "" || imageID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "org_id and image_id are required",
		})
		return
	}

	ctx := context.Background()
	err := h.DeleteImageScans(ctx, orgID, imageID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to delete scans: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Scans deleted successfully",
		"org_id":   orgID,
		"image_id": imageID,
	})
}

// DownloadScanFile downloads a specific scan file from S3
func (h *ScanHandler) DownloadScanFile(c *gin.Context) {
	orgID := c.Param("org_id")
	imageID := c.Param("image_id")
	filename := c.Param("filename")

	if orgID == "" || imageID == "" || filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "org_id, image_id, and filename are required",
		})
		return
	}

	s3Key := fmt.Sprintf("otterxf/%s/%s/%s", orgID, imageID, filename)
	localFile := fmt.Sprintf("/tmp/%s", filename)

	ctx := context.Background()
	err := h.S3Client.DownloadFile(ctx, h.BucketName, s3Key, localFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to download file: %v", err),
		})
		return
	}
	defer os.Remove(localFile)

	c.File(localFile)
}
