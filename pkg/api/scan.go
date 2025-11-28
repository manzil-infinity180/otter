package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

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

// GenerateScanSbomVul generates SBOM, scans for vulnerabilities, and uploads both to S3
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

	// ==================== SBOM Generation ====================
	sbom := scan.GetSBOM(src)

	// Save SBOM to file
	sbomFilePath := "sbom.json"
	if err := scan.SaveSBOMToFile(sbom, sbomFilePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to save SBOM: %v", err),
		})
		return
	}
	defer os.Remove(sbomFilePath)

	// ==================== Vulnerability Scan ====================
	vulnFilePath, err := scan.GetAllVulnAndUpload(sbom)
	if err != nil {
		os.Remove(sbomFilePath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to generate vulnerabilities: %v", err),
		})
		return
	}

	// ==================== Upload Both Files to S3 ====================
	ctx := context.Background()

	// Upload SBOM
	sbomS3Key := fmt.Sprintf("otterxf/%s/%s/sbom.json", orgID, imageID)
	err = h.S3Client.UploadFile(ctx, h.BucketName, sbomS3Key, sbomFilePath)
	if err != nil {
		os.Remove(sbomFilePath)
		os.Remove(vulnFilePath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to upload SBOM to S3: %v", err),
		})
		return
	}

	// Upload Vulnerabilities
	vulnS3Key := fmt.Sprintf("otterxf/%s/%s/vulnerabilities.json", orgID, imageID)
	err = h.S3Client.UploadFile(ctx, h.BucketName, vulnS3Key, vulnFilePath)
	if err != nil {
		os.Remove(sbomFilePath)
		os.Remove(vulnFilePath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to upload vulnerabilities to S3: %v", err),
		})
		return
	}

	// ==================== Clean Up Local Files ====================
	if err := os.Remove(sbomFilePath); err != nil {
		log.Printf("Warning: failed to delete local SBOM file %s: %v", sbomFilePath, err)
	}
	if err := os.Remove(vulnFilePath); err != nil {
		log.Printf("Warning: failed to delete local vulnerability file %s: %v", vulnFilePath, err)
	}

	// ==================== Generate Presigned URLs (Optional) ====================
	sbomPresignedURL, _ := h.S3Client.GetPresignedURL(ctx, h.BucketName, sbomS3Key, time.Hour)
	vulnPresignedURL, _ := h.S3Client.GetPresignedURL(ctx, h.BucketName, vulnS3Key, time.Hour)

	c.JSON(http.StatusOK, gin.H{
		"message":    "SBOM and vulnerabilities generated and uploaded successfully",
		"org_id":     orgID,
		"image_id":   imageID,
		"image_name": payload.ImageName,
		"bucket":     h.BucketName,
		"files": gin.H{
			"sbom": gin.H{
				"s3_key":       sbomS3Key,
				"download_url": sbomPresignedURL,
			},
			"vulnerabilities": gin.H{
				"s3_key":       vulnS3Key,
				"download_url": vulnPresignedURL,
			},
		},
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
