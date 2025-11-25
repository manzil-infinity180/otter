package api

import (
	"context"
	"fmt"
	"log"
)

// S3KeyBuilder creates S3 keys following the pattern:
// otterxf/<org_id>/<image_id>/<filename>
type S3KeyBuilder struct {
	OrgID   string
	ImageID string
}

// BuildKey creates an S3 key for a given filename
func (b *S3KeyBuilder) BuildKey(filename string) string {
	return fmt.Sprintf("otterxf/%s/%s/%s", b.OrgID, b.ImageID, filename)
}

// BuildSBOMKey creates an S3 key for SBOM file
func (b *S3KeyBuilder) BuildSBOMKey() string {
	return b.BuildKey("sbom.json")
}

// BuildVulnerabilityKey creates an S3 key for vulnerability report
func (b *S3KeyBuilder) BuildVulnerabilityKey() string {
	return b.BuildKey("vulnerabilities.json")
}

// BuildProvenanceKey creates an S3 key for provenance file
func (b *S3KeyBuilder) BuildProvenanceKey() string {
	return b.BuildKey("provenance.json")
}

// EnsureBucketExists checks if bucket exists and creates it if it doesn't
func (h *ScanHandler) EnsureBucketExists(ctx context.Context, region string) error {
	exists, err := h.S3Client.BucketExists(ctx, h.BucketName)
	if err != nil {
		return fmt.Errorf("failed to check bucket existence: %w", err)
	}

	if !exists {
		log.Printf("Bucket %s does not exist, creating...", h.BucketName)
		err = h.S3Client.CreateBucket(ctx, h.BucketName, region)
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
		log.Printf("Bucket %s created successfully", h.BucketName)
	}

	return nil
}

// ListImageScans lists all scans for a specific image
func (h *ScanHandler) ListImageScans(ctx context.Context, orgID, imageID string) ([]string, error) {
	objects, err := h.S3Client.ListObjects(ctx, h.BucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects: %w", err)
	}

	prefix := fmt.Sprintf("otterxf/%s/%s/", orgID, imageID)
	var files []string
	for _, obj := range objects {
		if obj.Key != nil && len(*obj.Key) >= len(prefix) && (*obj.Key)[:len(prefix)] == prefix {
			files = append(files, *obj.Key)
		}
	}

	return files, nil
}

// DeleteImageScans deletes all scan files for a specific image
func (h *ScanHandler) DeleteImageScans(ctx context.Context, orgID, imageID string) error {
	files, err := h.ListImageScans(ctx, orgID, imageID)
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	if len(files) == 0 {
		return nil
	}

	err = h.S3Client.DeleteObjects(ctx, h.BucketName, files)
	if err != nil {
		return fmt.Errorf("failed to delete scans: %w", err)
	}

	return nil
}
