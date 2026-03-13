package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/otterXf/otter/pkg/compare"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

const (
	scanTimeout       = 10 * time.Minute
	maxSBOMUploadSize = 25 << 20
	maxVEXUploadSize  = 5 << 20
)

type ImageGeneratePayload struct {
	Arch      string `json:"arch"`
	ImageName string `json:"image_name"`
	Registry  string `json:"registry"`
	OrgID     string `json:"org_id"`
	ImageID   string `json:"image_id"`
}

type ScanHandler struct {
	store     storage.Store
	sbomIndex sbomindex.Repository
	vulnIndex vulnindex.Repository
	analyzer  scan.ImageAnalyzer
}

func NewScanHandler(store storage.Store, sbomIndex sbomindex.Repository, vulnIndex vulnindex.Repository, analyzer scan.ImageAnalyzer) *ScanHandler {
	return &ScanHandler{store: store, sbomIndex: sbomIndex, vulnIndex: vulnIndex, analyzer: analyzer}
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

	result, err := h.analyzer.Analyze(ctx, payload.ImageName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("analyze image: %v", err)})
		return
	}
	record, err := sbomindex.BuildRecordFromSyft(orgID, imageID, payload.ImageName, result.SBOMData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("index sbom: %v", err)})
		return
	}
	existingVulnerabilities, err := h.getExistingVulnerabilityRecord(ctx, orgID, imageID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load vulnerability history: %v", err)})
		return
	}
	vulnerabilityRecord, err := vulnindex.BuildRecordFromReport(orgID, imageID, payload.ImageName, result.CombinedReport, existingVulnerabilities, vulnindex.BuildOptions{TrackTrend: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("index vulnerabilities: %v", err)})
		return
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}
	sbomKey, err := keyBuilder.BuildSBOMKey()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cycloneDXKey, err := keyBuilder.BuildSBOMKeyForFormat(sbomindex.FormatCycloneDX)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	spdxKey, err := keyBuilder.BuildSBOMKeyForFormat(sbomindex.FormatSPDX)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	vulnerabilityKey, err := keyBuilder.BuildVulnerabilityKey()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	type artifactUpload struct {
		ResponseName string
		Key          string
		Data         []byte
		ContentType  string
		Metadata     map[string]string
	}

	uploads := []artifactUpload{
		{
			ResponseName: "sbom",
			Key:          sbomKey,
			Data:         result.SBOMDocument,
			ContentType:  "application/vnd.cyclonedx+json",
			Metadata: map[string]string{
				"artifact":   "sbom",
				"format":     sbomindex.FormatCycloneDX,
				"image_name": payload.ImageName,
			},
		},
		{
			ResponseName: "sbom_cyclonedx",
			Key:          cycloneDXKey,
			Data:         result.SBOMDocument,
			ContentType:  "application/vnd.cyclonedx+json",
			Metadata: map[string]string{
				"artifact":   "sbom",
				"format":     sbomindex.FormatCycloneDX,
				"image_name": payload.ImageName,
			},
		},
		{
			ResponseName: "sbom_spdx",
			Key:          spdxKey,
			Data:         result.SBOMSPDXDocument,
			ContentType:  "application/spdx+json",
			Metadata: map[string]string{
				"artifact":   "sbom",
				"format":     sbomindex.FormatSPDX,
				"image_name": payload.ImageName,
			},
		},
		{
			ResponseName: "vulnerabilities",
			Key:          vulnerabilityKey,
			Data:         result.CombinedVulnerabilities,
			ContentType:  "application/json",
			Metadata: map[string]string{
				"artifact":   "vulnerabilities",
				"scanner":    "combined",
				"image_name": payload.ImageName,
			},
		},
	}
	for _, report := range result.ScannerReports {
		key, err := keyBuilder.BuildScannerVulnerabilityKey(report.Scanner)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		uploads = append(uploads, artifactUpload{
			ResponseName: scannerResponseKey(report.Scanner),
			Key:          key,
			Data:         report.Document,
			ContentType:  report.ContentType,
			Metadata: map[string]string{
				"artifact":   "vulnerabilities",
				"scanner":    report.Scanner,
				"image_name": payload.ImageName,
			},
		})
	}

	storedFiles := make(gin.H, len(uploads))
	storedKeys := make([]string, 0, len(uploads))
	var mu sync.Mutex

	group, groupCtx := errgroup.WithContext(ctx)
	for _, upload := range uploads {
		upload := upload
		group.Go(func() error {
			info, err := h.store.Put(groupCtx, upload.Key, upload.Data, storage.PutOptions{
				ContentType: upload.ContentType,
				Metadata:    upload.Metadata,
			})
			if err != nil {
				return err
			}
			mu.Lock()
			storedKeys = append(storedKeys, upload.Key)
			storedFiles[upload.ResponseName] = toObjectResponse(info)
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		for _, key := range storedKeys {
			_ = h.store.Delete(context.Background(), key)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store scan artifacts: %v", err)})
		return
	}
	record, err = h.sbomIndex.Save(ctx, record)
	if err != nil {
		for _, key := range storedKeys {
			_ = h.store.Delete(context.Background(), key)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store sbom index: %v", err)})
		return
	}
	vulnerabilityRecord, err = h.vulnIndex.Save(ctx, vulnerabilityRecord)
	if err != nil {
		for _, key := range storedKeys {
			_ = h.store.Delete(context.Background(), key)
		}
		_ = h.sbomIndex.Delete(context.Background(), orgID, imageID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store vulnerability index: %v", err)})
		return
	}

	scanners := make([]string, 0, len(result.ScannerReports))
	for _, report := range result.ScannerReports {
		scanners = append(scanners, report.Scanner)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "SBOM and vulnerabilities generated successfully",
		"org_id":          orgID,
		"image_id":        imageID,
		"image_name":      payload.ImageName,
		"storage_backend": h.store.Backend(),
		"summary":         result.Summary,
		"sbom": gin.H{
			"source_format":    record.SourceFormat,
			"package_count":    record.PackageCount,
			"license_summary":  record.LicenseSummary,
			"dependency_roots": record.DependencyRoots,
			"dependency_tree":  record.DependencyTree,
		},
		"vulnerabilities": gin.H{
			"summary":             vulnerabilityRecord.Summary,
			"fix_recommendations": vulnerabilityRecord.FixRecommendations,
			"trend":               vulnerabilityRecord.Trend,
		},
		"scanners": scanners,
		"files":    storedFiles,
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
	if err := h.sbomIndex.Delete(c.Request.Context(), orgID, imageID); err != nil && !errors.Is(err, sbomindex.ErrNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("delete sbom index: %v", err)})
		return
	}
	if err := h.vulnIndex.Delete(c.Request.Context(), orgID, imageID); err != nil && !errors.Is(err, vulnindex.ErrNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("delete vulnerability index: %v", err)})
		return
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

func (h *ScanHandler) GetImageSBOM(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	format, err := sbomindex.NormalizeFormat(c.DefaultQuery("format", sbomindex.FormatCycloneDX))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}
	object, err := h.getSBOMArtifact(c.Request.Context(), keyBuilder, format)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "sbom document not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("get sbom document: %v", err)})
		return
	}

	record, err := h.getOrCreateSBOMRecord(c.Request.Context(), orgID, imageID, format, object.Data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load sbom index: %v", err)})
		return
	}

	if record.SourceFormat == "" {
		record.SourceFormat = format
	}

	c.JSON(http.StatusOK, gin.H{
		"org_id":           orgID,
		"image_id":         imageID,
		"image_name":       record.ImageName,
		"format":           format,
		"content_type":     object.Info.ContentType,
		"storage_backend":  h.store.Backend(),
		"package_count":    record.PackageCount,
		"packages":         record.Packages,
		"license_summary":  record.LicenseSummary,
		"dependency_roots": record.DependencyRoots,
		"dependency_tree":  record.DependencyTree,
		"document":         json.RawMessage(object.Data),
		"updated_at":       record.UpdatedAt,
	})
}

func (h *ScanHandler) ImportImageSBOM(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSBOMUploadSize)
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file upload is required"})
		return
	}
	defer file.Close()

	document, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("read uploaded sbom: %v", err)})
		return
	}
	if !json.Valid(document) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uploaded sbom must be valid JSON"})
		return
	}

	format := c.PostForm("format")
	if format == "" {
		format = c.Query("format")
	}
	if format == "" {
		format, err = sbomindex.DetectFormat(document)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	format, err = sbomindex.NormalizeFormat(format)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	imageName := strings.TrimSpace(c.PostForm("image_name"))
	record, err := sbomindex.BuildRecordFromDocument(orgID, imageID, imageName, format, document)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("parse sbom document: %v", err)})
		return
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}
	key, err := keyBuilder.BuildSBOMKeyForFormat(format)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	contentType := "application/vnd.cyclonedx+json"
	if format == sbomindex.FormatSPDX {
		contentType = "application/spdx+json"
	}

	objectInfo, err := h.store.Put(c.Request.Context(), key, document, storage.PutOptions{
		ContentType: contentType,
		Metadata: map[string]string{
			"artifact":   "sbom",
			"format":     format,
			"image_name": imageName,
			"source":     "import",
			"filename":   header.Filename,
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store sbom document: %v", err)})
		return
	}

	if format == sbomindex.FormatCycloneDX {
		legacyKey, err := keyBuilder.BuildSBOMKey()
		if err == nil {
			if _, err := h.store.Put(c.Request.Context(), legacyKey, document, storage.PutOptions{
				ContentType: contentType,
				Metadata: map[string]string{
					"artifact":   "sbom",
					"format":     format,
					"image_name": imageName,
					"source":     "import",
					"filename":   header.Filename,
				},
			}); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store legacy sbom document: %v", err)})
				return
			}
		}
	}

	record, err = h.sbomIndex.Save(c.Request.Context(), record)
	if err != nil {
		_ = h.store.Delete(context.Background(), key)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store sbom index: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":          "SBOM imported successfully",
		"org_id":           orgID,
		"image_id":         imageID,
		"format":           format,
		"package_count":    record.PackageCount,
		"license_summary":  record.LicenseSummary,
		"dependency_roots": record.DependencyRoots,
		"file":             toObjectResponse(objectInfo),
	})
}

func (h *ScanHandler) GetImageVulnerabilities(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	record, err := h.getOrCreateVulnerabilityRecord(c.Request.Context(), orgID, imageID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, vulnindex.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "vulnerability report not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load vulnerabilities: %v", err)})
		return
	}

	filtered, err := vulnindex.FilterRecord(record, vulnindex.FilterOptions{
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"org_id":              orgID,
		"image_id":            imageID,
		"image_name":          filtered.ImageName,
		"storage_backend":     h.store.Backend(),
		"summary":             filtered.Summary,
		"fix_recommendations": filtered.FixRecommendations,
		"vulnerabilities":     filtered.Vulnerabilities,
		"trend":               filtered.Trend,
		"vex_documents":       filtered.VEXDocuments,
		"updated_at":          filtered.UpdatedAt,
	}
	if c.Query("severity") != "" || c.Query("status") != "" {
		response["summary_all"] = record.Summary
	}

	c.JSON(http.StatusOK, response)
}

func (h *ScanHandler) CompareImages(c *gin.Context) {
	image1Ref := strings.TrimSpace(c.Query("image1"))
	image2Ref := strings.TrimSpace(c.Query("image2"))
	if image1Ref == "" || image2Ref == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "image1 and image2 are required"})
		return
	}

	target1, err := h.resolveComparisonTarget(c.Request.Context(), image1Ref, strings.TrimSpace(c.Query("org1")))
	if err != nil {
		h.renderComparisonLookupError(c, "image1", err)
		return
	}
	target2, err := h.resolveComparisonTarget(c.Request.Context(), image2Ref, strings.TrimSpace(c.Query("org2")))
	if err != nil {
		h.renderComparisonLookupError(c, "image2", err)
		return
	}

	report, err := compare.BuildReport(compare.Inputs{
		Image1:           target1.SBOM,
		Image2:           target2.SBOM,
		Vulnerabilities1: target1.Vulnerabilities,
		Vulnerabilities2: target2.Vulnerabilities,
		CycloneDX1:       target1.CycloneDXDocument,
		CycloneDX2:       target2.CycloneDXDocument,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("build comparison: %v", err)})
		return
	}

	document, err := compare.MarshalReport(report)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("marshal comparison: %v", err)})
		return
	}

	key, err := BuildComparisonKey(report.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("build comparison key: %v", err)})
		return
	}

	info, err := h.store.Put(c.Request.Context(), key, document, storage.PutOptions{
		ContentType: "application/json",
		Metadata: map[string]string{
			"artifact": "comparison",
			"image1":   target1.SBOM.ImageName,
			"image2":   target2.SBOM.ImageName,
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store comparison: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"comparison_id":   report.ID,
		"storage_backend": h.store.Backend(),
		"comparison_file": toObjectResponse(info),
		"comparison":      report,
	})
}

func (h *ScanHandler) GetStoredComparison(c *gin.Context) {
	comparisonID := strings.TrimSpace(c.Param("id"))
	key, err := BuildComparisonKey(comparisonID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	object, err := h.store.Get(c.Request.Context(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "comparison report not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load comparison report: %v", err)})
		return
	}

	var report compare.Report
	if err := json.Unmarshal(object.Data, &report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("decode comparison report: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"comparison_id":   comparisonID,
		"storage_backend": h.store.Backend(),
		"comparison_file": toObjectResponse(object.Info),
		"comparison":      report,
	})
}

func (h *ScanHandler) ImportImageVEX(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxVEXUploadSize)
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file upload is required"})
		return
	}
	defer file.Close()

	document, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("read uploaded VEX document: %v", err)})
		return
	}

	record, err := h.getExistingVulnerabilityRecord(c.Request.Context(), orgID, imageID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load vulnerability record: %v", err)})
		return
	}
	if record == nil {
		record = &vulnindex.Record{
			OrgID:     orgID,
			ImageID:   imageID,
			ImageName: strings.TrimSpace(c.PostForm("image_name")),
		}
	}

	importedAt := time.Now().UTC()
	updatedRecord, vexDocument, err := vulnindex.ApplyVEXDocument(*record, document, header.Filename, importedAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filename, err := buildVEXFilename(header, importedAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	key, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildVEXKey(filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	objectInfo, err := h.store.Put(c.Request.Context(), key, document, storage.PutOptions{
		ContentType: "application/vnd.openvex+json",
		Metadata: map[string]string{
			"artifact":    "vex",
			"document_id": vexDocument.DocumentID,
			"source":      "import",
			"filename":    header.Filename,
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store VEX document: %v", err)})
		return
	}

	updatedRecord, err = h.vulnIndex.Save(c.Request.Context(), updatedRecord)
	if err != nil {
		_ = h.store.Delete(context.Background(), key)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("store vulnerability advisories: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":             "VEX imported successfully",
		"org_id":              orgID,
		"image_id":            imageID,
		"summary":             updatedRecord.Summary,
		"fix_recommendations": updatedRecord.FixRecommendations,
		"vex_document":        vexDocument,
		"vulnerability_count": len(updatedRecord.Vulnerabilities),
		"file":                toObjectResponse(objectInfo),
		"updated_at":          updatedRecord.UpdatedAt,
	})
}

func (h *ScanHandler) getSBOMArtifact(ctx context.Context, keyBuilder ArtifactKeyBuilder, format string) (storage.Object, error) {
	key, err := keyBuilder.BuildSBOMKeyForFormat(format)
	if err != nil {
		return storage.Object{}, err
	}
	object, err := h.store.Get(ctx, key)
	if err == nil {
		return object, nil
	}
	if format == sbomindex.FormatCycloneDX && errors.Is(err, storage.ErrNotFound) {
		legacyKey, legacyErr := keyBuilder.BuildSBOMKey()
		if legacyErr != nil {
			return storage.Object{}, legacyErr
		}
		return h.store.Get(ctx, legacyKey)
	}
	return storage.Object{}, err
}

func (h *ScanHandler) getOrCreateSBOMRecord(ctx context.Context, orgID, imageID, format string, document []byte) (sbomindex.Record, error) {
	record, err := h.sbomIndex.Get(ctx, orgID, imageID)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, sbomindex.ErrNotFound) {
		return sbomindex.Record{}, err
	}

	record, err = sbomindex.BuildRecordFromDocument(orgID, imageID, "", format, document)
	if err != nil {
		return sbomindex.Record{}, err
	}
	return h.sbomIndex.Save(ctx, record)
}

func (h *ScanHandler) getOrCreateVulnerabilityRecord(ctx context.Context, orgID, imageID string) (vulnindex.Record, error) {
	record, err := h.vulnIndex.Get(ctx, orgID, imageID)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, vulnindex.ErrNotFound) {
		return vulnindex.Record{}, err
	}

	key, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildVulnerabilityKey()
	if err != nil {
		return vulnindex.Record{}, err
	}
	object, err := h.store.Get(ctx, key)
	if err != nil {
		return vulnindex.Record{}, err
	}

	record, err = vulnindex.BuildRecordFromDocument(orgID, imageID, "", object.Data, nil, vulnindex.BuildOptions{})
	if err != nil {
		return vulnindex.Record{}, err
	}
	return h.vulnIndex.Save(ctx, record)
}

func (h *ScanHandler) getExistingVulnerabilityRecord(ctx context.Context, orgID, imageID string) (*vulnindex.Record, error) {
	record, err := h.vulnIndex.Get(ctx, orgID, imageID)
	if err == nil {
		return &record, nil
	}
	if errors.Is(err, vulnindex.ErrNotFound) {
		return nil, nil
	}
	return nil, err
}

type comparisonTarget struct {
	SBOM              sbomindex.Record
	Vulnerabilities   vulnindex.Record
	CycloneDXDocument []byte
}

var errComparisonTargetAmbiguous = errors.New("comparison target is ambiguous")
var errComparisonTargetNotFound = errors.New("comparison target not found")

func (h *ScanHandler) resolveComparisonTarget(ctx context.Context, imageName, orgID string) (comparisonTarget, error) {
	if err := validateImageReference(imageName); err != nil {
		return comparisonTarget{}, err
	}
	if orgID != "" {
		if err := storage.ValidateSegment("org_id", orgID); err != nil {
			return comparisonTarget{}, err
		}
	}

	records, err := h.sbomIndex.FindByImageName(ctx, imageName)
	if err != nil {
		return comparisonTarget{}, err
	}

	filtered := make([]sbomindex.Record, 0, len(records))
	for _, record := range records {
		if orgID == "" || record.OrgID == orgID {
			filtered = append(filtered, record)
		}
	}
	if len(filtered) == 0 {
		return comparisonTarget{}, errComparisonTargetNotFound
	}
	if len(filtered) > 1 {
		return comparisonTarget{}, fmt.Errorf("%w: image %q found in multiple orgs", errComparisonTargetAmbiguous, imageName)
	}

	record := filtered[0]
	keyBuilder := ArtifactKeyBuilder{OrgID: record.OrgID, ImageID: record.ImageID}
	object, err := h.getSBOMArtifact(ctx, keyBuilder, sbomindex.FormatCycloneDX)
	if err != nil {
		return comparisonTarget{}, err
	}

	vulnerabilities, err := h.getOrCreateVulnerabilityRecord(ctx, record.OrgID, record.ImageID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, vulnindex.ErrNotFound) {
			vulnerabilities = vulnindex.Record{
				OrgID:     record.OrgID,
				ImageID:   record.ImageID,
				ImageName: record.ImageName,
				Summary: vulnindex.Summary{
					BySeverity: map[string]int{},
					ByScanner:  map[string]int{},
					ByStatus:   map[string]int{},
				},
			}
		} else {
			return comparisonTarget{}, err
		}
	}

	return comparisonTarget{
		SBOM:              record,
		Vulnerabilities:   vulnerabilities,
		CycloneDXDocument: object.Data,
	}, nil
}

func (h *ScanHandler) renderComparisonLookupError(c *gin.Context, field string, err error) {
	switch {
	case errors.Is(err, errComparisonTargetNotFound), errors.Is(err, storage.ErrNotFound), errors.Is(err, sbomindex.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("%s not found in stored scans", field)})
	case errors.Is(err, errComparisonTargetAmbiguous):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
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

func scannerResponseKey(scanner string) string {
	return strings.ReplaceAll(scanner, "-", "_") + "_vulnerabilities"
}

func buildVEXFilename(header *multipart.FileHeader, importedAt time.Time) (string, error) {
	extension := strings.ToLower(filepath.Ext(strings.TrimSpace(header.Filename)))
	if extension != ".json" {
		extension = ".json"
	}
	filename := fmt.Sprintf("vex-%d%s", importedAt.UTC().UnixNano(), extension)
	if err := validateDownloadFilename(filename); err != nil {
		return "", err
	}
	return filename, nil
}
