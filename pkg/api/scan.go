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

	"github.com/otterXf/otter/pkg/attestation"
	"github.com/otterXf/otter/pkg/audit"
	"github.com/otterXf/otter/pkg/catalogscan"
	"github.com/otterXf/otter/pkg/compare"
	"github.com/otterXf/otter/pkg/compliance"
	"github.com/otterXf/otter/pkg/registry"
	reportexport "github.com/otterXf/otter/pkg/reportexport"
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
	Platform  string `json:"platform"`
	ImageName string `json:"image_name"`
	Registry  string `json:"registry"`
	OrgID     string `json:"org_id"`
	ImageID   string `json:"image_id"`
	Async     bool   `json:"async"`
}

type ComparisonPayload struct {
	Image1 string `json:"image1"`
	Image2 string `json:"image2"`
	Org1   string `json:"org1"`
	Org2   string `json:"org2"`
}

type ScanHandler struct {
	store      storage.Store
	sbomIndex  sbomindex.Repository
	vulnIndex  vulnindex.Repository
	analyzer   scan.ImageAnalyzer
	attestor   attestation.Fetcher
	compliance compliance.Assessor
	registry   registry.Service
	jobs       scanJobQueue
	auditor    audit.Recorder
}

type scanJobQueue interface {
	Enqueue(catalogscan.Request) (catalogscan.Job, error)
	Get(string) (catalogscan.Job, bool)
}

type ScanSBOMSummary struct {
	SourceFormat    string                          `json:"source_format"`
	PackageCount    int                             `json:"package_count"`
	LicenseSummary  []sbomindex.LicenseSummaryEntry `json:"license_summary,omitempty"`
	DependencyRoots []string                        `json:"dependency_roots,omitempty"`
	DependencyTree  []sbomindex.DependencyNode      `json:"dependency_tree,omitempty"`
}

type ScanVulnerabilitySummary struct {
	Summary            vulnindex.Summary             `json:"summary"`
	FixRecommendations []vulnindex.FixRecommendation `json:"fix_recommendations,omitempty"`
	Trend              []vulnindex.TrendPoint        `json:"trend,omitempty"`
}

type ScanExecutionResult struct {
	Message         string                    `json:"message"`
	OrgID           string                    `json:"org_id"`
	ImageID         string                    `json:"image_id"`
	ImageName       string                    `json:"image_name"`
	Registry        string                    `json:"registry"`
	Platform        string                    `json:"platform,omitempty"`
	RegistryAuth    string                    `json:"registry_auth"`
	StorageBackend  string                    `json:"storage_backend"`
	Summary         scan.VulnerabilitySummary `json:"summary"`
	SBOM            ScanSBOMSummary           `json:"sbom"`
	Vulnerabilities ScanVulnerabilitySummary  `json:"vulnerabilities"`
	Scanners        []string                  `json:"scanners,omitempty"`
	Files           map[string]ObjectResponse `json:"files,omitempty"`
}

func NewScanHandler(store storage.Store, sbomIndex sbomindex.Repository, vulnIndex vulnindex.Repository, analyzer scan.ImageAnalyzer) *ScanHandler {
	return NewScanHandlerWithRegistry(store, sbomIndex, vulnIndex, analyzer, registry.NewManager(registry.NewMemoryRepository(), registry.Config{}))
}

func NewScanHandlerWithRegistry(store storage.Store, sbomIndex sbomindex.Repository, vulnIndex vulnindex.Repository, analyzer scan.ImageAnalyzer, registryService registry.Service) *ScanHandler {
	if registryService == nil {
		registryService = registry.NewManager(registry.NewMemoryRepository(), registry.Config{})
	}
	return &ScanHandler{
		store:      store,
		sbomIndex:  sbomIndex,
		vulnIndex:  vulnIndex,
		analyzer:   analyzer,
		attestor:   attestation.NewDiscoverer(attestation.ConfigFromEnv()),
		compliance: compliance.NewService(compliance.ConfigFromEnv()),
		registry:   registryService,
		auditor:    audit.NewNopRecorder(),
	}
}

func (h *ScanHandler) SetJobQueue(queue scanJobQueue) {
	h.jobs = queue
}

func (h *ScanHandler) GenerateScanSbomVul(c *gin.Context) {
	var payload ImageGeneratePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	orgID, imageID, err := normalizeArtifactIDs(payload.OrgID, payload.ImageID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}
	payload.OrgID = orgID
	payload.ImageID = imageID
	requestedPlatform, err := normalizeRequestedPlatform(payload.Arch, payload.Platform)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	payload.Platform = platformString(requestedPlatform)
	actor := auditActorFromContext(c)

	if payload.Async || strings.EqualFold(c.Query("async"), "true") {
		request, err := catalogscan.NewRequest(payload.OrgID, payload.ImageID, payload.ImageName, payload.Registry, catalogscan.SourceAPI, catalogscan.TriggerManual)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		request.Platform = payload.Platform
		request.Actor = actor.ID
		request.ActorType = actor.Type
		if h.jobs == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan job queue is not configured"})
			return
		}
		job, err := h.jobs.Enqueue(request)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, catalogscan.ErrQueueFull) {
				status = http.StatusTooManyRequests
			}
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}
		h.recordAuditEvent(c.Request.Context(), audit.Event{
			Action:     "scan.enqueued",
			Outcome:    "queued",
			Actor:      actor.ID,
			ActorType:  actor.Type,
			OrgID:      request.OrgID,
			Target:     imageAuditTarget(request.OrgID, request.ImageID),
			TargetType: "image",
			Metadata: map[string]any{
				"image_name": request.ImageName,
				"registry":   request.Registry,
				"job_id":     job.ID,
				"mode":       "async",
				"platform":   request.Platform,
				"source":     request.Source,
				"trigger":    request.Trigger,
			},
		})
		c.JSON(http.StatusAccepted, gin.H{
			"message":    "scan queued successfully",
			"job":        job,
			"status_url": "/api/v1/scan-jobs/" + job.ID,
		})
		return
	}

	result, err := h.executeScan(c.Request.Context(), payload)
	if err != nil {
		h.recordAuditEvent(c.Request.Context(), audit.Event{
			Action:     "scan.completed",
			Outcome:    "failed",
			Actor:      actor.ID,
			ActorType:  actor.Type,
			OrgID:      payload.OrgID,
			Target:     imageAuditTarget(payload.OrgID, payload.ImageID),
			TargetType: "image",
			Error:      err.Error(),
			Metadata: map[string]any{
				"image_name": payload.ImageName,
				"registry":   payload.Registry,
				"mode":       "sync",
				"platform":   payload.Platform,
				"source":     catalogscan.SourceAPI,
				"trigger":    catalogscan.TriggerManual,
			},
		})
		h.renderScanExecutionError(c, err)
		return
	}
	h.recordAuditEvent(c.Request.Context(), audit.Event{
		Action:     "scan.completed",
		Outcome:    "succeeded",
		Actor:      actor.ID,
		ActorType:  actor.Type,
		OrgID:      result.OrgID,
		Target:     imageAuditTarget(result.OrgID, result.ImageID),
		TargetType: "image",
		Metadata: map[string]any{
			"image_name":      result.ImageName,
			"registry":        result.Registry,
			"registry_auth":   result.RegistryAuth,
			"storage_backend": result.StorageBackend,
			"summary_total":   result.Summary.Total,
			"scanners":        append([]string(nil), result.Scanners...),
			"mode":            "sync",
			"platform":        result.Platform,
			"source":          catalogscan.SourceAPI,
			"trigger":         catalogscan.TriggerManual,
		},
	})
	c.JSON(http.StatusOK, result)
}

func (h *ScanHandler) GetScanJob(c *gin.Context) {
	if h.jobs == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "scan job queue is not configured"})
		return
	}

	jobID := strings.TrimSpace(c.Param("id"))
	if jobID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan job id is required"})
		return
	}

	job, ok := h.jobs.Get(jobID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan job not found"})
		return
	}
	if !authorizeOrgRequest(c, job.Request.OrgID) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"job":             job,
		"storage_backend": h.store.Backend(),
	})
}

func (h *ScanHandler) ExecuteCatalogScan(ctx context.Context, req catalogscan.Request) (catalogscan.Result, error) {
	actor := auditActorFromRequest(req)
	result, err := h.executeScan(ctx, ImageGeneratePayload{
		ImageName: req.ImageName,
		Registry:  req.Registry,
		OrgID:     req.OrgID,
		ImageID:   req.ImageID,
		Platform:  req.Platform,
	})
	if err != nil {
		h.recordAuditEvent(ctx, audit.Event{
			Action:     "scan.completed",
			Outcome:    "failed",
			Actor:      actor.ID,
			ActorType:  actor.Type,
			OrgID:      req.OrgID,
			Target:     imageAuditTarget(req.OrgID, req.ImageID),
			TargetType: "image",
			Error:      err.Error(),
			Metadata: map[string]any{
				"image_name": req.ImageName,
				"registry":   req.Registry,
				"mode":       "async",
				"platform":   req.Platform,
				"source":     req.Source,
				"trigger":    req.Trigger,
			},
		})
		return catalogscan.Result{}, err
	}

	catalogResult := catalogscan.Result{
		OrgID:       result.OrgID,
		ImageID:     result.ImageID,
		ImageName:   result.ImageName,
		Registry:    result.Registry,
		Platform:    result.Platform,
		Scanners:    append([]string(nil), result.Scanners...),
		Summary:     result.Summary,
		CompletedAt: time.Now().UTC(),
	}
	h.recordAuditEvent(ctx, audit.Event{
		Action:     "scan.completed",
		Outcome:    "succeeded",
		Actor:      actor.ID,
		ActorType:  actor.Type,
		OrgID:      catalogResult.OrgID,
		Target:     imageAuditTarget(catalogResult.OrgID, catalogResult.ImageID),
		TargetType: "image",
		Metadata: map[string]any{
			"image_name":      catalogResult.ImageName,
			"registry":        catalogResult.Registry,
			"summary_total":   catalogResult.Summary.Total,
			"scanners":        append([]string(nil), catalogResult.Scanners...),
			"mode":            "async",
			"platform":        catalogResult.Platform,
			"source":          req.Source,
			"trigger":         req.Trigger,
			"storage_backend": h.store.Backend(),
		},
	})

	return catalogResult, nil
}

func (h *ScanHandler) executeScan(ctx context.Context, payload ImageGeneratePayload) (ScanExecutionResult, error) {
	if err := validateImageReference(payload.ImageName); err != nil {
		return ScanExecutionResult{}, err
	}
	if err := validateRequestedRegistry(payload.ImageName, payload.Registry); err != nil {
		return ScanExecutionResult{}, err
	}

	orgID, imageID, err := normalizeArtifactIDs(payload.OrgID, payload.ImageID)
	if err != nil {
		return ScanExecutionResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	requestedPlatform, err := normalizeRequestedPlatform(payload.Arch, payload.Platform)
	if err != nil {
		return ScanExecutionResult{}, err
	}

	imageAccess, err := h.registry.PrepareImage(ctx, payload.ImageName)
	if err != nil {
		return ScanExecutionResult{}, fmt.Errorf("prepare image pull: %w", err)
	}
	ctx = scan.ContextWithRegistryOptions(ctx, imageAccess.RegistryOptions)
	ctx = scan.ContextWithPlatform(ctx, requestedPlatform)

	result, err := h.analyzer.Analyze(ctx, payload.ImageName)
	if err != nil {
		return ScanExecutionResult{}, fmt.Errorf("analyze image: %w", err)
	}
	resolvedPlatform := resolvedPlatformFromSBOM(result.SBOMData)
	if resolvedPlatform == "" {
		resolvedPlatform = platformString(requestedPlatform)
	}
	record, err := sbomindex.BuildRecordFromSyft(orgID, imageID, payload.ImageName, result.SBOMData)
	if err != nil {
		return ScanExecutionResult{}, fmt.Errorf("index sbom: %w", err)
	}
	record.Platform = resolvedPlatform
	existingVulnerabilities, err := h.getExistingVulnerabilityRecord(ctx, orgID, imageID)
	if err != nil {
		return ScanExecutionResult{}, fmt.Errorf("load vulnerability history: %w", err)
	}
	vulnerabilityRecord, err := vulnindex.BuildRecordFromReport(orgID, imageID, payload.ImageName, result.CombinedReport, existingVulnerabilities, vulnindex.BuildOptions{TrackTrend: true})
	if err != nil {
		return ScanExecutionResult{}, fmt.Errorf("index vulnerabilities: %w", err)
	}
	vulnerabilityRecord.Platform = resolvedPlatform

	keyBuilder := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}
	sbomKey, err := keyBuilder.BuildSBOMKey()
	if err != nil {
		return ScanExecutionResult{}, err
	}
	cycloneDXKey, err := keyBuilder.BuildSBOMKeyForFormat(sbomindex.FormatCycloneDX)
	if err != nil {
		return ScanExecutionResult{}, err
	}
	spdxKey, err := keyBuilder.BuildSBOMKeyForFormat(sbomindex.FormatSPDX)
	if err != nil {
		return ScanExecutionResult{}, err
	}
	vulnerabilityKey, err := keyBuilder.BuildVulnerabilityKey()
	if err != nil {
		return ScanExecutionResult{}, err
	}

	type artifactUpload struct {
		ResponseName string
		Key          string
		Data         []byte
		ContentType  string
		Metadata     map[string]string
	}

	artifactMetadata := func(values map[string]string) map[string]string {
		metadata := make(map[string]string, len(values)+1)
		for key, value := range values {
			metadata[key] = value
		}
		if resolvedPlatform != "" {
			metadata["platform"] = resolvedPlatform
		}
		return metadata
	}

	uploads := []artifactUpload{
		{
			ResponseName: "sbom",
			Key:          sbomKey,
			Data:         result.SBOMDocument,
			ContentType:  "application/vnd.cyclonedx+json",
			Metadata: artifactMetadata(map[string]string{
				"artifact":   "sbom",
				"format":     sbomindex.FormatCycloneDX,
				"image_name": payload.ImageName,
			}),
		},
		{
			ResponseName: "sbom_cyclonedx",
			Key:          cycloneDXKey,
			Data:         result.SBOMDocument,
			ContentType:  "application/vnd.cyclonedx+json",
			Metadata: artifactMetadata(map[string]string{
				"artifact":   "sbom",
				"format":     sbomindex.FormatCycloneDX,
				"image_name": payload.ImageName,
			}),
		},
		{
			ResponseName: "sbom_spdx",
			Key:          spdxKey,
			Data:         result.SBOMSPDXDocument,
			ContentType:  "application/spdx+json",
			Metadata: artifactMetadata(map[string]string{
				"artifact":   "sbom",
				"format":     sbomindex.FormatSPDX,
				"image_name": payload.ImageName,
			}),
		},
		{
			ResponseName: "vulnerabilities",
			Key:          vulnerabilityKey,
			Data:         result.CombinedVulnerabilities,
			ContentType:  "application/json",
			Metadata: artifactMetadata(map[string]string{
				"artifact":   "vulnerabilities",
				"scanner":    "combined",
				"image_name": payload.ImageName,
			}),
		},
	}
	for _, report := range result.ScannerReports {
		key, err := keyBuilder.BuildScannerVulnerabilityKey(report.Scanner)
		if err != nil {
			return ScanExecutionResult{}, err
		}
		uploads = append(uploads, artifactUpload{
			ResponseName: scannerResponseKey(report.Scanner),
			Key:          key,
			Data:         report.Document,
			ContentType:  report.ContentType,
			Metadata: artifactMetadata(map[string]string{
				"artifact":   "vulnerabilities",
				"scanner":    report.Scanner,
				"image_name": payload.ImageName,
			}),
		})
	}

	storedFiles := make(map[string]ObjectResponse, len(uploads))
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
		return ScanExecutionResult{}, fmt.Errorf("store scan artifacts: %w", err)
	}
	record, err = h.sbomIndex.Save(ctx, record)
	if err != nil {
		for _, key := range storedKeys {
			_ = h.store.Delete(context.Background(), key)
		}
		return ScanExecutionResult{}, fmt.Errorf("store sbom index: %w", err)
	}
	vulnerabilityRecord, err = h.vulnIndex.Save(ctx, vulnerabilityRecord)
	if err != nil {
		for _, key := range storedKeys {
			_ = h.store.Delete(context.Background(), key)
		}
		_ = h.sbomIndex.Delete(context.Background(), orgID, imageID)
		return ScanExecutionResult{}, fmt.Errorf("store vulnerability index: %w", err)
	}

	scanners := make([]string, 0, len(result.ScannerReports))
	for _, report := range result.ScannerReports {
		scanners = append(scanners, report.Scanner)
	}

	return ScanExecutionResult{
		Message:        "SBOM and vulnerabilities generated successfully",
		OrgID:          orgID,
		ImageID:        imageID,
		ImageName:      payload.ImageName,
		Registry:       imageAccess.Registry,
		Platform:       resolvedPlatform,
		RegistryAuth:   imageAccess.AuthSource,
		StorageBackend: h.store.Backend(),
		Summary:        result.Summary,
		SBOM: ScanSBOMSummary{
			SourceFormat:    record.SourceFormat,
			PackageCount:    record.PackageCount,
			LicenseSummary:  record.LicenseSummary,
			DependencyRoots: record.DependencyRoots,
			DependencyTree:  record.DependencyTree,
		},
		Vulnerabilities: ScanVulnerabilitySummary{
			Summary:            vulnerabilityRecord.Summary,
			FixRecommendations: vulnerabilityRecord.FixRecommendations,
			Trend:              vulnerabilityRecord.Trend,
		},
		Scanners: scanners,
		Files:    storedFiles,
	}, nil
}

func (h *ScanHandler) renderScanExecutionError(c *gin.Context, err error) {
	var policyErr *registry.PolicyError
	switch {
	case errors.As(err, &policyErr):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, context.DeadlineExceeded):
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
	case strings.Contains(err.Error(), "prepare image pull:"):
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
	case strings.Contains(err.Error(), "invalid image_name"), strings.Contains(err.Error(), "invalid org_id"), strings.Contains(err.Error(), "invalid image_id"), strings.Contains(err.Error(), "registry "):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

func (h *ScanHandler) GetImageScans(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Param("org_id"), c.Param("image_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
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
	if !authorizeOrgRequest(c, orgID) {
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

	actor := auditActorFromContext(c)
	h.recordAuditEvent(c.Request.Context(), audit.Event{
		Action:     "scan.deleted",
		Outcome:    "succeeded",
		Actor:      actor.ID,
		ActorType:  actor.Type,
		OrgID:      orgID,
		Target:     imageAuditTarget(orgID, imageID),
		TargetType: "image",
		Metadata: map[string]any{
			"deleted_objects": len(objects),
			"storage_backend": h.store.Backend(),
		},
	})
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
	if !authorizeOrgRequest(c, orgID) {
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

	writeAttachment(c, filename, contentType, object.Data)
}

func (h *ScanHandler) ExportImage(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	format, err := normalizeImageExportFormat(c.Query("format"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	switch format {
	case sbomindex.FormatCycloneDX, sbomindex.FormatSPDX:
		keyBuilder := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}
		object, err := h.getSBOMArtifact(c.Request.Context(), keyBuilder, format)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "sbom document not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("get sbom export: %v", err)})
			return
		}

		filename, err := buildImageExportFilename(orgID, imageID, "sbom", format)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		contentType := object.Info.ContentType
		if contentType == "" {
			contentType = "application/json"
		}
		writeAttachment(c, filename, contentType, object.Data)
		return
	case reportexport.FormatCSV, reportexport.FormatJSON, reportexport.FormatSARIF:
		record, err := h.getOrBuildVulnerabilityRecord(c.Request.Context(), orgID, imageID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, vulnindex.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "vulnerability report not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load vulnerability export: %v", err)})
			return
		}

		var (
			document    []byte
			contentType string
		)
		switch format {
		case reportexport.FormatCSV:
			document, err = reportexport.MarshalVulnerabilitiesCSV(record)
			contentType = "text/csv; charset=utf-8"
		case reportexport.FormatSARIF:
			document, err = reportexport.MarshalVulnerabilitiesSARIF(record)
			contentType = "application/sarif+json"
		default:
			document, err = reportexport.MarshalVulnerabilitiesJSON(record)
			contentType = "application/json"
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("build %s export: %v", format, err)})
			return
		}

		filename, err := buildImageExportFilename(orgID, imageID, "vulnerabilities", format)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		writeAttachment(c, filename, contentType, document)
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported export format %q", format)})
	}
}

func (h *ScanHandler) ExportComparison(c *gin.Context) {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load comparison export: %v", err)})
		return
	}
	var report compare.Report
	if err := json.Unmarshal(object.Data, &report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("decode comparison report: %v", err)})
		return
	}
	if !authorizeComparisonReport(c, report) {
		return
	}

	filename, err := buildComparisonExportFilename(comparisonID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	contentType := object.Info.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	writeAttachment(c, filename, contentType, object.Data)
}

func (h *ScanHandler) GetImageSBOM(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
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

	record, err := h.getOrBuildSBOMRecord(c.Request.Context(), orgID, imageID, format, object)
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

func (h *ScanHandler) RepairImageIndexes(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	sbomRecord, sbomStatus, err := h.repairSBOMIndex(c.Request.Context(), orgID, imageID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, sbomindex.ErrNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("repair sbom index: %v", err)})
		return
	}

	vulnerabilityRecord, vulnerabilityStatus, err := h.repairVulnerabilityIndex(c.Request.Context(), orgID, imageID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, vulnindex.ErrNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("repair vulnerability index: %v", err)})
		return
	}

	if sbomStatus == "missing" && vulnerabilityStatus == "missing" {
		c.JSON(http.StatusNotFound, gin.H{"error": "stored indexes could not be repaired from existing artifacts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "image indexes repaired",
		"org_id":          orgID,
		"image_id":        imageID,
		"storage_backend": h.store.Backend(),
		"sbom_index": gin.H{
			"status":        sbomStatus,
			"source_format": sbomRecord.SourceFormat,
			"package_count": sbomRecord.PackageCount,
			"updated_at":    sbomRecord.UpdatedAt,
		},
		"vulnerability_index": gin.H{
			"status":              vulnerabilityStatus,
			"vulnerability_count": len(vulnerabilityRecord.Vulnerabilities),
			"updated_at":          vulnerabilityRecord.UpdatedAt,
		},
	})
}

func (h *ScanHandler) ImportImageSBOM(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSBOMUploadSize)
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file upload is required"})
		return
	}
	defer file.Close() //nolint:errcheck // request file cleanup

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

	actor := auditActorFromContext(c)
	h.recordAuditEvent(c.Request.Context(), audit.Event{
		Action:     "sbom.imported",
		Outcome:    "succeeded",
		Actor:      actor.ID,
		ActorType:  actor.Type,
		OrgID:      orgID,
		Target:     imageAuditTarget(orgID, imageID),
		TargetType: "image",
		Metadata: map[string]any{
			"format":           format,
			"filename":         header.Filename,
			"image_name":       imageName,
			"package_count":    record.PackageCount,
			"storage_backend":  h.store.Backend(),
			"dependency_roots": append([]string(nil), record.DependencyRoots...),
		},
	})
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
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	record, err := h.getOrBuildVulnerabilityRecord(c.Request.Context(), orgID, imageID)
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

func (h *ScanHandler) GetImageAttestations(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	imageRef, err := h.resolveStoredImageReference(c.Request.Context(), orgID, imageID)
	if err != nil {
		if errors.Is(err, sbomindex.ErrNotFound) || errors.Is(err, vulnindex.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "stored image reference not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("resolve image reference: %v", err)})
		return
	}

	result, err := h.attestor.Discover(c.Request.Context(), imageRef)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("discover attestations: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"org_id":          orgID,
		"image_id":        imageID,
		"image_name":      imageRef,
		"storage_backend": h.store.Backend(),
		"image_digest":    result.ImageDigest,
		"canonical_ref":   result.CanonicalRef,
		"summary":         result.Summary,
		"signatures":      result.Signatures,
		"attestations":    result.Attestations,
		"updated_at":      result.UpdatedAt,
	})
}

func (h *ScanHandler) CompareImages(c *gin.Context) {
	payload := ComparisonPayload{
		Image1: strings.TrimSpace(c.Query("image1")),
		Image2: strings.TrimSpace(c.Query("image2")),
		Org1:   strings.TrimSpace(c.Query("org1")),
		Org2:   strings.TrimSpace(c.Query("org2")),
	}

	if err := h.respondComparison(c, payload, false); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}

func (h *ScanHandler) CreateComparison(c *gin.Context) {
	var payload ComparisonPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.respondComparison(c, payload, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
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
	if !authorizeComparisonReport(c, report) {
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
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxVEXUploadSize)
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file upload is required"})
		return
	}
	defer file.Close() //nolint:errcheck // request file cleanup

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

	actor := auditActorFromContext(c)
	h.recordAuditEvent(c.Request.Context(), audit.Event{
		Action:     "vex.imported",
		Outcome:    "succeeded",
		Actor:      actor.ID,
		ActorType:  actor.Type,
		OrgID:      orgID,
		Target:     imageAuditTarget(orgID, imageID),
		TargetType: "image",
		Metadata: map[string]any{
			"document_id":         vexDocument.DocumentID,
			"filename":            header.Filename,
			"image_name":          updatedRecord.ImageName,
			"storage_backend":     h.store.Backend(),
			"vulnerability_count": len(updatedRecord.Vulnerabilities),
		},
	})
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

func (h *ScanHandler) getOrBuildSBOMRecord(ctx context.Context, orgID, imageID, format string, object storage.Object) (sbomindex.Record, error) {
	record, err := h.sbomIndex.Get(ctx, orgID, imageID)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, sbomindex.ErrNotFound) {
		return sbomindex.Record{}, err
	}

	return h.buildSBOMRecordFromArtifact(ctx, orgID, imageID, format, object)
}

func (h *ScanHandler) getOrBuildVulnerabilityRecord(ctx context.Context, orgID, imageID string) (vulnindex.Record, error) {
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

	return h.buildVulnerabilityRecordFromArtifact(ctx, orgID, imageID, object)
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

func (h *ScanHandler) getExistingSBOMRecord(ctx context.Context, orgID, imageID string) (*sbomindex.Record, error) {
	record, err := h.sbomIndex.Get(ctx, orgID, imageID)
	if err == nil {
		return &record, nil
	}
	if errors.Is(err, sbomindex.ErrNotFound) {
		return nil, nil
	}
	return nil, err
}

func (h *ScanHandler) buildSBOMRecordFromArtifact(ctx context.Context, orgID, imageID, format string, object storage.Object) (sbomindex.Record, error) {
	imageName := strings.TrimSpace(object.Info.Metadata["image_name"])
	if imageName == "" {
		record, err := h.getExistingVulnerabilityRecord(ctx, orgID, imageID)
		if err != nil {
			return sbomindex.Record{}, err
		}
		if record != nil {
			imageName = record.ImageName
		}
	}

	record, err := sbomindex.BuildRecordFromDocument(orgID, imageID, imageName, format, object.Data)
	if err != nil {
		return sbomindex.Record{}, err
	}
	if platform := strings.TrimSpace(object.Info.Metadata["platform"]); platform != "" {
		record.Platform = platform
	}
	return record, nil
}

func (h *ScanHandler) buildVulnerabilityRecordFromArtifact(ctx context.Context, orgID, imageID string, object storage.Object) (vulnindex.Record, error) {
	imageName := strings.TrimSpace(object.Info.Metadata["image_name"])
	if imageName == "" {
		record, err := h.getExistingSBOMRecord(ctx, orgID, imageID)
		if err != nil {
			return vulnindex.Record{}, err
		}
		if record != nil {
			imageName = record.ImageName
		}
	}

	record, err := vulnindex.BuildRecordFromDocument(orgID, imageID, imageName, object.Data, nil, vulnindex.BuildOptions{})
	if err != nil {
		return vulnindex.Record{}, err
	}
	if platform := strings.TrimSpace(object.Info.Metadata["platform"]); platform != "" {
		record.Platform = platform
	}
	return record, nil
}

func (h *ScanHandler) repairSBOMIndex(ctx context.Context, orgID, imageID string) (sbomindex.Record, string, error) {
	record, err := h.sbomIndex.Get(ctx, orgID, imageID)
	if err == nil {
		return record, "present", nil
	}
	if !errors.Is(err, sbomindex.ErrNotFound) {
		return sbomindex.Record{}, "", err
	}

	keyBuilder := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}
	for _, format := range []string{sbomindex.FormatCycloneDX, sbomindex.FormatSPDX} {
		object, err := h.getSBOMArtifact(ctx, keyBuilder, format)
		switch {
		case err == nil:
			record, err := h.buildSBOMRecordFromArtifact(ctx, orgID, imageID, format, object)
			if err != nil {
				return sbomindex.Record{}, "", err
			}
			record, err = h.sbomIndex.Save(ctx, record)
			return record, "repaired", err
		case errors.Is(err, storage.ErrNotFound):
			continue
		default:
			return sbomindex.Record{}, "", err
		}
	}

	return sbomindex.Record{}, "missing", storage.ErrNotFound
}

func (h *ScanHandler) repairVulnerabilityIndex(ctx context.Context, orgID, imageID string) (vulnindex.Record, string, error) {
	record, err := h.vulnIndex.Get(ctx, orgID, imageID)
	if err == nil {
		return record, "present", nil
	}
	if !errors.Is(err, vulnindex.ErrNotFound) {
		return vulnindex.Record{}, "", err
	}

	key, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildVulnerabilityKey()
	if err != nil {
		return vulnindex.Record{}, "", err
	}
	object, err := h.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return vulnindex.Record{}, "missing", err
		}
		return vulnindex.Record{}, "", err
	}

	record, err = h.buildVulnerabilityRecordFromArtifact(ctx, orgID, imageID, object)
	if err != nil {
		return vulnindex.Record{}, "", err
	}
	record, err = h.vulnIndex.Save(ctx, record)
	return record, "repaired", err
}

func (h *ScanHandler) resolveStoredImageReference(ctx context.Context, orgID, imageID string) (string, error) {
	sbomMissing := false
	record, err := h.sbomIndex.Get(ctx, orgID, imageID)
	switch {
	case err == nil && strings.TrimSpace(record.ImageName) != "":
		return record.ImageName, nil
	case err != nil && !errors.Is(err, sbomindex.ErrNotFound):
		return "", err
	case errors.Is(err, sbomindex.ErrNotFound):
		sbomMissing = true
	}

	vulnerabilityMissing := false
	vulnerabilities, err := h.vulnIndex.Get(ctx, orgID, imageID)
	switch {
	case err == nil && strings.TrimSpace(vulnerabilities.ImageName) != "":
		return vulnerabilities.ImageName, nil
	case err != nil && !errors.Is(err, vulnindex.ErrNotFound):
		return "", err
	case errors.Is(err, vulnindex.ErrNotFound):
		vulnerabilityMissing = true
	}

	prefix, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildImagePrefix()
	if err != nil {
		return "", err
	}
	objects, err := h.store.List(ctx, prefix)
	if err != nil {
		return "", err
	}
	for _, object := range objects {
		imageName := strings.TrimSpace(object.Metadata["image_name"])
		if imageName == "" {
			continue
		}
		if err := validateImageReference(imageName); err == nil {
			return imageName, nil
		}
	}

	if vulnerabilityMissing {
		if sbomMissing {
			return "", sbomindex.ErrNotFound
		}
		return "", vulnindex.ErrNotFound
	}
	return "", sbomindex.ErrNotFound
}

type comparisonTarget struct {
	SBOM              sbomindex.Record
	Vulnerabilities   vulnindex.Record
	CycloneDXDocument []byte
}

var errComparisonTargetAmbiguous = errors.New("comparison target is ambiguous")
var errComparisonTargetNotFound = errors.New("comparison target not found")

func (h *ScanHandler) resolveComparisonTarget(ctx context.Context, imageName, orgID string, allowedOrgs map[string]struct{}) (comparisonTarget, error) {
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
		if orgID != "" && record.OrgID != orgID {
			continue
		}
		if len(allowedOrgs) > 0 {
			if _, ok := allowedOrgs[record.OrgID]; !ok {
				continue
			}
		}
		filtered = append(filtered, record)
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

	vulnerabilities, err := h.getOrBuildVulnerabilityRecord(ctx, record.OrgID, record.ImageID)
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

func (h *ScanHandler) respondComparison(c *gin.Context, payload ComparisonPayload, persist bool) error {
	payload.Image1 = strings.TrimSpace(payload.Image1)
	payload.Image2 = strings.TrimSpace(payload.Image2)
	payload.Org1 = strings.TrimSpace(payload.Org1)
	payload.Org2 = strings.TrimSpace(payload.Org2)

	if payload.Image1 == "" || payload.Image2 == "" {
		return errors.New("image1 and image2 are required")
	}
	if payload.Org1 != "" && !authorizeOrgRequest(c, payload.Org1) {
		return nil
	}
	if payload.Org2 != "" && !authorizeOrgRequest(c, payload.Org2) {
		return nil
	}
	allowedOrgs := authorizedOrgSet(c)

	target1, err := h.resolveComparisonTarget(c.Request.Context(), payload.Image1, payload.Org1, allowedOrgs)
	if err != nil {
		h.renderComparisonLookupError(c, "image1", err)
		return nil
	}
	target2, err := h.resolveComparisonTarget(c.Request.Context(), payload.Image2, payload.Org2, allowedOrgs)
	if err != nil {
		h.renderComparisonLookupError(c, "image2", err)
		return nil
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
		return nil
	}

	response := gin.H{
		"comparison_id":   report.ID,
		"storage_backend": h.store.Backend(),
		"comparison":      report,
	}
	if !persist {
		c.JSON(http.StatusOK, response)
		return nil
	}

	document, err := compare.MarshalReport(report)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("marshal comparison: %v", err)})
		return nil
	}

	key, err := BuildComparisonKey(report.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("build comparison key: %v", err)})
		return nil
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
		return nil
	}

	response["comparison_file"] = toObjectResponse(info)
	c.JSON(http.StatusOK, response)
	return nil
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

func normalizeImageExportFormat(value string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	switch format {
	case "":
		return "", fmt.Errorf("format is required")
	case sbomindex.FormatCycloneDX, sbomindex.FormatSPDX, reportexport.FormatCSV, reportexport.FormatJSON, reportexport.FormatSARIF:
		return format, nil
	default:
		return "", fmt.Errorf("unsupported export format %q", value)
	}
}

func buildImageExportFilename(orgID, imageID, artifact, format string) (string, error) {
	var filename string
	switch artifact {
	case "sbom":
		filename = fmt.Sprintf("%s-%s-sbom-%s.json", orgID, imageID, format)
	case "vulnerabilities":
		switch format {
		case reportexport.FormatCSV:
			filename = fmt.Sprintf("%s-%s-vulnerabilities.csv", orgID, imageID)
		case reportexport.FormatSARIF:
			filename = fmt.Sprintf("%s-%s-vulnerabilities.sarif", orgID, imageID)
		default:
			filename = fmt.Sprintf("%s-%s-vulnerabilities.json", orgID, imageID)
		}
	default:
		return "", fmt.Errorf("unsupported export artifact %q", artifact)
	}
	if err := validateDownloadFilename(filename); err != nil {
		return "", err
	}
	return filename, nil
}

func buildComparisonExportFilename(comparisonID string) (string, error) {
	filename := fmt.Sprintf("comparison-%s.json", comparisonID)
	if err := validateDownloadFilename(filename); err != nil {
		return "", err
	}
	return filename, nil
}

func writeAttachment(c *gin.Context, filename, contentType string, data []byte) {
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Data(http.StatusOK, contentType, data)
}
