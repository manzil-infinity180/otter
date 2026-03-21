package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/otterXf/otter/pkg/policy"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

type ImageCatalogEntry struct {
	OrgID                string                          `json:"org_id"`
	ImageID              string                          `json:"image_id"`
	ImageName            string                          `json:"image_name"`
	Registry             string                          `json:"registry"`
	Platform             string                          `json:"platform,omitempty"`
	Repository           string                          `json:"repository"`
	RepositoryPath       string                          `json:"repository_path"`
	Tag                  string                          `json:"tag,omitempty"`
	Digest               string                          `json:"digest,omitempty"`
	PackageCount         int                             `json:"package_count"`
	LicenseSummary       []sbomindex.LicenseSummaryEntry `json:"license_summary,omitempty"`
	VulnerabilitySummary vulnindex.Summary               `json:"vulnerability_summary"`
	Scanners             []string                        `json:"scanners,omitempty"`
	UpdatedAt            time.Time                       `json:"updated_at"`
}

type ImageTagSummary struct {
	OrgID                string            `json:"org_id"`
	ImageID              string            `json:"image_id"`
	ImageName            string            `json:"image_name"`
	Platform             string            `json:"platform,omitempty"`
	Tag                  string            `json:"tag,omitempty"`
	Digest               string            `json:"digest,omitempty"`
	PackageCount         int               `json:"package_count"`
	VulnerabilitySummary vulnindex.Summary `json:"vulnerability_summary"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

type ImageTagListItem struct {
	OrgID                string            `json:"org_id,omitempty"`
	ImageID              string            `json:"image_id,omitempty"`
	ImageName            string            `json:"image_name"`
	Platform             string            `json:"platform,omitempty"`
	Tag                  string            `json:"tag,omitempty"`
	Digest               string            `json:"digest,omitempty"`
	PackageCount         int               `json:"package_count"`
	VulnerabilitySummary vulnindex.Summary `json:"vulnerability_summary"`
	UpdatedAt            time.Time         `json:"updated_at,omitempty"`
	Current              bool              `json:"current"`
	Scanned              bool              `json:"scanned"`
	Source               string            `json:"source"`
}

type ImageTagsResponse struct {
	OrgID                string             `json:"org_id"`
	ImageID              string             `json:"image_id"`
	ImageName            string             `json:"image_name"`
	Repository           string             `json:"repository"`
	StorageBackend       string             `json:"storage_backend"`
	Page                 int                `json:"page"`
	PageSize             int                `json:"page_size"`
	Count                int                `json:"count"`
	Total                int                `json:"total"`
	HasMore              bool               `json:"has_more"`
	Items                []ImageTagListItem `json:"items"`
	RemoteCached         bool               `json:"remote_cached"`
	RemoteCacheExpiresAt time.Time          `json:"remote_cache_expires_at,omitempty"`
	RemoteTagError       string             `json:"remote_tag_error,omitempty"`
}

type ImageOverview struct {
	ImageCatalogEntry
	StorageBackend  string            `json:"storage_backend"`
	DependencyRoots []string          `json:"dependency_roots,omitempty"`
	Files           []ObjectResponse  `json:"files"`
	Tags            []ImageTagSummary `json:"tags"`
	Policy          policy.Evaluation `json:"policy"`
}

type catalogFilters struct {
	OrgID       string
	Query       string
	Severity    string
	SortBy      string
	Page        int
	PageSize    int
	AllowedOrgs map[string]struct{}
}

type imageTagFilters struct {
	Query    string
	Page     int
	PageSize int
}

type imageReferenceParts struct {
	Registry       string
	Repository     string
	RepositoryPath string
	Tag            string
	Digest         string
}

func (h *ScanHandler) ListCatalog(c *gin.Context) {
	filters, err := parseCatalogFilters(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeCatalogFilters(c, &filters) {
		return
	}

	entries, total, err := h.buildCatalog(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load catalog: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"storage_backend": h.store.Backend(),
		"count":           len(entries),
		"total":           total,
		"page":            filters.Page,
		"page_size":       filters.PageSize,
		"has_more":        filters.Page*filters.PageSize < total,
		"items":           entries,
		"filters": gin.H{
			"org_id":    filters.OrgID,
			"query":     filters.Query,
			"severity":  filters.Severity,
			"sort":      filters.SortBy,
			"page":      filters.Page,
			"page_size": filters.PageSize,
		},
	})
}

func (h *ScanHandler) GetImageOverview(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	overview, err := h.buildImageOverview(c.Request.Context(), orgID, imageID)
	if err != nil {
		switch {
		case errors.Is(err, sbomindex.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "image overview not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load image overview: %v", err)})
		}
		return
	}

	c.JSON(http.StatusOK, overview)
}

func (h *ScanHandler) GetImageTags(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	filters, err := parseImageTagFilters(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.buildImageTags(c.Request.Context(), orgID, imageID, filters)
	if err != nil {
		switch {
		case errors.Is(err, sbomindex.ErrNotFound), errors.Is(err, vulnindex.ErrNotFound), errors.Is(err, storage.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "stored image reference not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load image tags: %v", err)})
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *ScanHandler) BrowseCatalog(c *gin.Context) {
	filters, err := parseCatalogFilters(c)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	if !authorizeCatalogFilters(c, &filters) {
		return
	}

	entries, total, err := h.buildCatalog(c.Request.Context(), filters)
	if err != nil {
		c.String(http.StatusInternalServerError, "load catalog: %v", err)
		return
	}

	var body bytes.Buffer
	data := struct {
		Entries []ImageCatalogEntry
		Filters catalogFilters
		Total   int
	}{
		Entries: entries,
		Filters: filters,
		Total:   total,
	}
	if err := browseCatalogTemplate.Execute(&body, data); err != nil {
		c.String(http.StatusInternalServerError, "render catalog: %v", err)
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", body.Bytes())
}

func (h *ScanHandler) BrowseImage(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Param("org_id"), c.Param("id"))
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	overview, err := h.buildImageOverview(c.Request.Context(), orgID, imageID)
	if err != nil {
		switch {
		case errors.Is(err, sbomindex.ErrNotFound):
			c.String(http.StatusNotFound, "image overview not found")
		default:
			c.String(http.StatusInternalServerError, "load image overview: %v", err)
		}
		return
	}

	sbomRecord, err := h.sbomIndex.Get(c.Request.Context(), orgID, imageID)
	if err != nil {
		c.String(http.StatusInternalServerError, "load sbom index: %v", err)
		return
	}

	vulnerabilityRecord, err := h.getOrBuildVulnerabilityRecord(c.Request.Context(), orgID, imageID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, vulnindex.ErrNotFound) {
		c.String(http.StatusInternalServerError, "load vulnerabilities: %v", err)
		return
	}
	complianceReport, err := h.buildImageCompliance(c.Request.Context(), orgID, imageID)
	if err != nil {
		c.String(http.StatusInternalServerError, "load compliance: %v", err)
		return
	}

	var body bytes.Buffer
	data := struct {
		Overview        ImageOverview
		Compliance      ImageComplianceResponse
		Packages        []sbomindex.PackageRecord
		Vulnerabilities []vulnindex.VulnerabilityRecord
	}{
		Overview:        overview,
		Compliance:      complianceReport,
		Packages:        limitPackages(sbomRecord.Packages, 25),
		Vulnerabilities: limitVulnerabilities(vulnerabilityRecord.Vulnerabilities, 25),
	}
	if err := browseImageTemplate.Execute(&body, data); err != nil {
		c.String(http.StatusInternalServerError, "render image page: %v", err)
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", body.Bytes())
}

func parseCatalogFilters(c *gin.Context) (catalogFilters, error) {
	filters := catalogFilters{
		OrgID:    strings.TrimSpace(c.Query("org_id")),
		Query:    strings.TrimSpace(c.Query("query")),
		SortBy:   strings.TrimSpace(c.DefaultQuery("sort", "recent")),
		Page:     1,
		PageSize: 20,
	}
	if filters.Query == "" {
		filters.Query = strings.TrimSpace(c.Query("q"))
	}
	if filters.Severity = strings.TrimSpace(c.Query("severity")); filters.Severity != "" {
		normalized, err := normalizeSeverityFilter(filters.Severity)
		if err != nil {
			return catalogFilters{}, err
		}
		filters.Severity = normalized
	}

	switch filters.SortBy {
	case "", "recent", "critical", "packages", "name":
		if filters.SortBy == "" {
			filters.SortBy = "recent"
		}
	default:
		return catalogFilters{}, fmt.Errorf("unsupported sort %q", filters.SortBy)
	}
	if c.Query("page") != "" {
		value, err := strconv.Atoi(strings.TrimSpace(c.Query("page")))
		if err != nil || value <= 0 {
			return catalogFilters{}, fmt.Errorf("page must be a positive integer")
		}
		filters.Page = value
	}
	if c.Query("page_size") != "" {
		value, err := strconv.Atoi(strings.TrimSpace(c.Query("page_size")))
		if err != nil || value <= 0 {
			return catalogFilters{}, fmt.Errorf("page_size must be a positive integer")
		}
		if value > 100 {
			value = 100
		}
		filters.PageSize = value
	}

	return filters, nil
}

func parseImageTagFilters(c *gin.Context) (imageTagFilters, error) {
	filters := imageTagFilters{
		Query:    strings.TrimSpace(c.Query("query")),
		Page:     1,
		PageSize: 25,
	}
	if filters.Query == "" {
		filters.Query = strings.TrimSpace(c.Query("q"))
	}
	if c.Query("page") != "" {
		value, err := strconv.Atoi(strings.TrimSpace(c.Query("page")))
		if err != nil || value <= 0 {
			return imageTagFilters{}, fmt.Errorf("page must be a positive integer")
		}
		filters.Page = value
	}
	if c.Query("page_size") != "" {
		value, err := strconv.Atoi(strings.TrimSpace(c.Query("page_size")))
		if err != nil || value <= 0 {
			return imageTagFilters{}, fmt.Errorf("page_size must be a positive integer")
		}
		if value > 100 {
			value = 100
		}
		filters.PageSize = value
	}
	return filters, nil
}

func (h *ScanHandler) buildCatalog(ctx context.Context, filters catalogFilters) ([]ImageCatalogEntry, int, error) {
	query := sbomindex.CatalogQuery{
		OrgID:    filters.OrgID,
		Query:    filters.Query,
		Severity: filters.Severity,
		SortBy:   filters.SortBy,
		Page:     filters.Page,
		PageSize: filters.PageSize,
	}
	if len(filters.AllowedOrgs) > 0 {
		query.AllowedOrgs = make([]string, 0, len(filters.AllowedOrgs))
		for orgID := range filters.AllowedOrgs {
			query.AllowedOrgs = append(query.AllowedOrgs, orgID)
		}
	}

	page, err := h.sbomIndex.QueryCatalog(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("query catalog records: %w", err)
	}

	entries := make([]ImageCatalogEntry, 0, len(page.Items))
	for _, record := range page.Items {
		entries = append(entries, buildImageCatalogEntry(record))
	}

	return entries, page.Total, nil
}

func (h *ScanHandler) buildImageTags(ctx context.Context, orgID, imageID string, filters imageTagFilters) (ImageTagsResponse, error) {
	imageRef, err := h.resolveStoredImageReference(ctx, orgID, imageID)
	if err != nil {
		return ImageTagsResponse{}, err
	}

	refParts := parseImageReference(imageRef)
	repositoryKey := refParts.Repository
	if repositoryKey == "" {
		repositoryKey = strings.TrimSpace(refParts.RepositoryPath)
	}

	storedRecords, err := h.sbomIndex.ListRepositoryTags(ctx, sbomindex.RepositoryTagQuery{
		OrgID:          orgID,
		RepositoryKey:  repositoryKey,
		ExcludeImageID: imageID,
	})
	if err != nil {
		return ImageTagsResponse{}, fmt.Errorf("list stored repository tags: %w", err)
	}

	itemsByKey := make(map[string]ImageTagListItem)
	if currentItem, ok, err := h.buildCurrentImageTagItem(ctx, orgID, imageID, imageRef); err != nil {
		return ImageTagsResponse{}, err
	} else if ok {
		itemsByKey[tagListItemKey(currentItem)] = currentItem
	}
	for _, record := range storedRecords {
		item := buildStoredTagListItem(record)
		if item.Tag == "" && item.Digest == "" {
			continue
		}
		key := tagListItemKey(item)
		if existing, ok := itemsByKey[key]; ok {
			item = mergeImageTagItems(existing, item)
		}
		itemsByKey[key] = item
	}

	response := ImageTagsResponse{
		OrgID:          orgID,
		ImageID:        imageID,
		ImageName:      imageRef,
		Repository:     repositoryKey,
		StorageBackend: h.store.Backend(),
		Page:           filters.Page,
		PageSize:       filters.PageSize,
	}
	if response.Repository == "" {
		response.Repository = refParts.Repository
	}

	remoteTags, remoteErr := h.registry.ListRepositoryTags(ctx, imageRef)
	if remoteErr != nil {
		response.RemoteTagError = remoteErr.Error()
	} else {
		response.RemoteCached = remoteTags.Cached
		response.RemoteCacheExpiresAt = remoteTags.CacheExpiresAt
		for _, tag := range remoteTags.Tags {
			item := ImageTagListItem{
				ImageName:            remoteTags.Repository + ":" + tag,
				Tag:                  tag,
				Current:              tag == refParts.Tag,
				Scanned:              false,
				Source:               "remote",
				VulnerabilitySummary: vulnindex.Summary{},
			}
			key := tagListItemKey(item)
			if existing, ok := itemsByKey[key]; ok {
				existing.Source = mergeTagSources(existing.Source, "remote")
				itemsByKey[key] = existing
				continue
			}
			itemsByKey[key] = item
		}
	}

	items := make([]ImageTagListItem, 0, len(itemsByKey))
	for _, item := range itemsByKey {
		if matchesImageTagQuery(item, filters.Query) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Current != items[j].Current {
			return items[i].Current
		}
		if items[i].Scanned != items[j].Scanned {
			return items[i].Scanned
		}
		if !items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		if items[i].Tag != items[j].Tag {
			return items[i].Tag < items[j].Tag
		}
		return items[i].ImageName < items[j].ImageName
	})

	response.Total = len(items)
	start := (filters.Page - 1) * filters.PageSize
	if start < len(items) {
		end := start + filters.PageSize
		if end > len(items) {
			end = len(items)
		}
		response.Items = items[start:end]
	}
	response.Count = len(response.Items)
	response.HasMore = filters.Page*filters.PageSize < response.Total
	return response, nil
}

func buildImageCatalogEntry(record sbomindex.CatalogRecord) ImageCatalogEntry {
	refParts := parseImageReference(record.ImageName)
	entry := ImageCatalogEntry{
		OrgID:                record.OrgID,
		ImageID:              record.ImageID,
		ImageName:            record.ImageName,
		Registry:             refParts.Registry,
		Platform:             record.Platform,
		Repository:           refParts.Repository,
		RepositoryPath:       refParts.RepositoryPath,
		Tag:                  refParts.Tag,
		Digest:               refParts.Digest,
		PackageCount:         record.PackageCount,
		LicenseSummary:       record.LicenseSummary,
		VulnerabilitySummary: record.VulnerabilitySummary,
		Scanners:             sortedSummaryKeys(record.VulnerabilitySummary.ByScanner),
		UpdatedAt:            record.UpdatedAt,
	}
	return entry
}

func (h *ScanHandler) buildImageOverview(ctx context.Context, orgID, imageID string) (ImageOverview, error) {
	record, err := h.sbomIndex.Get(ctx, orgID, imageID)
	if err != nil {
		return ImageOverview{}, err
	}

	entry := buildImageCatalogEntry(sbomindex.CatalogRecord{
		OrgID:          record.OrgID,
		ImageID:        record.ImageID,
		ImageName:      record.ImageName,
		RepositoryKey:  record.RepositoryKey,
		Platform:       record.Platform,
		SourceFormat:   record.SourceFormat,
		PackageCount:   record.PackageCount,
		LicenseSummary: record.LicenseSummary,
		UpdatedAt:      record.UpdatedAt,
	})
	var vulnerabilityRecord *vulnindex.Record
	if vulnerabilityRecord, err = h.getExistingVulnerabilityRecord(ctx, record.OrgID, record.ImageID); err != nil {
		return ImageOverview{}, fmt.Errorf("load vulnerability summary for %s/%s: %w", record.OrgID, record.ImageID, err)
	} else if vulnerabilityRecord != nil {
		entry.VulnerabilitySummary = vulnerabilityRecord.Summary
		entry.Scanners = sortedSummaryKeys(vulnerabilityRecord.Summary.ByScanner)
		entry.UpdatedAt = latestTimestamp(entry.UpdatedAt, vulnerabilityRecord.UpdatedAt)
	}

	prefix, err := ArtifactKeyBuilder{OrgID: orgID, ImageID: imageID}.BuildImagePrefix()
	if err != nil {
		return ImageOverview{}, err
	}
	objects, err := h.store.List(ctx, prefix)
	if err != nil {
		return ImageOverview{}, fmt.Errorf("list scan artifacts: %w", err)
	}
	files := make([]ObjectResponse, 0, len(objects))
	for _, object := range objects {
		files = append(files, toObjectResponse(object))
	}

	repositoryKey := record.RepositoryKey
	if repositoryKey == "" {
		repositoryKey = entry.Repository
	}
	records, err := h.sbomIndex.ListRepositoryTags(ctx, sbomindex.RepositoryTagQuery{
		OrgID:          orgID,
		RepositoryKey:  repositoryKey,
		ExcludeImageID: imageID,
	})
	if err != nil {
		return ImageOverview{}, fmt.Errorf("list related repository tags: %w", err)
	}

	tags := make([]ImageTagSummary, 0)
	for _, candidate := range records {
		candidateRef := parseImageReference(candidate.ImageName)
		tag := ImageTagSummary{
			OrgID:                candidate.OrgID,
			ImageID:              candidate.ImageID,
			ImageName:            candidate.ImageName,
			Platform:             candidate.Platform,
			Tag:                  candidateRef.Tag,
			Digest:               candidateRef.Digest,
			PackageCount:         candidate.PackageCount,
			UpdatedAt:            candidate.UpdatedAt,
			VulnerabilitySummary: candidate.VulnerabilitySummary,
		}
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool {
		if tags[i].UpdatedAt.Equal(tags[j].UpdatedAt) {
			return tags[i].ImageName < tags[j].ImageName
		}
		return tags[i].UpdatedAt.After(tags[j].UpdatedAt)
	})

	return ImageOverview{
		ImageCatalogEntry: entry,
		StorageBackend:    h.store.Backend(),
		DependencyRoots:   record.DependencyRoots,
		Files:             files,
		Tags:              tags,
		Policy:            h.evaluatePolicy(ctx, orgID, imageID, record.ImageName, vulnerabilityRecord, nil, nil),
	}, nil
}

func (h *ScanHandler) buildCurrentImageTagItem(ctx context.Context, orgID, imageID, imageRef string) (ImageTagListItem, bool, error) {
	parts := parseImageReference(imageRef)
	if parts.Tag == "" && parts.Digest == "" {
		return ImageTagListItem{}, false, nil
	}

	item := ImageTagListItem{
		OrgID:                orgID,
		ImageID:              imageID,
		ImageName:            imageRef,
		Platform:             "",
		Tag:                  parts.Tag,
		Digest:               parts.Digest,
		Current:              true,
		Scanned:              true,
		Source:               "stored",
		VulnerabilitySummary: vulnindex.Summary{},
	}

	if record, err := h.sbomIndex.Get(ctx, orgID, imageID); err == nil {
		item.Platform = record.Platform
		item.PackageCount = record.PackageCount
		item.UpdatedAt = latestTimestamp(item.UpdatedAt, record.UpdatedAt)
	} else if !errors.Is(err, sbomindex.ErrNotFound) {
		return ImageTagListItem{}, false, fmt.Errorf("load current tag sbom summary: %w", err)
	}

	if vulnerabilityRecord, err := h.getExistingVulnerabilityRecord(ctx, orgID, imageID); err != nil {
		return ImageTagListItem{}, false, fmt.Errorf("load current tag vulnerability summary: %w", err)
	} else if vulnerabilityRecord != nil {
		item.VulnerabilitySummary = vulnerabilityRecord.Summary
		item.UpdatedAt = latestTimestamp(item.UpdatedAt, vulnerabilityRecord.UpdatedAt)
	}

	return item, true, nil
}

func buildStoredTagListItem(record sbomindex.CatalogRecord) ImageTagListItem {
	parts := parseImageReference(record.ImageName)
	return ImageTagListItem{
		OrgID:                record.OrgID,
		ImageID:              record.ImageID,
		ImageName:            record.ImageName,
		Platform:             record.Platform,
		Tag:                  parts.Tag,
		Digest:               parts.Digest,
		PackageCount:         record.PackageCount,
		VulnerabilitySummary: record.VulnerabilitySummary,
		UpdatedAt:            record.UpdatedAt,
		Scanned:              true,
		Source:               "stored",
	}
}

func matchesCatalogFilters(entry ImageCatalogEntry, filters catalogFilters) bool {
	if len(filters.AllowedOrgs) > 0 {
		if _, ok := filters.AllowedOrgs[entry.OrgID]; !ok {
			return false
		}
	}
	if filters.OrgID != "" && entry.OrgID != filters.OrgID {
		return false
	}
	if filters.Severity != "" && entry.VulnerabilitySummary.BySeverity[filters.Severity] == 0 {
		return false
	}
	if filters.Query == "" {
		return true
	}

	query := strings.ToLower(filters.Query)
	for _, field := range []string{
		entry.OrgID,
		entry.ImageID,
		entry.ImageName,
		entry.Repository,
		entry.RepositoryPath,
		entry.Tag,
		entry.Digest,
	} {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}

	return false
}

func matchesImageTagQuery(item ImageTagListItem, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}

	for _, field := range []string{item.Tag, item.Digest, item.ImageName} {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

func tagListItemKey(item ImageTagListItem) string {
	switch {
	case item.Tag != "":
		return "tag:" + item.Tag
	case item.Digest != "":
		return "digest:" + item.Digest
	default:
		return "image:" + item.ImageName
	}
}

func mergeTagSources(left, right string) string {
	switch {
	case left == "" || left == right:
		return right
	case right == "":
		return left
	case (left == "stored" && right == "remote") || (left == "remote" && right == "stored"):
		return "stored+remote"
	default:
		if strings.Contains(left, right) {
			return left
		}
		return left + "+" + right
	}
}

func mergeImageTagItems(existing, candidate ImageTagListItem) ImageTagListItem {
	merged := candidate
	if existing.Current {
		merged = existing
	} else if existing.Scanned && (!candidate.Scanned || existing.UpdatedAt.After(candidate.UpdatedAt)) {
		merged = existing
	}

	merged.Current = existing.Current || candidate.Current
	merged.Scanned = existing.Scanned || candidate.Scanned
	merged.Source = mergeTagSources(existing.Source, candidate.Source)

	if merged.PackageCount == 0 {
		if existing.PackageCount != 0 {
			merged.PackageCount = existing.PackageCount
		} else {
			merged.PackageCount = candidate.PackageCount
		}
	}
	if merged.Platform == "" {
		merged.Platform = existing.Platform
	}
	if merged.ImageName == "" {
		merged.ImageName = existing.ImageName
	}
	if merged.OrgID == "" {
		merged.OrgID = existing.OrgID
	}
	if merged.ImageID == "" {
		merged.ImageID = existing.ImageID
	}
	if merged.Tag == "" {
		merged.Tag = existing.Tag
	}
	if merged.Digest == "" {
		merged.Digest = existing.Digest
	}
	if merged.UpdatedAt.IsZero() {
		merged.UpdatedAt = existing.UpdatedAt
	}
	if merged.VulnerabilitySummary.Total == 0 && existing.VulnerabilitySummary.Total != 0 {
		merged.VulnerabilitySummary = existing.VulnerabilitySummary
	}
	return merged
}

func sortCatalogEntries(entries []ImageCatalogEntry, sortBy string) {
	sort.Slice(entries, func(i, j int) bool {
		left := entries[i]
		right := entries[j]

		switch sortBy {
		case "critical":
			leftCritical := left.VulnerabilitySummary.BySeverity["CRITICAL"]
			rightCritical := right.VulnerabilitySummary.BySeverity["CRITICAL"]
			if leftCritical != rightCritical {
				return leftCritical > rightCritical
			}
		case "packages":
			if left.PackageCount != right.PackageCount {
				return left.PackageCount > right.PackageCount
			}
		case "name":
			if left.Repository != right.Repository {
				return left.Repository < right.Repository
			}
			return left.ImageName < right.ImageName
		}

		if left.UpdatedAt.Equal(right.UpdatedAt) {
			if left.Repository != right.Repository {
				return left.Repository < right.Repository
			}
			if left.OrgID != right.OrgID {
				return left.OrgID < right.OrgID
			}
			return left.ImageID < right.ImageID
		}
		return left.UpdatedAt.After(right.UpdatedAt)
	})
}

func parseImageReference(imageName string) imageReferenceParts {
	imageName = strings.TrimSpace(imageName)
	if imageName == "" {
		return imageReferenceParts{}
	}

	ref, err := name.ParseReference(imageName, name.WeakValidation)
	if err != nil {
		return imageReferenceParts{Repository: imageName, RepositoryPath: imageName}
	}

	context := ref.Context()
	parts := imageReferenceParts{
		Registry:       context.RegistryStr(),
		RepositoryPath: context.RepositoryStr(),
	}
	if parts.Registry != "" && parts.RepositoryPath != "" {
		parts.Repository = parts.Registry + "/" + parts.RepositoryPath
	} else {
		parts.Repository = parts.RepositoryPath
	}

	identifier := ref.Identifier()
	if strings.HasPrefix(identifier, "sha256:") {
		parts.Digest = identifier
	} else {
		parts.Tag = identifier
	}

	return parts
}

func normalizeSeverityFilter(value string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return "CRITICAL", nil
	case "HIGH":
		return "HIGH", nil
	case "MEDIUM":
		return "MEDIUM", nil
	case "LOW":
		return "LOW", nil
	case "NEGLIGIBLE":
		return "NEGLIGIBLE", nil
	case "UNKNOWN":
		return "UNKNOWN", nil
	default:
		return "", fmt.Errorf("unsupported severity %q", value)
	}
}

func sortedSummaryKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func latestTimestamp(left, right time.Time) time.Time {
	if left.IsZero() {
		return right
	}
	if right.After(left) {
		return right
	}
	return left
}

func limitPackages(packages []sbomindex.PackageRecord, count int) []sbomindex.PackageRecord {
	if len(packages) <= count {
		return packages
	}
	return packages[:count]
}

func limitVulnerabilities(vulnerabilities []vulnindex.VulnerabilityRecord, count int) []vulnindex.VulnerabilityRecord {
	if len(vulnerabilities) <= count {
		return vulnerabilities
	}
	return vulnerabilities[:count]
}

var browseCatalogTemplate = template.Must(template.New("browse-catalog").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Otter Directory</title>
  <style>
    :root { color-scheme: dark light; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; background: #0b1020; color: #e6edf7; }
    main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }
    h1, h2 { margin: 0; }
    p { color: #97a5c0; }
    a { color: #7dd3fc; }
    .hero { display: grid; gap: 12px; margin-bottom: 24px; }
    .panel { border: 1px solid #22314d; background: rgba(14, 23, 42, 0.92); border-radius: 18px; padding: 18px; }
    .grid { display: grid; gap: 16px; }
    .entry { display: grid; gap: 10px; }
    .meta { display: flex; gap: 12px; flex-wrap: wrap; color: #97a5c0; font-size: 14px; }
    .chips { display: flex; gap: 8px; flex-wrap: wrap; }
    .chip { border: 1px solid #335180; border-radius: 999px; padding: 4px 10px; font-size: 12px; color: #dce8ff; }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Otter image directory</h1>
      <p>JavaScript-free browse mode. Use the React app at <a href="/">/</a> for the full vertical-tab UI.</p>
      <div class="meta">
        <span>Org: {{if .Filters.OrgID}}{{.Filters.OrgID}}{{else}}all{{end}}</span>
        <span>Query: {{if .Filters.Query}}{{.Filters.Query}}{{else}}none{{end}}</span>
        <span>Sort: {{.Filters.SortBy}}</span>
      </div>
    </section>
    <section class="grid">
      {{range .Entries}}
      <article class="panel entry">
        <div>
          <h2><a href="/browse/images/{{.OrgID}}/{{.ImageID}}">{{if .Repository}}{{.Repository}}{{else}}{{.ImageName}}{{end}}</a></h2>
          <div class="meta">
            <span>{{.ImageName}}</span>
            <span>{{.OrgID}} / {{.ImageID}}</span>
            <span>{{.UpdatedAt.Format "2006-01-02 15:04 MST"}}</span>
          </div>
        </div>
        <div class="chips">
          <span class="chip">{{.PackageCount}} packages</span>
          <span class="chip">{{.VulnerabilitySummary.Total}} vulnerabilities</span>
          {{if .Platform}}<span class="chip">platform {{.Platform}}</span>{{end}}
          {{if .Tag}}<span class="chip">tag {{.Tag}}</span>{{end}}
          {{if .Digest}}<span class="chip">{{.Digest}}</span>{{end}}
        </div>
      </article>
      {{else}}
      <section class="panel">
        <h2>No scanned images matched the current filters.</h2>
      </section>
      {{end}}
    </section>
  </main>
</body>
</html>`))

var browseImageTemplate = template.Must(template.New("browse-image").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Overview.ImageName}} | Otter</title>
  <style>
    :root { color-scheme: dark light; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; background: #0b1020; color: #e6edf7; }
    main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; display: grid; gap: 24px; }
    a { color: #7dd3fc; }
    .panel { border: 1px solid #22314d; background: rgba(14, 23, 42, 0.92); border-radius: 18px; padding: 18px; }
    .meta { display: flex; gap: 12px; flex-wrap: wrap; color: #97a5c0; font-size: 14px; }
    .grid { display: grid; gap: 16px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
    .stat { border: 1px solid #335180; border-radius: 14px; padding: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #22314d; vertical-align: top; }
  </style>
</head>
<body>
  <main>
    <section class="panel grid">
      <div>
        <a href="/browse">Back to directory</a>
      </div>
      <div>
        <h1>{{.Overview.ImageName}}</h1>
        <div class="meta">
          <span>{{.Overview.OrgID}} / {{.Overview.ImageID}}</span>
          <span>{{.Overview.UpdatedAt.Format "2006-01-02 15:04 MST"}}</span>
          {{if .Overview.Platform}}<span>platform {{.Overview.Platform}}</span>{{end}}
          <span>storage {{.Overview.StorageBackend}}</span>
        </div>
      </div>
      <div class="stats">
        <div class="stat"><strong>{{.Overview.PackageCount}}</strong><br>packages</div>
        <div class="stat"><strong>{{.Overview.VulnerabilitySummary.Total}}</strong><br>vulnerabilities</div>
        <div class="stat"><strong>{{len .Overview.Tags}}</strong><br>related tags</div>
        <div class="stat"><strong>{{len .Overview.Files}}</strong><br>artifacts</div>
      </div>
      <div class="meta">
        <a href="/api/v1/images/{{.Overview.ImageID}}/overview?org_id={{.Overview.OrgID}}">overview JSON</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/compliance?org_id={{.Overview.OrgID}}">compliance JSON</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/vulnerabilities?org_id={{.Overview.OrgID}}">vulnerabilities JSON</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/sbom?org_id={{.Overview.OrgID}}">sbom JSON</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/attestations?org_id={{.Overview.OrgID}}">attestations JSON</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/export?org_id={{.Overview.OrgID}}&format=cyclonedx">export CycloneDX</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/export?org_id={{.Overview.OrgID}}&format=spdx">export SPDX</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/export?org_id={{.Overview.OrgID}}&format=csv">export CSV</a>
        <a href="/api/v1/images/{{.Overview.ImageID}}/export?org_id={{.Overview.OrgID}}&format=sarif">export SARIF</a>
      </div>
    </section>
    <section class="panel">
      <h2>Compliance</h2>
      <div class="stats">
        <div class="stat"><strong>{{.Compliance.Summary.OverallStatus}}</strong><br>overall posture</div>
        <div class="stat"><strong>SLSA {{.Compliance.SLSA.Level}}</strong><br>{{if .Compliance.SLSA.Verified}}verified{{else}}unverified{{end}}</div>
        <div class="stat"><strong>{{if .Compliance.Scorecard.Available}}{{printf "%.1f" .Compliance.Scorecard.Score}}{{else}}n/a{{end}}</strong><br>OpenSSF Scorecard</div>
      </div>
      <div class="meta" style="margin-top: 12px;">
        {{if .Compliance.SourceRepo}}<span>Source: <a href="{{.Compliance.SourceRepo.URL}}">{{.Compliance.SourceRepo.Repository}}</a></span>{{end}}
        <span>{{.Compliance.ScopeNote}}</span>
      </div>
      <table>
        <thead><tr><th>Standard</th><th>Status</th><th>Summary</th></tr></thead>
        <tbody>
          {{range .Compliance.Standards}}
          <tr>
            <td>{{.Name}}</td>
            <td>{{.Status}}</td>
            <td>{{.Summary}}</td>
          </tr>
          {{else}}
          <tr><td colspan="3">No compliance signals available.</td></tr>
          {{end}}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Tags</h2>
      <table>
        <thead><tr><th>Tag</th><th>Image</th><th>Platform</th><th>Updated</th><th>Vulnerabilities</th></tr></thead>
        <tbody>
          {{range .Overview.Tags}}
          <tr>
            <td>{{if .Tag}}{{.Tag}}{{else}}{{.Digest}}{{end}}</td>
            <td><a href="/browse/images/{{.OrgID}}/{{.ImageID}}">{{.ImageName}}</a></td>
            <td>{{if .Platform}}{{.Platform}}{{else}}default{{end}}</td>
            <td>{{.UpdatedAt.Format "2006-01-02 15:04 MST"}}</td>
            <td>{{.VulnerabilitySummary.Total}}</td>
          </tr>
          {{else}}
          <tr><td colspan="5">No related tags.</td></tr>
          {{end}}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Top vulnerabilities</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Package</th><th>Fix</th></tr></thead>
        <tbody>
          {{range .Vulnerabilities}}
          <tr>
            <td>{{.ID}}</td>
            <td>{{.Severity}}</td>
            <td>{{.PackageName}} {{.PackageVersion}}</td>
            <td>{{if .FixVersion}}{{.FixVersion}}{{else}}none{{end}}</td>
          </tr>
          {{else}}
          <tr><td colspan="4">No structured vulnerabilities stored for this image.</td></tr>
          {{end}}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Top packages</h2>
      <table>
        <thead><tr><th>Name</th><th>Version</th><th>Type</th><th>Licenses</th></tr></thead>
        <tbody>
          {{range .Packages}}
          <tr>
            <td>{{.Name}}</td>
            <td>{{.Version}}</td>
            <td>{{.Type}}</td>
            <td>{{range $index, $license := .Licenses}}{{if $index}}, {{end}}{{$license}}{{end}}</td>
          </tr>
          {{else}}
          <tr><td colspan="4">No structured packages stored for this image.</td></tr>
          {{end}}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>`))
