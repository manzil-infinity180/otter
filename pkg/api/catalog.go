package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/sync/errgroup"

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

type ImageOverview struct {
	ImageCatalogEntry
	StorageBackend  string            `json:"storage_backend"`
	DependencyRoots []string          `json:"dependency_roots,omitempty"`
	Files           []ObjectResponse  `json:"files"`
	Tags            []ImageTagSummary `json:"tags"`
}

type catalogFilters struct {
	OrgID       string
	Query       string
	Severity    string
	SortBy      string
	AllowedOrgs map[string]struct{}
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

	entries, err := h.buildCatalog(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load catalog: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"storage_backend": h.store.Backend(),
		"count":           len(entries),
		"items":           entries,
		"filters": gin.H{
			"org_id":   filters.OrgID,
			"query":    filters.Query,
			"severity": filters.Severity,
			"sort":     filters.SortBy,
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

func (h *ScanHandler) BrowseCatalog(c *gin.Context) {
	filters, err := parseCatalogFilters(c)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
	if !authorizeCatalogFilters(c, &filters) {
		return
	}

	entries, err := h.buildCatalog(c.Request.Context(), filters)
	if err != nil {
		c.String(http.StatusInternalServerError, "load catalog: %v", err)
		return
	}

	var body bytes.Buffer
	data := struct {
		Entries []ImageCatalogEntry
		Filters catalogFilters
	}{
		Entries: entries,
		Filters: filters,
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

	vulnerabilityRecord, err := h.getOrCreateVulnerabilityRecord(c.Request.Context(), orgID, imageID)
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
		OrgID:  strings.TrimSpace(c.Query("org_id")),
		Query:  strings.TrimSpace(c.Query("query")),
		SortBy: strings.TrimSpace(c.DefaultQuery("sort", "recent")),
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

	return filters, nil
}

func (h *ScanHandler) buildCatalog(ctx context.Context, filters catalogFilters) ([]ImageCatalogEntry, error) {
	records, err := h.sbomIndex.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list sbom index records: %w", err)
	}

	entries := make([]ImageCatalogEntry, len(records))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(8)
	for index, record := range records {
		index := index
		record := record
		group.Go(func() error {
			entry, err := h.buildCatalogEntry(groupCtx, record)
			if err != nil {
				return err
			}
			entries[index] = entry
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}

	filtered := make([]ImageCatalogEntry, 0, len(entries))
	for _, entry := range entries {
		if !matchesCatalogFilters(entry, filters) {
			continue
		}
		filtered = append(filtered, entry)
	}

	sortCatalogEntries(filtered, filters.SortBy)
	return filtered, nil
}

func (h *ScanHandler) buildCatalogEntry(ctx context.Context, record sbomindex.Record) (ImageCatalogEntry, error) {
	refParts := parseImageReference(record.ImageName)
	vulnerabilityRecord, err := h.getExistingVulnerabilityRecord(ctx, record.OrgID, record.ImageID)
	if err != nil {
		return ImageCatalogEntry{}, fmt.Errorf("load vulnerability summary for %s/%s: %w", record.OrgID, record.ImageID, err)
	}

	entry := ImageCatalogEntry{
		OrgID:          record.OrgID,
		ImageID:        record.ImageID,
		ImageName:      record.ImageName,
		Registry:       refParts.Registry,
		Platform:       record.Platform,
		Repository:     refParts.Repository,
		RepositoryPath: refParts.RepositoryPath,
		Tag:            refParts.Tag,
		Digest:         refParts.Digest,
		PackageCount:   record.PackageCount,
		LicenseSummary: record.LicenseSummary,
		UpdatedAt:      record.UpdatedAt,
	}
	if vulnerabilityRecord != nil {
		entry.VulnerabilitySummary = vulnerabilityRecord.Summary
		entry.Scanners = sortedSummaryKeys(vulnerabilityRecord.Summary.ByScanner)
		entry.UpdatedAt = latestTimestamp(entry.UpdatedAt, vulnerabilityRecord.UpdatedAt)
	}

	return entry, nil
}

func (h *ScanHandler) buildImageOverview(ctx context.Context, orgID, imageID string) (ImageOverview, error) {
	record, err := h.sbomIndex.Get(ctx, orgID, imageID)
	if err != nil {
		return ImageOverview{}, err
	}

	entry, err := h.buildCatalogEntry(ctx, record)
	if err != nil {
		return ImageOverview{}, err
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

	records, err := h.sbomIndex.List(ctx)
	if err != nil {
		return ImageOverview{}, fmt.Errorf("list related sbom index records: %w", err)
	}

	tags := make([]ImageTagSummary, 0)
	for _, candidate := range records {
		if candidate.OrgID != orgID {
			continue
		}
		if candidate.ImageID == imageID {
			continue
		}
		candidateRef := parseImageReference(candidate.ImageName)
		if candidateRef.Repository == "" || candidateRef.Repository != entry.Repository {
			continue
		}

		vulnerabilityRecord, err := h.getExistingVulnerabilityRecord(ctx, candidate.OrgID, candidate.ImageID)
		if err != nil {
			return ImageOverview{}, fmt.Errorf("load related vulnerability summary for %s/%s: %w", candidate.OrgID, candidate.ImageID, err)
		}

		tag := ImageTagSummary{
			OrgID:        candidate.OrgID,
			ImageID:      candidate.ImageID,
			ImageName:    candidate.ImageName,
			Platform:     candidate.Platform,
			Tag:          candidateRef.Tag,
			Digest:       candidateRef.Digest,
			PackageCount: candidate.PackageCount,
			UpdatedAt:    candidate.UpdatedAt,
		}
		if vulnerabilityRecord != nil {
			tag.VulnerabilitySummary = vulnerabilityRecord.Summary
			tag.UpdatedAt = latestTimestamp(tag.UpdatedAt, vulnerabilityRecord.UpdatedAt)
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
	}, nil
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
