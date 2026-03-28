package sbomindex

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/otterXf/otter/pkg/storage"
)

const (
	defaultCatalogPage     = 1
	defaultCatalogPageSize = 20
	maxCatalogPageSize     = 100
)

type catalogReferenceParts struct {
	Repository     string
	RepositoryPath string
	Tag            string
	Digest         string
}

func validateRecordKey(orgID, imageID string) error {
	if err := storage.ValidateSegment("org_id", orgID); err != nil {
		return err
	}
	if err := storage.ValidateSegment("image_id", imageID); err != nil {
		return err
	}
	return nil
}

func normalizeCatalogQuery(query CatalogQuery) CatalogQuery {
	if query.Page <= 0 {
		query.Page = defaultCatalogPage
	}
	if query.PageSize <= 0 {
		query.PageSize = defaultCatalogPageSize
	}
	if query.PageSize > maxCatalogPageSize {
		query.PageSize = maxCatalogPageSize
	}
	query.SortBy = normalizeCatalogSort(query.SortBy)
	query.Query = strings.TrimSpace(query.Query)
	query.OrgID = strings.TrimSpace(query.OrgID)
	query.Severity = strings.ToUpper(strings.TrimSpace(query.Severity))
	query.AllowedOrgs = compactStrings(query.AllowedOrgs)
	return query
}

func normalizeCatalogSort(value string) string {
	switch strings.TrimSpace(value) {
	case "", "recent":
		return "recent"
	case "critical", "packages", "name":
		return value
	default:
		return "recent"
	}
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeRepositoryKey(imageName string) string {
	imageName = strings.TrimSpace(imageName)
	if imageName == "" {
		return ""
	}

	ref, err := name.ParseReference(imageName, name.WeakValidation)
	if err != nil {
		return stripReferenceIdentifier(imageName)
	}

	context := ref.Context()
	if context.RepositoryStr() == "" {
		return stripReferenceIdentifier(imageName)
	}
	return context.Name()
}

func stripReferenceIdentifier(imageName string) string {
	imageName = strings.TrimSpace(imageName)
	if imageName == "" {
		return ""
	}
	if index := strings.Index(imageName, "@"); index >= 0 {
		return imageName[:index]
	}
	slashIndex := strings.LastIndex(imageName, "/")
	colonIndex := strings.LastIndex(imageName, ":")
	if colonIndex > slashIndex {
		return imageName[:colonIndex]
	}
	return imageName
}

func parseCatalogReference(imageName string) catalogReferenceParts {
	imageName = strings.TrimSpace(imageName)
	if imageName == "" {
		return catalogReferenceParts{}
	}

	ref, err := name.ParseReference(imageName, name.WeakValidation)
	if err != nil {
		repository := stripReferenceIdentifier(imageName)
		return catalogReferenceParts{
			Repository:     repository,
			RepositoryPath: repository,
		}
	}

	context := ref.Context()
	parts := catalogReferenceParts{
		Repository:     context.Name(),
		RepositoryPath: context.RepositoryStr(),
	}
	identifier := ref.Identifier()
	if strings.HasPrefix(identifier, "sha256:") {
		parts.Digest = identifier
	} else {
		parts.Tag = identifier
	}
	return parts
}

func normalizeRecordForSave(record Record) Record {
	record.RepositoryKey = strings.TrimSpace(record.RepositoryKey)
	if record.RepositoryKey == "" {
		record.RepositoryKey = normalizeRepositoryKey(record.ImageName)
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = time.Now().UTC()
	} else {
		record.UpdatedAt = record.UpdatedAt.UTC()
	}
	return record
}

func catalogRecordFromSBOM(record Record) CatalogRecord {
	record = normalizeRecordForSave(record)
	return CatalogRecord{
		OrgID:          record.OrgID,
		ImageID:        record.ImageID,
		ImageName:      record.ImageName,
		RepositoryKey:  record.RepositoryKey,
		Platform:       record.Platform,
		SourceFormat:   record.SourceFormat,
		PackageCount:   record.PackageCount,
		LicenseSummary: append([]LicenseSummaryEntry(nil), record.LicenseSummary...),
		UpdatedAt:      record.UpdatedAt,
	}
}

func matchesCatalogRecord(record CatalogRecord, query CatalogQuery) bool {
	if len(query.AllowedOrgs) > 0 && !containsString(query.AllowedOrgs, record.OrgID) {
		return false
	}
	if query.OrgID != "" && record.OrgID != query.OrgID {
		return false
	}
	if query.Severity != "" && record.VulnerabilitySummary.BySeverity[query.Severity] == 0 {
		return false
	}
	if query.Query == "" {
		return true
	}

	ref := parseCatalogReference(record.ImageName)
	searchable := []string{
		record.OrgID,
		record.ImageID,
		record.ImageName,
		record.RepositoryKey,
		ref.Repository,
		ref.RepositoryPath,
		ref.Tag,
		ref.Digest,
	}
	lowerQuery := strings.ToLower(query.Query)
	for _, field := range searchable {
		if strings.Contains(strings.ToLower(field), lowerQuery) {
			return true
		}
	}

	return false
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func compareCatalogRecords(left, right CatalogRecord, sortBy string) bool {
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
		leftRepository := catalogRepositorySortKey(left)
		rightRepository := catalogRepositorySortKey(right)
		if leftRepository != rightRepository {
			return leftRepository < rightRepository
		}
		if left.ImageName != right.ImageName {
			return left.ImageName < right.ImageName
		}
	}

	if left.UpdatedAt.Equal(right.UpdatedAt) {
		leftRepository := catalogRepositorySortKey(left)
		rightRepository := catalogRepositorySortKey(right)
		if leftRepository != rightRepository {
			return leftRepository < rightRepository
		}
		if left.OrgID != right.OrgID {
			return left.OrgID < right.OrgID
		}
		return left.ImageID < right.ImageID
	}
	return left.UpdatedAt.After(right.UpdatedAt)
}

func catalogRepositorySortKey(record CatalogRecord) string {
	if strings.TrimSpace(record.RepositoryKey) != "" {
		return record.RepositoryKey
	}
	return parseCatalogReference(record.ImageName).Repository
}

func sortCatalogRecords(records []CatalogRecord, sortBy string) {
	sort.Slice(records, func(i, j int) bool {
		return compareCatalogRecords(records[i], records[j], sortBy)
	})
}

func catalogPageBounds(query CatalogQuery) (start int, end int) {
	query = normalizeCatalogQuery(query)
	start = (query.Page - 1) * query.PageSize
	end = start + query.PageSize
	return start, end
}

func repositoryKeyStoragePath(repositoryKey string) string {
	return url.PathEscape(strings.TrimSpace(repositoryKey))
}
