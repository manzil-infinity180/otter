package sbomindex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

const (
	sbomIndexFilename              = "sbom-index.json"
	catalogIndexFilename           = "catalog-record.json"
	vulnerabilitySummaryFilename   = "vulnerability-summary.json"
	vulnerabilityIndexFilename     = "vulnerability-index.json"
	localCatalogRootDir            = "_catalog"
	localRepositoryCatalogRootDir  = "_repositories"
	localVulnerabilityIndexRootDir = "_vulnerability_index"
)

type LocalRepository struct {
	rootDir string
}

func NewLocalRepository(rootDir string) (*LocalRepository, error) {
	if rootDir == "" {
		return nil, errors.New("sbom index root directory is required")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sbom index root: %w", err)
	}
	return &LocalRepository{rootDir: rootDir}, nil
}

func (r *LocalRepository) Save(_ context.Context, record Record) (Record, error) {
	if err := validateRecordKey(record.OrgID, record.ImageID); err != nil {
		return Record{}, err
	}

	record = normalizeRecordForSave(record)
	existingCatalog, _ := r.readCatalogRecord(record.OrgID, record.ImageID)

	if err := writeJSONAtomic(r.recordPath(record.OrgID, record.ImageID), record); err != nil {
		return Record{}, fmt.Errorf("write sbom index record: %w", err)
	}

	catalogRecord := catalogRecordFromSBOM(record)
	if err := writeJSONAtomic(r.catalogRecordPath(record.OrgID, record.ImageID), catalogRecord); err != nil {
		return Record{}, fmt.Errorf("write catalog index record: %w", err)
	}
	if err := writeJSONAtomic(r.repositoryRecordPath(catalogRecord.OrgID, catalogRecord.RepositoryKey, catalogRecord.ImageID), catalogRecord); err != nil {
		return Record{}, fmt.Errorf("write repository catalog record: %w", err)
	}

	if existingCatalog.RepositoryKey != "" && existingCatalog.RepositoryKey != catalogRecord.RepositoryKey {
		if err := os.Remove(r.repositoryRecordPath(existingCatalog.OrgID, existingCatalog.RepositoryKey, existingCatalog.ImageID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Record{}, fmt.Errorf("remove stale repository catalog record: %w", err)
		}
	}

	return record, nil
}

func (r *LocalRepository) Get(_ context.Context, orgID, imageID string) (Record, error) {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return Record{}, err
	}

	data, err := os.ReadFile(r.recordPath(orgID, imageID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("read sbom index record: %w", err)
	}

	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, fmt.Errorf("decode sbom index record: %w", err)
	}
	record = normalizeRecordForSave(record)
	return record, nil
}

func (r *LocalRepository) List(_ context.Context) ([]Record, error) {
	root := filepath.Join(r.rootDir, storage.ArtifactRootPrefix)
	records := make([]Record, 0)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || d.Name() != sbomIndexFilename {
			return nil
		}

		record, err := readJSONFile[Record](path)
		if err != nil {
			return fmt.Errorf("read sbom index record: %w", err)
		}
		records = append(records, normalizeRecordForSave(record))
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list sbom indexes: %w", err)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			if records[i].OrgID != records[j].OrgID {
				return records[i].OrgID < records[j].OrgID
			}
			return records[i].ImageID < records[j].ImageID
		}
		if records[i].UpdatedAt.IsZero() {
			return false
		}
		if records[j].UpdatedAt.IsZero() {
			return true
		}
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})

	return records, nil
}

func (r *LocalRepository) QueryCatalog(_ context.Context, query CatalogQuery) (CatalogPage, error) {
	query = normalizeCatalogQuery(query)
	start, end := catalogPageBounds(query)
	catalogRoot := filepath.Join(r.rootDir, localCatalogRootDir)

	best := make([]CatalogRecord, 0, end)
	total := 0
	err := filepath.WalkDir(catalogRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || d.Name() != catalogIndexFilename {
			return nil
		}

		record, err := readJSONFile[CatalogRecord](path)
		if err != nil {
			return fmt.Errorf("read catalog index record: %w", err)
		}
		record = r.enrichCatalogRecord(record)
		if !matchesCatalogRecord(record, query) {
			return nil
		}

		total++
		best = keepBestCatalogRecords(best, record, end, query.SortBy)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CatalogPage{}, nil
		}
		return CatalogPage{}, fmt.Errorf("query catalog: %w", err)
	}

	sortCatalogRecords(best, query.SortBy)
	if start >= len(best) {
		return CatalogPage{Items: []CatalogRecord{}, Total: total}, nil
	}
	if end > len(best) {
		end = len(best)
	}
	return CatalogPage{
		Items: append([]CatalogRecord(nil), best[start:end]...),
		Total: total,
	}, nil
}

func (r *LocalRepository) ListRepositoryTags(_ context.Context, query RepositoryTagQuery) ([]CatalogRecord, error) {
	query.OrgID = strings.TrimSpace(query.OrgID)
	query.RepositoryKey = strings.TrimSpace(query.RepositoryKey)
	query.ExcludeImageID = strings.TrimSpace(query.ExcludeImageID)
	if err := storage.ValidateSegment("org_id", query.OrgID); err != nil {
		return nil, err
	}
	if query.RepositoryKey == "" {
		return nil, errors.New("repository_key is required")
	}

	repositoryRoot := r.repositoryRoot(query.OrgID, query.RepositoryKey)
	records := make([]CatalogRecord, 0)
	err := filepath.WalkDir(repositoryRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || d.Name() != catalogIndexFilename {
			return nil
		}

		record, err := readJSONFile[CatalogRecord](path)
		if err != nil {
			return fmt.Errorf("read repository catalog record: %w", err)
		}
		record = r.enrichCatalogRecord(record)
		if record.ImageID == query.ExcludeImageID {
			return nil
		}
		records = append(records, record)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list repository tags: %w", err)
	}

	sortCatalogRecords(records, "recent")
	return records, nil
}

func (r *LocalRepository) FindByImageName(_ context.Context, imageName string) ([]Record, error) {
	imageName = strings.TrimSpace(imageName)
	if imageName == "" {
		return nil, errors.New("image_name is required")
	}

	root := filepath.Join(r.rootDir, storage.ArtifactRootPrefix)
	matches := make([]Record, 0)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || d.Name() != sbomIndexFilename {
			return nil
		}

		record, err := readJSONFile[Record](path)
		if err != nil {
			return fmt.Errorf("read sbom index record: %w", err)
		}
		record = normalizeRecordForSave(record)
		if strings.TrimSpace(record.ImageName) == imageName {
			matches = append(matches, record)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("find sbom indexes by image name: %w", err)
	}

	return matches, nil
}

func (r *LocalRepository) Delete(_ context.Context, orgID, imageID string) error {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return err
	}

	catalogRecord, _ := r.readCatalogRecord(orgID, imageID)
	for _, path := range []string{
		r.recordPath(orgID, imageID),
		r.catalogRecordPath(orgID, imageID),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete sbom index record: %w", err)
		}
	}
	if catalogRecord.RepositoryKey != "" {
		if err := os.Remove(r.repositoryRecordPath(orgID, catalogRecord.RepositoryKey, imageID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete repository catalog record: %w", err)
		}
	}
	return nil
}

func (r *LocalRepository) Close() error {
	return nil
}

func (r *LocalRepository) recordPath(orgID, imageID string) string {
	return filepath.Join(r.rootDir, storage.ArtifactRootPrefix, orgID, imageID, sbomIndexFilename)
}

func (r *LocalRepository) catalogRecordPath(orgID, imageID string) string {
	return filepath.Join(r.rootDir, localCatalogRootDir, orgID, imageID, catalogIndexFilename)
}

func (r *LocalRepository) repositoryRoot(orgID, repositoryKey string) string {
	return filepath.Join(r.rootDir, localRepositoryCatalogRootDir, orgID, repositoryKeyStoragePath(repositoryKey))
}

func (r *LocalRepository) repositoryRecordPath(orgID, repositoryKey, imageID string) string {
	return filepath.Join(r.repositoryRoot(orgID, repositoryKey), imageID, catalogIndexFilename)
}

func (r *LocalRepository) readCatalogRecord(orgID, imageID string) (CatalogRecord, error) {
	record, err := readJSONFile[CatalogRecord](r.catalogRecordPath(orgID, imageID))
	if err != nil {
		return CatalogRecord{}, err
	}
	return record, nil
}

func (r *LocalRepository) enrichCatalogRecord(record CatalogRecord) CatalogRecord {
	record.RepositoryKey = strings.TrimSpace(record.RepositoryKey)
	if record.RepositoryKey == "" {
		record.RepositoryKey = normalizeRepositoryKey(record.ImageName)
	}

	summary, updatedAt, err := r.loadVulnerabilitySummary(record.OrgID, record.ImageID)
	if err == nil {
		record.VulnerabilitySummary = summary
		if updatedAt.After(record.UpdatedAt) {
			record.UpdatedAt = updatedAt
		}
	}
	return record
}

func (r *LocalRepository) loadVulnerabilitySummary(orgID, imageID string) (vulnindex.Summary, time.Time, error) {
	summaryPath := filepath.Join(r.vulnerabilityRootDir(), storage.ArtifactRootPrefix, orgID, imageID, vulnerabilitySummaryFilename)
	summaryRecord, err := readJSONFile[struct {
		Summary   vulnindex.Summary `json:"summary"`
		UpdatedAt time.Time         `json:"updated_at"`
	}](summaryPath)
	if err == nil {
		return ensureSummaryMaps(summaryRecord.Summary), summaryRecord.UpdatedAt.UTC(), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return vulnindex.Summary{}, time.Time{}, err
	}

	fullRecordPath := filepath.Join(r.vulnerabilityRootDir(), storage.ArtifactRootPrefix, orgID, imageID, vulnerabilityIndexFilename)
	fullRecord, err := readJSONFile[vulnindex.Record](fullRecordPath)
	if err != nil {
		return vulnindex.Summary{}, time.Time{}, err
	}
	return ensureSummaryMaps(fullRecord.Summary), fullRecord.UpdatedAt.UTC(), nil
}

func (r *LocalRepository) vulnerabilityRootDir() string {
	return filepath.Join(filepath.Dir(r.rootDir), localVulnerabilityIndexRootDir)
}

func keepBestCatalogRecords(records []CatalogRecord, candidate CatalogRecord, limit int, sortBy string) []CatalogRecord {
	if limit <= 0 {
		return records
	}

	if len(records) < limit {
		records = append(records, candidate)
		sortCatalogRecords(records, sortBy)
		return records
	}

	sortCatalogRecords(records, sortBy)
	if !compareCatalogRecords(candidate, records[len(records)-1], sortBy) {
		return records
	}
	records[len(records)-1] = candidate
	sortCatalogRecords(records, sortBy)
	return records
}

func ensureSummaryMaps(summary vulnindex.Summary) vulnindex.Summary {
	if summary.BySeverity == nil {
		summary.BySeverity = map[string]int{}
	}
	if summary.ByScanner == nil {
		summary.ByScanner = map[string]int{}
	}
	if summary.ByStatus == nil {
		summary.ByStatus = map[string]int{}
	}
	return summary
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create directories for %s: %w", path, err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("move %s into place: %w", path, err)
	}
	return nil
}

func readJSONFile[T any](path string) (T, error) {
	var value T

	data, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, err
	}
	return value, nil
}
