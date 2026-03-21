package sbomindex

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/otterXf/otter/pkg/vulnindex"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(ctx context.Context, dsn string) (*PostgresRepository, error) {
	if dsn == "" {
		return nil, errors.New("postgres dsn is required")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	repo := &PostgresRepository{db: db}
	if err := repo.db.PingContext(ctx); err != nil {
		_ = repo.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return repo, nil
}

func newPostgresRepositoryWithDB(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) Save(ctx context.Context, record Record) (Record, error) {
	if err := validateRecordKey(record.OrgID, record.ImageID); err != nil {
		return Record{}, err
	}

	record = normalizeRecordForSave(record)

	packagesJSON, err := json.Marshal(record.Packages)
	if err != nil {
		return Record{}, fmt.Errorf("marshal sbom packages: %w", err)
	}
	dependenciesJSON, err := json.Marshal(record.DependencyTree)
	if err != nil {
		return Record{}, fmt.Errorf("marshal sbom dependency tree: %w", err)
	}
	rootsJSON, err := json.Marshal(record.DependencyRoots)
	if err != nil {
		return Record{}, fmt.Errorf("marshal sbom dependency roots: %w", err)
	}
	licenseSummaryJSON, err := json.Marshal(record.LicenseSummary)
	if err != nil {
		return Record{}, fmt.Errorf("marshal sbom license summary: %w", err)
	}

	const query = `
INSERT INTO sbom_indexes (
	org_id, image_id, image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12)
ON CONFLICT (org_id, image_id) DO UPDATE SET
	image_name = EXCLUDED.image_name,
	repository_key = EXCLUDED.repository_key,
	platform = EXCLUDED.platform,
	source_format = EXCLUDED.source_format,
	package_count = EXCLUDED.package_count,
	packages = EXCLUDED.packages,
	dependency_tree = EXCLUDED.dependency_tree,
	dependency_roots = EXCLUDED.dependency_roots,
	license_summary = EXCLUDED.license_summary,
	updated_at = EXCLUDED.updated_at
RETURNING updated_at;
`

	if err := r.db.QueryRowContext(
		ctx,
		query,
		record.OrgID,
		record.ImageID,
		record.ImageName,
		record.RepositoryKey,
		record.Platform,
		record.SourceFormat,
		record.PackageCount,
		packagesJSON,
		dependenciesJSON,
		rootsJSON,
		licenseSummaryJSON,
		record.UpdatedAt,
	).Scan(&record.UpdatedAt); err != nil {
		return Record{}, fmt.Errorf("upsert sbom index: %w", err)
	}

	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func (r *PostgresRepository) Get(ctx context.Context, orgID, imageID string) (Record, error) {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return Record{}, err
	}

	const query = `
SELECT image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
WHERE org_id = $1 AND image_id = $2;
`

	record, err := scanSBOMRecordRow(r.db.QueryRowContext(ctx, query, orgID, imageID), true)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("get sbom index: %w", err)
	}
	record.OrgID = orgID
	record.ImageID = imageID
	return record, nil
}

func (r *PostgresRepository) List(ctx context.Context) ([]Record, error) {
	const query = `
SELECT org_id, image_id, image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
ORDER BY updated_at DESC, org_id ASC, image_id ASC;
`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list sbom indexes: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows cleanup after iteration

	return scanSBOMRecordRows(rows, false)
}

func (r *PostgresRepository) QueryCatalog(ctx context.Context, query CatalogQuery) (CatalogPage, error) {
	query = normalizeCatalogQuery(query)
	baseArgs := make([]any, 0, 8)
	whereClause, args := buildCatalogWhereClause(query, baseArgs)

	countQuery := `
SELECT COUNT(*)
FROM sbom_indexes s
LEFT JOIN vulnerability_indexes v
	ON v.org_id = s.org_id AND v.image_id = s.image_id
WHERE ` + whereClause + `;`

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return CatalogPage{}, fmt.Errorf("count catalog records: %w", err)
	}
	if total == 0 {
		return CatalogPage{Items: []CatalogRecord{}, Total: 0}, nil
	}

	selectArgs := append([]any(nil), args...)
	start, _ := catalogPageBounds(query)
	selectArgs = append(selectArgs, query.PageSize, start)

	selectQuery := `
SELECT
	s.org_id,
	s.image_id,
	s.image_name,
	s.repository_key,
	s.platform,
	s.source_format,
	s.package_count,
	s.license_summary,
	COALESCE(v.summary, '{}'::jsonb) AS vulnerability_summary,
	GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) AS updated_at
FROM sbom_indexes s
LEFT JOIN vulnerability_indexes v
	ON v.org_id = s.org_id AND v.image_id = s.image_id
WHERE ` + whereClause + `
ORDER BY ` + catalogOrderByClause(query.SortBy) + `
LIMIT $` + fmt.Sprintf("%d", len(selectArgs)-1) + ` OFFSET $` + fmt.Sprintf("%d", len(selectArgs)) + `;
`

	rows, err := r.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return CatalogPage{}, fmt.Errorf("query catalog records: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows cleanup after iteration

	items, err := scanCatalogRows(rows)
	if err != nil {
		return CatalogPage{}, fmt.Errorf("scan catalog records: %w", err)
	}

	return CatalogPage{Items: items, Total: total}, nil
}

func (r *PostgresRepository) ListRepositoryTags(ctx context.Context, query RepositoryTagQuery) ([]CatalogRecord, error) {
	query.OrgID = strings.TrimSpace(query.OrgID)
	query.RepositoryKey = strings.TrimSpace(query.RepositoryKey)
	query.ExcludeImageID = strings.TrimSpace(query.ExcludeImageID)

	if err := validateRecordKey(query.OrgID, "placeholder-image"); err != nil {
		return nil, fmt.Errorf("validate repository tag org: %w", err)
	}
	if query.RepositoryKey == "" {
		return nil, errors.New("repository_key is required")
	}

	const sqlQuery = `
SELECT
	s.org_id,
	s.image_id,
	s.image_name,
	s.repository_key,
	s.platform,
	s.source_format,
	s.package_count,
	s.license_summary,
	COALESCE(v.summary, '{}'::jsonb) AS vulnerability_summary,
	GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) AS updated_at
FROM sbom_indexes s
LEFT JOIN vulnerability_indexes v
	ON v.org_id = s.org_id AND v.image_id = s.image_id
WHERE s.org_id = $1
	AND s.repository_key = $2
	AND ($3 = '' OR s.image_id <> $3)
ORDER BY GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) DESC, s.image_name ASC;
`

	rows, err := r.db.QueryContext(ctx, sqlQuery, query.OrgID, query.RepositoryKey, query.ExcludeImageID)
	if err != nil {
		return nil, fmt.Errorf("list repository tags: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows cleanup after iteration

	return scanCatalogRows(rows)
}

func (r *PostgresRepository) FindByImageName(ctx context.Context, imageName string) ([]Record, error) {
	imageName = strings.TrimSpace(imageName)
	if imageName == "" {
		return nil, errors.New("image_name is required")
	}

	const query = `
SELECT org_id, image_id, image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
WHERE image_name = $1
ORDER BY updated_at DESC, org_id ASC, image_id ASC;
`

	rows, err := r.db.QueryContext(ctx, query, imageName)
	if err != nil {
		return nil, fmt.Errorf("find sbom indexes by image name: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows cleanup after iteration

	return scanSBOMRecordRows(rows, false)
}

func (r *PostgresRepository) Delete(ctx context.Context, orgID, imageID string) error {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return err
	}

	if _, err := r.db.ExecContext(ctx, `DELETE FROM sbom_indexes WHERE org_id = $1 AND image_id = $2`, orgID, imageID); err != nil {
		return fmt.Errorf("delete sbom index: %w", err)
	}
	return nil
}

func (r *PostgresRepository) Close() error {
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}

type sbomRowScanner interface {
	Scan(dest ...any) error
}

func scanSBOMRecordRow(scanner sbomRowScanner, withoutOrgKeys bool) (Record, error) {
	var (
		record              Record
		packagesJSON        []byte
		dependencyTreeJSON  []byte
		dependencyRootsJSON []byte
		licenseSummaryJSON  []byte
		updatedAt           time.Time
	)

	if withoutOrgKeys {
		if err := scanner.Scan(
			&record.ImageName,
			&record.RepositoryKey,
			&record.Platform,
			&record.SourceFormat,
			&record.PackageCount,
			&packagesJSON,
			&dependencyTreeJSON,
			&dependencyRootsJSON,
			&licenseSummaryJSON,
			&updatedAt,
		); err != nil {
			return Record{}, err
		}
	} else {
		if err := scanner.Scan(
			&record.OrgID,
			&record.ImageID,
			&record.ImageName,
			&record.RepositoryKey,
			&record.Platform,
			&record.SourceFormat,
			&record.PackageCount,
			&packagesJSON,
			&dependencyTreeJSON,
			&dependencyRootsJSON,
			&licenseSummaryJSON,
			&updatedAt,
		); err != nil {
			return Record{}, err
		}
	}

	record.UpdatedAt = updatedAt.UTC()
	if err := json.Unmarshal(packagesJSON, &record.Packages); err != nil {
		return Record{}, fmt.Errorf("decode sbom packages: %w", err)
	}
	if err := json.Unmarshal(dependencyTreeJSON, &record.DependencyTree); err != nil {
		return Record{}, fmt.Errorf("decode sbom dependency tree: %w", err)
	}
	if len(dependencyRootsJSON) > 0 {
		if err := json.Unmarshal(dependencyRootsJSON, &record.DependencyRoots); err != nil {
			return Record{}, fmt.Errorf("decode sbom dependency roots: %w", err)
		}
	}
	if err := json.Unmarshal(licenseSummaryJSON, &record.LicenseSummary); err != nil {
		return Record{}, fmt.Errorf("decode sbom license summary: %w", err)
	}

	return normalizeRecordForSave(record), nil
}

func scanSBOMRecordRows(rows *sql.Rows, withoutOrgKeys bool) ([]Record, error) {
	records := make([]Record, 0)
	for rows.Next() {
		record, err := scanSBOMRecordRow(rows, withoutOrgKeys)
		if err != nil {
			return nil, fmt.Errorf("scan sbom index: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sbom indexes: %w", err)
	}
	return records, nil
}

func scanCatalogRows(rows *sql.Rows) ([]CatalogRecord, error) {
	records := make([]CatalogRecord, 0)
	for rows.Next() {
		var (
			record                   CatalogRecord
			licenseSummaryJSON       []byte
			vulnerabilitySummaryJSON []byte
			updatedAt                time.Time
		)

		if err := rows.Scan(
			&record.OrgID,
			&record.ImageID,
			&record.ImageName,
			&record.RepositoryKey,
			&record.Platform,
			&record.SourceFormat,
			&record.PackageCount,
			&licenseSummaryJSON,
			&vulnerabilitySummaryJSON,
			&updatedAt,
		); err != nil {
			return nil, err
		}

		record.UpdatedAt = updatedAt.UTC()
		if len(licenseSummaryJSON) > 0 {
			if err := json.Unmarshal(licenseSummaryJSON, &record.LicenseSummary); err != nil {
				return nil, fmt.Errorf("decode license summary: %w", err)
			}
		}
		if len(vulnerabilitySummaryJSON) > 0 {
			if err := json.Unmarshal(vulnerabilitySummaryJSON, &record.VulnerabilitySummary); err != nil {
				return nil, fmt.Errorf("decode vulnerability summary: %w", err)
			}
		}
		record.VulnerabilitySummary = ensureCatalogSummaryMaps(record.VulnerabilitySummary)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func ensureCatalogSummaryMaps(summary vulnindex.Summary) vulnindex.Summary {
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

func buildCatalogWhereClause(query CatalogQuery, args []any) (string, []any) {
	clauses := []string{"1=1"}
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	if query.OrgID != "" {
		clauses = append(clauses, "s.org_id = "+addArg(query.OrgID))
	}
	if len(query.AllowedOrgs) > 0 {
		placeholders := make([]string, 0, len(query.AllowedOrgs))
		for _, orgID := range query.AllowedOrgs {
			placeholders = append(placeholders, addArg(orgID))
		}
		clauses = append(clauses, "s.org_id IN ("+strings.Join(placeholders, ", ")+")")
	}
	if query.Query != "" {
		like := addArg("%" + strings.ToLower(query.Query) + "%")
		clauses = append(clauses, "(LOWER(s.org_id) LIKE "+like+" OR LOWER(s.image_id) LIKE "+like+" OR LOWER(s.image_name) LIKE "+like+" OR LOWER(COALESCE(s.repository_key, '')) LIKE "+like+")")
	}
	if query.Severity != "" {
		severity := addArg(query.Severity)
		clauses = append(clauses, "COALESCE((v.summary->'by_severity'->>"+severity+")::int, 0) > 0")
	}

	return strings.Join(clauses, " AND "), args
}

func catalogOrderByClause(sortBy string) string {
	switch normalizeCatalogSort(sortBy) {
	case "critical":
		return "COALESCE((v.summary->'by_severity'->>'CRITICAL')::int, 0) DESC, GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) DESC, s.org_id ASC, s.image_id ASC"
	case "packages":
		return "s.package_count DESC, GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) DESC, s.org_id ASC, s.image_id ASC"
	case "name":
		return "COALESCE(s.repository_key, s.image_name) ASC, s.image_name ASC, GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) DESC, s.org_id ASC, s.image_id ASC"
	default:
		return "GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) DESC, s.org_id ASC, s.image_id ASC"
	}
}
