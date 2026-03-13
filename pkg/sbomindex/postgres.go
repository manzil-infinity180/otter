package sbomindex

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
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

	record.UpdatedAt = time.Now().UTC()

	const query = `
INSERT INTO sbom_indexes (
	org_id, image_id, image_name, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10)
ON CONFLICT (org_id, image_id) DO UPDATE SET
	image_name = EXCLUDED.image_name,
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
SELECT image_name, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
WHERE org_id = $1 AND image_id = $2;
`

	var (
		record              Record
		packagesJSON        []byte
		dependencyTreeJSON  []byte
		dependencyRootsJSON []byte
		licenseSummaryJSON  []byte
		updatedAt           time.Time
	)

	if err := r.db.QueryRowContext(ctx, query, orgID, imageID).Scan(
		&record.ImageName,
		&record.SourceFormat,
		&record.PackageCount,
		&packagesJSON,
		&dependencyTreeJSON,
		&dependencyRootsJSON,
		&licenseSummaryJSON,
		&updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("get sbom index: %w", err)
	}

	record.OrgID = orgID
	record.ImageID = imageID
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

	return record, nil
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
