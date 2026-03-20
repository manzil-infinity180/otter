package vulnindex

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

	summaryJSON, err := json.Marshal(record.Summary)
	if err != nil {
		return Record{}, fmt.Errorf("marshal vulnerability summary: %w", err)
	}
	vulnerabilitiesJSON, err := json.Marshal(record.Vulnerabilities)
	if err != nil {
		return Record{}, fmt.Errorf("marshal vulnerabilities: %w", err)
	}
	recommendationsJSON, err := json.Marshal(record.FixRecommendations)
	if err != nil {
		return Record{}, fmt.Errorf("marshal fix recommendations: %w", err)
	}
	trendJSON, err := json.Marshal(record.Trend)
	if err != nil {
		return Record{}, fmt.Errorf("marshal vulnerability trend: %w", err)
	}
	vexJSON, err := json.Marshal(record.VEXDocuments)
	if err != nil {
		return Record{}, fmt.Errorf("marshal VEX documents: %w", err)
	}

	record.UpdatedAt = time.Now().UTC()

	const query = `
INSERT INTO vulnerability_indexes (
	org_id, image_id, image_name, platform, summary, vulnerabilities, fix_recommendations, trend, vex_documents, updated_at
)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10)
ON CONFLICT (org_id, image_id) DO UPDATE SET
	image_name = EXCLUDED.image_name,
	platform = EXCLUDED.platform,
	summary = EXCLUDED.summary,
	vulnerabilities = EXCLUDED.vulnerabilities,
	fix_recommendations = EXCLUDED.fix_recommendations,
	trend = EXCLUDED.trend,
	vex_documents = EXCLUDED.vex_documents,
	updated_at = EXCLUDED.updated_at
RETURNING updated_at;
`

	if err := r.db.QueryRowContext(
		ctx,
		query,
		record.OrgID,
		record.ImageID,
		record.ImageName,
		record.Platform,
		summaryJSON,
		vulnerabilitiesJSON,
		recommendationsJSON,
		trendJSON,
		vexJSON,
		record.UpdatedAt,
	).Scan(&record.UpdatedAt); err != nil {
		return Record{}, fmt.Errorf("upsert vulnerability index: %w", err)
	}

	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func (r *PostgresRepository) Get(ctx context.Context, orgID, imageID string) (Record, error) {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return Record{}, err
	}

	const query = `
SELECT image_name, platform, summary, vulnerabilities, fix_recommendations, trend, vex_documents, updated_at
FROM vulnerability_indexes
WHERE org_id = $1 AND image_id = $2;
`

	var (
		record              Record
		summaryJSON         []byte
		vulnerabilitiesJSON []byte
		recommendationsJSON []byte
		trendJSON           []byte
		vexJSON             []byte
		updatedAt           time.Time
	)

	if err := r.db.QueryRowContext(ctx, query, orgID, imageID).Scan(
		&record.ImageName,
		&record.Platform,
		&summaryJSON,
		&vulnerabilitiesJSON,
		&recommendationsJSON,
		&trendJSON,
		&vexJSON,
		&updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("get vulnerability index: %w", err)
	}

	record.OrgID = orgID
	record.ImageID = imageID
	record.UpdatedAt = updatedAt.UTC()

	if err := json.Unmarshal(summaryJSON, &record.Summary); err != nil {
		return Record{}, fmt.Errorf("decode vulnerability summary: %w", err)
	}
	if err := json.Unmarshal(vulnerabilitiesJSON, &record.Vulnerabilities); err != nil {
		return Record{}, fmt.Errorf("decode vulnerabilities: %w", err)
	}
	if len(recommendationsJSON) > 0 {
		if err := json.Unmarshal(recommendationsJSON, &record.FixRecommendations); err != nil {
			return Record{}, fmt.Errorf("decode fix recommendations: %w", err)
		}
	}
	if len(trendJSON) > 0 {
		if err := json.Unmarshal(trendJSON, &record.Trend); err != nil {
			return Record{}, fmt.Errorf("decode vulnerability trend: %w", err)
		}
	}
	if len(vexJSON) > 0 {
		if err := json.Unmarshal(vexJSON, &record.VEXDocuments); err != nil {
			return Record{}, fmt.Errorf("decode VEX documents: %w", err)
		}
	}

	return record, nil
}

func (r *PostgresRepository) Delete(ctx context.Context, orgID, imageID string) error {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return err
	}

	if _, err := r.db.ExecContext(ctx, `DELETE FROM vulnerability_indexes WHERE org_id = $1 AND image_id = $2`, orgID, imageID); err != nil {
		return fmt.Errorf("delete vulnerability index: %w", err)
	}
	return nil
}

func (r *PostgresRepository) Close() error {
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}
