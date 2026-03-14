package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(ctx context.Context, dsn, migrationsPath string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("postgres dsn is required")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	store := &PostgresStore{db: db}
	if err := store.db.PingContext(ctx); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	if err := runPostgresMigrations(dsn, migrationsPath); err != nil {
		_ = store.Close()
		return nil, err
	}

	return store, nil
}

func newPostgresStoreWithDB(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Backend() string {
	return BackendPostgres
}

func (s *PostgresStore) Put(ctx context.Context, key string, data []byte, opts PutOptions) (ObjectInfo, error) {
	parts, err := ParseArtifactKey(key)
	if err != nil {
		return ObjectInfo{}, err
	}

	var payload json.RawMessage
	if !json.Valid(data) {
		return ObjectInfo{}, errors.New("postgres storage only supports valid JSON payloads")
	}
	payload = append(payload[:0], data...)

	artifactType := strings.TrimSuffix(parts.Filename, filepath.Ext(parts.Filename))

	const query = `
INSERT INTO scan_artifacts (
	key, org_id, image_id, filename, artifact_type, content_type, payload, size_bytes
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
ON CONFLICT (key) DO UPDATE SET
	content_type = EXCLUDED.content_type,
	payload = EXCLUDED.payload,
	size_bytes = EXCLUDED.size_bytes,
	updated_at = NOW()
RETURNING created_at;
`

	var createdAt sql.NullTime
	if err := s.db.QueryRowContext(
		ctx,
		query,
		key,
		parts.OrgID,
		parts.ImageID,
		parts.Filename,
		artifactType,
		opts.ContentType,
		payload,
		len(data),
	).Scan(&createdAt); err != nil {
		return ObjectInfo{}, fmt.Errorf("upsert artifact %s: %w", key, err)
	}

	return ObjectInfo{
		Key:         key,
		Size:        int64(len(data)),
		ContentType: opts.ContentType,
		CreatedAt:   createdAt.Time.UTC(),
		Backend:     s.Backend(),
		Metadata:    opts.Metadata,
	}, nil
}

func (s *PostgresStore) Get(ctx context.Context, key string) (Object, error) {
	if _, err := ParseArtifactKey(key); err != nil {
		return Object{}, err
	}

	const query = `
SELECT content_type, payload, size_bytes, created_at
FROM scan_artifacts
WHERE key = $1;
`

	var (
		contentType string
		payload     []byte
		size        int64
		createdAt   sql.NullTime
	)
	if err := s.db.QueryRowContext(ctx, query, key).Scan(&contentType, &payload, &size, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Object{}, ErrNotFound
		}
		return Object{}, fmt.Errorf("get artifact %s: %w", key, err)
	}

	return Object{
		Info: ObjectInfo{
			Key:         key,
			Size:        size,
			ContentType: contentType,
			CreatedAt:   createdAt.Time.UTC(),
			Backend:     s.Backend(),
		},
		Data: payload,
	}, nil
}

func (s *PostgresStore) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	if err := ValidatePrefix(prefix); err != nil {
		return nil, err
	}

	const query = `
SELECT key, content_type, size_bytes, created_at
FROM scan_artifacts
WHERE key LIKE $1
ORDER BY key;
`

	rows, err := s.db.QueryContext(ctx, query, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("list artifacts for prefix %s: %w", prefix, err)
	}
	defer rows.Close() //nolint:errcheck // rows cleanup after iteration

	var objects []ObjectInfo
	for rows.Next() {
		var (
			info      ObjectInfo
			createdAt sql.NullTime
		)
		if err := rows.Scan(&info.Key, &info.ContentType, &info.Size, &createdAt); err != nil {
			return nil, fmt.Errorf("scan artifact row: %w", err)
		}
		info.CreatedAt = createdAt.Time.UTC()
		info.Backend = s.Backend()
		objects = append(objects, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact rows: %w", err)
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key < objects[j].Key
	})
	return objects, nil
}

func (s *PostgresStore) Delete(ctx context.Context, key string) error {
	if _, err := ParseArtifactKey(key); err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM scan_artifacts WHERE key = $1`, key); err != nil {
		return fmt.Errorf("delete artifact %s: %w", key, err)
	}
	return nil
}

func (s *PostgresStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func runPostgresMigrations(dsn, migrationsPath string) error {
	if migrationsPath == "" {
		return errors.New("postgres migrations path is required")
	}

	migrator, err := migrate.New("file://"+filepath.Clean(migrationsPath), dsn)
	if err != nil {
		return fmt.Errorf("create postgres migrator: %w", err)
	}
	defer func() {
		_, _ = migrator.Close()
	}()

	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run postgres migrations: %w", err)
	}
	return nil
}
