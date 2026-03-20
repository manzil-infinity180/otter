package storage

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestLocalStoreErrorPaths(t *testing.T) {
	t.Parallel()

	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}

	if _, err := store.Get(context.Background(), "invalid"); err == nil {
		t.Fatal("expected Get() to reject invalid keys")
	}
	if _, err := store.List(context.Background(), "../bad"); err == nil {
		t.Fatal("expected List() to reject invalid prefixes")
	}
	if err := store.Delete(context.Background(), "invalid"); err == nil {
		t.Fatal("expected Delete() to reject invalid keys")
	}
}

func TestPostgresStoreErrorPaths(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	store := newPostgresStoreWithDB(db)
	key := "otterxf/demo-org/demo-image/sbom.json"

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT content_type, payload, size_bytes, created_at, metadata
FROM scan_artifacts
WHERE key = $1;
`)).
		WithArgs(key).
		WillReturnError(sql.ErrNoRows)
	if _, err := store.Get(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT key, content_type, size_bytes, created_at, metadata
FROM scan_artifacts
WHERE key LIKE $1
ORDER BY key;
`)).
		WithArgs("otterxf/demo-org/demo-image/%").
		WillReturnError(errors.New("query failed"))
	if _, err := store.List(context.Background(), "otterxf/demo-org/demo-image/"); err == nil {
		t.Fatal("expected List() to return query errors")
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM scan_artifacts WHERE key = $1`)).
		WithArgs(key).
		WillReturnError(errors.New("delete failed"))
	if err := store.Delete(context.Background(), key); err == nil {
		t.Fatal("expected Delete() to return database errors")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresConstructionValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewPostgresStore(context.Background(), "", "/tmp/migrations"); err == nil {
		t.Fatal("expected NewPostgresStore() to require a DSN")
	}
	if err := runPostgresMigrations("postgres://otter:otter@localhost:5432/otter?sslmode=disable", ""); err == nil {
		t.Fatal("expected runPostgresMigrations() to require a migrations path")
	}
}
