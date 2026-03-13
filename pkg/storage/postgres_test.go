package storage

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresStorePutGetListDelete(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	store := newPostgresStoreWithDB(db)
	key := "otterxf/demo-org/demo-image/sbom.json"
	now := time.Now().UTC()
	payload := []byte(`{"bomFormat":"CycloneDX"}`)

	mock.ExpectQuery(regexp.QuoteMeta(`
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
`)).
		WithArgs(key, "demo-org", "demo-image", "sbom.json", "sbom", "application/json", payload, len(payload)).
		WillReturnRows(sqlmock.NewRows([]string{"created_at"}).AddRow(now))

	info, err := store.Put(context.Background(), key, payload, PutOptions{ContentType: "application/json"})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if info.Key != key || info.Size != int64(len(payload)) {
		t.Fatalf("Put() info = %#v", info)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT content_type, payload, size_bytes, created_at
FROM scan_artifacts
WHERE key = $1;
`)).
		WithArgs(key).
		WillReturnRows(sqlmock.NewRows([]string{"content_type", "payload", "size_bytes", "created_at"}).
			AddRow("application/json", payload, len(payload), now))

	object, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(object.Data) != string(payload) {
		t.Fatalf("Get() payload = %s, want %s", object.Data, payload)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT key, content_type, size_bytes, created_at
FROM scan_artifacts
WHERE key LIKE $1
ORDER BY key;
`)).
		WithArgs("otterxf/demo-org/demo-image/%").
		WillReturnRows(sqlmock.NewRows([]string{"key", "content_type", "size_bytes", "created_at"}).
			AddRow(key, "application/json", len(payload), now))

	objects, err := store.List(context.Background(), "otterxf/demo-org/demo-image/")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(objects) != 1 || objects[0].Key != key {
		t.Fatalf("List() = %#v", objects)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM scan_artifacts WHERE key = $1`)).
		WithArgs(key).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresStoreRejectsNonJSONPayload(t *testing.T) {
	t.Parallel()

	store := newPostgresStoreWithDB(&sql.DB{})
	_, err := store.Put(context.Background(), "otterxf/demo-org/demo-image/sbom.json", []byte("not-json"), PutOptions{})
	if err == nil {
		t.Fatal("expected Put() to reject non-JSON payload")
	}
}
