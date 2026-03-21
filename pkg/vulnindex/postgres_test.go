package vulnindex

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresRepositorySaveGetDelete(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	repo := newPostgresRepositoryWithDB(db)
	record := Record{
		OrgID:     "demo-org",
		ImageID:   "demo-image",
		ImageName: "alpine:latest",
		Platform:  "linux/arm64",
		Summary: Summary{
			Total:      1,
			BySeverity: map[string]int{"HIGH": 1},
			ByScanner:  map[string]int{"grype": 1},
			ByStatus:   map[string]int{StatusAffected: 1},
			Fixable:    1,
		},
		Vulnerabilities: []VulnerabilityRecord{
			{
				ID:          "CVE-2024-0001",
				Severity:    "HIGH",
				PackageName: "openssl",
				Status:      StatusAffected,
				Scanners:    []string{"grype"},
				FirstSeenAt: time.Now().UTC(),
				LastSeenAt:  time.Now().UTC(),
			},
		},
		Trend: []TrendPoint{
			{
				ObservedAt: time.Now().UTC(),
				Summary: Summary{
					Total:      1,
					BySeverity: map[string]int{"HIGH": 1},
					ByScanner:  map[string]int{"grype": 1},
					ByStatus:   map[string]int{StatusAffected: 1},
					Fixable:    1,
				},
			},
		},
	}
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
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
`)).
		WithArgs(
			record.OrgID,
			record.ImageID,
			record.ImageName,
			record.Platform,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))

	saved, err := repo.Save(context.Background(), record)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if saved.UpdatedAt.IsZero() {
		t.Fatalf("Save() UpdatedAt = %v", saved.UpdatedAt)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT image_name, platform, summary, vulnerabilities, fix_recommendations, trend, vex_documents, updated_at
FROM vulnerability_indexes
WHERE org_id = $1 AND image_id = $2;
`)).
		WithArgs(record.OrgID, record.ImageID).
		WillReturnRows(sqlmock.NewRows([]string{
			"image_name", "platform", "summary", "vulnerabilities", "fix_recommendations", "trend", "vex_documents", "updated_at",
		}).AddRow(
			record.ImageName,
			record.Platform,
			`{"total":1,"by_severity":{"HIGH":1},"by_scanner":{"grype":1},"by_status":{"affected":1},"fixable":1,"unfixable":0}`,
			`[{"id":"CVE-2024-0001","severity":"HIGH","package_name":"openssl","status":"affected","status_source":"scanner","scanners":["grype"],"first_seen_at":"2026-03-13T18:00:00Z","last_seen_at":"2026-03-13T18:00:00Z"}]`,
			`[]`,
			`[]`,
			`[]`,
			now,
		))

	got, err := repo.Get(context.Background(), record.OrgID, record.ImageID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ImageName != "alpine:latest" || got.Summary.Total != 1 {
		t.Fatalf("Get() = %#v", got)
	}
	if got.Platform != record.Platform {
		t.Fatalf("Get() Platform = %q, want %q", got.Platform, record.Platform)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM vulnerability_indexes WHERE org_id = $1 AND image_id = $2`)).
		WithArgs(record.OrgID, record.ImageID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.Delete(context.Background(), record.OrgID, record.ImageID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresRepositoryRejectsInvalidKey(t *testing.T) {
	t.Parallel()

	repo := newPostgresRepositoryWithDB(&sql.DB{})
	if _, err := repo.Save(context.Background(), Record{OrgID: "../bad", ImageID: "demo-image"}); err == nil {
		t.Fatal("expected Save() to reject invalid org ID")
	}
}

func TestPostgresRepositoryErrorPaths(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	repo := newPostgresRepositoryWithDB(db)
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT image_name, platform, summary, vulnerabilities, fix_recommendations, trend, vex_documents, updated_at
FROM vulnerability_indexes
WHERE org_id = $1 AND image_id = $2;
`)).
		WithArgs("demo-org", "missing").
		WillReturnError(sql.ErrNoRows)
	if _, err := repo.Get(context.Background(), "demo-org", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM vulnerability_indexes WHERE org_id = $1 AND image_id = $2`)).
		WithArgs("demo-org", "demo-image").
		WillReturnError(errors.New("delete failed"))
	if err := repo.Delete(context.Background(), "demo-org", "demo-image"); err == nil {
		t.Fatal("expected Delete() to return database errors")
	}

	if err := (&PostgresRepository{}).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
