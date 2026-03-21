package sbomindex

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
		OrgID:         "demo-org",
		ImageID:       "demo-image",
		ImageName:     "alpine:latest",
		RepositoryKey: normalizeRepositoryKey("alpine:latest"),
		Platform:      "linux/arm64",
		SourceFormat:  FormatCycloneDX,
		PackageCount:  1,
		Packages: []PackageRecord{
			{ID: "pkg:apk/alpine/busybox@1.0.0", Name: "busybox", Version: "1.0.0", Licenses: []string{"MIT"}},
		},
		DependencyTree: []DependencyNode{
			{ID: "pkg:apk/alpine/busybox@1.0.0", Name: "busybox"},
		},
		DependencyRoots: []string{"pkg:apk/alpine/busybox@1.0.0"},
		LicenseSummary:  []LicenseSummaryEntry{{License: "MIT", Count: 1}},
	}
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
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
`)).
		WithArgs(
			record.OrgID,
			record.ImageID,
			record.ImageName,
			record.RepositoryKey,
			record.Platform,
			record.SourceFormat,
			record.PackageCount,
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
SELECT image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
WHERE org_id = $1 AND image_id = $2;
`)).
		WithArgs(record.OrgID, record.ImageID).
		WillReturnRows(sqlmock.NewRows([]string{
			"image_name", "repository_key", "platform", "source_format", "package_count", "packages", "dependency_tree", "dependency_roots", "license_summary", "updated_at",
		}).AddRow(
			record.ImageName,
			record.RepositoryKey,
			record.Platform,
			record.SourceFormat,
			record.PackageCount,
			`[{"id":"pkg:apk/alpine/busybox@1.0.0","name":"busybox","version":"1.0.0","licenses":["MIT"]}]`,
			`[{"id":"pkg:apk/alpine/busybox@1.0.0","name":"busybox"}]`,
			`["pkg:apk/alpine/busybox@1.0.0"]`,
			`[{"license":"MIT","count":1}]`,
			now,
		))

	got, err := repo.Get(context.Background(), record.OrgID, record.ImageID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.PackageCount != 1 || got.Packages[0].Name != "busybox" {
		t.Fatalf("Get() = %#v", got)
	}
	if got.Platform != record.Platform {
		t.Fatalf("Get() Platform = %q, want %q", got.Platform, record.Platform)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM sbom_indexes WHERE org_id = $1 AND image_id = $2`)).
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

func TestPostgresRepositoryFindByImageName(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	repo := newPostgresRepositoryWithDB(db)
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT org_id, image_id, image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
WHERE image_name = $1
ORDER BY updated_at DESC, org_id ASC, image_id ASC;
`)).
		WithArgs("alpine:latest").
		WillReturnRows(sqlmock.NewRows([]string{
			"org_id", "image_id", "image_name", "repository_key", "platform", "source_format", "package_count", "packages", "dependency_tree", "dependency_roots", "license_summary", "updated_at",
		}).
			AddRow("demo-org", "image-a", "alpine:latest", normalizeRepositoryKey("alpine:latest"), "linux/amd64", FormatCycloneDX, 1, `[]`, `[]`, `[]`, `[]`, now).
			AddRow("demo-two", "image-b", "alpine:latest", normalizeRepositoryKey("alpine:latest"), "linux/arm64", FormatCycloneDX, 2, `[]`, `[]`, `[]`, `[]`, now))

	records, err := repo.FindByImageName(context.Background(), "alpine:latest")
	if err != nil {
		t.Fatalf("FindByImageName() error = %v", err)
	}
	if got, want := len(records), 2; got != want {
		t.Fatalf("len(records) = %d, want %d", got, want)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestPostgresRepositoryList(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	repo := newPostgresRepositoryWithDB(db)
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT org_id, image_id, image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
ORDER BY updated_at DESC, org_id ASC, image_id ASC;
`)).
		WillReturnRows(sqlmock.NewRows([]string{
			"org_id", "image_id", "image_name", "repository_key", "platform", "source_format", "package_count", "packages", "dependency_tree", "dependency_roots", "license_summary", "updated_at",
		}).
			AddRow("demo-org", "image-a", "alpine:3.20", normalizeRepositoryKey("alpine:3.20"), "linux/amd64", FormatCycloneDX, 2, `[]`, `[]`, `[]`, `[]`, now).
			AddRow("demo-org", "image-b", "alpine:3.19", normalizeRepositoryKey("alpine:3.19"), "linux/arm64", FormatCycloneDX, 1, `[]`, `[]`, `[]`, `[]`, now.Add(-time.Hour)))

	records, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := len(records), 2; got != want {
		t.Fatalf("len(records) = %d, want %d", got, want)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
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
SELECT image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
WHERE org_id = $1 AND image_id = $2;
`)).
		WithArgs("demo-org", "missing").
		WillReturnError(sql.ErrNoRows)
	if _, err := repo.Get(context.Background(), "demo-org", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT org_id, image_id, image_name, repository_key, platform, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
ORDER BY updated_at DESC, org_id ASC, image_id ASC;
`)).
		WillReturnError(errors.New("query failed"))
	if _, err := repo.List(context.Background()); err == nil {
		t.Fatal("expected List() to return query errors")
	}

	if err := (&PostgresRepository{}).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestPostgresRepositoryQueryCatalog(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	repo := newPostgresRepositoryWithDB(db)
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT COUNT(*)
FROM sbom_indexes s
LEFT JOIN vulnerability_indexes v
	ON v.org_id = s.org_id AND v.image_id = s.image_id
WHERE 1=1 AND (LOWER(s.org_id) LIKE $1 OR LOWER(s.image_id) LIKE $1 OR LOWER(s.image_name) LIKE $1 OR LOWER(COALESCE(s.repository_key, '')) LIKE $1);
`)).
		WithArgs("%demo%").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery(regexp.QuoteMeta(`
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
WHERE 1=1 AND (LOWER(s.org_id) LIKE $1 OR LOWER(s.image_id) LIKE $1 OR LOWER(s.image_name) LIKE $1 OR LOWER(COALESCE(s.repository_key, '')) LIKE $1)
ORDER BY GREATEST(s.updated_at, COALESCE(v.updated_at, s.updated_at)) DESC, s.org_id ASC, s.image_id ASC
LIMIT $2 OFFSET $3;
`)).
		WithArgs("%demo%", 1, 1).
		WillReturnRows(sqlmock.NewRows([]string{
			"org_id", "image_id", "image_name", "repository_key", "platform", "source_format", "package_count", "license_summary", "vulnerability_summary", "updated_at",
		}).AddRow(
			"demo-org",
			"image-b",
			"alpine:3.20",
			normalizeRepositoryKey("alpine:3.20"),
			"linux/arm64",
			FormatCycloneDX,
			3,
			`[]`,
			`{"total":2,"by_severity":{"CRITICAL":2},"by_scanner":{},"by_status":{}}`,
			now,
		))

	page, err := repo.QueryCatalog(context.Background(), CatalogQuery{
		Query:    "demo",
		Page:     2,
		PageSize: 1,
	})
	if err != nil {
		t.Fatalf("QueryCatalog() error = %v", err)
	}
	if got, want := page.Total, 1; got != want {
		t.Fatalf("page.Total = %d, want %d", got, want)
	}
	if got, want := page.Items[0].ImageID, "image-b"; got != want {
		t.Fatalf("page.Items[0].ImageID = %q, want %q", got, want)
	}
	if got, want := page.Items[0].VulnerabilitySummary.BySeverity["CRITICAL"], 2; got != want {
		t.Fatalf("critical severity count = %d, want %d", got, want)
	}
}

func TestPostgresRepositoryListRepositoryTags(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	repo := newPostgresRepositoryWithDB(db)
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`
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
`)).
		WithArgs("demo-org", normalizeRepositoryKey("alpine:latest"), "image-a").
		WillReturnRows(sqlmock.NewRows([]string{
			"org_id", "image_id", "image_name", "repository_key", "platform", "source_format", "package_count", "license_summary", "vulnerability_summary", "updated_at",
		}).AddRow(
			"demo-org",
			"image-b",
			"alpine:3.20",
			normalizeRepositoryKey("alpine:latest"),
			"linux/arm64",
			FormatCycloneDX,
			3,
			`[]`,
			`{"total":1,"by_severity":{"HIGH":1},"by_scanner":{},"by_status":{}}`,
			now,
		))

	records, err := repo.ListRepositoryTags(context.Background(), RepositoryTagQuery{
		OrgID:          "demo-org",
		RepositoryKey:  normalizeRepositoryKey("alpine:latest"),
		ExcludeImageID: "image-a",
	})
	if err != nil {
		t.Fatalf("ListRepositoryTags() error = %v", err)
	}
	if got, want := len(records), 1; got != want {
		t.Fatalf("len(records) = %d, want %d", got, want)
	}
	if got, want := records[0].ImageID, "image-b"; got != want {
		t.Fatalf("records[0].ImageID = %q, want %q", got, want)
	}
}
