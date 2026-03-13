package sbomindex

import (
	"context"
	"database/sql"
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
	defer db.Close()

	repo := newPostgresRepositoryWithDB(db)
	record := Record{
		OrgID:        "demo-org",
		ImageID:      "demo-image",
		ImageName:    "alpine:latest",
		SourceFormat: FormatCycloneDX,
		PackageCount: 1,
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
`)).
		WithArgs(
			record.OrgID,
			record.ImageID,
			record.ImageName,
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
SELECT image_name, source_format, package_count, packages, dependency_tree, dependency_roots, license_summary, updated_at
FROM sbom_indexes
WHERE org_id = $1 AND image_id = $2;
`)).
		WithArgs(record.OrgID, record.ImageID).
		WillReturnRows(sqlmock.NewRows([]string{
			"image_name", "source_format", "package_count", "packages", "dependency_tree", "dependency_roots", "license_summary", "updated_at",
		}).AddRow(
			record.ImageName,
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
