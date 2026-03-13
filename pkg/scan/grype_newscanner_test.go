package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewScannerReturnsContextualErrorForMissingImportedArchive(t *testing.T) {
	t.Parallel()

	_, err := NewScanner(Options{
		PathOfDatabaseArchiveToImport:      "/definitely/missing/grype-db.tar.gz",
		PathOfDatabaseDestinationDirectory: t.TempDir(),
		DisableDatabaseAgeValidation:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "opening vulnerability database archive for hashing") {
		t.Fatalf("NewScanner() error = %v, want contextual archive error", err)
	}
}

func TestNewScannerReturnsContextualErrorForInvalidImportedArchive(t *testing.T) {
	t.Parallel()

	archivePath := filepath.Join(t.TempDir(), "grype-db.tar.gz")
	if err := os.WriteFile(archivePath, []byte("not a real grype db"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := NewScanner(Options{
		PathOfDatabaseArchiveToImport:      archivePath,
		PathOfDatabaseDestinationDirectory: t.TempDir(),
		DisableDatabaseAgeValidation:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "unable to import vulnerability database") {
		t.Fatalf("NewScanner() error = %v, want contextual import error", err)
	}
}
