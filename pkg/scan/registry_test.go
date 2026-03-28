package scan

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/sbom"
)

type mockScanner struct{ name string }

func (m *mockScanner) Name() string { return m.name }
func (m *mockScanner) Scan(_ context.Context, _ string, _ *sbom.SBOM) (ScannerReport, error) {
	return ScannerReport{Scanner: m.name, Status: ScannerStatusCompleted}, nil
}

func TestScannerRegistryRegisterAndCreate(t *testing.T) {
	r := NewScannerRegistry()

	err := r.Register("test-scanner", func(config map[string]string) (VulnerabilityScanner, error) {
		return &mockScanner{name: "test-scanner"}, nil
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	scanner, err := r.Create("test-scanner", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if scanner.Name() != "test-scanner" {
		t.Fatalf("expected name test-scanner, got %s", scanner.Name())
	}
}

func TestScannerRegistryDuplicateRegistration(t *testing.T) {
	r := NewScannerRegistry()
	factory := func(config map[string]string) (VulnerabilityScanner, error) {
		return &mockScanner{}, nil
	}

	if err := r.Register("dup", factory); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("dup", factory); err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestScannerRegistryCreateUnknown(t *testing.T) {
	r := NewScannerRegistry()
	_, err := r.Create("nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for unknown scanner")
	}
}

func TestScannerRegistryAvailable(t *testing.T) {
	r := NewScannerRegistry()
	r.Register("a", func(config map[string]string) (VulnerabilityScanner, error) { return &mockScanner{}, nil })
	r.Register("b", func(config map[string]string) (VulnerabilityScanner, error) { return &mockScanner{}, nil })

	avail := r.Available()
	if len(avail) != 2 {
		t.Fatalf("expected 2 available, got %d", len(avail))
	}
}
