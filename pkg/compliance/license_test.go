package compliance

import (
	"testing"

	"github.com/otterXf/otter/pkg/sbomindex"
)

func TestCheckLicenseCompliancePassesCleanPackages(t *testing.T) {
	packages := []sbomindex.PackageRecord{
		{Name: "express", Version: "4.18.2", Licenses: []string{"MIT"}},
		{Name: "lodash", Version: "4.17.21", Licenses: []string{"MIT"}},
		{Name: "react", Version: "18.2.0", Licenses: []string{"MIT"}},
	}

	result := CheckLicenseCompliance(packages, DefaultLicensePolicy())
	if result.Status != "pass" {
		t.Fatalf("expected pass, got %s", result.Status)
	}
	if len(result.Violations) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(result.Violations))
	}
	if result.Scanned != 3 {
		t.Fatalf("expected 3 scanned, got %d", result.Scanned)
	}
}

func TestCheckLicenseComplianceDeniesGPL(t *testing.T) {
	packages := []sbomindex.PackageRecord{
		{Name: "safe-pkg", Version: "1.0", Licenses: []string{"MIT"}},
		{Name: "gpl-pkg", Version: "2.0", Licenses: []string{"GPL-3.0-only"}},
		{Name: "agpl-pkg", Version: "1.0", Licenses: []string{"AGPL-3.0-only"}},
	}

	result := CheckLicenseCompliance(packages, DefaultLicensePolicy())
	if result.Status != "fail" {
		t.Fatalf("expected fail, got %s", result.Status)
	}
	if len(result.Violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(result.Violations))
	}
	for _, v := range result.Violations {
		if v.Severity != LicenseViolationDeny {
			t.Fatalf("expected deny severity, got %s", v.Severity)
		}
	}
}

func TestCheckLicenseComplianceWarnsOnWeakCopyleft(t *testing.T) {
	packages := []sbomindex.PackageRecord{
		{Name: "lgpl-pkg", Version: "1.0", Licenses: []string{"LGPL-2.1-only"}},
	}

	result := CheckLicenseCompliance(packages, DefaultLicensePolicy())
	if result.Status != "warn" {
		t.Fatalf("expected warn, got %s", result.Status)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Severity != LicenseViolationWarn {
		t.Fatalf("expected warn severity, got %s", result.Violations[0].Severity)
	}
}

func TestCheckLicenseComplianceDenyOverridesWarn(t *testing.T) {
	packages := []sbomindex.PackageRecord{
		{Name: "lgpl-pkg", Version: "1.0", Licenses: []string{"LGPL-2.1-only"}},
		{Name: "gpl-pkg", Version: "2.0", Licenses: []string{"GPL-3.0-only"}},
	}

	result := CheckLicenseCompliance(packages, DefaultLicensePolicy())
	if result.Status != "fail" {
		t.Fatalf("expected fail when both deny and warn present, got %s", result.Status)
	}
}

func TestCheckLicenseComplianceCustomPolicy(t *testing.T) {
	policy := LicensePolicy{
		Denied: []string{"Proprietary"},
		Warned: []string{"Apache-2.0"},
	}

	packages := []sbomindex.PackageRecord{
		{Name: "apache-pkg", Version: "1.0", Licenses: []string{"Apache-2.0"}},
	}

	result := CheckLicenseCompliance(packages, policy)
	if result.Status != "warn" {
		t.Fatalf("expected warn, got %s", result.Status)
	}
}

func TestLicensePolicyFromEnvUsesDefaults(t *testing.T) {
	policy := LicensePolicyFromEnv()
	if len(policy.Denied) == 0 {
		t.Fatal("expected default denied licenses")
	}
}

func TestLicensePolicyFromEnvOverrides(t *testing.T) {
	t.Setenv("OTTER_LICENSE_DENY", "Custom-1.0, Custom-2.0")
	t.Setenv("OTTER_LICENSE_WARN", "Mild-1.0")

	policy := LicensePolicyFromEnv()
	if len(policy.Denied) != 2 || policy.Denied[0] != "Custom-1.0" {
		t.Fatalf("expected custom denied policy, got %v", policy.Denied)
	}
	if len(policy.Warned) != 1 || policy.Warned[0] != "Mild-1.0" {
		t.Fatalf("expected custom warned policy, got %v", policy.Warned)
	}
}
