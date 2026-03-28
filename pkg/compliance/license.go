package compliance

import (
	"os"
	"strings"

	"github.com/otterXf/otter/pkg/sbomindex"
)

const (
	LicenseViolationDeny = "deny"
	LicenseViolationWarn = "warn"
)

// LicensePolicy defines which licenses are denied or warned about.
type LicensePolicy struct {
	Denied []string `json:"denied"`
	Warned []string `json:"warned"`
}

// LicenseViolation represents a single license compliance issue.
type LicenseViolation struct {
	Package  string `json:"package"`
	Version  string `json:"version,omitempty"`
	License  string `json:"license"`
	Severity string `json:"severity"` // "deny" or "warn"
}

// LicenseComplianceResult is the result of checking an image's packages.
type LicenseComplianceResult struct {
	Status     string             `json:"status"` // "pass", "warn", "fail"
	Violations []LicenseViolation `json:"violations"`
	Scanned    int                `json:"scanned"`
}

// DefaultLicensePolicy returns the default policy that denies strong
// copyleft licenses and warns on weak copyleft.
func DefaultLicensePolicy() LicensePolicy {
	return LicensePolicy{
		Denied: []string{
			"GPL-3.0-only", "GPL-3.0-or-later", "GPL-3.0",
			"AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-3.0",
			"GPL-2.0-only", "GPL-2.0-or-later", "GPL-2.0",
			"SSPL-1.0",
		},
		Warned: []string{
			"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-2.1",
			"LGPL-3.0-only", "LGPL-3.0-or-later", "LGPL-3.0",
			"MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0",
		},
	}
}

// LicensePolicyFromEnv creates a policy from environment variables.
// OTTER_LICENSE_DENY and OTTER_LICENSE_WARN are comma-separated SPDX IDs.
// Falls back to defaults if not set.
func LicensePolicyFromEnv() LicensePolicy {
	policy := DefaultLicensePolicy()

	if v := os.Getenv("OTTER_LICENSE_DENY"); v != "" {
		policy.Denied = splitTrimmed(v)
	}
	if v := os.Getenv("OTTER_LICENSE_WARN"); v != "" {
		policy.Warned = splitTrimmed(v)
	}
	return policy
}

func splitTrimmed(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// CheckLicenseCompliance checks all packages in an SBOM record against the policy.
func CheckLicenseCompliance(packages []sbomindex.PackageRecord, policy LicensePolicy) LicenseComplianceResult {
	denied := toSet(policy.Denied)
	warned := toSet(policy.Warned)

	result := LicenseComplianceResult{
		Status:  "pass",
		Scanned: len(packages),
	}

	for _, pkg := range packages {
		for _, license := range pkg.Licenses {
			normalized := strings.TrimSpace(license)
			if _, ok := denied[normalized]; ok {
				result.Violations = append(result.Violations, LicenseViolation{
					Package:  pkg.Name,
					Version:  pkg.Version,
					License:  normalized,
					Severity: LicenseViolationDeny,
				})
				result.Status = "fail"
			} else if _, ok := warned[normalized]; ok {
				result.Violations = append(result.Violations, LicenseViolation{
					Package:  pkg.Name,
					Version:  pkg.Version,
					License:  normalized,
					Severity: LicenseViolationWarn,
				})
				if result.Status != "fail" {
					result.Status = "warn"
				}
			}
		}
	}

	return result
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[strings.TrimSpace(item)] = struct{}{}
	}
	return set
}
