package vulnindex

// DisagreementEntry represents a vulnerability found by some scanners but not others.
type DisagreementEntry struct {
	VulnID         string   `json:"vuln_id"`
	Severity       string   `json:"severity"`
	PackageName    string   `json:"package_name"`
	PackageVersion string   `json:"package_version,omitempty"`
	FoundBy        []string `json:"found_by"`
	MissedBy       []string `json:"missed_by"`
}

// DisagreementReport shows where vulnerability scanners disagree.
type DisagreementReport struct {
	TotalVulnerabilities int                  `json:"total_vulnerabilities"`
	AgreedCount          int                  `json:"agreed_count"`
	DisagreedCount       int                  `json:"disagreed_count"`
	DisagreementRate     float64              `json:"disagreement_rate"`
	AllScanners          []string             `json:"all_scanners"`
	Disagreements        []DisagreementEntry  `json:"disagreements"`
}

// BuildDisagreementReport analyzes vulnerability records to find where scanners disagree.
func BuildDisagreementReport(vulnerabilities []VulnerabilityRecord, allScanners []string) DisagreementReport {
	report := DisagreementReport{
		TotalVulnerabilities: len(vulnerabilities),
		AllScanners:          allScanners,
	}

	if len(allScanners) <= 1 {
		report.AgreedCount = len(vulnerabilities)
		return report
	}

	scannerSet := make(map[string]struct{}, len(allScanners))
	for _, s := range allScanners {
		scannerSet[s] = struct{}{}
	}

	for _, vuln := range vulnerabilities {
		foundBySet := make(map[string]struct{}, len(vuln.Scanners))
		for _, s := range vuln.Scanners {
			foundBySet[s] = struct{}{}
		}

		var missedBy []string
		for _, s := range allScanners {
			if _, ok := foundBySet[s]; !ok {
				missedBy = append(missedBy, s)
			}
		}

		if len(missedBy) > 0 && len(vuln.Scanners) > 0 {
			report.DisagreedCount++
			report.Disagreements = append(report.Disagreements, DisagreementEntry{
				VulnID:         vuln.ID,
				Severity:       vuln.Severity,
				PackageName:    vuln.PackageName,
				PackageVersion: vuln.PackageVersion,
				FoundBy:        vuln.Scanners,
				MissedBy:       missedBy,
			})
		} else {
			report.AgreedCount++
		}
	}

	if report.TotalVulnerabilities > 0 {
		report.DisagreementRate = float64(report.DisagreedCount) / float64(report.TotalVulnerabilities)
	}

	return report
}
