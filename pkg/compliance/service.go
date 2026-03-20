package compliance

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Assessor interface {
	Assess(ctx context.Context, input Input) Result
}

type Service struct {
	scorecard ScorecardClient
}

func NewService(cfg Config) *Service {
	return &Service{
		scorecard: NewHTTPScorecardClient(cfg),
	}
}

func NewServiceWithClient(client ScorecardClient) *Service {
	return &Service{scorecard: client}
}

func (s *Service) Assess(ctx context.Context, input Input) Result {
	result := Result{
		ImageRef:  strings.TrimSpace(input.ImageRef),
		ScopeNote: "Otter evaluates supply-chain evidence visible from stored scan results and live attestation discovery; it does not inspect runtime configuration or Dockerfiles.",
		SLSA: SLSAAssessment{
			TargetLevel: 3,
			Status:      StatusFail,
		},
		Scorecard: ScorecardSummary{
			Enabled: s.scorecard != nil,
			Status:  StatusUnavailable,
		},
		UpdatedAt: time.Now().UTC(),
	}

	if input.AttestationError != nil {
		result.EvidenceErrors = append(result.EvidenceErrors, "attestation discovery: "+input.AttestationError.Error())
	}
	if input.Attestations != nil && input.Attestations.UpdatedAt.After(result.UpdatedAt) {
		result.UpdatedAt = input.Attestations.UpdatedAt.UTC()
	}

	result.SLSA = assessSLSA(input.Attestations)
	result.SourceRepository = resolveRepository(result.ImageRef, input.Attestations)

	if s.scorecard == nil {
		result.Scorecard.Error = "scorecard integration disabled"
	} else if result.SourceRepository == nil {
		result.Scorecard.Error = "no GitHub source repository evidence found"
	} else {
		scorecard, err := s.scorecard.Lookup(ctx, *result.SourceRepository)
		if err != nil {
			result.Scorecard.Enabled = true
			result.Scorecard.Status = StatusUnavailable
			result.Scorecard.Repository = result.SourceRepository.Repository
			result.Scorecard.Error = err.Error()
		} else {
			result.Scorecard = scorecard
		}
	}

	result.Standards = buildStandards(result.SLSA, result.Scorecard, input.Vulnerabilities, input.Attestations)
	result.Summary = summarizeStandards(result.Standards)
	return result
}

func assessSLSA(attestations *AttestationSummary) SLSAAssessment {
	assessment := SLSAAssessment{
		TargetLevel: 3,
		Status:      StatusFail,
		Missing: []string{
			"no SLSA provenance attestation was discovered",
		},
	}
	if attestations == nil || len(attestations.Attestations) == 0 {
		return assessment
	}

	var candidate ProvenanceRecord
	found := false
	for _, record := range attestations.Attestations {
		if !found || betterProvenanceRecord(record, candidate) {
			candidate = record
			found = true
		}
	}
	if !found {
		return assessment
	}

	assessment.Evidence = append(assessment.Evidence, "provenance attestation detected")
	assessment.Level = 1
	assessment.BuilderID = strings.TrimSpace(candidate.BuilderID)
	assessment.BuildType = strings.TrimSpace(candidate.BuildType)
	assessment.InvocationID = strings.TrimSpace(candidate.InvocationID)
	assessment.Materials = compactStrings(candidate.Materials)
	assessment.Verified = strings.EqualFold(strings.TrimSpace(candidate.VerificationStatus), "valid")
	assessment.Missing = nil

	if assessment.BuilderID != "" {
		assessment.Evidence = append(assessment.Evidence, "builder identity captured")
	}
	if assessment.BuildType != "" {
		assessment.Evidence = append(assessment.Evidence, "build type captured")
	}
	if len(assessment.Materials) > 0 {
		assessment.Evidence = append(assessment.Evidence, "provenance materials captured")
	}
	if assessment.InvocationID != "" {
		assessment.Evidence = append(assessment.Evidence, "invocation ID captured")
	}
	if assessment.Verified {
		assessment.Evidence = append(assessment.Evidence, "attestation verification succeeded")
	}

	if assessment.BuilderID == "" {
		assessment.Missing = append(assessment.Missing, "builder identity")
	}
	if assessment.BuildType == "" {
		assessment.Missing = append(assessment.Missing, "build type")
	}
	if len(assessment.Materials) == 0 {
		assessment.Missing = append(assessment.Missing, "source materials")
	}
	if assessment.InvocationID == "" {
		assessment.Missing = append(assessment.Missing, "invocation ID")
	}
	if !assessment.Verified {
		assessment.Missing = append(assessment.Missing, "verified provenance")
	}

	if assessment.BuilderID != "" && assessment.BuildType != "" && len(assessment.Materials) > 0 {
		assessment.Level = 2
	}
	if assessment.Level >= 2 && assessment.InvocationID != "" && assessment.Verified {
		assessment.Level = 3
	}

	switch assessment.Level {
	case 3:
		assessment.Status = StatusPass
	case 2:
		assessment.Status = StatusPartial
	default:
		assessment.Status = StatusPartial
	}

	return assessment
}

func betterProvenanceRecord(left, right ProvenanceRecord) bool {
	return provenanceRank(left) > provenanceRank(right)
}

func provenanceRank(record ProvenanceRecord) int {
	score := 0
	if strings.TrimSpace(record.BuilderID) != "" {
		score++
	}
	if strings.TrimSpace(record.BuildType) != "" {
		score++
	}
	if len(compactStrings(record.Materials)) > 0 {
		score++
	}
	if strings.TrimSpace(record.InvocationID) != "" {
		score++
	}
	if strings.EqualFold(strings.TrimSpace(record.VerificationStatus), "valid") {
		score++
	}
	return score
}

func resolveRepository(imageRef string, attestations *AttestationSummary) *Repository {
	if attestations != nil {
		for _, record := range attestations.Attestations {
			for _, material := range record.Materials {
				if repository, ok := parseGitHubRepository(material, "attestation.materials", "high"); ok {
					return &repository
				}
			}
			if repository, ok := parseGitHubRepository(record.SourceRepositoryURL, "attestation.source", "high"); ok {
				return &repository
			}
			if repository, ok := parseGitHubRepository(record.BuilderID, "attestation.builder", "medium"); ok {
				return &repository
			}
		}
	}

	ref := strings.TrimSpace(imageRef)
	if strings.HasPrefix(ref, "ghcr.io/") {
		path := strings.TrimPrefix(ref, "ghcr.io/")
		if at := strings.Index(path, "@"); at >= 0 {
			path = path[:at]
		}
		if colon := strings.Index(path, ":"); colon >= 0 {
			path = path[:colon]
		}
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) >= 2 {
			return &Repository{
				Host:        "github.com",
				Owner:       parts[0],
				Name:        parts[1],
				Repository:  "github.com/" + parts[0] + "/" + parts[1],
				URL:         "https://github.com/" + parts[0] + "/" + parts[1],
				DerivedFrom: "image.reference",
				Confidence:  "low",
			}
		}
	}

	return nil
}

func parseGitHubRepository(raw, derivedFrom, confidence string) (Repository, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Repository{}, false
	}
	value = strings.TrimPrefix(value, "git+")
	if strings.HasPrefix(value, "git@github.com:") {
		value = "ssh://git@github.com/" + strings.TrimPrefix(value, "git@github.com:")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return Repository{}, false
	}
	host := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "www.")
	if host != "github.com" {
		return Repository{}, false
	}

	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 {
		return Repository{}, false
	}
	owner := sanitizePathPart(parts[0])
	repo := sanitizePathPart(parts[1])
	if owner == "" || repo == "" {
		return Repository{}, false
	}

	return Repository{
		Host:        "github.com",
		Owner:       owner,
		Name:        repo,
		Repository:  "github.com/" + owner + "/" + repo,
		URL:         "https://github.com/" + owner + "/" + repo,
		DerivedFrom: derivedFrom,
		Confidence:  confidence,
	}, true
}

func sanitizePathPart(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".git")
	if at := strings.Index(value, "@"); at >= 0 {
		value = value[:at]
	}
	value = strings.Trim(value, "/")
	return value
}

func buildStandards(slsa SLSAAssessment, scorecard ScorecardSummary, vulnerabilities *VulnerabilitySummary, attestations *AttestationSummary) []StandardSummary {
	return []StandardSummary{
		buildSLSAStandard(slsa),
		buildSSDFStandard(slsa, scorecard, vulnerabilities, attestations),
		buildCISStandard(vulnerabilities, attestations),
	}
}

func buildSLSAStandard(slsa SLSAAssessment) StandardSummary {
	checks := []StandardCheck{
		{
			ID:     "slsa-provenance",
			Title:  "Provenance attestation",
			Status: ternaryStatus(slsa.Level >= 1, StatusPass, StatusFail),
			Detail: detailOrDefault(slsa.Level >= 1, "An in-toto/SLSA provenance attestation was discovered.", "No provenance attestation was discovered."),
		},
		{
			ID:     "slsa-traceability",
			Title:  "Builder and source traceability",
			Status: aggregateSignalStatus(slsa.BuilderID != "", slsa.BuildType != "", len(slsa.Materials) > 0),
			Detail: "Checks for builder identity, build type, and source materials in provenance metadata.",
		},
		{
			ID:     "slsa-verification",
			Title:  "Verified provenance",
			Status: ternaryStatus(slsa.Verified, StatusPass, StatusFail),
			Detail: detailOrDefault(slsa.Verified, "At least one provenance attestation verified successfully.", "No verified provenance attestation was observed."),
		},
	}

	summary := "No provenance evidence was discovered."
	switch slsa.Status {
	case StatusPass:
		summary = "SLSA Level 3 evidence is present with verified provenance, builder identity, invocation ID, and source materials."
	case StatusPartial:
		summary = "Partial provenance evidence is present, but it does not yet satisfy the full Level 3 signal set."
	}

	return StandardSummary{
		Name:    "SLSA",
		Status:  slsa.Status,
		Summary: summary,
		Checks:  checks,
	}
}

func buildSSDFStandard(slsa SLSAAssessment, scorecard ScorecardSummary, vulnerabilities *VulnerabilitySummary, attestations *AttestationSummary) StandardSummary {
	checks := []StandardCheck{
		{
			ID:     "ssdf-provenance",
			Title:  "Build provenance retained",
			Status: ternaryStatus(slsa.Level >= 1, StatusPass, StatusFail),
			Detail: detailOrDefault(slsa.Level >= 1, "Provenance data is available for the scanned image.", "No provenance data was discovered."),
		},
		{
			ID:     "ssdf-verification",
			Title:  "Artifact verification",
			Status: ternaryStatus(attestations != nil && attestations.Verified, StatusPass, StatusFail),
			Detail: detailOrDefault(attestations != nil && attestations.Verified, "Otter observed at least one verified signature or attestation.", "No verified signature or attestation was observed."),
		},
		{
			ID:     "ssdf-vuln-response",
			Title:  "Vulnerability response signal",
			Status: vulnerabilityRecordStatus(vulnerabilities),
			Detail: vulnerabilityDetail(vulnerabilities),
		},
		{
			ID:     "ssdf-project-posture",
			Title:  "Upstream project posture",
			Status: projectPostureStatus(scorecard),
			Detail: projectPostureDetail(scorecard),
		},
	}

	status := summarizeChecks(checks)
	return StandardSummary{
		Name:    "NIST SSDF",
		Status:  status,
		Summary: "Best-effort alignment based on provenance, verification, vulnerability-management, and upstream project posture signals.",
		Checks:  checks,
	}
}

func buildCISStandard(vulnerabilities *VulnerabilitySummary, attestations *AttestationSummary) StandardSummary {
	critical := 0
	fixable := 0
	if vulnerabilities != nil {
		critical = vulnerabilities.Critical
		fixable = vulnerabilities.Fixable
	}

	checks := []StandardCheck{
		{
			ID:     "cis-attestation",
			Title:  "Signed or attested image",
			Status: ternaryStatus(attestations != nil && attestations.Total > 0, StatusPass, StatusFail),
			Detail: detailOrDefault(attestations != nil && attestations.Total > 0, "The image has signatures or attestations attached.", "No signatures or attestations were discovered."),
		},
		{
			ID:     "cis-critical-vulns",
			Title:  "Critical vulnerability backlog",
			Status: ternaryStatus(critical == 0, StatusPass, StatusFail),
			Detail: criticalVulnerabilityDetail(critical),
		},
		{
			ID:     "cis-fixable-vulns",
			Title:  "Fixable vulnerability backlog",
			Status: fixableStatus(fixable),
			Detail: fixableVulnerabilityDetail(fixable),
		},
	}

	status := summarizeChecks(checks)
	return StandardSummary{
		Name:    "CIS Container Image",
		Status:  status,
		Summary: "Image-hardening heuristics based on signature presence and current vulnerability posture.",
		Checks:  checks,
	}
}

func summarizeStandards(standards []StandardSummary) Summary {
	summary := Summary{}
	for _, standard := range standards {
		switch standard.Status {
		case StatusPass:
			summary.Passed++
		case StatusPartial:
			summary.Partial++
		case StatusFail:
			summary.Failed++
		default:
			summary.Unavailable++
		}
	}

	switch {
	case summary.Failed > 0:
		summary.OverallStatus = StatusFail
	case summary.Partial > 0:
		summary.OverallStatus = StatusPartial
	case summary.Passed > 0:
		summary.OverallStatus = StatusPass
	default:
		summary.OverallStatus = StatusUnavailable
	}
	return summary
}

func summarizeChecks(checks []StandardCheck) string {
	counts := map[string]int{}
	for _, check := range checks {
		counts[check.Status]++
	}
	switch {
	case counts[StatusFail] > 0 && counts[StatusPass] == 0 && counts[StatusPartial] == 0:
		return StatusFail
	case counts[StatusPass] == len(checks):
		return StatusPass
	case counts[StatusUnavailable] == len(checks):
		return StatusUnavailable
	default:
		return StatusPartial
	}
}

func aggregateSignalStatus(values ...bool) string {
	passed := 0
	for _, value := range values {
		if value {
			passed++
		}
	}
	switch {
	case passed == 0:
		return StatusFail
	case passed == len(values):
		return StatusPass
	default:
		return StatusPartial
	}
}

func vulnerabilityRecordStatus(vulnerabilities *VulnerabilitySummary) string {
	if vulnerabilities == nil {
		return StatusUnavailable
	}
	if vulnerabilities.Total == 0 {
		return StatusPass
	}
	if vulnerabilities.Fixable == 0 {
		return StatusPartial
	}
	return StatusPass
}

func vulnerabilityDetail(vulnerabilities *VulnerabilitySummary) string {
	if vulnerabilities == nil {
		return "No structured vulnerability record is stored for this image."
	}
	if vulnerabilities.Total == 0 {
		return "No known vulnerabilities are currently indexed."
	}
	return "Structured vulnerability data is stored, including fixability counts used for remediation planning."
}

func projectPostureStatus(scorecard ScorecardSummary) string {
	if !scorecard.Available {
		return StatusUnavailable
	}
	return scorecard.Status
}

func projectPostureDetail(scorecard ScorecardSummary) string {
	if !scorecard.Available {
		if scorecard.Error != "" {
			return scorecard.Error
		}
		return "OpenSSF Scorecard data is unavailable."
	}
	return "OpenSSF Scorecard reports an upstream score of " + trimFloat(scorecard.Score) + "."
}

func criticalVulnerabilityDetail(count int) string {
	if count == 0 {
		return "No critical vulnerabilities are currently indexed."
	}
	return trimInt(count) + " critical vulnerabilities are currently indexed."
}

func fixableStatus(count int) string {
	switch {
	case count == 0:
		return StatusPass
	case count <= 5:
		return StatusPartial
	default:
		return StatusFail
	}
}

func fixableVulnerabilityDetail(count int) string {
	if count == 0 {
		return "No fixable vulnerabilities are currently indexed."
	}
	return trimInt(count) + " fixable vulnerabilities remain in the current scan results."
}

func ternaryStatus(condition bool, whenTrue, whenFalse string) string {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func detailOrDefault(condition bool, whenTrue, whenFalse string) string {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func compactStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func trimInt(value int) string {
	return strconv.Itoa(value)
}

func trimFloat(value float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", value), "0"), ".")
}
