package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/otterXf/otter/pkg/attestation"
	"github.com/otterXf/otter/pkg/vulnindex"
)

const (
	ModeDisabled = "disabled"
	ModeReport   = "report"
	ModeEnforce  = "enforce"

	StatusDisabled = "disabled"
	StatusPass     = "pass"
	StatusFail     = "fail"
)

var defaultIgnoredStatuses = []string{"fixed", "not_affected"}

type Config struct {
	BundlePath string
	Mode       string
}

type Bundle struct {
	Name     string   `json:"name" yaml:"name"`
	Version  int      `json:"version,omitempty" yaml:"version,omitempty"`
	Mode     string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	Policies []Policy `json:"policies" yaml:"policies"`
}

type Policy struct {
	ID                    string   `json:"id" yaml:"id"`
	Title                 string   `json:"title,omitempty" yaml:"title,omitempty"`
	Description           string   `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled               *bool    `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	MaxSeverity           string   `json:"max_severity,omitempty" yaml:"max_severity,omitempty"`
	IgnoreStatuses        []string `json:"ignore_statuses,omitempty" yaml:"ignore_statuses,omitempty"`
	AllowedScanners       []string `json:"allowed_scanners,omitempty" yaml:"allowed_scanners,omitempty"`
	MinSignatures         int      `json:"min_signatures,omitempty" yaml:"min_signatures,omitempty"`
	MinVerifiedSignatures int      `json:"min_verified_signatures,omitempty" yaml:"min_verified_signatures,omitempty"`
	MinProvenance         int      `json:"min_provenance,omitempty" yaml:"min_provenance,omitempty"`
	MinVerifiedProvenance int      `json:"min_verified_provenance,omitempty" yaml:"min_verified_provenance,omitempty"`
}

type Input struct {
	OrgID            string
	ImageID          string
	ImageName        string
	Vulnerabilities  vulnindex.Record
	Attestations     *attestation.Result
	AttestationError string
	EvaluatedAt      time.Time
}

type Evaluation struct {
	Enabled     bool           `json:"enabled"`
	BundleName  string         `json:"bundle_name,omitempty"`
	BundlePath  string         `json:"bundle_path,omitempty"`
	BundleVer   int            `json:"bundle_version,omitempty"`
	Mode        string         `json:"mode"`
	Status      string         `json:"status"`
	Allowed     bool           `json:"allowed"`
	Summary     string         `json:"summary"`
	EvaluatedAt time.Time      `json:"evaluated_at"`
	Total       int            `json:"total"`
	Passed      int            `json:"passed"`
	Failed      int            `json:"failed"`
	Policies    []PolicyResult `json:"policies,omitempty"`
}

type PolicyResult struct {
	ID         string      `json:"id"`
	Title      string      `json:"title,omitempty"`
	Status     string      `json:"status"`
	Summary    string      `json:"summary"`
	Violations []Violation `json:"violations,omitempty"`
}

type Violation struct {
	Type            string `json:"type"`
	Message         string `json:"message"`
	Severity        string `json:"severity,omitempty"`
	Scanner         string `json:"scanner,omitempty"`
	VulnerabilityID string `json:"vulnerability_id,omitempty"`
}

type Engine struct {
	bundle              Bundle
	mode                string
	bundlePath          string
	requiresAttestation bool
}

type attestationCounts struct {
	signatures         int
	verifiedSignatures int
	provenance         int
	verifiedProvenance int
}

func ConfigFromEnv() Config {
	return Config{
		BundlePath: strings.TrimSpace(os.Getenv("OTTER_POLICY_BUNDLE")),
		Mode:       strings.TrimSpace(os.Getenv("OTTER_POLICY_MODE")),
	}
}

func NewDisabledEngine() *Engine {
	return &Engine{mode: ModeDisabled}
}

func NewEngine(cfg Config) (*Engine, error) {
	bundlePath := strings.TrimSpace(cfg.BundlePath)
	if bundlePath == "" {
		return NewDisabledEngine(), nil
	}

	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		return nil, err
	}

	mode, err := resolveMode(cfg.Mode, bundle.Mode)
	if err != nil {
		return nil, err
	}

	return newEngine(bundle, bundlePath, mode), nil
}

func NewEngineFromBundle(bundle Bundle, mode string) (*Engine, error) {
	if err := normalizeBundle(&bundle); err != nil {
		return nil, err
	}
	resolvedMode, err := resolveMode(mode, bundle.Mode)
	if err != nil {
		return nil, err
	}
	return newEngine(bundle, "", resolvedMode), nil
}

func LoadBundle(path string) (Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("read policy bundle %s: %w", path, err)
	}

	var bundle Bundle
	if json.Unmarshal(data, &bundle) != nil {
		if err := yaml.Unmarshal(data, &bundle); err != nil {
			return Bundle{}, fmt.Errorf("decode policy bundle %s: %w", path, err)
		}
	}
	if bundle.Name == "" {
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		bundle.Name = strings.TrimSpace(base)
	}
	if err := normalizeBundle(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("normalize policy bundle %s: %w", path, err)
	}
	return bundle, nil
}

func (e *Engine) Enabled() bool {
	return e != nil && e.mode != ModeDisabled
}

func (e *Engine) Mode() string {
	if e == nil || e.mode == "" {
		return ModeDisabled
	}
	return e.mode
}

func (e *Engine) RequiresAttestations() bool {
	return e != nil && e.requiresAttestation
}

func (e *Engine) Evaluate(input Input) Evaluation {
	if e == nil || e.mode == ModeDisabled {
		return Evaluation{
			Enabled:     false,
			Mode:        ModeDisabled,
			Status:      StatusDisabled,
			Allowed:     true,
			Summary:     "policy evaluation disabled",
			EvaluatedAt: evaluationTime(input.EvaluatedAt),
		}
	}

	evaluation := Evaluation{
		Enabled:     true,
		BundleName:  e.bundle.Name,
		BundlePath:  e.bundlePath,
		BundleVer:   e.bundle.Version,
		Mode:        e.mode,
		Status:      StatusPass,
		Allowed:     true,
		EvaluatedAt: evaluationTime(input.EvaluatedAt),
	}

	counts := summarizeAttestations(input.Attestations)
	for _, rule := range e.bundle.Policies {
		if !rule.isEnabled() {
			continue
		}

		result := evaluatePolicy(rule, input, counts)
		evaluation.Total++
		if result.Status == StatusFail {
			evaluation.Failed++
		} else {
			evaluation.Passed++
		}
		evaluation.Policies = append(evaluation.Policies, result)
	}

	switch {
	case evaluation.Total == 0:
		evaluation.Summary = "policy bundle loaded with no active rules"
	case evaluation.Failed > 0:
		evaluation.Status = StatusFail
		evaluation.Allowed = false
		evaluation.Summary = fmt.Sprintf("%d of %d policy checks failed", evaluation.Failed, evaluation.Total)
	default:
		evaluation.Summary = fmt.Sprintf("all %d policy checks passed", evaluation.Total)
	}

	return evaluation
}

func newEngine(bundle Bundle, bundlePath, mode string) *Engine {
	engine := &Engine{
		bundle:     bundle,
		mode:       mode,
		bundlePath: bundlePath,
	}
	for _, rule := range bundle.Policies {
		if !rule.isEnabled() {
			continue
		}
		if rule.MinSignatures > 0 || rule.MinVerifiedSignatures > 0 || rule.MinProvenance > 0 || rule.MinVerifiedProvenance > 0 {
			engine.requiresAttestation = true
			break
		}
	}
	return engine
}

func resolveMode(primary, fallback string) (string, error) {
	for _, candidate := range []string{primary, fallback} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		return normalizeMode(candidate)
	}
	return ModeReport, nil
}

func normalizeMode(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ModeReport:
		return ModeReport, nil
	case ModeDisabled:
		return ModeDisabled, nil
	case ModeEnforce:
		return ModeEnforce, nil
	default:
		return "", fmt.Errorf("unsupported policy mode %q", value)
	}
}

func normalizeBundle(bundle *Bundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle is required")
	}
	bundle.Name = strings.TrimSpace(bundle.Name)
	if bundle.Name == "" {
		bundle.Name = "default"
	}
	if strings.TrimSpace(bundle.Mode) != "" {
		mode, err := normalizeMode(bundle.Mode)
		if err != nil {
			return err
		}
		bundle.Mode = mode
	}

	seen := make(map[string]struct{}, len(bundle.Policies))
	for index := range bundle.Policies {
		rule := &bundle.Policies[index]
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Title = strings.TrimSpace(rule.Title)
		rule.Description = strings.TrimSpace(rule.Description)
		if rule.ID == "" {
			return fmt.Errorf("policy at index %d is missing id", index)
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate policy id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.MaxSeverity != "" {
			normalized, err := normalizeSeverity(rule.MaxSeverity)
			if err != nil {
				return fmt.Errorf("policy %q max_severity: %w", rule.ID, err)
			}
			rule.MaxSeverity = normalized
		}
		rule.IgnoreStatuses = normalizeStatuses(rule.IgnoreStatuses)
		if len(rule.IgnoreStatuses) == 0 && rule.MaxSeverity != "" {
			rule.IgnoreStatuses = append([]string(nil), defaultIgnoredStatuses...)
		}
		rule.AllowedScanners = normalizeScanners(rule.AllowedScanners)
		if rule.MinSignatures < 0 || rule.MinVerifiedSignatures < 0 || rule.MinProvenance < 0 || rule.MinVerifiedProvenance < 0 {
			return fmt.Errorf("policy %q minimum counts cannot be negative", rule.ID)
		}
		if !rule.hasRules() {
			return fmt.Errorf("policy %q must define at least one rule", rule.ID)
		}
	}
	return nil
}

func (p Policy) isEnabled() bool {
	return p.Enabled == nil || *p.Enabled
}

func (p Policy) hasRules() bool {
	return p.MaxSeverity != "" || len(p.AllowedScanners) > 0 || p.MinSignatures > 0 || p.MinVerifiedSignatures > 0 || p.MinProvenance > 0 || p.MinVerifiedProvenance > 0
}

func evaluatePolicy(rule Policy, input Input, counts attestationCounts) PolicyResult {
	result := PolicyResult{
		ID:     rule.ID,
		Title:  rule.Title,
		Status: StatusPass,
	}

	if rule.MaxSeverity != "" {
		result.Violations = append(result.Violations, evaluateSeverityRule(rule, input.Vulnerabilities)...)
	}
	if len(rule.AllowedScanners) > 0 {
		result.Violations = append(result.Violations, evaluateScannerRule(rule, input.Vulnerabilities)...)
	}
	if rule.MinSignatures > 0 || rule.MinVerifiedSignatures > 0 || rule.MinProvenance > 0 || rule.MinVerifiedProvenance > 0 {
		result.Violations = append(result.Violations, evaluateAttestationRule(rule, input.AttestationError, counts)...)
	}

	if len(result.Violations) > 0 {
		result.Status = StatusFail
		result.Summary = fmt.Sprintf("%d gate condition(s) failed", len(result.Violations))
		return result
	}

	result.Summary = "all gate conditions passed"
	return result
}

func evaluateSeverityRule(rule Policy, record vulnindex.Record) []Violation {
	violations := make([]Violation, 0)
	threshold := severityRank(rule.MaxSeverity)
	if len(record.Vulnerabilities) == 0 {
		count := countSeverityAtOrAbove(record.Summary.BySeverity, threshold)
		if count > 0 {
			violations = append(violations, Violation{
				Type:     "max_severity",
				Severity: rule.MaxSeverity,
				Message:  fmt.Sprintf("%d summarized vulnerabilities remain at or above %s", count, rule.MaxSeverity),
			})
		}
		return violations
	}
	for _, finding := range record.Vulnerabilities {
		if severityRank(finding.Severity) < threshold {
			continue
		}
		if statusIgnored(rule.IgnoreStatuses, finding.Status) {
			continue
		}
		violations = append(violations, Violation{
			Type:            "max_severity",
			Message:         fmt.Sprintf("vulnerability %s remains at %s for %s", strings.TrimSpace(finding.ID), finding.Severity, strings.TrimSpace(finding.PackageName)),
			Severity:        finding.Severity,
			VulnerabilityID: finding.ID,
		})
	}
	return violations
}

func countSeverityAtOrAbove(summary map[string]int, threshold int) int {
	total := 0
	for severity, count := range summary {
		if severityRank(severity) >= threshold {
			total += count
		}
	}
	return total
}

func evaluateScannerRule(rule Policy, record vulnindex.Record) []Violation {
	actual := scannerSet(record)
	violations := make([]Violation, 0)
	if len(actual) == 0 {
		return []Violation{{
			Type:    "allowed_scanners",
			Message: "no scanner results were available to validate allowed_scanners",
		}}
	}

	allowed := make(map[string]struct{}, len(rule.AllowedScanners))
	for _, scanner := range rule.AllowedScanners {
		allowed[scanner] = struct{}{}
	}
	actualNames := make([]string, 0, len(actual))
	for scanner := range actual {
		actualNames = append(actualNames, scanner)
	}
	sort.Strings(actualNames)
	for _, scanner := range actualNames {
		if _, ok := allowed[scanner]; ok {
			continue
		}
		violations = append(violations, Violation{
			Type:    "allowed_scanners",
			Scanner: scanner,
			Message: fmt.Sprintf("scanner %q is not permitted by this policy", scanner),
		})
	}
	return violations
}

func evaluateAttestationRule(rule Policy, attestationError string, counts attestationCounts) []Violation {
	if strings.TrimSpace(attestationError) != "" {
		return []Violation{{
			Type:    "attestation_evidence",
			Message: "attestation evidence unavailable: " + strings.TrimSpace(attestationError),
		}}
	}

	violations := make([]Violation, 0)
	if rule.MinSignatures > 0 && counts.signatures < rule.MinSignatures {
		violations = append(violations, Violation{
			Type:    "min_signatures",
			Message: fmt.Sprintf("found %d signatures, require at least %d", counts.signatures, rule.MinSignatures),
		})
	}
	if rule.MinVerifiedSignatures > 0 && counts.verifiedSignatures < rule.MinVerifiedSignatures {
		violations = append(violations, Violation{
			Type:    "min_verified_signatures",
			Message: fmt.Sprintf("found %d verified signatures, require at least %d", counts.verifiedSignatures, rule.MinVerifiedSignatures),
		})
	}
	if rule.MinProvenance > 0 && counts.provenance < rule.MinProvenance {
		violations = append(violations, Violation{
			Type:    "min_provenance",
			Message: fmt.Sprintf("found %d provenance attestations, require at least %d", counts.provenance, rule.MinProvenance),
		})
	}
	if rule.MinVerifiedProvenance > 0 && counts.verifiedProvenance < rule.MinVerifiedProvenance {
		violations = append(violations, Violation{
			Type:    "min_verified_provenance",
			Message: fmt.Sprintf("found %d verified provenance attestations, require at least %d", counts.verifiedProvenance, rule.MinVerifiedProvenance),
		})
	}
	return violations
}

func summarizeAttestations(result *attestation.Result) attestationCounts {
	if result == nil {
		return attestationCounts{}
	}

	counts := attestationCounts{
		signatures: len(result.Signatures),
	}
	for _, record := range result.Signatures {
		if record.VerificationStatus == attestation.VerificationStatusValid {
			counts.verifiedSignatures++
		}
	}
	for _, record := range result.Attestations {
		if !isProvenanceRecord(record) {
			continue
		}
		counts.provenance++
		if record.VerificationStatus == attestation.VerificationStatusValid {
			counts.verifiedProvenance++
		}
	}
	return counts
}

func isProvenanceRecord(record attestation.Record) bool {
	if record.Provenance != nil {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(record.PredicateType)), "slsa.dev/provenance")
}

func normalizeSeverity(value string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return "CRITICAL", nil
	case "HIGH":
		return "HIGH", nil
	case "MEDIUM":
		return "MEDIUM", nil
	case "LOW":
		return "LOW", nil
	case "NEGLIGIBLE":
		return "NEGLIGIBLE", nil
	case "UNKNOWN":
		return "UNKNOWN", nil
	default:
		return "", fmt.Errorf("unsupported severity %q", value)
	}
}

func severityRank(value string) int {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NEGLIGIBLE":
		return 1
	default:
		return 0
	}
}

func normalizeStatuses(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result
}

func normalizeScanners(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result
}

func statusIgnored(ignored []string, status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	for _, candidate := range ignored {
		if candidate == normalized {
			return true
		}
	}
	return false
}

func scannerSet(record vulnindex.Record) map[string]struct{} {
	result := make(map[string]struct{})
	for scanner := range record.Summary.ByScanner {
		normalized := strings.ToLower(strings.TrimSpace(scanner))
		if normalized != "" {
			result[normalized] = struct{}{}
		}
	}
	for _, vulnerability := range record.Vulnerabilities {
		for _, scanner := range vulnerability.Scanners {
			normalized := strings.ToLower(strings.TrimSpace(scanner))
			if normalized != "" {
				result[normalized] = struct{}{}
			}
		}
	}
	return result
}

func evaluationTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}
