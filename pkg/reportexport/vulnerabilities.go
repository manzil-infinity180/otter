package reportexport

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/otterXf/otter/pkg/policy"
	"github.com/otterXf/otter/pkg/vulnindex"
)

const (
	FormatCSV   = "csv"
	FormatJSON  = "json"
	FormatSARIF = "sarif"
)

type vulnerabilityDocument struct {
	OrgID              string                          `json:"org_id"`
	ImageID            string                          `json:"image_id"`
	ImageName          string                          `json:"image_name"`
	Summary            vulnindex.Summary               `json:"summary"`
	Vulnerabilities    []vulnindex.VulnerabilityRecord `json:"vulnerabilities"`
	FixRecommendations []vulnindex.FixRecommendation   `json:"fix_recommendations"`
	Trend              []vulnindex.TrendPoint          `json:"trend,omitempty"`
	VEXDocuments       []vulnindex.VEXDocumentRecord   `json:"vex_documents,omitempty"`
	Policy             *policy.Evaluation              `json:"policy,omitempty"`
	UpdatedAt          string                          `json:"updated_at"`
}

func MarshalVulnerabilitiesJSON(record vulnindex.Record, evaluation *policy.Evaluation) ([]byte, error) {
	document := vulnerabilityDocument{
		OrgID:              record.OrgID,
		ImageID:            record.ImageID,
		ImageName:          record.ImageName,
		Summary:            record.Summary,
		Vulnerabilities:    record.Vulnerabilities,
		FixRecommendations: record.FixRecommendations,
		Trend:              record.Trend,
		VEXDocuments:       record.VEXDocuments,
		Policy:             evaluation,
		UpdatedAt:          record.UpdatedAt.UTC().Format(timeLayoutRFC3339),
	}
	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal vulnerabilities json: %w", err)
	}
	return payload, nil
}

func MarshalVulnerabilitiesCSV(record vulnindex.Record, evaluation *policy.Evaluation) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	header := []string{
		"id",
		"severity",
		"package_name",
		"package_version",
		"package_type",
		"namespace",
		"status",
		"status_source",
		"fix_version",
		"fix_versions",
		"cvss",
		"scanners",
		"primary_url",
		"first_seen_at",
		"last_seen_at",
		"advisory_document_id",
		"advisory_status_notes",
		"policy_mode",
		"policy_status",
		"policy_allowed",
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("write csv header: %w", err)
	}

	for _, vulnerability := range record.Vulnerabilities {
		advisoryDocumentID := ""
		advisoryStatusNotes := ""
		if vulnerability.Advisory != nil {
			advisoryDocumentID = vulnerability.Advisory.DocumentID
			advisoryStatusNotes = vulnerability.Advisory.StatusNotes
		}

		row := []string{
			vulnerability.ID,
			vulnerability.Severity,
			vulnerability.PackageName,
			vulnerability.PackageVersion,
			vulnerability.PackageType,
			vulnerability.Namespace,
			vulnerability.Status,
			vulnerability.StatusSource,
			vulnerability.FixVersion,
			strings.Join(vulnerability.FixVersions, "|"),
			formatCVSS(vulnerability),
			strings.Join(vulnerability.Scanners, "|"),
			vulnerability.PrimaryURL,
			vulnerability.FirstSeenAt.UTC().Format(timeLayoutRFC3339),
			vulnerability.LastSeenAt.UTC().Format(timeLayoutRFC3339),
			advisoryDocumentID,
			advisoryStatusNotes,
			policyField(evaluation, "mode"),
			policyField(evaluation, "status"),
			policyField(evaluation, "allowed"),
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("write csv row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}
	return buf.Bytes(), nil
}

func MarshalVulnerabilitiesSARIF(record vulnindex.Record, evaluation *policy.Evaluation) ([]byte, error) {
	rulesByID := make(map[string]sarifRule, len(record.Vulnerabilities))
	for _, vulnerability := range record.Vulnerabilities {
		if _, ok := rulesByID[vulnerability.ID]; ok {
			continue
		}
		rulesByID[vulnerability.ID] = sarifRule{
			ID:               vulnerability.ID,
			Name:             vulnerability.ID,
			ShortDescription: sarifMessage{Text: chooseDescription(vulnerability.Title, vulnerability.Description, vulnerability.ID)},
			FullDescription:  sarifMessage{Text: chooseDescription(vulnerability.Description, vulnerability.Title, vulnerability.ID)},
			HelpURI:          vulnerability.PrimaryURL,
			DefaultConfiguration: sarifDefaultConfiguration{
				Level: sarifLevel(vulnerability.Severity),
			},
			Properties: sarifRuleProperties{
				Tags: []string{
					"container",
					"otter",
					strings.ToLower(vulnerability.Severity),
				},
				SecuritySeverity: formatSecuritySeverity(vulnerability),
			},
		}
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	rules := make([]sarifRule, 0, len(ruleIDs))
	ruleIndexes := make(map[string]int, len(ruleIDs))
	for index, id := range ruleIDs {
		ruleIndexes[id] = index
		rules = append(rules, rulesByID[id])
	}

	results := make([]sarifResult, 0, len(record.Vulnerabilities))
	for _, vulnerability := range record.Vulnerabilities {
		artifactURI := sarifArtifactURI(record, vulnerability)
		results = append(results, sarifResult{
			RuleID:    vulnerability.ID,
			RuleIndex: ruleIndexes[vulnerability.ID],
			Level:     sarifLevel(vulnerability.Severity),
			Message: sarifMessage{
				Text: sarifResultMessage(record, vulnerability),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
						Region:           sarifRegion{StartLine: 1},
					},
				},
			},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": stableFingerprint(record.OrgID, record.ImageID, vulnerability.ID, vulnerability.PackageName, artifactURI),
				"vulnerability/id":        stableFingerprint(vulnerability.ID),
				"package/name":            stableFingerprint(vulnerability.PackageName, vulnerability.PackageVersion),
			},
			Properties: sarifResultProperties{
				ImageName:      record.ImageName,
				PackageName:    vulnerability.PackageName,
				PackageVersion: vulnerability.PackageVersion,
				PackageType:    vulnerability.PackageType,
				Namespace:      vulnerability.Namespace,
				Severity:       vulnerability.Severity,
				Status:         vulnerability.Status,
				StatusSource:   vulnerability.StatusSource,
				FixVersion:     vulnerability.FixVersion,
				Scanners:       append([]string(nil), vulnerability.Scanners...),
				References:     append([]string(nil), vulnerability.References...),
				PrimaryURL:     vulnerability.PrimaryURL,
			},
		})
	}

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				AutomationDetails: sarifAutomationDetails{
					ID: fmt.Sprintf("otter/container-image/%s/%s", record.OrgID, record.ImageID),
				},
				Properties: sarifRunProperties{
					Policy: evaluation,
				},
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "otter",
						InformationURI: "https://github.com/otterXf/otter",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal vulnerabilities sarif: %w", err)
	}
	return payload, nil
}

const timeLayoutRFC3339 = "2006-01-02T15:04:05Z07:00"

type sarifReport struct {
	Schema  string     `json:"$schema,omitempty"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	AutomationDetails sarifAutomationDetails `json:"automationDetails,omitempty"`
	Properties        sarifRunProperties     `json:"properties,omitempty"`
	Tool              sarifTool              `json:"tool"`
	Results           []sarifResult          `json:"results"`
}

type sarifRunProperties struct {
	Policy *policy.Evaluation `json:"policy,omitempty"`
}

type sarifAutomationDetails struct {
	ID string `json:"id"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name,omitempty"`
	ShortDescription     sarifMessage              `json:"shortDescription,omitempty"`
	FullDescription      sarifMessage              `json:"fullDescription,omitempty"`
	HelpURI              string                    `json:"helpUri,omitempty"`
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           sarifRuleProperties       `json:"properties,omitempty"`
}

type sarifDefaultConfiguration struct {
	Level string `json:"level,omitempty"`
}

type sarifRuleProperties struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex,omitempty"`
	Level               string                `json:"level,omitempty"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations,omitempty"`
	PartialFingerprints map[string]string     `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProperties `json:"properties,omitempty"`
}

type sarifResultProperties struct {
	ImageName      string   `json:"imageName,omitempty"`
	PackageName    string   `json:"packageName,omitempty"`
	PackageVersion string   `json:"packageVersion,omitempty"`
	PackageType    string   `json:"packageType,omitempty"`
	Namespace      string   `json:"namespace,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Status         string   `json:"status,omitempty"`
	StatusSource   string   `json:"statusSource,omitempty"`
	FixVersion     string   `json:"fixVersion,omitempty"`
	Scanners       []string `json:"scanners,omitempty"`
	References     []string `json:"references,omitempty"`
	PrimaryURL     string   `json:"primaryUrl,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func formatCVSS(vulnerability vulnindex.VulnerabilityRecord) string {
	if len(vulnerability.CVSS) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vulnerability.CVSS))
	for _, score := range vulnerability.CVSS {
		label := strings.TrimSpace(score.Source)
		if label == "" {
			label = "cvss"
		}
		parts = append(parts, fmt.Sprintf("%s=%.1f", label, score.Score))
	}
	return strings.Join(parts, "|")
}

func policyField(evaluation *policy.Evaluation, field string) string {
	if evaluation == nil {
		return ""
	}
	switch field {
	case "mode":
		return evaluation.Mode
	case "status":
		return evaluation.Status
	case "allowed":
		if evaluation.Allowed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func chooseDescription(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return "container vulnerability"
}

func formatSecuritySeverity(vulnerability vulnindex.VulnerabilityRecord) string {
	if len(vulnerability.CVSS) == 0 {
		return ""
	}
	highest := vulnerability.CVSS[0].Score
	for _, score := range vulnerability.CVSS[1:] {
		if score.Score > highest {
			highest = score.Score
		}
	}
	return fmt.Sprintf("%.1f", highest)
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "NEGLIGIBLE":
		return "note"
	default:
		return "warning"
	}
}

func sarifResultMessage(record vulnindex.Record, vulnerability vulnindex.VulnerabilityRecord) string {
	packageName := strings.TrimSpace(vulnerability.PackageName)
	if packageName == "" {
		packageName = "unknown package"
	}
	version := strings.TrimSpace(vulnerability.PackageVersion)
	if version == "" {
		version = "unknown version"
	}
	return fmt.Sprintf("%s affects %s %s in %s (%s)", vulnerability.ID, packageName, version, chooseDescription(record.ImageName, record.ImageID), vulnerability.Status)
}

func sarifArtifactURI(record vulnindex.Record, vulnerability vulnindex.VulnerabilityRecord) string {
	pkg := sanitizeSARIFSegment(vulnerability.PackageName)
	packageType := sanitizeSARIFSegment(vulnerability.PackageType)
	if packageType == "unknown" {
		packageType = "package"
	}
	return strings.Join([]string{
		"container-images",
		sanitizeSARIFSegment(record.OrgID),
		sanitizeSARIFSegment(record.ImageID),
		packageType,
		pkg + ".txt",
	}, "/")
}

func sanitizeSARIFSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-', r == '_', r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteRune('_')
		}
	}
	sanitized := strings.Trim(builder.String(), "._")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

func stableFingerprint(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "|")))
	return hex.EncodeToString(sum[:16])
}
