package vulnindex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
)

func BuildRecordFromReport(orgID, imageID, imageName string, report scan.CombinedVulnerabilityReport, previous *Record, opts BuildOptions) (Record, error) {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return Record{}, err
	}

	observedAt := report.GeneratedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	record := Record{
		OrgID:        orgID,
		ImageID:      imageID,
		ImageName:    strings.TrimSpace(imageName),
		UpdatedAt:    observedAt,
		VEXDocuments: nil,
	}
	if previous != nil {
		if record.ImageName == "" {
			record.ImageName = previous.ImageName
		}
		record.VEXDocuments = cloneVEXDocuments(previous.VEXDocuments)
		record.Trend = cloneTrend(previous.Trend)
	}

	existingFindings := map[string]VulnerabilityRecord{}
	if previous != nil {
		for _, finding := range previous.Vulnerabilities {
			existingFindings[vulnerabilityKey(finding)] = finding
		}
	}

	record.Vulnerabilities = make([]VulnerabilityRecord, 0, len(report.Vulnerabilities))
	for _, finding := range report.Vulnerabilities {
		item := normalizeFinding(finding)
		vuln := VulnerabilityRecord{
			ID:             item.ID,
			Severity:       item.Severity,
			PackageName:    item.PackageName,
			PackageVersion: item.PackageVersion,
			PackageType:    item.PackageType,
			Namespace:      item.Namespace,
			Title:          item.Title,
			Description:    item.Description,
			PrimaryURL:     item.PrimaryURL,
			References:     uniqueSortedStrings(item.References),
			FixVersion:     item.FixVersion,
			FixVersions:    uniqueSortedStrings(item.FixVersions),
			CVSS:           uniqueSortedCVSS(item.CVSS),
			Scanners:       uniqueSortedStrings(item.Scanners),
			Status:         StatusAffected,
			StatusSource:   StatusSourceScanner,
			FirstSeenAt:    observedAt,
			LastSeenAt:     observedAt,
		}
		if existing, ok := existingFindings[vulnerabilityKey(vuln)]; ok && !existing.FirstSeenAt.IsZero() {
			vuln.FirstSeenAt = existing.FirstSeenAt.UTC()
		}
		record.Vulnerabilities = append(record.Vulnerabilities, vuln)
	}

	applyVEXStatuses(&record)
	sortVulnerabilities(record.Vulnerabilities)
	record.Summary = summarize(record.Vulnerabilities)
	record.FixRecommendations = buildFixRecommendations(record.Vulnerabilities)
	if opts.TrackTrend {
		record.Trend = append(record.Trend, TrendPoint{
			ObservedAt: observedAt,
			Summary:    record.Summary,
		})
	}

	return record, nil
}

func BuildRecordFromDocument(orgID, imageID, imageName string, document []byte, previous *Record, opts BuildOptions) (Record, error) {
	var report scan.CombinedVulnerabilityReport
	if err := json.Unmarshal(document, &report); err != nil {
		return Record{}, fmt.Errorf("decode vulnerability report: %w", err)
	}
	return BuildRecordFromReport(orgID, imageID, imageName, report, previous, opts)
}

func ApplyVEXDocument(record Record, document []byte, filename string, importedAt time.Time) (Record, VEXDocumentRecord, error) {
	if err := validateRecordKey(record.OrgID, record.ImageID); err != nil {
		return Record{}, VEXDocumentRecord{}, err
	}
	if importedAt.IsZero() {
		importedAt = time.Now().UTC()
	}

	doc, err := parseOpenVEXDocument(document, filename, importedAt)
	if err != nil {
		return Record{}, VEXDocumentRecord{}, err
	}

	record.VEXDocuments = upsertVEXDocument(record.VEXDocuments, doc)
	applyVEXStatuses(&record)
	sortVulnerabilities(record.Vulnerabilities)
	record.Summary = summarize(record.Vulnerabilities)
	record.FixRecommendations = buildFixRecommendations(record.Vulnerabilities)
	record.UpdatedAt = importedAt.UTC()

	return record, doc, nil
}

func FilterRecord(record Record, opts FilterOptions) (Record, error) {
	severity := ""
	if strings.TrimSpace(opts.Severity) != "" {
		severity = normalizeSeverity(opts.Severity)
		if severity == "UNKNOWN" {
			return Record{}, fmt.Errorf("unsupported severity %q", opts.Severity)
		}
	}

	status := ""
	if strings.TrimSpace(opts.Status) != "" {
		var err error
		status, err = NormalizeStatus(opts.Status)
		if err != nil {
			return Record{}, err
		}
	}

	filtered := record
	filtered.Vulnerabilities = make([]VulnerabilityRecord, 0, len(record.Vulnerabilities))
	for _, vulnerability := range record.Vulnerabilities {
		if severity != "" && vulnerability.Severity != severity {
			continue
		}
		if status != "" && vulnerability.Status != status {
			continue
		}
		filtered.Vulnerabilities = append(filtered.Vulnerabilities, vulnerability)
	}
	filtered.Summary = summarize(filtered.Vulnerabilities)
	filtered.FixRecommendations = buildFixRecommendations(filtered.Vulnerabilities)

	return filtered, nil
}

func NormalizeStatus(status string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case StatusAffected:
		return StatusAffected, nil
	case StatusNotAffected:
		return StatusNotAffected, nil
	case StatusFixed:
		return StatusFixed, nil
	case StatusUnderInvestigation:
		return StatusUnderInvestigation, nil
	default:
		return "", fmt.Errorf("unsupported status %q", status)
	}
}

func validateRecordKey(orgID, imageID string) error {
	if err := storage.ValidateSegment("org_id", orgID); err != nil {
		return err
	}
	if err := storage.ValidateSegment("image_id", imageID); err != nil {
		return err
	}
	return nil
}

func parseOpenVEXDocument(document []byte, filename string, importedAt time.Time) (VEXDocumentRecord, error) {
	if !json.Valid(document) {
		return VEXDocumentRecord{}, fmt.Errorf("uploaded VEX document must be valid JSON")
	}

	doc, err := openvex.Parse(document)
	if err != nil {
		return VEXDocumentRecord{}, fmt.Errorf("parse openvex document: %w", err)
	}
	if len(doc.Statements) == 0 {
		return VEXDocumentRecord{}, fmt.Errorf("openvex document must contain at least one statement")
	}

	record := VEXDocumentRecord{
		DocumentID:  strings.TrimSpace(doc.ID),
		Author:      strings.TrimSpace(doc.Author),
		AuthorRole:  strings.TrimSpace(doc.AuthorRole),
		Timestamp:   derefTime(doc.Timestamp, importedAt),
		LastUpdated: derefTime(doc.LastUpdated, derefTime(doc.Timestamp, importedAt)),
		Version:     doc.Version,
		ImportedAt:  importedAt.UTC(),
		Filename:    strings.TrimSpace(filename),
		Statements:  make([]VEXStatementRecord, 0, len(doc.Statements)),
	}
	if record.DocumentID == "" {
		sum := sha256.Sum256(document)
		record.DocumentID = "openvex-sha256-" + hex.EncodeToString(sum[:8])
	}

	for idx, statement := range doc.Statements {
		if err := statement.Validate(); err != nil {
			return VEXDocumentRecord{}, fmt.Errorf("validate openvex statement %d: %w", idx, err)
		}
		vulnerabilityID := firstNonEmpty(
			string(statement.Vulnerability.Name),
			statement.Vulnerability.ID,
		)
		if vulnerabilityID == "" && len(statement.Vulnerability.Aliases) > 0 {
			vulnerabilityID = string(statement.Vulnerability.Aliases[0])
		}
		vulnerabilityID = normalizeVulnerabilityID(vulnerabilityID)
		if vulnerabilityID == "" {
			return VEXDocumentRecord{}, fmt.Errorf("openvex statement %d is missing a vulnerability identifier", idx)
		}

		status, err := NormalizeStatus(string(statement.Status))
		if err != nil {
			return VEXDocumentRecord{}, fmt.Errorf("normalize openvex statement %d: %w", idx, err)
		}

		docStatement := VEXStatementRecord{
			StatementID:     strings.TrimSpace(statement.ID),
			VulnerabilityID: vulnerabilityID,
			Status:          status,
			StatusNotes:     strings.TrimSpace(statement.StatusNotes),
			Justification:   strings.TrimSpace(string(statement.Justification)),
			ImpactStatement: strings.TrimSpace(statement.ImpactStatement),
			ActionStatement: strings.TrimSpace(statement.ActionStatement),
			Timestamp:       derefTime(statement.Timestamp, record.Timestamp),
			LastUpdated:     derefTime(statement.LastUpdated, derefTime(statement.Timestamp, record.LastUpdated)),
		}
		for _, product := range statement.Products {
			if id := strings.TrimSpace(product.ID); id != "" {
				docStatement.ProductIDs = append(docStatement.ProductIDs, id)
			}
			for identifier := range product.Identifiers {
				value := strings.TrimSpace(product.Identifiers[identifier])
				if value != "" {
					docStatement.ProductIDs = append(docStatement.ProductIDs, value)
				}
			}
			for _, subcomponent := range product.Subcomponents {
				if id := strings.TrimSpace(subcomponent.ID); id != "" {
					docStatement.SubcomponentIDs = append(docStatement.SubcomponentIDs, id)
				}
				for identifier := range subcomponent.Identifiers {
					value := strings.TrimSpace(subcomponent.Identifiers[identifier])
					if value != "" {
						docStatement.SubcomponentIDs = append(docStatement.SubcomponentIDs, value)
					}
				}
			}
		}
		docStatement.ProductIDs = uniqueSortedStrings(docStatement.ProductIDs)
		docStatement.SubcomponentIDs = uniqueSortedStrings(docStatement.SubcomponentIDs)
		record.Statements = append(record.Statements, docStatement)
	}

	sort.Slice(record.Statements, func(i, j int) bool {
		if record.Statements[i].VulnerabilityID != record.Statements[j].VulnerabilityID {
			return record.Statements[i].VulnerabilityID < record.Statements[j].VulnerabilityID
		}
		return effectiveStatementTime(record, record.Statements[i]).Before(effectiveStatementTime(record, record.Statements[j]))
	})

	return record, nil
}

func applyVEXStatuses(record *Record) {
	if record == nil {
		return
	}

	overlays := latestVEXStatements(record.VEXDocuments)
	for idx := range record.Vulnerabilities {
		record.Vulnerabilities[idx].Status = StatusAffected
		record.Vulnerabilities[idx].StatusSource = StatusSourceScanner
		record.Vulnerabilities[idx].Advisory = nil

		overlay, ok := overlays[normalizeVulnerabilityID(record.Vulnerabilities[idx].ID)]
		if !ok {
			continue
		}

		record.Vulnerabilities[idx].Status = overlay.Statement.Status
		record.Vulnerabilities[idx].StatusSource = StatusSourceVEX
		record.Vulnerabilities[idx].Advisory = &Advisory{
			DocumentID:      overlay.Document.DocumentID,
			Filename:        overlay.Document.Filename,
			StatementID:     overlay.Statement.StatementID,
			Author:          overlay.Document.Author,
			StatusNotes:     overlay.Statement.StatusNotes,
			Justification:   overlay.Statement.Justification,
			ImpactStatement: overlay.Statement.ImpactStatement,
			ActionStatement: overlay.Statement.ActionStatement,
			Timestamp:       effectiveStatementTime(overlay.Document, overlay.Statement),
		}
	}
}

func latestVEXStatements(documents []VEXDocumentRecord) map[string]vexOverlay {
	result := make(map[string]vexOverlay)
	for _, document := range documents {
		for _, statement := range document.Statements {
			key := normalizeVulnerabilityID(statement.VulnerabilityID)
			candidate := vexOverlay{
				Document:   document,
				Statement:  statement,
				ObservedAt: effectiveStatementTime(document, statement),
			}
			current, ok := result[key]
			if !ok || candidate.isNewerThan(current) {
				result[key] = candidate
			}
		}
	}
	return result
}

type vexOverlay struct {
	Document   VEXDocumentRecord
	Statement  VEXStatementRecord
	ObservedAt time.Time
}

func (o vexOverlay) isNewerThan(other vexOverlay) bool {
	if o.ObservedAt.After(other.ObservedAt) {
		return true
	}
	if other.ObservedAt.After(o.ObservedAt) {
		return false
	}
	if o.Document.Version != other.Document.Version {
		return o.Document.Version > other.Document.Version
	}
	return o.Document.DocumentID > other.Document.DocumentID
}

func effectiveStatementTime(document VEXDocumentRecord, statement VEXStatementRecord) time.Time {
	switch {
	case !statement.LastUpdated.IsZero():
		return statement.LastUpdated.UTC()
	case !statement.Timestamp.IsZero():
		return statement.Timestamp.UTC()
	case !document.LastUpdated.IsZero():
		return document.LastUpdated.UTC()
	case !document.Timestamp.IsZero():
		return document.Timestamp.UTC()
	default:
		return document.ImportedAt.UTC()
	}
}

func summarize(vulnerabilities []VulnerabilityRecord) Summary {
	summary := Summary{
		Total:      len(vulnerabilities),
		BySeverity: make(map[string]int),
		ByScanner:  make(map[string]int),
		ByStatus:   make(map[string]int),
	}
	for _, vulnerability := range vulnerabilities {
		summary.BySeverity[vulnerability.Severity]++
		summary.ByStatus[vulnerability.Status]++
		if vulnerability.FixVersion == "" {
			summary.Unfixable++
		} else {
			summary.Fixable++
		}
		for _, scannerName := range vulnerability.Scanners {
			summary.ByScanner[scannerName]++
		}
	}
	return summary
}

func buildFixRecommendations(vulnerabilities []VulnerabilityRecord) []FixRecommendation {
	type recommendationState struct {
		recommendation FixRecommendation
	}

	recommendations := map[string]*recommendationState{}
	for _, vulnerability := range vulnerabilities {
		recommendedVersion := recommendedFixVersion(vulnerability)
		if recommendedVersion == "" {
			continue
		}

		key := strings.Join([]string{
			strings.ToLower(vulnerability.PackageName),
			vulnerability.PackageVersion,
			strings.ToLower(vulnerability.PackageType),
			strings.ToLower(vulnerability.Namespace),
		}, "|")
		state, ok := recommendations[key]
		if !ok {
			state = &recommendationState{
				recommendation: FixRecommendation{
					PackageName:        vulnerability.PackageName,
					PackageVersion:     vulnerability.PackageVersion,
					PackageType:        vulnerability.PackageType,
					Namespace:          vulnerability.Namespace,
					RecommendedVersion: recommendedVersion,
				},
			}
			recommendations[key] = state
		}
		if strings.Compare(recommendedVersion, state.recommendation.RecommendedVersion) > 0 {
			state.recommendation.RecommendedVersion = recommendedVersion
		}
		state.recommendation.VulnerabilityIDs = append(state.recommendation.VulnerabilityIDs, vulnerability.ID)
	}

	result := make([]FixRecommendation, 0, len(recommendations))
	for _, recommendation := range recommendations {
		recommendation.recommendation.VulnerabilityIDs = uniqueSortedStrings(recommendation.recommendation.VulnerabilityIDs)
		recommendation.recommendation.VulnerabilityCount = len(recommendation.recommendation.VulnerabilityIDs)
		result = append(result, recommendation.recommendation)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].PackageName != result[j].PackageName {
			return result[i].PackageName < result[j].PackageName
		}
		return result[i].RecommendedVersion < result[j].RecommendedVersion
	})

	return result
}

func recommendedFixVersion(vulnerability VulnerabilityRecord) string {
	if strings.TrimSpace(vulnerability.FixVersion) != "" {
		return strings.TrimSpace(vulnerability.FixVersion)
	}
	if len(vulnerability.FixVersions) == 0 {
		return ""
	}
	return strings.TrimSpace(vulnerability.FixVersions[len(vulnerability.FixVersions)-1])
}

func upsertVEXDocument(documents []VEXDocumentRecord, document VEXDocumentRecord) []VEXDocumentRecord {
	result := cloneVEXDocuments(documents)
	for idx := range result {
		if result[idx].DocumentID == document.DocumentID {
			result[idx] = document
			sortVEXDocuments(result)
			return result
		}
	}
	result = append(result, document)
	sortVEXDocuments(result)
	return result
}

func sortVEXDocuments(documents []VEXDocumentRecord) {
	sort.Slice(documents, func(i, j int) bool {
		if documents[i].ImportedAt != documents[j].ImportedAt {
			return documents[i].ImportedAt.Before(documents[j].ImportedAt)
		}
		return documents[i].DocumentID < documents[j].DocumentID
	})
}

func sortVulnerabilities(vulnerabilities []VulnerabilityRecord) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		a := vulnerabilities[i]
		b := vulnerabilities[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.PackageName != b.PackageName {
			return a.PackageName < b.PackageName
		}
		return a.PackageVersion < b.PackageVersion
	})
}

func normalizeFinding(finding scan.VulnerabilityFinding) scan.VulnerabilityFinding {
	finding.ID = normalizeVulnerabilityID(finding.ID)
	finding.Severity = normalizeSeverity(finding.Severity)
	finding.PackageName = strings.TrimSpace(finding.PackageName)
	finding.PackageVersion = strings.TrimSpace(finding.PackageVersion)
	finding.PackageType = strings.TrimSpace(finding.PackageType)
	finding.Namespace = strings.TrimSpace(finding.Namespace)
	finding.Title = strings.TrimSpace(finding.Title)
	finding.Description = strings.TrimSpace(finding.Description)
	finding.PrimaryURL = strings.TrimSpace(finding.PrimaryURL)
	finding.References = uniqueSortedStrings(finding.References)
	finding.FixVersions = uniqueSortedStrings(finding.FixVersions)
	if finding.FixVersion == "" && len(finding.FixVersions) > 0 {
		finding.FixVersion = finding.FixVersions[0]
	}
	finding.Scanners = uniqueSortedStrings(finding.Scanners)
	finding.CVSS = uniqueSortedCVSS(finding.CVSS)
	return finding
}

func normalizeVulnerabilityID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

func normalizeSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "NEGLIGIBLE":
		return "NEGLIGIBLE"
	default:
		return "UNKNOWN"
	}
}

func severityRank(severity string) int {
	switch normalizeSeverity(severity) {
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

func vulnerabilityKey(vulnerability VulnerabilityRecord) string {
	return strings.Join([]string{
		normalizeVulnerabilityID(vulnerability.ID),
		strings.ToLower(strings.TrimSpace(vulnerability.PackageName)),
		strings.TrimSpace(vulnerability.PackageVersion),
		strings.ToLower(strings.TrimSpace(vulnerability.Namespace)),
	}, "|")
}

func cloneTrend(trend []TrendPoint) []TrendPoint {
	if len(trend) == 0 {
		return nil
	}
	result := make([]TrendPoint, len(trend))
	copy(result, trend)
	return result
}

func cloneVEXDocuments(documents []VEXDocumentRecord) []VEXDocumentRecord {
	if len(documents) == 0 {
		return nil
	}
	result := make([]VEXDocumentRecord, len(documents))
	for idx := range documents {
		result[idx] = documents[idx]
		result[idx].Statements = append([]VEXStatementRecord(nil), documents[idx].Statements...)
	}
	return result
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func uniqueSortedCVSS(values []scan.CVSSScore) []scan.CVSSScore {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]scan.CVSSScore, 0, len(values))
	for _, value := range values {
		key := fmt.Sprintf("%s|%s|%s|%.2f", strings.TrimSpace(value.Source), strings.TrimSpace(value.Version), strings.TrimSpace(value.Vector), value.Score)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, scan.CVSSScore{
			Source:  strings.TrimSpace(value.Source),
			Version: strings.TrimSpace(value.Version),
			Vector:  strings.TrimSpace(value.Vector),
			Score:   value.Score,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		if result[i].Version != result[j].Version {
			return result[i].Version < result[j].Version
		}
		return result[i].Vector < result[j].Vector
	})

	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func derefTime(value *time.Time, fallback time.Time) time.Time {
	if value != nil && !value.IsZero() {
		return value.UTC()
	}
	return fallback.UTC()
}
