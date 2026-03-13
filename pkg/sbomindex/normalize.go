package sbomindex

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
)

func NormalizeFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatCycloneDX:
		return FormatCycloneDX, nil
	case FormatSPDX:
		return FormatSPDX, nil
	default:
		return "", fmt.Errorf("unsupported sbom format %q", format)
	}
}

func DetectFormat(document []byte) (string, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(document, &envelope); err != nil {
		return "", fmt.Errorf("decode sbom document: %w", err)
	}

	if raw, ok := envelope["bomFormat"]; ok {
		var bomFormat string
		if err := json.Unmarshal(raw, &bomFormat); err == nil && strings.EqualFold(bomFormat, "CycloneDX") {
			return FormatCycloneDX, nil
		}
	}
	if _, ok := envelope["spdxVersion"]; ok {
		return FormatSPDX, nil
	}
	return "", fmt.Errorf("unable to detect sbom format")
}

func BuildRecordFromSyft(orgID, imageID, imageName string, document *syftsbom.SBOM) (Record, error) {
	if document == nil {
		return Record{}, fmt.Errorf("sbom document is required")
	}

	packages := make([]PackageRecord, 0, document.Artifacts.Packages.PackageCount())
	packageIndex := make(map[string]PackageRecord, document.Artifacts.Packages.PackageCount())
	licenseCounts := make(map[string]int)

	for _, pkg := range document.Artifacts.Packages.Sorted() {
		record := PackageRecord{
			ID:       string(pkg.ID()),
			Name:     pkg.Name,
			Version:  pkg.Version,
			Type:     string(pkg.Type),
			PURL:     strings.TrimSpace(pkg.PURL),
			Licenses: normalizeSyftLicenses(pkg.Licenses.ToSlice()),
		}
		if record.ID == "" {
			record.ID = fallbackPackageID(pkg.Name, pkg.Version, record.Type)
		}
		packages = append(packages, record)
		packageIndex[record.ID] = record
		for _, license := range record.Licenses {
			licenseCounts[license]++
		}
	}

	sortPackages(packages)
	dependencyTree, dependencyRoots := buildDependencyTreeFromSyft(document.Relationships, packageIndex)

	return Record{
		OrgID:           orgID,
		ImageID:         imageID,
		ImageName:       imageName,
		SourceFormat:    FormatCycloneDX,
		PackageCount:    len(packages),
		Packages:        packages,
		DependencyTree:  dependencyTree,
		DependencyRoots: dependencyRoots,
		LicenseSummary:  summarizeLicenses(licenseCounts),
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

func BuildRecordFromDocument(orgID, imageID, imageName, format string, document []byte) (Record, error) {
	normalizedFormat, err := NormalizeFormat(format)
	if err != nil {
		return Record{}, err
	}

	switch normalizedFormat {
	case FormatCycloneDX:
		return buildRecordFromCycloneDX(orgID, imageID, imageName, document)
	case FormatSPDX:
		return buildRecordFromSPDX(orgID, imageID, imageName, document)
	default:
		return Record{}, fmt.Errorf("unsupported sbom format %q", normalizedFormat)
	}
}

type cycloneDXDocument struct {
	BOMFormat    string                `json:"bomFormat"`
	Metadata     cycloneDXMetadata     `json:"metadata"`
	Components   []cycloneDXComponent  `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies"`
}

type cycloneDXMetadata struct {
	Component *cycloneDXComponent `json:"component"`
}

type cycloneDXComponent struct {
	BOMRef   string                   `json:"bom-ref"`
	Name     string                   `json:"name"`
	Version  string                   `json:"version"`
	Type     string                   `json:"type"`
	PURL     string                   `json:"purl"`
	Licenses []cycloneDXLicenseChoice `json:"licenses"`
}

type cycloneDXLicenseChoice struct {
	Expression string               `json:"expression"`
	License    *cycloneDXLicenseRef `json:"license"`
}

type cycloneDXLicenseRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func buildRecordFromCycloneDX(orgID, imageID, imageName string, document []byte) (Record, error) {
	var decoded cycloneDXDocument
	if err := json.Unmarshal(document, &decoded); err != nil {
		return Record{}, fmt.Errorf("decode cyclonedx sbom: %w", err)
	}

	components := make([]cycloneDXComponent, 0, len(decoded.Components)+1)
	if decoded.Metadata.Component != nil && strings.TrimSpace(decoded.Metadata.Component.Name) != "" {
		components = append(components, *decoded.Metadata.Component)
	}
	components = append(components, decoded.Components...)

	packages := make([]PackageRecord, 0, len(components))
	packageIndex := make(map[string]PackageRecord, len(components))
	licenseCounts := make(map[string]int)
	for _, component := range components {
		record := PackageRecord{
			ID:       strings.TrimSpace(component.BOMRef),
			Name:     strings.TrimSpace(component.Name),
			Version:  strings.TrimSpace(component.Version),
			Type:     strings.TrimSpace(component.Type),
			PURL:     strings.TrimSpace(component.PURL),
			Licenses: normalizeCycloneDXLicenses(component.Licenses),
		}
		if record.Name == "" {
			continue
		}
		if record.ID == "" {
			record.ID = fallbackPackageID(record.Name, record.Version, record.Type)
		}
		packages = append(packages, record)
		packageIndex[record.ID] = record
		for _, license := range record.Licenses {
			licenseCounts[license]++
		}
	}

	sortPackages(packages)
	dependencyTree, dependencyRoots := buildDependencyTreeFromCycloneDX(decoded.Dependencies, packageIndex)

	return Record{
		OrgID:           orgID,
		ImageID:         imageID,
		ImageName:       imageName,
		SourceFormat:    FormatCycloneDX,
		PackageCount:    len(packages),
		Packages:        packages,
		DependencyTree:  dependencyTree,
		DependencyRoots: dependencyRoots,
		LicenseSummary:  summarizeLicenses(licenseCounts),
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func buildRecordFromSPDX(orgID, imageID, imageName string, document []byte) (Record, error) {
	var decoded spdxDocument
	if err := json.Unmarshal(document, &decoded); err != nil {
		return Record{}, fmt.Errorf("decode spdx sbom: %w", err)
	}

	packages := make([]PackageRecord, 0, len(decoded.Packages))
	packageIndex := make(map[string]PackageRecord, len(decoded.Packages))
	licenseCounts := make(map[string]int)
	for _, pkg := range decoded.Packages {
		record := PackageRecord{
			ID:       strings.TrimSpace(pkg.SPDXID),
			Name:     strings.TrimSpace(pkg.Name),
			Version:  strings.TrimSpace(pkg.VersionInfo),
			PURL:     extractSPDXPURL(pkg.ExternalRefs),
			Licenses: normalizeSPDXLicenses(pkg.LicenseDeclared, pkg.LicenseConcluded),
		}
		if record.Name == "" {
			continue
		}
		if record.ID == "" {
			record.ID = fallbackPackageID(record.Name, record.Version, "")
		}
		packages = append(packages, record)
		packageIndex[record.ID] = record
		for _, license := range record.Licenses {
			licenseCounts[license]++
		}
	}

	sortPackages(packages)
	dependencyTree, dependencyRoots := buildDependencyTreeFromSPDX(decoded.DocumentDescribes, decoded.Relationships, packageIndex)

	return Record{
		OrgID:           orgID,
		ImageID:         imageID,
		ImageName:       imageName,
		SourceFormat:    FormatSPDX,
		PackageCount:    len(packages),
		Packages:        packages,
		DependencyTree:  dependencyTree,
		DependencyRoots: dependencyRoots,
		LicenseSummary:  summarizeLicenses(licenseCounts),
		UpdatedAt:       time.Now().UTC(),
	}, nil
}

func buildDependencyTreeFromSyft(relationships []artifact.Relationship, packageIndex map[string]PackageRecord) ([]DependencyNode, []string) {
	adjacency := make(map[string][]string, len(packageIndex))
	referencedBy := make(map[string]int, len(packageIndex))
	for _, relationship := range relationships {
		if relationship.Type != artifact.DependencyOfRelationship {
			continue
		}
		fromID := identifyPackageID(relationship.From)
		toID := identifyPackageID(relationship.To)
		if fromID == "" || toID == "" {
			continue
		}
		if _, ok := packageIndex[fromID]; !ok {
			continue
		}
		if _, ok := packageIndex[toID]; !ok {
			continue
		}
		adjacency[toID] = appendUnique(adjacency[toID], fromID)
		referencedBy[fromID]++
	}
	return buildDependencyNodes(packageIndex, adjacency, referencedBy, nil)
}

func buildDependencyTreeFromCycloneDX(dependencies []cycloneDXDependency, packageIndex map[string]PackageRecord) ([]DependencyNode, []string) {
	adjacency := make(map[string][]string, len(packageIndex))
	referencedBy := make(map[string]int, len(packageIndex))
	explicitRoots := make([]string, 0)

	for _, dependency := range dependencies {
		ref := strings.TrimSpace(dependency.Ref)
		if _, ok := packageIndex[ref]; !ok {
			continue
		}
		explicitRoots = appendUnique(explicitRoots, ref)
		for _, child := range dependency.DependsOn {
			child = strings.TrimSpace(child)
			if _, ok := packageIndex[child]; !ok {
				continue
			}
			adjacency[ref] = appendUnique(adjacency[ref], child)
			referencedBy[child]++
		}
	}

	return buildDependencyNodes(packageIndex, adjacency, referencedBy, explicitRoots)
}

func buildDependencyTreeFromSPDX(documentDescribes []string, relationships []spdxRelationship, packageIndex map[string]PackageRecord) ([]DependencyNode, []string) {
	adjacency := make(map[string][]string, len(packageIndex))
	referencedBy := make(map[string]int, len(packageIndex))
	explicitRoots := make([]string, 0, len(documentDescribes))
	for _, described := range documentDescribes {
		described = strings.TrimSpace(described)
		if _, ok := packageIndex[described]; ok {
			explicitRoots = appendUnique(explicitRoots, described)
		}
	}

	for _, relationship := range relationships {
		left := strings.TrimSpace(relationship.SPDXElementID)
		right := strings.TrimSpace(relationship.RelatedSPDXElement)
		switch strings.ToUpper(strings.TrimSpace(relationship.RelationshipType)) {
		case "DEPENDS_ON":
			if _, ok := packageIndex[left]; !ok {
				continue
			}
			if _, ok := packageIndex[right]; !ok {
				continue
			}
			adjacency[left] = appendUnique(adjacency[left], right)
			referencedBy[right]++
		case "DEPENDENCY_OF":
			if _, ok := packageIndex[left]; !ok {
				continue
			}
			if _, ok := packageIndex[right]; !ok {
				continue
			}
			adjacency[right] = appendUnique(adjacency[right], left)
			referencedBy[left]++
		}
	}

	return buildDependencyNodes(packageIndex, adjacency, referencedBy, explicitRoots)
}

func buildDependencyNodes(packageIndex map[string]PackageRecord, adjacency map[string][]string, referencedBy map[string]int, explicitRoots []string) ([]DependencyNode, []string) {
	nodes := make([]DependencyNode, 0, len(packageIndex))
	for _, pkg := range packageIndex {
		dependsOn := append([]string(nil), adjacency[pkg.ID]...)
		sort.Strings(dependsOn)
		nodes = append(nodes, DependencyNode{
			ID:        pkg.ID,
			Name:      pkg.Name,
			Version:   pkg.Version,
			DependsOn: dependsOn,
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Name != nodes[j].Name {
			return nodes[i].Name < nodes[j].Name
		}
		if nodes[i].Version != nodes[j].Version {
			return nodes[i].Version < nodes[j].Version
		}
		return nodes[i].ID < nodes[j].ID
	})

	roots := make([]string, 0)
	for _, node := range nodes {
		if referencedBy[node.ID] == 0 {
			roots = append(roots, node.ID)
		}
	}
	sort.Strings(roots)
	if len(explicitRoots) > 0 {
		sort.Strings(explicitRoots)
		roots = uniqueStrings(append(explicitRoots, roots...))
	}

	return nodes, roots
}

func identifyPackageID(value any) string {
	switch typed := value.(type) {
	case syftpkg.Package:
		return string(typed.ID())
	case *syftpkg.Package:
		if typed == nil {
			return ""
		}
		return string(typed.ID())
	default:
		return ""
	}
}

func normalizeSyftLicenses(licenses []syftpkg.License) []string {
	values := make([]string, 0, len(licenses))
	for _, license := range licenses {
		candidate := strings.TrimSpace(license.SPDXExpression)
		if candidate == "" {
			candidate = strings.TrimSpace(license.Value)
		}
		if candidate == "" {
			continue
		}
		values = append(values, candidate)
	}
	return uniqueStrings(values)
}

func normalizeCycloneDXLicenses(licenses []cycloneDXLicenseChoice) []string {
	values := make([]string, 0, len(licenses))
	for _, license := range licenses {
		if expression := strings.TrimSpace(license.Expression); expression != "" {
			values = append(values, expression)
			continue
		}
		if license.License == nil {
			continue
		}
		candidate := strings.TrimSpace(license.License.ID)
		if candidate == "" {
			candidate = strings.TrimSpace(license.License.Name)
		}
		if candidate != "" {
			values = append(values, candidate)
		}
	}
	return uniqueStrings(values)
}

func normalizeSPDXLicenses(licenseDeclared, licenseConcluded string) []string {
	values := make([]string, 0, 2)
	for _, candidate := range []string{licenseDeclared, licenseConcluded} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || strings.EqualFold(candidate, "NOASSERTION") || strings.EqualFold(candidate, "NONE") {
			continue
		}
		values = append(values, candidate)
	}
	return uniqueStrings(values)
}

func extractSPDXPURL(refs []spdxExternalRef) string {
	for _, ref := range refs {
		if strings.EqualFold(strings.TrimSpace(ref.ReferenceType), "purl") {
			return strings.TrimSpace(ref.ReferenceLocator)
		}
	}
	return ""
}

func summarizeLicenses(counts map[string]int) []LicenseSummaryEntry {
	summary := make([]LicenseSummaryEntry, 0, len(counts))
	for license, count := range counts {
		summary = append(summary, LicenseSummaryEntry{
			License: license,
			Count:   count,
		})
	}
	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count != summary[j].Count {
			return summary[i].Count > summary[j].Count
		}
		return summary[i].License < summary[j].License
	})
	return summary
}

func sortPackages(packages []PackageRecord) {
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		if packages[i].Version != packages[j].Version {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].ID < packages[j].ID
	})
}

func fallbackPackageID(name, version, packageType string) string {
	base := strings.TrimSpace(name)
	if version != "" {
		base += "@" + strings.TrimSpace(version)
	}
	if packageType != "" {
		base += ":" + strings.TrimSpace(packageType)
	}
	return base
}

func appendUnique(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || slices.Contains(values, candidate) {
		return values
	}
	return append(values, candidate)
}

func uniqueStrings(values []string) []string {
	unique := make([]string, 0, len(values))
	for _, value := range values {
		unique = appendUnique(unique, value)
	}
	sort.Strings(unique)
	return unique
}
