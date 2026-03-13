package sbomindex

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
)

func TestNormalizeFormatRejectsUnsupportedValue(t *testing.T) {
	t.Parallel()

	if _, err := NormalizeFormat("yaml"); err == nil {
		t.Fatal("expected NormalizeFormat() to reject unsupported format")
	}
}

func TestDetectFormatRejectsUnknownDocument(t *testing.T) {
	t.Parallel()

	if _, err := DetectFormat([]byte(`{"name":"otter"}`)); err == nil {
		t.Fatal("expected DetectFormat() to reject unknown document")
	}
}

func TestBuildRecordFromSyftCapturesFallbackIDsDependenciesAndLicenses(t *testing.T) {
	t.Parallel()

	root := syftpkg.Package{
		Name:     "alpine",
		Version:  "3.20.0",
		Type:     syftpkg.Type("apk"),
		PURL:     "pkg:oci/alpine@3.20.0",
		Licenses: syftpkg.NewLicenseSet(syftpkg.License{SPDXExpression: "Apache-2.0"}),
	}
	root.SetID()

	dependency := syftpkg.Package{
		Name:     "busybox",
		Version:  "1.36.1-r0",
		Type:     syftpkg.Type("apk"),
		PURL:     "pkg:apk/alpine/busybox@1.36.1-r0",
		Licenses: syftpkg.NewLicenseSet(syftpkg.License{Value: "MIT"}, syftpkg.License{SPDXExpression: "MIT"}),
	}
	dependency.SetID()

	extra := syftpkg.Package{
		Name:     "openssl",
		Version:  "3.0.0-r0",
		Type:     syftpkg.Type("apk"),
		Licenses: syftpkg.NewLicenseSet(syftpkg.License{Value: "OpenSSL"}),
	}

	record, err := BuildRecordFromSyft("demo-org", "demo-image", "alpine:latest", &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(root, dependency, extra),
		},
		Relationships: []artifact.Relationship{
			{From: dependency, To: root, Type: artifact.DependencyOfRelationship},
			{From: dependency, To: root, Type: artifact.ContainsRelationship},
			{From: syftpkg.Package{Name: "missing"}, To: root, Type: artifact.DependencyOfRelationship},
		},
	})
	if err != nil {
		t.Fatalf("BuildRecordFromSyft() error = %v", err)
	}

	if got, want := record.PackageCount, 3; got != want {
		t.Fatalf("PackageCount = %d, want %d", got, want)
	}
	if got := record.Packages[2].ID; got == "" {
		t.Fatal("expected BuildRecordFromSyft() to assign a package ID")
	}
	if len(record.DependencyTree) != 3 {
		t.Fatalf("DependencyTree = %#v", record.DependencyTree)
	}
	foundRoot := false
	for _, dependencyRoot := range record.DependencyRoots {
		if dependencyRoot == string(root.ID()) {
			foundRoot = true
			break
		}
	}
	if !foundRoot {
		t.Fatalf("DependencyRoots = %#v, want %q to be present", record.DependencyRoots, string(root.ID()))
	}
	foundMIT := false
	for _, entry := range record.LicenseSummary {
		if entry.License == "MIT" {
			foundMIT = true
			break
		}
	}
	if !foundMIT {
		t.Fatalf("LicenseSummary = %#v, want MIT entry", record.LicenseSummary)
	}
}

func TestDependencyTreeHelpersAndLicenseNormalizers(t *testing.T) {
	t.Parallel()

	packageIndex := map[string]PackageRecord{
		"root":  {ID: "root", Name: "root", Version: "1.0.0"},
		"child": {ID: "child", Name: "child", Version: "1.0.0"},
		"leaf":  {ID: "leaf", Name: "leaf", Version: "1.0.0"},
	}

	cycloneNodes, cycloneRoots := buildDependencyTreeFromCycloneDX([]cycloneDXDependency{
		{Ref: "root", DependsOn: []string{"child", "missing", "child"}},
		{Ref: "child", DependsOn: []string{"leaf"}},
	}, packageIndex)
	if len(cycloneNodes) != 3 || len(cycloneRoots) != 2 || cycloneRoots[0] != "child" || cycloneRoots[1] != "root" {
		t.Fatalf("cyclonedx dependency result = %#v %#v", cycloneNodes, cycloneRoots)
	}

	spdxNodes, spdxRoots := buildDependencyTreeFromSPDX(
		[]string{"root"},
		[]spdxRelationship{
			{SPDXElementID: "root", RelationshipType: "DEPENDS_ON", RelatedSPDXElement: "child"},
			{SPDXElementID: "leaf", RelationshipType: "DEPENDENCY_OF", RelatedSPDXElement: "child"},
		},
		packageIndex,
	)
	if len(spdxNodes) != 3 || len(spdxRoots) == 0 || spdxRoots[0] != "root" {
		t.Fatalf("spdx dependency result = %#v %#v", spdxNodes, spdxRoots)
	}

	if got := identifyPackageID((*syftpkg.Package)(nil)); got != "" {
		t.Fatalf("identifyPackageID(nil) = %q, want empty", got)
	}
	if got := identifyPackageID(syftpkg.Package{}); got != "" {
		t.Fatalf("identifyPackageID(empty) = %q, want empty", got)
	}
	if got, want := normalizeSyftLicenses([]syftpkg.License{{Value: "MIT"}, {SPDXExpression: "Apache-2.0"}, {Value: "MIT"}}), []string{"Apache-2.0", "MIT"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("normalizeSyftLicenses() = %#v, want %#v", got, want)
	}
	if got, want := normalizeCycloneDXLicenses([]cycloneDXLicenseChoice{
		{Expression: "MIT"},
		{License: &cycloneDXLicenseRef{Name: "Apache-2.0"}},
		{License: &cycloneDXLicenseRef{ID: "MIT"}},
	}), []string{"Apache-2.0", "MIT"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("normalizeCycloneDXLicenses() = %#v, want %#v", got, want)
	}
	if got, want := normalizeSPDXLicenses("MIT", "NOASSERTION"), []string{"MIT"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("normalizeSPDXLicenses() = %#v, want %#v", got, want)
	}
	if got, want := extractSPDXPURL([]spdxExternalRef{{ReferenceType: "purl", ReferenceLocator: "pkg:apk/demo/pkg@1.0.0"}}), "pkg:apk/demo/pkg@1.0.0"; got != want {
		t.Fatalf("extractSPDXPURL() = %q, want %q", got, want)
	}
	if got := summarizeLicenses(map[string]int{"MIT": 2, "Apache-2.0": 1}); len(got) != 2 || got[0].License != "MIT" {
		t.Fatalf("summarizeLicenses() = %#v", got)
	}
	if got, want := fallbackPackageID("pkg", "1.0.0", "apk"), "pkg@1.0.0:apk"; got != want {
		t.Fatalf("fallbackPackageID() = %q, want %q", got, want)
	}
	if got, want := appendUnique([]string{"root"}, "root"), 1; len(got) != want {
		t.Fatalf("appendUnique() length = %d, want %d", len(got), want)
	}
	if got, want := uniqueStrings([]string{"b", "a", "b", " "}), []string{"a", "b"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("uniqueStrings() = %#v, want %#v", got, want)
	}
}
