package sbomindex

import "testing"

func TestBuildRecordFromDocumentCycloneDX(t *testing.T) {
	t.Parallel()

	record, err := BuildRecordFromDocument("demo-org", "demo-image", "alpine:latest", FormatCycloneDX, []byte(testCycloneDXDocument))
	if err != nil {
		t.Fatalf("BuildRecordFromDocument() error = %v", err)
	}

	if got, want := record.PackageCount, 2; got != want {
		t.Fatalf("PackageCount = %d, want %d", got, want)
	}
	if len(record.DependencyRoots) == 0 || record.DependencyRoots[0] != "pkg:oci/alpine@latest" {
		t.Fatalf("DependencyRoots = %#v", record.DependencyRoots)
	}
	if len(record.LicenseSummary) == 0 || record.LicenseSummary[0].License != "MIT" {
		t.Fatalf("LicenseSummary = %#v", record.LicenseSummary)
	}
}

func TestBuildRecordFromDocumentSPDX(t *testing.T) {
	t.Parallel()

	record, err := BuildRecordFromDocument("demo-org", "demo-image", "alpine:latest", FormatSPDX, []byte(testSPDXDocument))
	if err != nil {
		t.Fatalf("BuildRecordFromDocument() error = %v", err)
	}

	if got, want := record.PackageCount, 2; got != want {
		t.Fatalf("PackageCount = %d, want %d", got, want)
	}
	if len(record.DependencyTree) != 2 {
		t.Fatalf("DependencyTree = %#v", record.DependencyTree)
	}
	if record.Packages[0].Name != "alpine" {
		t.Fatalf("Packages = %#v", record.Packages)
	}
}

func TestDetectFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		want     string
	}{
		{name: "cyclonedx", document: testCycloneDXDocument, want: FormatCycloneDX},
		{name: "spdx", document: testSPDXDocument, want: FormatSPDX},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DetectFormat([]byte(tt.document))
			if err != nil {
				t.Fatalf("DetectFormat() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("DetectFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

const testCycloneDXDocument = `{
  "bomFormat": "CycloneDX",
  "metadata": {
    "component": {
      "bom-ref": "pkg:oci/alpine@latest",
      "name": "alpine",
      "version": "latest",
      "type": "container"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:apk/alpine/busybox@1.36.1-r0",
      "name": "busybox",
      "version": "1.36.1-r0",
      "type": "library",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:oci/alpine@latest",
      "dependsOn": [
        "pkg:apk/alpine/busybox@1.36.1-r0"
      ]
    }
  ]
}`

const testSPDXDocument = `{
  "spdxVersion": "SPDX-2.3",
  "documentDescribes": [
    "SPDXRef-alpine"
  ],
  "packages": [
    {
      "SPDXID": "SPDXRef-alpine",
      "name": "alpine",
      "versionInfo": "latest",
      "licenseDeclared": "Apache-2.0"
    },
    {
      "SPDXID": "SPDXRef-busybox",
      "name": "busybox",
      "versionInfo": "1.36.1-r0",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/busybox@1.36.1-r0"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-alpine",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-busybox"
    }
  ]
}`
