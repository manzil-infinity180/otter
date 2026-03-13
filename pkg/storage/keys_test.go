package storage

import "testing"

func TestBuildAndParseArtifactKey(t *testing.T) {
	t.Parallel()

	key, err := BuildArtifactKey("demo-org", "demo-image", "sbom.json")
	if err != nil {
		t.Fatalf("BuildArtifactKey() error = %v", err)
	}

	if want := "otterxf/demo-org/demo-image/sbom.json"; key != want {
		t.Fatalf("BuildArtifactKey() = %q, want %q", key, want)
	}

	parts, err := ParseArtifactKey(key)
	if err != nil {
		t.Fatalf("ParseArtifactKey() error = %v", err)
	}

	if parts.OrgID != "demo-org" || parts.ImageID != "demo-image" || parts.Filename != "sbom.json" {
		t.Fatalf("ParseArtifactKey() = %#v", parts)
	}
}

func TestBuildArtifactKeyRejectsUnsafeSegments(t *testing.T) {
	t.Parallel()

	if _, err := BuildArtifactKey("../org", "image", "sbom.json"); err == nil {
		t.Fatal("expected invalid org_id to fail")
	}
	if _, err := BuildArtifactKey("org", "image", "../sbom.json"); err == nil {
		t.Fatal("expected invalid filename to fail")
	}
}
