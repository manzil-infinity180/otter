package catalogscan

import "testing"

func TestDefaultImageRefsCoverCatalogSeeds(t *testing.T) {
	t.Parallel()

	refs := DefaultImageRefs()
	if len(refs) < 7 {
		t.Fatalf("len(refs) = %d, want at least 7", len(refs))
	}

	required := []string{
		"alpine:latest",
		"debian:latest",
		"ubuntu:latest",
		"nginx:latest",
		"python:latest",
		"golang:latest",
		"cgr.dev/chainguard/static:latest",
	}
	for _, ref := range required {
		if !containsString(refs, ref) {
			t.Fatalf("DefaultImageRefs() missing %q", ref)
		}
	}
	if !containsString(refs, "alpine:3.19") {
		t.Fatal("DefaultImageRefs() should include a version-pinned alpine tag")
	}
}

func TestDefaultRequestsGenerateStableCatalogTargets(t *testing.T) {
	t.Parallel()

	requests := DefaultRequests(Config{OrgID: "catalog"})
	if len(requests) == 0 {
		t.Fatal("DefaultRequests() returned no requests")
	}

	for _, request := range requests {
		if request.OrgID != "catalog" {
			t.Fatalf("request.OrgID = %q, want catalog", request.OrgID)
		}
		if request.ImageID == "" {
			t.Fatalf("request for %q has empty ImageID", request.ImageName)
		}
		if request.Source != SourceCatalog || request.Trigger != TriggerScheduler {
			t.Fatalf("request = %#v", request)
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
