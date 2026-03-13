package api

import "github.com/otterXf/otter/pkg/storage"

type ArtifactKeyBuilder struct {
	OrgID   string
	ImageID string
}

func (b ArtifactKeyBuilder) BuildKey(filename string) (string, error) {
	return storage.BuildArtifactKey(b.OrgID, b.ImageID, filename)
}

func (b ArtifactKeyBuilder) BuildSBOMKey() (string, error) {
	return b.BuildKey("sbom.json")
}

func (b ArtifactKeyBuilder) BuildVulnerabilityKey() (string, error) {
	return b.BuildKey("vulnerabilities.json")
}

func (b ArtifactKeyBuilder) BuildScannerVulnerabilityKey(scanner string) (string, error) {
	return b.BuildKey(scanner + "-vulnerabilities.json")
}

func (b ArtifactKeyBuilder) BuildImagePrefix() (string, error) {
	return storage.BuildImagePrefix(b.OrgID, b.ImageID)
}

func normalizeArtifactIDs(orgID, imageID string) (string, string, error) {
	if orgID == "" {
		orgID = "default_org"
	}
	if imageID == "" {
		imageID = "default_image"
	}
	if err := storage.ValidateSegment("org_id", orgID); err != nil {
		return "", "", err
	}
	if err := storage.ValidateSegment("image_id", imageID); err != nil {
		return "", "", err
	}
	return orgID, imageID, nil
}
