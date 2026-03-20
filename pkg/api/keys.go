package api

import (
	"errors"
	"fmt"
	"strings"

	"github.com/otterXf/otter/pkg/storage"
)

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

func (b ArtifactKeyBuilder) BuildSBOMKeyForFormat(format string) (string, error) {
	switch format {
	case "cyclonedx":
		return b.BuildKey("sbom-cyclonedx.json")
	case "spdx":
		return b.BuildKey("sbom-spdx.json")
	default:
		return "", fmt.Errorf("unsupported sbom format %q", format)
	}
}

func (b ArtifactKeyBuilder) BuildVulnerabilityKey() (string, error) {
	return b.BuildKey("vulnerabilities.json")
}

func (b ArtifactKeyBuilder) BuildScannerVulnerabilityKey(scanner string) (string, error) {
	return b.BuildKey(scanner + "-vulnerabilities.json")
}

func (b ArtifactKeyBuilder) BuildVEXKey(filename string) (string, error) {
	return b.BuildKey(filename)
}

func (b ArtifactKeyBuilder) BuildImagePrefix() (string, error) {
	return storage.BuildImagePrefix(b.OrgID, b.ImageID)
}

func BuildComparisonKey(comparisonID string) (string, error) {
	if err := storage.ValidateSegment("comparison_id", comparisonID); err != nil {
		return "", err
	}
	return storage.BuildArtifactKey("comparisons", comparisonID, "comparison.json")
}

func normalizeArtifactIDs(orgID, imageID string) (string, string, error) {
	orgID = strings.TrimSpace(orgID)
	imageID = strings.TrimSpace(imageID)
	if orgID == "" {
		return "", "", errors.New("org_id is required")
	}
	if imageID == "" {
		return "", "", errors.New("image_id is required")
	}
	if err := storage.ValidateSegment("org_id", orgID); err != nil {
		return "", "", err
	}
	if err := storage.ValidateSegment("image_id", imageID); err != nil {
		return "", "", err
	}
	return orgID, imageID, nil
}
