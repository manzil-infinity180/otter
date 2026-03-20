package storage

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

const ArtifactRootPrefix = "otterxf"

var safeSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type ArtifactKeyParts struct {
	OrgID    string
	ImageID  string
	Filename string
}

func ValidateSegment(name, value string) error {
	if !safeSegmentPattern.MatchString(value) {
		return fmt.Errorf("invalid %s %q", name, value)
	}
	return nil
}

func ValidateFilename(filename string) error {
	if strings.Contains(filename, "/") || strings.Contains(filename, `\`) || strings.Contains(filename, "..") {
		return fmt.Errorf("invalid filename %q", filename)
	}
	return ValidateSegment("filename", filename)
}

func BuildArtifactKey(orgID, imageID, filename string) (string, error) {
	if err := ValidateSegment("org_id", orgID); err != nil {
		return "", err
	}
	if err := ValidateSegment("image_id", imageID); err != nil {
		return "", err
	}
	if err := ValidateFilename(filename); err != nil {
		return "", err
	}
	return path.Join(ArtifactRootPrefix, orgID, imageID, filename), nil
}

func BuildImagePrefix(orgID, imageID string) (string, error) {
	if err := ValidateSegment("org_id", orgID); err != nil {
		return "", err
	}
	if err := ValidateSegment("image_id", imageID); err != nil {
		return "", err
	}
	return path.Join(ArtifactRootPrefix, orgID, imageID) + "/", nil
}

func ParseArtifactKey(key string) (ArtifactKeyParts, error) {
	cleaned := path.Clean(strings.TrimSpace(key))
	parts := strings.Split(cleaned, "/")
	if len(parts) != 4 || parts[0] != ArtifactRootPrefix {
		return ArtifactKeyParts{}, fmt.Errorf("invalid artifact key %q", key)
	}

	result := ArtifactKeyParts{
		OrgID:    parts[1],
		ImageID:  parts[2],
		Filename: parts[3],
	}
	if err := ValidateSegment("org_id", result.OrgID); err != nil {
		return ArtifactKeyParts{}, err
	}
	if err := ValidateSegment("image_id", result.ImageID); err != nil {
		return ArtifactKeyParts{}, err
	}
	if err := ValidateFilename(result.Filename); err != nil {
		return ArtifactKeyParts{}, err
	}
	return result, nil
}

func ValidatePrefix(prefix string) error {
	trimmed := strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	if trimmed == "" {
		return nil
	}

	cleaned := path.Clean(trimmed)
	if cleaned == "." {
		return nil
	}

	parts := strings.Split(cleaned, "/")
	if parts[0] != ArtifactRootPrefix {
		return fmt.Errorf("invalid prefix %q", prefix)
	}
	for _, part := range parts[1:] {
		if err := ValidateSegment("prefix segment", part); err != nil {
			return err
		}
	}
	return nil
}
