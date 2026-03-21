package api

import (
	"fmt"
	"strings"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	syftsbom "github.com/anchore/syft/syft/sbom"
	syftsource "github.com/anchore/syft/syft/source"
)

func normalizeRequestedPlatform(arch, platform string) (*stereoscopeimage.Platform, error) {
	arch = strings.TrimSpace(arch)
	platform = strings.TrimSpace(platform)

	if platform == "" {
		platform = arch
	}
	if platform == "" {
		return nil, nil
	}

	normalized, err := stereoscopeimage.NewPlatform(platform)
	if err != nil {
		return nil, fmt.Errorf("invalid platform %q: %w", platform, err)
	}

	if arch != "" {
		archOnly, err := stereoscopeimage.NewPlatform(arch)
		if err != nil {
			return nil, fmt.Errorf("invalid arch %q: %w", arch, err)
		}
		if normalized.Architecture != archOnly.Architecture || normalized.Variant != archOnly.Variant {
			return nil, fmt.Errorf("arch %q does not match platform %q", arch, platform)
		}
	}

	return normalized, nil
}

func platformString(platform *stereoscopeimage.Platform) string {
	if platform == nil {
		return ""
	}
	return strings.TrimSpace(platform.String())
}

func resolvedPlatformFromSBOM(document *syftsbom.SBOM) string {
	if document == nil {
		return ""
	}
	metadata, ok := document.Source.Metadata.(syftsource.ImageMetadata)
	if !ok {
		return ""
	}

	parts := make([]string, 0, 3)
	if os := strings.TrimSpace(metadata.OS); os != "" {
		parts = append(parts, os)
	}
	if arch := strings.TrimSpace(metadata.Architecture); arch != "" {
		parts = append(parts, arch)
	}
	if variant := strings.TrimSpace(metadata.Variant); variant != "" {
		parts = append(parts, variant)
	}
	return strings.Join(parts, "/")
}
