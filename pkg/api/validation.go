package api

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/otterXf/otter/pkg/registry"
	"github.com/otterXf/otter/pkg/storage"
)

func validateImageReference(imageRef string) error {
	if imageRef == "" {
		return fmt.Errorf("image_name is required")
	}
	if _, err := name.ParseReference(imageRef); err != nil {
		return fmt.Errorf("invalid image_name %q: %w", imageRef, err)
	}
	return nil
}

func validateDownloadFilename(filename string) error {
	return storage.ValidateFilename(filename)
}

func validateRequestedRegistry(imageRef string, requested string) error {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return nil
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("invalid image_name %q: %w", imageRef, err)
	}

	expected := registry.NormalizeRegistry(ref.Context().RegistryStr())
	actual := registry.NormalizeRegistry(requested)
	if expected != actual {
		return fmt.Errorf("registry %q does not match image_name registry %q", requested, expected)
	}
	return nil
}
