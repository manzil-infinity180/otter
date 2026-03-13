package api

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
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
