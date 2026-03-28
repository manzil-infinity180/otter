package sbomindex

import (
	"testing"
)

func FuzzNormalize(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`))
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`invalid json`))
	f.Add([]byte(``))
	f.Add(make([]byte, 0))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic regardless of input
		_, _ = Normalize(data)
	})
}
