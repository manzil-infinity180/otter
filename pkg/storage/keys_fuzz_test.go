package storage

import (
	"testing"
)

func FuzzParseArtifactKey(f *testing.F) {
	f.Add("otterxf/org/image/sbom.json")
	f.Add("otterxf/default/nginx-latest/vuln.json")
	f.Add("")
	f.Add("../../../etc/passwd")
	f.Add("otterxf/../secret")
	f.Add(string(make([]byte, 2048)))

	f.Fuzz(func(t *testing.T, key string) {
		// Should never panic
		_, _ = ParseArtifactKey(key)
	})
}

func FuzzValidateFilename(f *testing.F) {
	f.Add("sbom.json")
	f.Add("vulnerabilities.csv")
	f.Add("")
	f.Add("../../../etc/passwd")
	f.Add("file\x00name.json")

	f.Fuzz(func(t *testing.T, filename string) {
		// Should never panic
		_ = ValidateFilename(filename)
	})
}
