package main

import (
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/otterXf/otter/pkg/scan"
	// _ "modernc.org/sqlite" // required for rpmdb and other features
)

func main() {
	// automagically get a source.Source for arbitrary string input
	src := scan.GetSource(scan.ImageReference())
	defer src.Close()

	// catalog the given source and return a SBOM
	// let's explicitly use catalogers that are:
	// - for installed software
	// - used in the directory scan
	_ = scan.GetSBOM(src, pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag)

	// Show a basic catalogers and input configuration used
	// enc := json.NewEncoder(os.Stdout)
	// enc.SetIndent("", "  ")
	// if err := enc.Encode(sbom.Descriptor.Configuration); err != nil {
	// 	panic(err)
	// }
}
