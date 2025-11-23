package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	_ "modernc.org/sqlite" // required for rpmdb and other features

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const defaultImage = "alpine:3.19"

func main() {
	// automagically get a source.Source for arbitrary string input
	src := getSource(imageReference())
	defer src.Close()

	// catalog the given source and return a SBOM
	// let's explicitly use catalogers that are:
	// - for installed software
	// - used in the directory scan
	_ = getSBOM(src, pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag)

	// Show a basic catalogers and input configuration used
	// enc := json.NewEncoder(os.Stdout)
	// enc.SetIndent("", "  ")
	// if err := enc.Encode(sbom.Descriptor.Configuration); err != nil {
	// 	panic(err)
	// }
}

func imageReference() string {
	// read an image string reference from the command line or use a default
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return defaultImage
}

func getSource(input string) source.Source {
	src, err := syft.GetSource(context.Background(), input, nil)
	if err != nil {
		panic(err)
	}

	return src
}

func getSBOM(src source.Source, defaultTags ...string) sbom.SBOM {
	// cfg := syft.DefaultCreateSBOMConfig().
	// 	WithCatalogerSelection(
	// 		// here you can sub-select, add, remove catalogers from the default selection...
	// 		// or replace the default selection entirely!
	// 		cataloging.NewSelectionRequest().
	// 			WithDefaults(defaultTags...),
	// 	)

	cfg := syft.DefaultCreateSBOMConfig()

	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		panic(err)
	}

	r, err := ToSpdxSchema(s)
	// r, err := ToCycloneDxSchema(s)
	if err != nil {
		panic(err)
	}

	filePath := "go-spdx.json"
	file, err := os.Create(filePath) // os.Create truncates if file exists
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		panic(err)
	}
	defer file.Close()

	_, err = io.Copy(file, r)
	if err != nil {
		fmt.Printf("Error copying content: %v\n", err)
		panic(err)
	}

	// PrintToTerminal(r)
	return *s
}

func ToSyftJSONSchemaRedacted(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)
	m := syftjson.ToFormatModel(*s, syftjson.DefaultEncoderConfig())
	m.Schema = model.Schema{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func ToCycloneDxSchema(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)
	bom := cyclonedxhelpers.ToFormatModel(*s)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(bom)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}
func ToSpdxSchema(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)
	spdx := spdxhelpers.ToFormatModel(*s)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(spdx)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func PrintToTerminal(source io.ReadSeeker) error {
	// io.Copy efficiently copies data from a source (io.Reader) to a destination (io.Writer).
	// os.Stdout is an io.Writer that represents the terminal's standard output.
	_, err := io.Copy(os.Stdout, source)
	if err != nil {
		return fmt.Errorf("error copying to stdout: %w", err)
	}
	// Add a newline at the end for clean terminal output if desired
	fmt.Println()
	return nil
}
