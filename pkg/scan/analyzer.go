package scan

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft/sbom"
	"golang.org/x/sync/errgroup"
)

type Analyzer struct {
	sbomGenerator SBOMGenerator
	scanners      []VulnerabilityScanner
}

func NewAnalyzer(sbomGenerator SBOMGenerator, scanners ...VulnerabilityScanner) *Analyzer {
	if sbomGenerator == nil {
		sbomGenerator = SyftSBOMGenerator{}
	}
	return &Analyzer{
		sbomGenerator: sbomGenerator,
		scanners:      append([]VulnerabilityScanner(nil), scanners...),
	}
}

func (a *Analyzer) Analyze(ctx context.Context, imageRef string) (AnalysisResult, error) {
	sbomDocument, sbomData, err := a.sbomGenerator.Generate(ctx, imageRef)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("generate sbom: %w", err)
	}
	spdxDocument, err := GenerateSPDXDocument(sbomData)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("generate spdx sbom: %w", err)
	}

	reports := make([]ScannerReport, len(a.scanners))
	group, groupCtx := errgroup.WithContext(ctx)
	for idx, scanner := range a.scanners {
		idx := idx
		scanner := scanner
		group.Go(func() error {
			report, err := scanner.Scan(groupCtx, imageRef, sbomData)
			if err != nil {
				return fmt.Errorf("%s scan: %w", scanner.Name(), err)
			}
			reports[idx] = report
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return AnalysisResult{}, err
	}

	combinedReport, combinedDocument, err := BuildCombinedReport(imageRef, reports)
	if err != nil {
		return AnalysisResult{}, err
	}

	return AnalysisResult{
		ImageRef:                imageRef,
		SBOMDocument:            sbomDocument,
		SBOMSPDXDocument:        spdxDocument,
		SBOMData:                sbomData,
		CombinedVulnerabilities: combinedDocument,
		Summary:                 combinedReport.Summary,
		ScannerReports:          reports,
	}, nil
}

type SyftSBOMGenerator struct{}

func (SyftSBOMGenerator) Generate(ctx context.Context, imageRef string) ([]byte, *sbom.SBOM, error) {
	src, err := GetSource(ctx, ImageReference(imageRef))
	if err != nil {
		return nil, nil, fmt.Errorf("load image source: %w", err)
	}
	defer src.Close()

	document, sbomData, err := GenerateSBOMDocument(ctx, src)
	if err != nil {
		return nil, nil, err
	}

	return document, sbomData, nil
}
