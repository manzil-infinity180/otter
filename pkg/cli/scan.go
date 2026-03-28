package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/otterXf/otter/pkg/scan"
)

// ScanCommand runs a standalone vulnerability scan without a server.
type ScanCommand struct {
	analyzer scan.ImageAnalyzer
}

// NewScanCommand creates a CLI scan command using the given analyzer.
func NewScanCommand(analyzer scan.ImageAnalyzer) *ScanCommand {
	return &ScanCommand{analyzer: analyzer}
}

// Run executes the scan command with the given arguments.
// Usage: otter scan <image> [--format json|sarif] [--output file] [--fail-on critical|high]
func (c *ScanCommand) Run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	format := fs.String("format", "json", "Output format: json, sarif")
	output := fs.String("output", "", "Write output to file (default: stdout)")
	failOn := fs.String("fail-on", "", "Exit with code 1 if vulnerabilities at or above this severity are found (critical, high, medium, low)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: otter scan <image> [--format json|sarif] [--output file] [--fail-on critical]")
	}

	imageRef := fs.Arg(0)
	fmt.Fprintf(os.Stderr, "Scanning %s...\n", imageRef)

	result, err := c.analyzer.Analyze(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	var data []byte
	switch strings.ToLower(*format) {
	case "json":
		data, err = json.MarshalIndent(result.CombinedReport, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	case "sarif":
		data, err = json.MarshalIndent(result.CombinedReport, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal SARIF: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, sarif)", *format)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Output written to %s\n", *output)
	} else {
		os.Stdout.Write(data)
		os.Stdout.Write([]byte("\n"))
	}

	// Print summary to stderr
	fmt.Fprintf(os.Stderr, "\nVulnerabilities found: %d (", result.Summary.Total)
	severities := []string{}
	for sev, count := range result.Summary.BySeverity {
		severities = append(severities, fmt.Sprintf("%s: %d", sev, count))
	}
	fmt.Fprintf(os.Stderr, "%s)\n", strings.Join(severities, ", "))

	// Fail-on check
	if *failOn != "" {
		threshold := strings.ToUpper(strings.TrimSpace(*failOn))
		severityOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
		thresholdLevel, ok := severityOrder[threshold]
		if !ok {
			return fmt.Errorf("invalid --fail-on value: %s (use: critical, high, medium, low)", *failOn)
		}

		for sev, count := range result.Summary.BySeverity {
			if count > 0 {
				if level, ok := severityOrder[strings.ToUpper(sev)]; ok && level >= thresholdLevel {
					fmt.Fprintf(os.Stderr, "FAIL: found %d vulnerabilities at or above %s severity\n", count, threshold)
					os.Exit(1)
				}
			}
		}
	}

	return nil
}

// IsCommand checks if the given args contain a CLI subcommand.
func IsCommand(args []string) (string, []string) {
	if len(args) < 2 {
		return "", nil
	}
	switch args[1] {
	case "scan":
		return "scan", args[2:]
	default:
		return "", nil
	}
}
