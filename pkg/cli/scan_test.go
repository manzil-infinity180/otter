package cli

import (
	"testing"
)

func TestIsCommandScan(t *testing.T) {
	cmd, args := IsCommand([]string{"otter", "scan", "alpine:latest", "--format", "json"})
	if cmd != "scan" {
		t.Fatalf("expected 'scan', got %q", cmd)
	}
	if len(args) != 3 || args[0] != "alpine:latest" {
		t.Fatalf("expected args [alpine:latest --format json], got %v", args)
	}
}

func TestIsCommandEmpty(t *testing.T) {
	cmd, _ := IsCommand([]string{"otter"})
	if cmd != "" {
		t.Fatalf("expected empty command for server mode, got %q", cmd)
	}
}

func TestIsCommandUnknown(t *testing.T) {
	cmd, _ := IsCommand([]string{"otter", "serve"})
	if cmd != "" {
		t.Fatalf("expected empty for unknown command, got %q", cmd)
	}
}
