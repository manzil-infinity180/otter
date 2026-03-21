package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterRecorderWritesStructuredJSON(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	recorder, err := NewWriterRecorder(&buffer)
	if err != nil {
		t.Fatalf("NewWriterRecorder() error = %v", err)
	}

	recordedAt := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	if err := recorder.Record(context.Background(), Event{
		Timestamp:  recordedAt,
		Action:     "scan.completed",
		Outcome:    "succeeded",
		Actor:      "auditor",
		ActorType:  "user",
		OrgID:      "demo-org",
		Target:     "demo-org/demo-image",
		TargetType: "image",
		Metadata:   map[string]any{"image_name": "alpine:latest"},
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	var event Event
	if err := json.Unmarshal(buffer.Bytes(), &event); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := event.Action, "scan.completed"; got != want {
		t.Fatalf("event.Action = %q, want %q", got, want)
	}
	if got, want := event.Actor, "auditor"; got != want {
		t.Fatalf("event.Actor = %q, want %q", got, want)
	}
	if got, want := event.OrgID, "demo-org"; got != want {
		t.Fatalf("event.OrgID = %q, want %q", got, want)
	}
	if got, want := event.Target, "demo-org/demo-image"; got != want {
		t.Fatalf("event.Target = %q, want %q", got, want)
	}
	if got, want := event.Timestamp, recordedAt; got != want {
		t.Fatalf("event.Timestamp = %v, want %v", got, want)
	}
}

func TestRecorderWritesToConfiguredFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	recorder, err := NewRecorder(Config{
		Enabled:  true,
		Outputs:  []string{"file"},
		FilePath: path,
	})
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	t.Cleanup(func() {
		if err := recorder.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	if err := recorder.Record(context.Background(), Event{
		Action: "registry.updated",
		Actor:  "admin",
		OrgID:  "global",
		Target: "ghcr.io",
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"registry.updated"`) {
		t.Fatalf("expected audit event in file, payload=%s", payload)
	}
}
