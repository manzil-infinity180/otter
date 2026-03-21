package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	EnvEnabled = "OTTER_AUDIT_ENABLED"
	EnvOutputs = "OTTER_AUDIT_OUTPUTS"
	EnvFile    = "OTTER_AUDIT_FILE"
)

type Config struct {
	Enabled  bool
	Outputs  []string
	FilePath string
}

type Event struct {
	Timestamp  time.Time      `json:"timestamp"`
	Action     string         `json:"action"`
	Outcome    string         `json:"outcome,omitempty"`
	Actor      string         `json:"actor"`
	ActorType  string         `json:"actor_type,omitempty"`
	OrgID      string         `json:"org_id,omitempty"`
	Target     string         `json:"target"`
	TargetType string         `json:"target_type,omitempty"`
	Error      string         `json:"error,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type Recorder interface {
	Record(context.Context, Event) error
	Close() error
}

func ConfigFromEnv(dataDir string) Config {
	cfg := Config{
		Enabled:  true,
		Outputs:  []string{"file"},
		FilePath: filepath.Join(dataDir, "_audit", "events.jsonl"),
	}

	if value := strings.TrimSpace(os.Getenv(EnvEnabled)); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err == nil {
			cfg.Enabled = enabled
		}
	}
	if value := strings.TrimSpace(os.Getenv(EnvOutputs)); value != "" {
		cfg.Outputs = splitList(value)
	}
	if value := strings.TrimSpace(os.Getenv(EnvFile)); value != "" {
		cfg.FilePath = value
	}

	return cfg
}

func NewRecorder(cfg Config) (Recorder, error) {
	if !cfg.Enabled {
		return NewNopRecorder(), nil
	}

	outputs := cfg.Outputs
	if len(outputs) == 0 {
		outputs = []string{"file"}
	}

	recorders := make([]Recorder, 0, len(outputs))
	seen := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		output = strings.TrimSpace(output)
		if output == "" {
			continue
		}
		if _, ok := seen[output]; ok {
			continue
		}
		seen[output] = struct{}{}

		switch {
		case output == "stdout":
			recorder, err := NewWriterRecorder(os.Stdout)
			if err != nil {
				return nil, err
			}
			recorders = append(recorders, recorder)
		case output == "stderr":
			recorder, err := NewWriterRecorder(os.Stderr)
			if err != nil {
				return nil, err
			}
			recorders = append(recorders, recorder)
		case output == "file":
			recorder, err := newFileRecorder(cfg.FilePath)
			if err != nil {
				return nil, err
			}
			recorders = append(recorders, recorder)
		case strings.HasPrefix(output, "file:"):
			recorder, err := newFileRecorder(strings.TrimSpace(strings.TrimPrefix(output, "file:")))
			if err != nil {
				return nil, err
			}
			recorders = append(recorders, recorder)
		default:
			return nil, fmt.Errorf("unsupported audit output %q", output)
		}
	}

	if len(recorders) == 0 {
		return NewNopRecorder(), nil
	}
	if len(recorders) == 1 {
		return recorders[0], nil
	}
	return &multiRecorder{recorders: recorders}, nil
}

func NewNopRecorder() Recorder {
	return nopRecorder{}
}

func NewWriterRecorder(writer io.Writer) (Recorder, error) {
	if writer == nil {
		return nil, errors.New("audit writer is required")
	}
	return &jsonLineRecorder{writer: writer}, nil
}

type nopRecorder struct{}

func (nopRecorder) Record(context.Context, Event) error {
	return nil
}

func (nopRecorder) Close() error {
	return nil
}

type jsonLineRecorder struct {
	writer io.Writer
	closer io.Closer
	mu     sync.Mutex
}

func (r *jsonLineRecorder) Record(_ context.Context, event Event) error {
	if r == nil || r.writer == nil {
		return nil
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	encoder := json.NewEncoder(r.writer)
	return encoder.Encode(event)
}

func (r *jsonLineRecorder) Close() error {
	if r == nil || r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

type multiRecorder struct {
	recorders []Recorder
}

func (r *multiRecorder) Record(ctx context.Context, event Event) error {
	var errs []error
	for _, recorder := range r.recorders {
		if recorder == nil {
			continue
		}
		if err := recorder.Record(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *multiRecorder) Close() error {
	var errs []error
	for _, recorder := range r.recorders {
		if recorder == nil {
			continue
		}
		if err := recorder.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func newFileRecorder(path string) (Recorder, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("audit file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	return &jsonLineRecorder{writer: file, closer: file}, nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return result
}
