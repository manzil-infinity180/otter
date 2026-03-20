package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type LocalRepository struct {
	path string
	mu   sync.Mutex
}

func NewLocalRepository(dataDir string) (*LocalRepository, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create registry data dir: %w", err)
	}
	return &LocalRepository{path: filepath.Join(dataDir, "registries.json")}, nil
}

func (r *LocalRepository) Save(_ context.Context, record Record) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.load()
	if err != nil {
		return Record{}, err
	}

	updated := false
	for idx := range state.Registries {
		if state.Registries[idx].Registry != record.Registry {
			continue
		}
		record.CreatedAt = state.Registries[idx].CreatedAt
		state.Registries[idx] = record
		updated = true
		break
	}
	if !updated {
		state.Registries = append(state.Registries, record)
	}

	sort.Slice(state.Registries, func(i, j int) bool {
		return state.Registries[i].Registry < state.Registries[j].Registry
	})

	if err := r.store(state); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (r *LocalRepository) Get(_ context.Context, registry string) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.load()
	if err != nil {
		return Record{}, err
	}

	for _, record := range state.Registries {
		if record.Registry == registry {
			return record, nil
		}
	}
	return Record{}, ErrNotFound
}

func (r *LocalRepository) List(_ context.Context) ([]Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.load()
	if err != nil {
		return nil, err
	}
	return append([]Record(nil), state.Registries...), nil
}

type localState struct {
	Registries []Record `json:"registries"`
}

func (r *LocalRepository) load() (localState, error) {
	raw, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return localState{}, nil
		}
		return localState{}, fmt.Errorf("read registry repository: %w", err)
	}

	var state localState
	if err := json.Unmarshal(raw, &state); err != nil {
		return localState{}, fmt.Errorf("decode registry repository: %w", err)
	}
	return state, nil
}

func (r *LocalRepository) store(state localState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode registry repository: %w", err)
	}

	tempPath := r.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return fmt.Errorf("write registry repository temp file: %w", err)
	}
	if err := os.Rename(tempPath, r.path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("replace registry repository: %w", err)
	}
	return nil
}
