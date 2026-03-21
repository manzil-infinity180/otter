package catalogscan

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type jobStore interface {
	Save(Job) error
	Delete(string) error
	List() ([]Job, error)
}

type localJobStore struct {
	rootDir string
}

func newLocalJobStore(rootDir string) (*localJobStore, error) {
	rootDir = strings.TrimSpace(rootDir)
	if rootDir == "" {
		return nil, fmt.Errorf("catalog scan state directory is required")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return nil, fmt.Errorf("create catalog scan state directory: %w", err)
	}
	return &localJobStore{rootDir: rootDir}, nil
}

func (s *localJobStore) Save(job Job) error {
	payload, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal catalog scan job: %w", err)
	}

	path := s.jobPath(job.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create catalog scan job directory: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o644); err != nil {
		return fmt.Errorf("write temp catalog scan job: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("move catalog scan job into place: %w", err)
	}
	return nil
}

func (s *localJobStore) Delete(jobID string) error {
	if strings.TrimSpace(jobID) == "" {
		return nil
	}
	if err := os.Remove(s.jobPath(jobID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete catalog scan job: %w", err)
	}
	return nil
}

func (s *localJobStore) List() ([]Job, error) {
	jobs := make([]Job, 0)
	err := filepath.WalkDir(s.rootDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(entry.Name()) != ".json" {
			return nil
		}

		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var job Job
		if err := json.Unmarshal(payload, &job); err != nil {
			return fmt.Errorf("decode catalog scan job %q: %w", entry.Name(), err)
		}
		jobs = append(jobs, job)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list catalog scan jobs: %w", err)
	}

	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].ID < jobs[j].ID
		}
		return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
	})
	return jobs, nil
}

func (s *localJobStore) jobPath(jobID string) string {
	return filepath.Join(s.rootDir, jobID+".json")
}
