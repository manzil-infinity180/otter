package vulnindex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/otterXf/otter/pkg/storage"
)

type LocalRepository struct {
	rootDir string
}

func NewLocalRepository(rootDir string) (*LocalRepository, error) {
	if rootDir == "" {
		return nil, errors.New("vulnerability index root directory is required")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return nil, fmt.Errorf("create vulnerability index root: %w", err)
	}
	return &LocalRepository{rootDir: rootDir}, nil
}

func (r *LocalRepository) Save(_ context.Context, record Record) (Record, error) {
	if err := validateRecordKey(record.OrgID, record.ImageID); err != nil {
		return Record{}, err
	}

	record.UpdatedAt = record.UpdatedAt.UTC()
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return Record{}, fmt.Errorf("marshal vulnerability index record: %w", err)
	}

	path := r.recordPath(record.OrgID, record.ImageID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Record{}, fmt.Errorf("create vulnerability index directories: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return Record{}, fmt.Errorf("write temp vulnerability index record: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return Record{}, fmt.Errorf("move vulnerability index record into place: %w", err)
	}
	if err := r.writeSummary(record); err != nil {
		return Record{}, err
	}

	return record, nil
}

func (r *LocalRepository) Get(_ context.Context, orgID, imageID string) (Record, error) {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return Record{}, err
	}

	data, err := os.ReadFile(r.recordPath(orgID, imageID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("read vulnerability index record: %w", err)
	}

	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, fmt.Errorf("decode vulnerability index record: %w", err)
	}
	return record, nil
}

func (r *LocalRepository) Delete(_ context.Context, orgID, imageID string) error {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return err
	}
	path := r.recordPath(orgID, imageID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete vulnerability index record: %w", err)
	}
	summaryPath := r.summaryPath(orgID, imageID)
	if err := os.Remove(summaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete vulnerability summary record: %w", err)
	}
	return nil
}

func (r *LocalRepository) Close() error {
	return nil
}

func (r *LocalRepository) recordPath(orgID, imageID string) string {
	return filepath.Join(r.rootDir, storage.ArtifactRootPrefix, orgID, imageID, "vulnerability-index.json")
}

func (r *LocalRepository) summaryPath(orgID, imageID string) string {
	return filepath.Join(r.rootDir, storage.ArtifactRootPrefix, orgID, imageID, "vulnerability-summary.json")
}

func (r *LocalRepository) writeSummary(record Record) error {
	summary := struct {
		OrgID     string    `json:"org_id"`
		ImageID   string    `json:"image_id"`
		ImageName string    `json:"image_name,omitempty"`
		Platform  string    `json:"platform,omitempty"`
		Summary   Summary   `json:"summary"`
		UpdatedAt time.Time `json:"updated_at"`
	}{
		OrgID:     record.OrgID,
		ImageID:   record.ImageID,
		ImageName: record.ImageName,
		Platform:  record.Platform,
		Summary:   record.Summary,
		UpdatedAt: record.UpdatedAt.UTC(),
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal vulnerability summary record: %w", err)
	}

	path := r.summaryPath(record.OrgID, record.ImageID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create vulnerability summary directories: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write temp vulnerability summary record: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("move vulnerability summary record into place: %w", err)
	}
	return nil
}
