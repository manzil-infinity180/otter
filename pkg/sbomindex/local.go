package sbomindex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/otterXf/otter/pkg/storage"
)

type LocalRepository struct {
	rootDir string
}

func NewLocalRepository(rootDir string) (*LocalRepository, error) {
	if rootDir == "" {
		return nil, errors.New("sbom index root directory is required")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sbom index root: %w", err)
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
		return Record{}, fmt.Errorf("marshal sbom index record: %w", err)
	}

	path := r.recordPath(record.OrgID, record.ImageID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Record{}, fmt.Errorf("create sbom index directories: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return Record{}, fmt.Errorf("write temp sbom index record: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return Record{}, fmt.Errorf("move sbom index record into place: %w", err)
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
		return Record{}, fmt.Errorf("read sbom index record: %w", err)
	}

	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, fmt.Errorf("decode sbom index record: %w", err)
	}
	return record, nil
}

func (r *LocalRepository) Delete(_ context.Context, orgID, imageID string) error {
	if err := validateRecordKey(orgID, imageID); err != nil {
		return err
	}
	path := r.recordPath(orgID, imageID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete sbom index record: %w", err)
	}
	return nil
}

func (r *LocalRepository) Close() error {
	return nil
}

func (r *LocalRepository) recordPath(orgID, imageID string) string {
	return filepath.Join(r.rootDir, storage.ArtifactRootPrefix, orgID, imageID, "sbom-index.json")
}

func validateRecordKey(orgID, imageID string) error {
	if err := storage.ValidateSegment("org_id", orgID); err != nil {
		return err
	}
	if err := storage.ValidateSegment("image_id", imageID); err != nil {
		return err
	}
	return nil
}
