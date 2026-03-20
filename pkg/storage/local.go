package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type LocalStore struct {
	rootDir string
}

func NewLocalStore(rootDir string) (*LocalStore, error) {
	if rootDir == "" {
		return nil, errors.New("local storage root directory is required")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return nil, fmt.Errorf("create local storage root: %w", err)
	}
	return &LocalStore{rootDir: rootDir}, nil
}

func (s *LocalStore) Backend() string {
	return BackendLocal
}

func (s *LocalStore) Put(_ context.Context, key string, data []byte, opts PutOptions) (ObjectInfo, error) {
	if _, err := ParseArtifactKey(key); err != nil {
		return ObjectInfo{}, err
	}

	fullPath := s.objectPath(key)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return ObjectInfo{}, fmt.Errorf("create object directory: %w", err)
	}

	tmpPath := fullPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return ObjectInfo{}, fmt.Errorf("write temp object: %w", err)
	}
	if err := os.Rename(tmpPath, fullPath); err != nil {
		_ = os.Remove(tmpPath)
		return ObjectInfo{}, fmt.Errorf("move temp object into place: %w", err)
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("stat stored object: %w", err)
	}

	return ObjectInfo{
		Key:         key,
		Size:        info.Size(),
		ContentType: opts.ContentType,
		CreatedAt:   info.ModTime().UTC(),
		Backend:     s.Backend(),
		Metadata:    opts.Metadata,
	}, nil
}

func (s *LocalStore) Get(_ context.Context, key string) (Object, error) {
	if _, err := ParseArtifactKey(key); err != nil {
		return Object{}, err
	}

	fullPath := s.objectPath(key)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Object{}, ErrNotFound
		}
		return Object{}, fmt.Errorf("read object: %w", err)
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return Object{}, fmt.Errorf("stat object: %w", err)
	}

	return Object{
		Info: ObjectInfo{
			Key:         key,
			Size:        info.Size(),
			ContentType: defaultContentTypeForKey(key),
			CreatedAt:   info.ModTime().UTC(),
			Backend:     s.Backend(),
		},
		Data: data,
	}, nil
}

func (s *LocalStore) List(_ context.Context, prefix string) ([]ObjectInfo, error) {
	if err := ValidatePrefix(prefix); err != nil {
		return nil, err
	}

	basePath := s.rootDir
	trimmed := strings.TrimSuffix(prefix, "/")
	if trimmed != "" {
		basePath = s.objectPath(trimmed)
	}

	entries := make([]ObjectInfo, 0)
	err := filepath.WalkDir(basePath, func(current string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		relative, err := filepath.Rel(s.rootDir, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if prefix != "" && !strings.HasPrefix(relative, prefix) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		entries = append(entries, ObjectInfo{
			Key:         relative,
			Size:        info.Size(),
			ContentType: defaultContentTypeForKey(relative),
			CreatedAt:   info.ModTime().UTC(),
			Backend:     s.Backend(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list objects: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	return entries, nil
}

func (s *LocalStore) Delete(_ context.Context, key string) error {
	if _, err := ParseArtifactKey(key); err != nil {
		return err
	}

	err := os.Remove(s.objectPath(key))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete object: %w", err)
	}
	return nil
}

func (s *LocalStore) Close() error {
	return nil
}

func (s *LocalStore) objectPath(key string) string {
	return filepath.Join(s.rootDir, filepath.FromSlash(key))
}
