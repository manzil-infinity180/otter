package registry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryRepositoryLifecycle(t *testing.T) {
	t.Parallel()

	repo := NewMemoryRepository()
	now := time.Now().UTC()

	saved, err := repo.Save(context.Background(), Record{Registry: "ghcr.io", AuthMode: AuthModeExplicit, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if saved.Registry != "ghcr.io" {
		t.Fatalf("saved record = %#v", saved)
	}

	saved, err = repo.Save(context.Background(), Record{Registry: "ghcr.io", AuthMode: AuthModeDockerConfig, UpdatedAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("Save(update) error = %v", err)
	}
	if !saved.CreatedAt.Equal(now) {
		t.Fatalf("created_at should be preserved, got %v want %v", saved.CreatedAt, now)
	}

	record, err := repo.Get(context.Background(), "ghcr.io")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if record.AuthMode != AuthModeDockerConfig {
		t.Fatalf("record = %#v", record)
	}

	if _, err := repo.Get(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound", err)
	}

	listed, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed) != 1 || listed[0].Registry != "ghcr.io" {
		t.Fatalf("List() = %#v", listed)
	}
}
