package storage

import (
	"context"
	"errors"
	"testing"
)

func TestLocalStoreLifecycle(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store, err := NewLocalStore(root)
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}

	key, err := BuildArtifactKey("demo-org", "demo-image", "sbom.json")
	if err != nil {
		t.Fatalf("BuildArtifactKey() error = %v", err)
	}

	payload := []byte(`{"bomFormat":"CycloneDX"}`)
	if _, err := store.Put(context.Background(), key, payload, PutOptions{ContentType: "application/json"}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	object, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(object.Data) != string(payload) {
		t.Fatalf("Get() payload = %s, want %s", object.Data, payload)
	}

	prefix, err := BuildImagePrefix("demo-org", "demo-image")
	if err != nil {
		t.Fatalf("BuildImagePrefix() error = %v", err)
	}

	objects, err := store.List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(objects) != 1 || objects[0].Key != key {
		t.Fatalf("List() = %#v", objects)
	}

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = store.Get(context.Background(), key)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after delete error = %v, want ErrNotFound", err)
	}
}
