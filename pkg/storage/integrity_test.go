package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestIntegrityStoreWritesAndVerifiesChecksum(t *testing.T) {
	dir := t.TempDir()
	local, err := NewLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store := NewIntegrityStore(local)
	ctx := context.Background()

	data := []byte(`{"format":"cyclonedx","packages":[]}`)
	key := "otterxf/test-org/test-image/sbom.json"

	info, err := store.Put(ctx, key, data, PutOptions{ContentType: "application/json"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	expectedHash := sha256.Sum256(data)
	expectedChecksum := hex.EncodeToString(expectedHash[:])
	if info.Metadata[MetadataKeySHA256] != expectedChecksum {
		t.Fatalf("checksum not stored in metadata: got %q, want %q", info.Metadata[MetadataKeySHA256], expectedChecksum)
	}

	obj, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(obj.Data) != string(data) {
		t.Fatalf("data mismatch")
	}
}

func TestIntegrityStoreRejectsTamperedArtifact(t *testing.T) {
	dir := t.TempDir()
	local, err := NewLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	key := "otterxf/test-org/test-image/sbom.json"
	data := []byte(`{"original": true}`)

	// Write via integrity store to get checksum
	store := NewIntegrityStore(local)
	if _, err := store.Put(ctx, key, data, PutOptions{}); err != nil {
		t.Fatal(err)
	}

	// Tamper directly via underlying store
	tampered := []byte(`{"original": false, "tampered": true}`)
	if _, err := local.Put(ctx, key, tampered, PutOptions{
		Metadata: map[string]string{MetadataKeySHA256: "deadbeef"},
	}); err != nil {
		t.Fatal(err)
	}

	// Reading via integrity store should fail
	_, err = store.Get(ctx, key)
	if err == nil {
		t.Fatal("expected integrity error for tampered artifact")
	}
	if !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch, got: %v", err)
	}
}

func TestIntegrityStoreSkipsVerificationForLegacyArtifacts(t *testing.T) {
	dir := t.TempDir()
	local, err := NewLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Write directly without checksum (simulates legacy artifact)
	key := "otterxf/test-org/test-image/vuln.json"
	data := []byte(`{"vulnerabilities":[]}`)
	if _, err := local.Put(ctx, key, data, PutOptions{}); err != nil {
		t.Fatal(err)
	}

	// Reading via integrity store should succeed (no checksum to verify)
	store := NewIntegrityStore(local)
	obj, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("expected legacy artifact to be readable, got: %v", err)
	}
	if string(obj.Data) != string(data) {
		t.Fatal("data mismatch")
	}
}
