package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const MetadataKeySHA256 = "sha256"

// ErrIntegrityMismatch is returned when a stored artifact's checksum
// does not match the data read back from storage.
var ErrIntegrityMismatch = fmt.Errorf("artifact integrity check failed: checksum mismatch")

// IntegrityStore wraps a Store and transparently computes SHA-256
// checksums on Put and verifies them on Get.
type IntegrityStore struct {
	inner Store
}

// NewIntegrityStore returns a store that adds checksum verification.
func NewIntegrityStore(inner Store) *IntegrityStore {
	return &IntegrityStore{inner: inner}
}

func (s *IntegrityStore) Backend() string {
	return s.inner.Backend()
}

func (s *IntegrityStore) Put(ctx context.Context, key string, data []byte, opts PutOptions) (ObjectInfo, error) {
	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])

	if opts.Metadata == nil {
		opts.Metadata = make(map[string]string)
	}
	opts.Metadata[MetadataKeySHA256] = checksum

	return s.inner.Put(ctx, key, data, opts)
}

func (s *IntegrityStore) Get(ctx context.Context, key string) (Object, error) {
	obj, err := s.inner.Get(ctx, key)
	if err != nil {
		return obj, err
	}

	expected := obj.Info.Metadata[MetadataKeySHA256]
	if expected == "" {
		// No checksum stored (legacy artifact) — skip verification.
		return obj, nil
	}

	hash := sha256.Sum256(obj.Data)
	actual := hex.EncodeToString(hash[:])
	if actual != expected {
		return Object{}, fmt.Errorf("%w: key=%s expected=%s actual=%s", ErrIntegrityMismatch, key, expected, actual)
	}

	return obj, nil
}

func (s *IntegrityStore) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	return s.inner.List(ctx, prefix)
}

func (s *IntegrityStore) Delete(ctx context.Context, key string) error {
	return s.inner.Delete(ctx, key)
}

func (s *IntegrityStore) Close() error {
	return s.inner.Close()
}
