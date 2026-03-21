package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const s3MetadataEnvelopeKey = "otter-metadata"

type persistedObjectInfo struct {
	ContentType string            `json:"content_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
}

func cloneMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}
	cloned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}

func marshalMetadata(metadata map[string]string) ([]byte, error) {
	if metadata == nil {
		return nil, nil
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return payload, nil
}

func unmarshalMetadata(payload []byte) (map[string]string, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	var metadata map[string]string
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}
	return metadata, nil
}

func encodeS3Metadata(metadata map[string]string) (map[string]string, error) {
	if metadata == nil {
		return nil, nil
	}
	payload, err := marshalMetadata(metadata)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		s3MetadataEnvelopeKey: base64.RawURLEncoding.EncodeToString(payload),
	}, nil
}

func decodeS3Metadata(metadata map[string]string) (map[string]string, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	encoded := strings.TrimSpace(metadata[s3MetadataEnvelopeKey])
	if encoded == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode s3 metadata envelope: %w", err)
	}
	decoded, err := unmarshalMetadata(payload)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
