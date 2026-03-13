package attestation

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	cosignSimpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"
	dsseEnvelopeMediaType        = "application/vnd.dsse.envelope.v1+json"
	inTotoJSONMediaType          = "application/vnd.in-toto+json"
)

type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

func enrichRecordFromArtifact(record *Record, descriptor v1.Descriptor, data []byte) {
	mediaType := string(descriptor.MediaType)
	if mediaType == "" || (!json.Valid(data) && !looksLikeJSONMediaType(mediaType)) {
		return
	}
	if !json.Valid(data) {
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}

	switch {
	case isSimpleSigningPayload(mediaType, payload):
		record.Kind = KindSignature
		if digest := nestedString(payload, "critical", "image", "docker-manifest-digest"); digest != "" && record.SubjectDigest == "" {
			record.SubjectDigest = digest
		}
		if ts := findTimestamp(payload); ts != nil && record.Timestamp == nil {
			record.Timestamp = ts
		}
	case isDSSEPayload(mediaType, payload):
		record.Kind = KindAttestation
		var envelope dsseEnvelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			return
		}
		record.DSSEPayloadType = strings.TrimSpace(envelope.PayloadType)
		record.Envelope = &EnvelopeSummary{
			PayloadType: record.DSSEPayloadType,
			Signatures:  len(envelope.Signatures),
		}

		decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return
		}
		enrichRecordFromStatement(record, decoded)
	case isInTotoStatement(mediaType, payload):
		record.Kind = KindAttestation
		enrichRecordFromStatement(record, data)
	}
}

func enrichRecordFromStatement(record *Record, payload []byte) {
	if !json.Valid(payload) {
		return
	}

	var statement map[string]any
	if err := json.Unmarshal(payload, &statement); err != nil {
		return
	}

	if value := stringValue(statement["_type"]); value != "" {
		record.StatementType = value
	}
	if value := stringValue(statement["predicateType"]); value != "" {
		record.PredicateType = value
	}
	if record.Timestamp == nil {
		record.Timestamp = findTimestamp(statement)
	}
	record.Subjects = extractStatementSubjects(statement["subject"])

	predicate, _ := statement["predicate"].(map[string]any)
	if predicate == nil {
		return
	}

	if isSLSAPredicate(record.PredicateType) {
		record.Provenance = &ProvenanceSummary{
			BuilderID: nestedMapString(predicate, "builder", "id"),
			BuildType: stringValue(predicate["buildType"]),
			InvocationID: firstNonEmpty(
				nestedMapString(predicate, "metadata", "invocationID"),
				nestedMapString(predicate, "invocation", "id"),
			),
			Materials: extractMaterials(predicate["materials"]),
		}
		if record.Timestamp == nil {
			record.Timestamp = firstNonNilTime(
				findTimestamp(predicate["metadata"]),
				findTimestamp(predicate["buildDefinition"]),
				findTimestamp(predicate),
			)
		}
	}
}

func mergeAnnotationMetadata(record *Record, annotations map[string]string) {
	if len(annotations) == 0 {
		return
	}
	signer, issuer, ts := extractCertificateMetadata(annotations)
	if record.Signer == "" {
		record.Signer = signer
	}
	if record.Issuer == "" {
		record.Issuer = issuer
	}
	if record.Timestamp == nil {
		record.Timestamp = ts
	}
}

func extractCertificateMetadata(values map[string]string) (string, string, *time.Time) {
	for _, value := range values {
		rest := []byte(value)
		for len(rest) > 0 {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = remaining
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			var signer string
			switch {
			case len(certificate.EmailAddresses) > 0:
				signer = certificate.EmailAddresses[0]
			case len(certificate.URIs) > 0:
				signer = certificate.URIs[0].String()
			case certificate.Subject.CommonName != "":
				signer = certificate.Subject.CommonName
			default:
				signer = strings.TrimSpace(certificate.Subject.String())
			}

			issuer := strings.TrimSpace(certificate.Issuer.String())
			timestamp := certificate.NotBefore.UTC()
			return signer, issuer, &timestamp
		}
	}
	return "", "", nil
}

func extractStatementSubjects(value any) []StatementSubject {
	items, ok := value.([]any)
	if !ok {
		return nil
	}

	subjects := make([]StatementSubject, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		subject := StatementSubject{
			Name:   stringValue(entry["name"]),
			Digest: stringMap(entry["digest"]),
		}
		if subject.Name == "" && len(subject.Digest) == 0 {
			continue
		}
		subjects = append(subjects, subject)
	}
	return subjects
}

func extractMaterials(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}

	materials := make([]string, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		uri := stringValue(entry["uri"])
		digest := stringValue(entry["digest"])
		if digest == "" {
			digestMap := stringMap(entry["digest"])
			if len(digestMap) > 0 {
				parts := make([]string, 0, len(digestMap))
				for algorithm, value := range digestMap {
					parts = append(parts, fmt.Sprintf("%s:%s", algorithm, value))
				}
				digest = strings.Join(parts, ",")
			}
		}
		switch {
		case uri != "" && digest != "":
			materials = append(materials, uri+"@"+digest)
		case uri != "":
			materials = append(materials, uri)
		case digest != "":
			materials = append(materials, digest)
		}
	}
	return materials
}

func findTimestamp(value any) *time.Time {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			lowerKey := strings.ToLower(strings.TrimSpace(key))
			if ts := parseTimestampValue(lowerKey, item); ts != nil {
				return ts
			}
			if nested := findTimestamp(item); nested != nil {
				return nested
			}
		}
	case []any:
		for _, item := range typed {
			if ts := findTimestamp(item); ts != nil {
				return ts
			}
		}
	}
	return nil
}

func parseTimestampValue(key string, value any) *time.Time {
	switch typed := value.(type) {
	case string:
		if !strings.Contains(key, "time") && !strings.Contains(key, "date") {
			return nil
		}
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z07:00"} {
			if parsed, err := time.Parse(layout, typed); err == nil {
				ts := parsed.UTC()
				return &ts
			}
		}
	case float64:
		if strings.Contains(key, "integrated") || strings.Contains(key, "timestamp") || strings.Contains(key, "time") {
			ts := time.Unix(int64(typed), 0).UTC()
			return &ts
		}
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			ts := time.Unix(parsed, 0).UTC()
			return &ts
		}
	}
	return nil
}

func looksLikeJSONMediaType(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.HasSuffix(value, "+json") || strings.HasSuffix(value, "/json")
}

func isSimpleSigningPayload(mediaType string, payload map[string]any) bool {
	if strings.EqualFold(strings.TrimSpace(mediaType), cosignSimpleSigningMediaType) {
		return true
	}
	return nestedString(payload, "critical", "image", "docker-manifest-digest") != ""
}

func isDSSEPayload(mediaType string, payload map[string]any) bool {
	if strings.EqualFold(strings.TrimSpace(mediaType), dsseEnvelopeMediaType) {
		return true
	}
	return stringValue(payload["payloadType"]) != "" && payload["payload"] != nil
}

func isInTotoStatement(mediaType string, payload map[string]any) bool {
	if strings.EqualFold(strings.TrimSpace(mediaType), inTotoJSONMediaType) {
		return true
	}
	return stringValue(payload["predicateType"]) != ""
}

func isSLSAPredicate(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "slsa.dev/provenance")
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func nestedString(value map[string]any, path ...string) string {
	var current any = value
	for _, part := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = next[part]
		if !ok {
			return ""
		}
	}
	return stringValue(current)
}

func nestedMapString(value map[string]any, path ...string) string {
	return nestedString(value, path...)
}

func stringMap(value any) map[string]string {
	input, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, item := range input {
		if text := stringValue(item); text != "" {
			result[key] = text
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstNonNilTime(values ...*time.Time) *time.Time {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
