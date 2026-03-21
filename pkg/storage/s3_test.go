package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	otteraws "github.com/otterXf/otter/pkg/aws"
)

type fakeS3Client struct {
	objects map[string]otteraws.ObjectData
}

func newFakeS3Client() *fakeS3Client {
	return &fakeS3Client{objects: make(map[string]otteraws.ObjectData)}
}

func (f *fakeS3Client) BucketExists(context.Context, string) (bool, error) {
	return true, nil
}

func (f *fakeS3Client) CreateBucket(context.Context, string, string) error {
	return nil
}

func (f *fakeS3Client) UploadFile(_ context.Context, _ string, objectKey string, fileName string, contentType string, metadata map[string]string) error {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	f.objects[objectKey] = otteraws.ObjectData{
		Data:         append([]byte(nil), data...),
		ContentType:  contentType,
		Metadata:     cloneMetadata(metadata),
		LastModified: time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC),
	}
	return nil
}

func (f *fakeS3Client) GetObject(_ context.Context, _ string, objectKey string) (otteraws.ObjectData, error) {
	object, ok := f.objects[objectKey]
	if !ok {
		return otteraws.ObjectData{}, &types.NoSuchKey{}
	}
	object.Data = append([]byte(nil), object.Data...)
	object.Metadata = cloneMetadata(object.Metadata)
	return object, nil
}

func (f *fakeS3Client) ListObjects(_ context.Context, _ string, prefix string) ([]otteraws.ObjectSummary, error) {
	keys := make([]string, 0, len(f.objects))
	for key := range f.objects {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	summaries := make([]otteraws.ObjectSummary, 0, len(keys))
	for _, key := range keys {
		object := f.objects[key]
		summaries = append(summaries, otteraws.ObjectSummary{
			Key:          key,
			Size:         int64(len(object.Data)),
			ContentType:  object.ContentType,
			Metadata:     cloneMetadata(object.Metadata),
			LastModified: object.LastModified,
		})
	}
	return summaries, nil
}

func (f *fakeS3Client) DeleteObjects(_ context.Context, _ string, objectKeys []string) error {
	for _, key := range objectKeys {
		delete(f.objects, key)
	}
	return nil
}

func (f *fakeS3Client) GetPresignedURL(_ context.Context, bucketName, key string, _ time.Duration) (string, error) {
	return fmt.Sprintf("https://example.com/%s/%s", bucketName, key), nil
}

func TestS3StoreValidationAndLightweightMethods(t *testing.T) {
	t.Parallel()

	if _, err := NewS3Store(nil, "bucket", time.Minute); err == nil {
		t.Fatal("expected NewS3Store() to require a client")
	}
	if _, err := NewS3Store(newFakeS3Client(), "", time.Minute); err == nil {
		t.Fatal("expected NewS3Store() to require a bucket name")
	}

	store, err := NewS3Store(newFakeS3Client(), "otter-test", time.Minute)
	if err != nil {
		t.Fatalf("NewS3Store() error = %v", err)
	}
	if got, want := store.Backend(), BackendS3; got != want {
		t.Fatalf("Backend() = %q, want %q", got, want)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := store.Put(context.Background(), "invalid", []byte(`{}`), PutOptions{}); err == nil {
		t.Fatal("expected Put() to reject invalid keys")
	}
	if _, err := store.Get(context.Background(), "invalid"); err == nil {
		t.Fatal("expected Get() to reject invalid keys")
	}
	if _, err := store.List(context.Background(), "../bad"); err == nil {
		t.Fatal("expected List() to reject invalid prefixes")
	}
	if err := store.Delete(context.Background(), "invalid"); err == nil {
		t.Fatal("expected Delete() to reject invalid keys")
	}
}

func TestS3StoreMetadataRoundTrip(t *testing.T) {
	t.Parallel()

	store, err := NewS3Store(newFakeS3Client(), "otter-test", time.Minute)
	if err != nil {
		t.Fatalf("NewS3Store() error = %v", err)
	}

	key, err := BuildArtifactKey("demo-org", "demo-image", "vex.json")
	if err != nil {
		t.Fatalf("BuildArtifactKey() error = %v", err)
	}
	payload := []byte(`{"bomFormat":"CycloneDX"}`)
	metadata := map[string]string{
		"image_name":           "nginx:latest",
		"availability_message": "scanner unavailable",
	}

	if _, err := store.Put(context.Background(), key, payload, PutOptions{
		ContentType: "application/vnd.openvex+json",
		Metadata:    metadata,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	object, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(object.Data) != string(payload) {
		t.Fatalf("Get() payload = %s, want %s", object.Data, payload)
	}
	if got, want := object.Info.ContentType, "application/vnd.openvex+json"; got != want {
		t.Fatalf("Get() content type = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(object.Info.Metadata, metadata) {
		t.Fatalf("Get() metadata = %#v, want %#v", object.Info.Metadata, metadata)
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
	if got, want := objects[0].ContentType, "application/vnd.openvex+json"; got != want {
		t.Fatalf("List() content type = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(objects[0].Metadata, metadata) {
		t.Fatalf("List() metadata = %#v, want %#v", objects[0].Metadata, metadata)
	}
	if objects[0].DownloadURL == "" {
		t.Fatal("expected List() to include a presigned URL")
	}

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Get(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after delete error = %v, want ErrNotFound", err)
	}
}
