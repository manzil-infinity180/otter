package storage

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	otteraws "github.com/otterXf/otter/pkg/aws"
)

func TestS3StoreValidationAndLightweightMethods(t *testing.T) {
	t.Parallel()

	if _, err := NewS3Store(otteraws.BucketBasics{}, "bucket", time.Minute); err == nil {
		t.Fatal("expected NewS3Store() to require a client")
	}
	if _, err := NewS3Store(otteraws.BucketBasics{S3Client: &s3.Client{}}, "", time.Minute); err == nil {
		t.Fatal("expected NewS3Store() to require a bucket name")
	}

	store, err := NewS3Store(otteraws.BucketBasics{S3Client: &s3.Client{}}, "otter-test", time.Minute)
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
