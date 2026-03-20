package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	otteraws "github.com/otterXf/otter/pkg/aws"
)

type s3API interface {
	BucketExists(ctx context.Context, bucketName string) (bool, error)
	CreateBucket(ctx context.Context, name string, region string) error
	UploadFile(ctx context.Context, bucketName string, objectKey string, fileName string, contentType string, metadata map[string]string) error
	GetObject(ctx context.Context, bucketName string, objectKey string) (otteraws.ObjectData, error)
	ListObjects(ctx context.Context, bucketName string, prefix string) ([]otteraws.ObjectSummary, error)
	DeleteObjects(ctx context.Context, bucketName string, objectKeys []string) error
	GetPresignedURL(ctx context.Context, bucketName, key string, expiration time.Duration) (string, error)
}

type S3Store struct {
	client        s3API
	bucketName    string
	presignExpiry time.Duration
}

func NewS3Store(client s3API, bucketName string, presignExpiry time.Duration) (*S3Store, error) {
	if client == nil {
		return nil, errors.New("s3 client is required")
	}
	if bucketName == "" {
		return nil, errors.New("s3 bucket name is required")
	}
	return &S3Store{
		client:        client,
		bucketName:    bucketName,
		presignExpiry: presignExpiry,
	}, nil
}

func (s *S3Store) Backend() string {
	return BackendS3
}

func (s *S3Store) EnsureBucket(ctx context.Context, region string) error {
	exists, err := s.client.BucketExists(ctx, s.bucketName)
	if err != nil {
		return fmt.Errorf("check s3 bucket: %w", err)
	}
	if exists {
		return nil
	}
	if err := s.client.CreateBucket(ctx, s.bucketName, region); err != nil {
		return fmt.Errorf("create s3 bucket: %w", err)
	}
	return nil
}

func (s *S3Store) Put(ctx context.Context, key string, data []byte, opts PutOptions) (ObjectInfo, error) {
	if _, err := ParseArtifactKey(key); err != nil {
		return ObjectInfo{}, err
	}

	tmpDir, err := os.MkdirTemp("", "otter-s3-*")
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("create temp dir for s3 upload: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck // best-effort temp dir cleanup

	filePath := filepath.Join(tmpDir, filepath.Base(key))
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		return ObjectInfo{}, fmt.Errorf("write temp s3 object: %w", err)
	}

	encodedMetadata, err := encodeS3Metadata(opts.Metadata)
	if err != nil {
		return ObjectInfo{}, err
	}

	if err := s.client.UploadFile(ctx, s.bucketName, key, filePath, opts.ContentType, encodedMetadata); err != nil {
		return ObjectInfo{}, fmt.Errorf("upload s3 object %s: %w", key, err)
	}

	info := ObjectInfo{
		Key:         key,
		Size:        int64(len(data)),
		ContentType: opts.ContentType,
		CreatedAt:   time.Now().UTC(),
		Backend:     s.Backend(),
		Metadata:    cloneMetadata(opts.Metadata),
	}

	if s.presignExpiry > 0 {
		url, err := s.client.GetPresignedURL(ctx, s.bucketName, key, s.presignExpiry)
		if err == nil {
			info.DownloadURL = url
		}
	}

	return info, nil
}

func (s *S3Store) Get(ctx context.Context, key string) (Object, error) {
	if _, err := ParseArtifactKey(key); err != nil {
		return Object{}, err
	}

	object, err := s.client.GetObject(ctx, s.bucketName, key)
	if err != nil {
		var noSuchKey *types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			return Object{}, ErrNotFound
		}
		return Object{}, fmt.Errorf("download s3 object %s: %w", key, err)
	}

	metadata, err := decodeS3Metadata(object.Metadata)
	if err != nil {
		return Object{}, fmt.Errorf("decode s3 object metadata %s: %w", key, err)
	}

	info := ObjectInfo{
		Key:         key,
		Size:        int64(len(object.Data)),
		ContentType: object.ContentType,
		CreatedAt:   object.LastModified.UTC(),
		Backend:     s.Backend(),
		Metadata:    metadata,
	}
	if info.ContentType == "" {
		info.ContentType = defaultContentTypeForKey(key)
	}
	if info.CreatedAt.IsZero() {
		info.CreatedAt = time.Now().UTC()
	}
	if s.presignExpiry > 0 {
		url, err := s.client.GetPresignedURL(ctx, s.bucketName, key, s.presignExpiry)
		if err == nil {
			info.DownloadURL = url
		}
	}

	return Object{Info: info, Data: object.Data}, nil
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	if err := ValidatePrefix(prefix); err != nil {
		return nil, err
	}

	objects, err := s.client.ListObjects(ctx, s.bucketName, prefix)
	if err != nil {
		return nil, fmt.Errorf("list s3 objects: %w", err)
	}

	result := make([]ObjectInfo, 0, len(objects))
	for _, object := range objects {
		metadata, err := decodeS3Metadata(object.Metadata)
		if err != nil {
			return nil, fmt.Errorf("decode s3 object metadata %s: %w", object.Key, err)
		}

		info := ObjectInfo{
			Key:         object.Key,
			Size:        object.Size,
			ContentType: object.ContentType,
			Backend:     s.Backend(),
			CreatedAt:   object.LastModified.UTC(),
			Metadata:    metadata,
		}
		if info.ContentType == "" {
			info.ContentType = defaultContentTypeForKey(object.Key)
		}
		if info.CreatedAt.IsZero() {
			info.CreatedAt = time.Now().UTC()
		}
		if s.presignExpiry > 0 {
			url, err := s.client.GetPresignedURL(ctx, s.bucketName, object.Key, s.presignExpiry)
			if err == nil {
				info.DownloadURL = url
			}
		}
		result = append(result, info)
	}
	return result, nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	if _, err := ParseArtifactKey(key); err != nil {
		return err
	}
	if err := s.client.DeleteObjects(ctx, s.bucketName, []string{key}); err != nil {
		return fmt.Errorf("delete s3 object %s: %w", key, err)
	}
	return nil
}

func (s *S3Store) Close() error {
	return nil
}
