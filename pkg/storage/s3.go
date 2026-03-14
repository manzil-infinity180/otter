package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	otteraws "github.com/otterXf/otter/pkg/aws"
)

type S3Store struct {
	client        otteraws.BucketBasics
	bucketName    string
	presignExpiry time.Duration
}

func NewS3Store(client otteraws.BucketBasics, bucketName string, presignExpiry time.Duration) (*S3Store, error) {
	if client.S3Client == nil {
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

	if err := s.client.UploadFile(ctx, s.bucketName, key, filePath); err != nil {
		return ObjectInfo{}, fmt.Errorf("upload s3 object %s: %w", key, err)
	}

	info := ObjectInfo{
		Key:         key,
		Size:        int64(len(data)),
		ContentType: opts.ContentType,
		CreatedAt:   time.Now().UTC(),
		Backend:     s.Backend(),
		Metadata:    opts.Metadata,
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

	tmpDir, err := os.MkdirTemp("", "otter-s3-*")
	if err != nil {
		return Object{}, fmt.Errorf("create temp dir for s3 download: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck // best-effort temp dir cleanup

	filePath := filepath.Join(tmpDir, filepath.Base(key))
	if err := s.client.DownloadFile(ctx, s.bucketName, key, filePath); err != nil {
		var noSuchKey *types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			return Object{}, ErrNotFound
		}
		return Object{}, fmt.Errorf("download s3 object %s: %w", key, err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return Object{}, fmt.Errorf("read downloaded s3 object %s: %w", key, err)
	}

	info := ObjectInfo{
		Key:         key,
		Size:        int64(len(data)),
		ContentType: defaultContentTypeForKey(key),
		CreatedAt:   time.Now().UTC(),
		Backend:     s.Backend(),
	}
	if s.presignExpiry > 0 {
		url, err := s.client.GetPresignedURL(ctx, s.bucketName, key, s.presignExpiry)
		if err == nil {
			info.DownloadURL = url
		}
	}

	return Object{Info: info, Data: data}, nil
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	if err := ValidatePrefix(prefix); err != nil {
		return nil, err
	}

	objects, err := s.client.ListObjects(ctx, s.bucketName)
	if err != nil {
		return nil, fmt.Errorf("list s3 objects: %w", err)
	}

	result := make([]ObjectInfo, 0, len(objects))
	for _, object := range objects {
		if object.Key == nil {
			continue
		}
		if prefix != "" && !strings.HasPrefix(*object.Key, prefix) {
			continue
		}

		info := ObjectInfo{
			Key:         *object.Key,
			ContentType: defaultContentTypeForKey(*object.Key),
			Backend:     s.Backend(),
			CreatedAt:   time.Now().UTC(),
		}
		if object.Size != nil {
			info.Size = *object.Size
		}
		if object.LastModified != nil {
			info.CreatedAt = object.LastModified.UTC()
		}
		if s.presignExpiry > 0 {
			url, err := s.client.GetPresignedURL(ctx, s.bucketName, *object.Key, s.presignExpiry)
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
