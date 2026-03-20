package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type BucketBasics struct {
	S3Client *s3.Client
}

type ObjectData struct {
	Data         []byte
	ContentType  string
	Metadata     map[string]string
	LastModified time.Time
}

type ObjectSummary struct {
	Key          string
	Size         int64
	ContentType  string
	Metadata     map[string]string
	LastModified time.Time
}

func (basics BucketBasics) GetPresignedURL(ctx context.Context, bucketName, key string, expiration time.Duration) (string, error) {
	presignClient := s3.NewPresignClient(basics.S3Client)

	request, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiration
	})

	if err != nil {
		return "", err
	}

	return request.URL, nil
}

// BucketExists checks whether a bucket exists in the current account.
func (bucket BucketBasics) BucketExists(ctx context.Context, bucketName string) (bool, error) {

	_, err := bucket.S3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	exists := true
	if err != nil {
		var apiError smithy.APIError
		if errors.As(err, &apiError) {
			switch apiError.(type) {
			case *types.NotFound:
				log.Printf("Bucket %v is available.\n", bucketName)
				exists = false
				err = nil
			default:
				log.Printf("Either you don't have access to bucket %v or another error occurred. "+
					"Here's what happened: %v\n", bucketName, err)
			}
		}
	} else {
		log.Printf("Bucket %v exists and you already own it.", bucketName)
	}

	return exists, err
}

func (bucket BucketBasics) CreateBucket(ctx context.Context, name string, region string) error {
	_, err := bucket.S3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(name),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(region),
		},
	})

	if err != nil {
		var owned *types.BucketAlreadyOwnedByYou
		var exists *types.BucketAlreadyExists
		if errors.As(err, &owned) {
			log.Printf("You already own bucket %s.\n", name)
			err = owned
		} else if errors.As(err, &exists) {
			log.Printf("Bucket %s already exists.\n", name)
			err = exists
		}
	} else {
		err = s3.NewBucketExistsWaiter(bucket.S3Client).Wait(
			ctx, &s3.HeadBucketInput{Bucket: aws.String(name)}, time.Minute)
		if err != nil {
			log.Printf("Failed attempt to wait for bucket %s to exist.\n", name)
		}
	}
	return err
}

func (bucket BucketBasics) UploadFile(ctx context.Context, bucketName string, objectKey string, fileName string, contentType string, metadata map[string]string) error {
	file, err := os.Open(fileName)
	if err != nil {
		log.Printf("Couldn't open file %v to upload. Here's why: %v\n", fileName, err)
	} else {
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("failed to close file: %v", err)
			}
		}()
		_, err := bucket.S3Client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      aws.String(bucketName),
			Key:         aws.String(objectKey),
			Body:        file,
			ContentType: aws.String(contentType),
			Metadata:    metadata,
		})

		if err != nil {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "EntityTooLarge" {
				log.Printf("Error while uploading object to %s. The object is too large.\n"+
					"To upload objects larger than 5GB, use the S3 console (160GB max)\n"+
					"or the multipart upload API (5TB max).", bucketName)
			} else {
				log.Printf("Couldn't upload file %v to %v:%v. Here's why: %v\n",
					fileName, bucketName, objectKey, err)
			}
		} else {
			err = s3.NewObjectExistsWaiter(bucket.S3Client).Wait(
				ctx, &s3.HeadObjectInput{Bucket: aws.String(bucketName), Key: aws.String(objectKey)}, time.Minute)
			if err != nil {
				log.Printf("Failed attempt to wait for object %s to exist.\n", objectKey)
			}
		}
	}
	return err
}

func (bucket BucketBasics) GetObject(ctx context.Context, bucketName string, objectKey string) (ObjectData, error) {
	result, err := bucket.S3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		var noKey *types.NoSuchKey
		if errors.As(err, &noKey) {
			log.Printf("Can't get object %s from bucket %s. No such key exists.\n", objectKey, bucketName)
			err = noKey
		} else {
			log.Printf("Couldn't get object %v:%v. Here's why: %v\n", bucketName, objectKey, err)
		}
		return ObjectData{}, err
	}
	defer func() {
		if err := result.Body.Close(); err != nil {
			log.Printf("failed to close file: %v", err)
		}
	}()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		log.Printf("Couldn't read object body from %v. Here's why: %v\n", objectKey, err)
		return ObjectData{}, err
	}

	object := ObjectData{
		Data:        body,
		ContentType: aws.ToString(result.ContentType),
		Metadata:    result.Metadata,
	}
	if result.LastModified != nil {
		object.LastModified = result.LastModified.UTC()
	}
	return object, nil
}

func (bucket BucketBasics) DownloadFile(ctx context.Context, bucketName string, objectKey string, fileName string) error {
	object, err := bucket.GetObject(ctx, bucketName, objectKey)
	if err != nil {
		return err
	}
	file, err := os.Create(fileName)
	if err != nil {
		log.Printf("Couldn't create file %v. Here's why: %v\n", fileName, err)
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("failed to close file: %v", err)
		}
	}()
	_, err = file.Write(object.Data)
	return err
}

// ListObjects lists the objects in a bucket.
func (bucket BucketBasics) ListObjects(ctx context.Context, bucketName string, prefix string) ([]ObjectSummary, error) {
	var err error
	var output *s3.ListObjectsV2Output
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	var objects []ObjectSummary
	objectPaginator := s3.NewListObjectsV2Paginator(bucket.S3Client, input)
	for objectPaginator.HasMorePages() {
		output, err = objectPaginator.NextPage(ctx)
		if err != nil {
			var noBucket *types.NoSuchBucket
			if errors.As(err, &noBucket) {
				log.Printf("Bucket %s does not exist.\n", bucketName)
				err = noBucket
			}
			break
		} else {
			for _, object := range output.Contents {
				if object.Key == nil {
					continue
				}
				head, headErr := bucket.S3Client.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket: aws.String(bucketName),
					Key:    object.Key,
				})
				if headErr != nil {
					err = headErr
					break
				}
				summary := ObjectSummary{
					Key:         *object.Key,
					ContentType: aws.ToString(head.ContentType),
					Metadata:    head.Metadata,
				}
				if object.Size != nil {
					summary.Size = *object.Size
				}
				if object.LastModified != nil {
					summary.LastModified = object.LastModified.UTC()
				}
				objects = append(objects, summary)
			}
			if err != nil {
				break
			}
		}
	}
	return objects, err
}

// DeleteObjects deletes a list of objects from a bucket.
func (bucket BucketBasics) DeleteObjects(ctx context.Context, bucketName string, objectKeys []string) error {
	var objectIds []types.ObjectIdentifier
	for _, key := range objectKeys {
		objectIds = append(objectIds, types.ObjectIdentifier{Key: aws.String(key)})
	}
	output, err := bucket.S3Client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucketName),
		Delete: &types.Delete{Objects: objectIds, Quiet: aws.Bool(true)},
	})
	if err != nil || len(output.Errors) > 0 {
		log.Printf("Error deleting objects from bucket %s.\n", bucketName)
		if err != nil {
			var noBucket *types.NoSuchBucket
			if errors.As(err, &noBucket) {
				log.Printf("Bucket %s does not exist.\n", bucketName)
				err = noBucket
			}
		} else if len(output.Errors) > 0 {
			for _, outErr := range output.Errors {
				log.Printf("%s: %s\n", *outErr.Key, *outErr.Message)
			}
			err = fmt.Errorf("%s", *output.Errors[0].Message)
		}
	} else {
		for _, delObjs := range output.Deleted {
			err = s3.NewObjectNotExistsWaiter(bucket.S3Client).Wait(
				ctx, &s3.HeadObjectInput{Bucket: aws.String(bucketName), Key: delObjs.Key}, time.Minute)
			if err != nil {
				log.Printf("Failed attempt to wait for object %s to be deleted.\n", *delObjs.Key)
			} else {
				log.Printf("Deleted %s.\n", *delObjs.Key)
			}
		}
	}
	return err
}
