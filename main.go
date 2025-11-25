package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/otterXf/otter/pkg/api"
	"github.com/otterXf/otter/pkg/aws"
	"github.com/otterXf/otter/pkg/routes"
)

func main() {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	// Create S3 client
	s3Client := s3.NewFromConfig(cfg)

	// Get bucket name from environment variable or use default
	bucketName := os.Getenv("S3_BUCKET_NAME")
	if bucketName == "" {
		bucketName = "otterxf-scans"
	}

	// Initialize handlers with dependencies
	scanHandler := api.NewScanHandler(aws.BucketBasics{
		S3Client: s3Client,
	}, bucketName)

	// Bundle all handlers
	handlers := &routes.Handlers{
		ScanHandler: scanHandler,
	}

	// Setup Gin router
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "hello",
		})
	})

	// Setup routes with handlers
	routes.SetupRoutes(router, handlers)

	// Start server
	router.Run(":7789")
}
