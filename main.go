package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/api"
	otteraws "github.com/otterXf/otter/pkg/aws"
	"github.com/otterXf/otter/pkg/routes"
	"github.com/otterXf/otter/pkg/storage"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := buildStore(ctx)
	if err != nil {
		log.Fatalf("build storage backend: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("close storage backend: %v", err)
		}
	}()

	scanHandler := api.NewScanHandler(store)
	handlers := &routes.Handlers{ScanHandler: scanHandler}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("set trusted proxies: %v", err)
	}

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":         "hello",
			"storage_backend": store.Backend(),
		})
	})

	routes.SetupRoutes(router, handlers)

	server := &http.Server{
		Addr:              ":7789",
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown server: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("run server: %v", err)
	}
}

func buildStore(ctx context.Context) (storage.Store, error) {
	cfg := storage.ConfigFromEnv()

	switch cfg.Backend {
	case storage.BackendLocal:
		return storage.NewLocalStore(cfg.LocalDataDir)
	case storage.BackendPostgres:
		return storage.NewPostgresStore(ctx, cfg.PostgresDSN, cfg.PostgresMigrations)
	case storage.BackendS3:
		awsCfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}

		s3Store, err := storage.NewS3Store(otteraws.BucketBasics{
			S3Client: s3.NewFromConfig(awsCfg),
		}, cfg.S3Bucket, cfg.PresignExpiry)
		if err != nil {
			return nil, err
		}
		if err := s3Store.EnsureBucket(ctx, cfg.S3Region); err != nil {
			return nil, err
		}
		return s3Store, nil
	default:
		return nil, errors.New("unsupported OTTER_STORAGE backend")
	}
}
