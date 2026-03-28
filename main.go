package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/api"
	"github.com/otterXf/otter/pkg/audit"
	"github.com/otterXf/otter/pkg/auth"
	otteraws "github.com/otterXf/otter/pkg/aws"
	"github.com/otterXf/otter/pkg/catalogscan"
	"github.com/otterXf/otter/pkg/policy"
	"github.com/otterXf/otter/pkg/registry"
	"github.com/otterXf/otter/pkg/routes"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/scan"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rawStore, err := buildStore(ctx)
	if err != nil {
		log.Fatalf("build storage backend: %v", err)
	}
	store := storage.NewIntegrityStore(rawStore)
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("close storage backend: %v", err)
		}
	}()
	sbomRepository, err := buildSBOMRepository(ctx)
	if err != nil {
		log.Fatalf("build sbom index backend: %v", err)
	}
	defer func() {
		if err := sbomRepository.Close(); err != nil {
			log.Printf("close sbom index backend: %v", err)
		}
	}()
	vulnerabilityRepository, err := buildVulnerabilityRepository(ctx)
	if err != nil {
		log.Fatalf("build vulnerability index backend: %v", err)
	}
	defer func() {
		if err := vulnerabilityRepository.Close(); err != nil {
			log.Printf("close vulnerability index backend: %v", err)
		}
	}()

	analyzer := buildAnalyzer()
	registryManager, err := buildRegistryManager()
	if err != nil {
		log.Fatalf("build registry manager: %v", err)
	}
	policyEngine, err := buildPolicyEngine()
	if err != nil {
		log.Fatalf("build policy engine: %v", err)
	}
	auditRecorder, err := buildAuditRecorder()
	if err != nil {
		log.Fatalf("build audit recorder: %v", err)
	}
	defer func() {
		if err := auditRecorder.Close(); err != nil {
			log.Printf("close audit recorder: %v", err)
		}
	}()
	catalogScanConfig := catalogscan.ConfigFromEnv()
	scanHandler := api.NewScanHandlerWithRegistry(store, sbomRepository, vulnerabilityRepository, analyzer, registryManager)
	scanHandler.SetAuditRecorder(auditRecorder)
	scanHandler.SetPolicyEngine(policyEngine)
	jobQueue, err := catalogscan.NewQueue(scanHandler, catalogScanConfig, log.Default())
	if err != nil {
		log.Fatalf("build catalog scan queue: %v", err)
	}
	jobQueue.Start(ctx)
	catalogscan.NewScheduler(jobQueue, catalogScanConfig, log.Default()).Start(ctx)
	scanHandler.SetJobQueue(jobQueue)
	authenticator, err := buildAuthenticator()
	if err != nil {
		log.Fatalf("build authenticator: %v", err)
	}
	handlers := &routes.Handlers{ScanHandler: scanHandler}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), securityHeaders())
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("set trusted proxies: %v", err)
	}

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":         "ok",
			"storage_backend": store.Backend(),
		})
	})

	routes.SetupRoutes(router, handlers, authenticator)

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

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; img-src 'self' data: https:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		c.Next()
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

func buildSBOMRepository(ctx context.Context) (sbomindex.Repository, error) {
	cfg := storage.ConfigFromEnv()

	switch cfg.Backend {
	case storage.BackendPostgres:
		return sbomindex.NewPostgresRepository(ctx, cfg.PostgresDSN)
	case storage.BackendLocal, storage.BackendS3:
		return sbomindex.NewLocalRepository(filepath.Join(cfg.LocalDataDir, "_sbom_index"))
	default:
		return nil, errors.New("unsupported OTTER_STORAGE backend")
	}
}

func buildVulnerabilityRepository(ctx context.Context) (vulnindex.Repository, error) {
	cfg := storage.ConfigFromEnv()

	switch cfg.Backend {
	case storage.BackendPostgres:
		return vulnindex.NewPostgresRepository(ctx, cfg.PostgresDSN)
	case storage.BackendLocal, storage.BackendS3:
		return vulnindex.NewLocalRepository(filepath.Join(cfg.LocalDataDir, "_vulnerability_index"))
	default:
		return nil, errors.New("unsupported OTTER_STORAGE backend")
	}
}

func buildAnalyzer() scan.ImageAnalyzer {
	scanConfig := scan.ConfigFromEnv()
	scanners := []scan.VulnerabilityScanner{
		scan.NewGrypeVulnerabilityScanner(scan.Options{MaxAllowedBuildAge: 120 * time.Hour}),
	}
	if scanConfig.TrivyEnabled {
		scanners = append(scanners, scan.NewTrivyScanner(scanConfig))
	}
	if scanConfig.OSVEnabled {
		scanners = append(scanners, scan.NewOSVScanner(scanConfig))
	}
	return scan.NewAnalyzer(scan.SyftSBOMGenerator{}, scanners...)
}

func buildRegistryManager() (registry.Service, error) {
	cfg := storage.ConfigFromEnv()
	registryCfg := registry.ConfigFromEnv(cfg.LocalDataDir)
	repo, err := registry.NewLocalRepository(registryCfg.DataDir)
	if err != nil {
		return nil, err
	}
	return registry.NewManager(repo, registryCfg), nil
}

func buildAuthenticator() (*auth.Authenticator, error) {
	cfg, err := auth.ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return auth.NewAuthenticator(cfg)
}

func buildPolicyEngine() (*policy.Engine, error) {
	return policy.NewEngine(policy.ConfigFromEnv())
}

func buildAuditRecorder() (audit.Recorder, error) {
	cfg := storage.ConfigFromEnv()
	return audit.NewRecorder(audit.ConfigFromEnv(cfg.LocalDataDir))
}
