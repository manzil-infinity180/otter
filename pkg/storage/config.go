package storage

import (
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Backend            string
	LocalDataDir       string
	PostgresDSN        string
	PostgresMigrations string
	S3Bucket           string
	S3Region           string
	PresignExpiry      time.Duration
}

func ConfigFromEnv() Config {
	workingDir, err := os.Getwd()
	if err != nil {
		workingDir = "."
	}

	backend := os.Getenv("OTTER_STORAGE")
	if backend == "" {
		backend = BackendLocal
	}

	localDataDir := os.Getenv("OTTER_DATA_DIR")
	if localDataDir == "" {
		localDataDir = filepath.Join(workingDir, "data")
	}

	postgresDSN := os.Getenv("OTTER_POSTGRES_DSN")
	if postgresDSN == "" {
		postgresDSN = "postgres://otter:otter@localhost:5432/otter?sslmode=disable"
	}

	postgresMigrations := os.Getenv("OTTER_POSTGRES_MIGRATIONS")
	if postgresMigrations == "" {
		postgresMigrations = filepath.Join(workingDir, "db", "migrations")
	}

	s3Bucket := os.Getenv("S3_BUCKET_NAME")
	if s3Bucket == "" {
		s3Bucket = "otterxf-scans"
	}

	s3Region := os.Getenv("AWS_REGION")
	if s3Region == "" {
		s3Region = "us-east-1"
	}

	return Config{
		Backend:            backend,
		LocalDataDir:       localDataDir,
		PostgresDSN:        postgresDSN,
		PostgresMigrations: postgresMigrations,
		S3Bucket:           s3Bucket,
		S3Region:           s3Region,
		PresignExpiry:      time.Hour,
	}
}
