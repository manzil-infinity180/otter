package catalogscan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/scan"
)

type fakeExecutor struct {
	mu       sync.Mutex
	requests []Request
	err      error
}

func (f *fakeExecutor) ExecuteCatalogScan(_ context.Context, req Request) (Result, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()

	if f.err != nil {
		return Result{}, f.err
	}
	return Result{
		OrgID:     req.OrgID,
		ImageID:   req.ImageID,
		ImageName: req.ImageName,
		Scanners:  []string{"grype"},
		Summary:   scan.VulnerabilitySummary{Total: 1},
	}, nil
}

type flakyExecutor struct {
	mu       sync.Mutex
	failures int
	calls    int
}

func (f *flakyExecutor) ExecuteCatalogScan(_ context.Context, req Request) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failures {
		return Result{}, errors.New("transient failure")
	}
	return Result{
		OrgID:     req.OrgID,
		ImageID:   req.ImageID,
		ImageName: req.ImageName,
		Scanners:  []string{"grype"},
		Summary:   scan.VulnerabilitySummary{Total: 1},
	}, nil
}

type countingExecutor struct {
	mu    sync.Mutex
	calls int
}

func (f *countingExecutor) ExecuteCatalogScan(_ context.Context, _ Request) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return Result{}, errors.New("persistent failure")
}

func TestQueueProcessesJobsAndTracksStatus(t *testing.T) {
	t.Parallel()

	executor := &fakeExecutor{}
	queue := mustQueue(t, executor, Config{
		WorkerCount:     1,
		QueueSize:       4,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
		StateDir:        t.TempDir(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx)

	request, err := NewRequest("catalog", "", "alpine:latest", "", SourceCatalog, TriggerScheduler)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	job, err := queue.Enqueue(request)
	if err != nil {
		t.Fatalf("queue.Enqueue() error = %v", err)
	}

	waitForJob(t, queue, job.ID, StatusSucceeded)

	stored, ok := queue.Get(job.ID)
	if !ok {
		t.Fatalf("queue.Get(%q) returned !ok", job.ID)
	}
	if stored.Result == nil || stored.Result.Summary.Total != 1 {
		t.Fatalf("stored.Result = %#v", stored.Result)
	}
	if got, want := stored.Attempts, 1; got != want {
		t.Fatalf("stored.Attempts = %d, want %d", got, want)
	}
	stats := queue.Stats()
	if got, want := stats.Succeeded, 1; got != want {
		t.Fatalf("stats.Succeeded = %d, want %d", got, want)
	}
}

func TestQueueDeduplicatesActiveTargets(t *testing.T) {
	t.Parallel()

	executor := &fakeExecutor{}
	queue := mustQueue(t, executor, Config{
		WorkerCount:     1,
		QueueSize:       4,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
		StateDir:        t.TempDir(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx)

	request, err := NewRequest("catalog", "", "nginx:latest", "", SourceCatalog, TriggerScheduler)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	first, err := queue.Enqueue(request)
	if err != nil {
		t.Fatalf("first queue.Enqueue() error = %v", err)
	}
	second, err := queue.Enqueue(request)
	if err != nil {
		t.Fatalf("second queue.Enqueue() error = %v", err)
	}

	if first.ID != second.ID {
		t.Fatalf("expected duplicate enqueue to return same job id, got %q and %q", first.ID, second.ID)
	}
}

func TestQueueRecoversPersistedPendingAndRunningJobs(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := newLocalJobStore(stateDir)
	if err != nil {
		t.Fatalf("newLocalJobStore() error = %v", err)
	}
	request, err := NewRequest("catalog", "alpine-job", "alpine:latest", "", SourceCatalog, TriggerScheduler)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	createdAt := time.Date(2026, 3, 20, 8, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(2 * time.Minute)

	for _, job := range []Job{
		{
			ID:          "scanjob-pending",
			Status:      StatusPending,
			Request:     request,
			CreatedAt:   createdAt,
			MaxAttempts: 3,
		},
		{
			ID:          "scanjob-running",
			Status:      StatusRunning,
			Request:     Request{OrgID: "catalog", ImageID: "nginx-job", ImageName: "nginx:latest", Source: SourceCatalog, Trigger: TriggerScheduler},
			CreatedAt:   createdAt.Add(time.Minute),
			StartedAt:   &startedAt,
			Attempts:    1,
			MaxAttempts: 3,
		},
	} {
		if err := store.Save(job); err != nil {
			t.Fatalf("store.Save(%q) error = %v", job.ID, err)
		}
	}

	executor := &fakeExecutor{}
	queue := mustQueue(t, executor, Config{
		WorkerCount:     1,
		QueueSize:       4,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
		StateDir:        stateDir,
	})

	recovered, ok := queue.Get("scanjob-running")
	if !ok {
		t.Fatal("expected recovered running job")
	}
	if got, want := recovered.Status, StatusPending; got != want {
		t.Fatalf("recovered.Status = %q, want %q", got, want)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx)

	waitForJob(t, queue, "scanjob-pending", StatusSucceeded)
	waitForJob(t, queue, "scanjob-running", StatusSucceeded)
}

func TestQueueRetriesFailuresAndCapsAttempts(t *testing.T) {
	t.Parallel()

	executor := &flakyExecutor{failures: 2}
	queue := mustQueue(t, executor, Config{
		WorkerCount:     1,
		QueueSize:       4,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
		StateDir:        t.TempDir(),
		RetryLimit:      2,
		RetryBackoff:    10 * time.Millisecond,
		RetryBackoffMax: 20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx)

	request, err := NewRequest("catalog", "", "busybox:latest", "", SourceCatalog, TriggerScheduler)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	job, err := queue.Enqueue(request)
	if err != nil {
		t.Fatalf("queue.Enqueue() error = %v", err)
	}

	waitForJob(t, queue, job.ID, StatusSucceeded)

	stored, ok := queue.Get(job.ID)
	if !ok {
		t.Fatalf("queue.Get(%q) returned !ok", job.ID)
	}
	if got, want := stored.Attempts, 3; got != want {
		t.Fatalf("stored.Attempts = %d, want %d", got, want)
	}
	if stored.NextAttemptAt != nil {
		t.Fatalf("stored.NextAttemptAt = %v, want nil", stored.NextAttemptAt)
	}
}

func TestQueueMarksJobFailedAfterRetryLimit(t *testing.T) {
	t.Parallel()

	executor := &countingExecutor{}
	queue := mustQueue(t, executor, Config{
		WorkerCount:     1,
		QueueSize:       4,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
		StateDir:        t.TempDir(),
		RetryLimit:      1,
		RetryBackoff:    10 * time.Millisecond,
		RetryBackoffMax: 20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx)

	request, err := NewRequest("catalog", "", "redis:latest", "", SourceCatalog, TriggerScheduler)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	job, err := queue.Enqueue(request)
	if err != nil {
		t.Fatalf("queue.Enqueue() error = %v", err)
	}

	waitForJob(t, queue, job.ID, StatusFailed)

	stored, ok := queue.Get(job.ID)
	if !ok {
		t.Fatalf("queue.Get(%q) returned !ok", job.ID)
	}
	if got, want := stored.Attempts, 2; got != want {
		t.Fatalf("stored.Attempts = %d, want %d", got, want)
	}
	if stored.Error == "" {
		t.Fatal("expected final failure error to be recorded")
	}
	stats := queue.Stats()
	if got, want := stats.Failed, 1; got != want {
		t.Fatalf("stats.Failed = %d, want %d", got, want)
	}
	if got, want := stats.QueueDepth, 0; got != want {
		t.Fatalf("stats.QueueDepth = %d, want %d", got, want)
	}
}

func TestSchedulerEnqueuesConfiguredSeeds(t *testing.T) {
	t.Parallel()

	executor := &fakeExecutor{}
	queue := mustQueue(t, executor, Config{
		WorkerCount:     1,
		QueueSize:       8,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
		StateDir:        t.TempDir(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue.Start(ctx)

	scheduler := NewScheduler(queue, Config{
		Enabled:   true,
		Interval:  time.Hour,
		OrgID:     "catalog",
		ImageRefs: []string{"alpine:latest", "nginx:latest"},
	}, nil)

	scheduler.enqueueConfiguredScans()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		executor.mu.Lock()
		count := len(executor.requests)
		executor.mu.Unlock()
		if count == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	executor.mu.Lock()
	defer executor.mu.Unlock()
	t.Fatalf("executor.requests = %d, want 2", len(executor.requests))
}

func mustQueue(t *testing.T, executor Executor, cfg Config) *Queue {
	t.Helper()

	queue, err := NewQueue(executor, cfg, nil)
	if err != nil {
		t.Fatalf("NewQueue() error = %v", err)
	}
	return queue
}

func waitForJob(t *testing.T, queue *Queue, jobID, wantStatus string) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := queue.Get(jobID)
		if ok && job.Status == wantStatus {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	job, _ := queue.Get(jobID)
	t.Fatalf("job %q status = %q, want %q", jobID, job.Status, wantStatus)
}
