package catalogscan

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otterXf/otter/pkg/scan"
)

type fakeExecutor struct {
	mu       sync.Mutex
	requests []Request
}

func (f *fakeExecutor) ExecuteCatalogScan(_ context.Context, req Request) (Result, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()

	return Result{
		OrgID:     req.OrgID,
		ImageID:   req.ImageID,
		ImageName: req.ImageName,
		Scanners:  []string{"grype"},
		Summary:   scan.VulnerabilitySummary{Total: 1},
	}, nil
}

func TestQueueProcessesJobsAndTracksStatus(t *testing.T) {
	t.Parallel()

	executor := &fakeExecutor{}
	queue := NewQueue(executor, Config{
		WorkerCount:     1,
		QueueSize:       4,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
	}, nil)

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
}

func TestQueueDeduplicatesActiveTargets(t *testing.T) {
	t.Parallel()

	executor := &fakeExecutor{}
	queue := NewQueue(executor, Config{
		WorkerCount:     1,
		QueueSize:       4,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
	}, nil)

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

func TestSchedulerEnqueuesConfiguredSeeds(t *testing.T) {
	t.Parallel()

	executor := &fakeExecutor{}
	queue := NewQueue(executor, Config{
		WorkerCount:     1,
		QueueSize:       8,
		Timeout:         time.Second,
		JobHistoryLimit: 16,
	}, nil)

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

func waitForJob(t *testing.T, queue *Queue, jobID, wantStatus string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
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
