package catalogscan

import (
	"context"
	"log"
	"testing"
	"time"
)

type noopExecutor struct{}

func (noopExecutor) ExecuteCatalogScan(context.Context, Request) (Result, error) {
	return Result{}, nil
}

func TestSchedulerStartAndEnqueueConfiguredScans(t *testing.T) {
	t.Parallel()

	queue := NewQueue(noopExecutor{}, Config{
		Enabled:         true,
		WorkerCount:     1,
		QueueSize:       5,
		JobHistoryLimit: 5,
		Interval:        time.Hour,
		ImageRefs:       []string{"alpine:latest"},
	}, log.Default())

	scheduler := NewScheduler(queue, Config{
		Enabled:  true,
		Interval: time.Hour,
		ImageRefs: []string{"alpine:latest"},
	}, nil)
	scheduler.enqueueConfiguredScans()

	if job, ok := queue.Get(queue.order[0]); !ok || job.Request.ImageName != "alpine:latest" {
		t.Fatalf("queue job = %#v, ok = %t", job, ok)
	}

	ctx, cancel := context.WithCancel(context.Background())
	scheduler.Start(ctx)
	cancel()

	NewScheduler(nil, Config{}, nil).Start(context.Background())
	(*Scheduler)(nil).Start(context.Background())
}
