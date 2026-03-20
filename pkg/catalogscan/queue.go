package catalogscan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

var ErrQueueFull = errors.New("catalog scan queue is full")

type Queue struct {
	executor Executor
	cfg      Config
	logger   *log.Logger

	mu           sync.RWMutex
	jobs         map[string]*Job
	activeByScan map[string]string
	order        []string
	work         chan string
	startOnce    sync.Once
}

func NewQueue(executor Executor, cfg Config, logger *log.Logger) *Queue {
	if logger == nil {
		logger = log.Default()
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 1
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Minute
	}
	if cfg.JobHistoryLimit <= 0 {
		cfg.JobHistoryLimit = 100
	}

	return &Queue{
		executor:     executor,
		cfg:          cfg,
		logger:       logger,
		jobs:         make(map[string]*Job),
		activeByScan: make(map[string]string),
		order:        make([]string, 0, cfg.JobHistoryLimit),
		work:         make(chan string, cfg.QueueSize),
	}
}

func (q *Queue) Start(ctx context.Context) {
	q.startOnce.Do(func() {
		for worker := 0; worker < q.cfg.WorkerCount; worker++ {
			go q.runWorker(ctx)
		}
	})
}

func (q *Queue) Enqueue(req Request) (Job, error) {
	targetKey := req.TargetKey()

	q.mu.Lock()
	if existingID, ok := q.activeByScan[targetKey]; ok {
		job := q.copyJobLocked(existingID)
		q.mu.Unlock()
		return job, nil
	}

	jobID, err := newJobID()
	if err != nil {
		q.mu.Unlock()
		return Job{}, err
	}
	job := &Job{
		ID:        jobID,
		Status:    StatusPending,
		Request:   req,
		CreatedAt: time.Now().UTC(),
	}
	q.jobs[job.ID] = job
	q.order = append(q.order, job.ID)
	q.activeByScan[targetKey] = job.ID
	q.pruneLocked()
	q.mu.Unlock()

	select {
	case q.work <- job.ID:
		job, _ := q.Get(job.ID)
		return job, nil
	default:
		q.mu.Lock()
		delete(q.jobs, job.ID)
		delete(q.activeByScan, targetKey)
		q.removeOrderLocked(job.ID)
		q.mu.Unlock()
		return Job{}, ErrQueueFull
	}
}

func (q *Queue) Get(jobID string) (Job, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	job, ok := q.jobs[jobID]
	if !ok {
		return Job{}, false
	}
	return cloneJob(*job), true
}

func (q *Queue) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case jobID := <-q.work:
			if jobID == "" {
				continue
			}
			q.executeJob(ctx, jobID)
		}
	}
}

func (q *Queue) executeJob(ctx context.Context, jobID string) {
	queuedJob, ok := q.Get(jobID)
	if !ok {
		return
	}

	startedAt := time.Now().UTC()
	q.mu.Lock()
	if job, exists := q.jobs[jobID]; exists {
		job.Status = StatusRunning
		job.StartedAt = &startedAt
	}
	q.mu.Unlock()

	jobCtx := ctx
	cancel := func() {}
	if q.cfg.Timeout > 0 {
		jobCtx, cancel = context.WithTimeout(ctx, q.cfg.Timeout)
	}
	defer cancel()

	result, err := q.executor.ExecuteCatalogScan(jobCtx, queuedJob.Request)
	completedAt := time.Now().UTC()

	q.mu.Lock()
	defer q.mu.Unlock()

	job, exists := q.jobs[jobID]
	if !exists {
		return
	}
	job.CompletedAt = &completedAt
	delete(q.activeByScan, queuedJob.Request.TargetKey())

	if err != nil {
		job.Status = StatusFailed
		job.Error = err.Error()
		q.logger.Printf("catalog scan failed for %s: %v", queuedJob.Request.ImageName, err)
		return
	}

	result.CompletedAt = completedAt
	job.Status = StatusSucceeded
	job.Result = &result
	job.Error = ""
}

func (q *Queue) copyJobLocked(jobID string) Job {
	job, ok := q.jobs[jobID]
	if !ok {
		return Job{}
	}
	return cloneJob(*job)
}

func (q *Queue) pruneLocked() {
	for len(q.order) > q.cfg.JobHistoryLimit {
		jobID := q.order[0]
		q.order = q.order[1:]
		job, ok := q.jobs[jobID]
		if !ok {
			continue
		}
		if job.Status == StatusPending || job.Status == StatusRunning {
			q.order = append(q.order, jobID)
			return
		}
		delete(q.jobs, jobID)
	}
}

func (q *Queue) removeOrderLocked(jobID string) {
	for index, candidate := range q.order {
		if candidate != jobID {
			continue
		}
		q.order = append(q.order[:index], q.order[index+1:]...)
		return
	}
}

func cloneJob(job Job) Job {
	cloned := job
	if job.Result != nil {
		result := *job.Result
		if len(job.Result.Scanners) > 0 {
			result.Scanners = append([]string(nil), job.Result.Scanners...)
		}
		cloned.Result = &result
	}
	return cloned
}

func newJobID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate scan job id: %w", err)
	}
	return "scanjob-" + hex.EncodeToString(raw[:]), nil
}
