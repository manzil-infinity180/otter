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
	store    jobStore

	mu           sync.RWMutex
	jobs         map[string]*Job
	activeByScan map[string]string
	enqueued     map[string]struct{}
	order        []string
	work         chan string
	dispatch     chan struct{}
	now          func() time.Time
	startOnce    sync.Once
}

func NewQueue(executor Executor, cfg Config, logger *log.Logger) (*Queue, error) {
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
	if cfg.RetryLimit < 0 {
		cfg.RetryLimit = 0
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 5 * time.Second
	}
	if cfg.RetryBackoffMax <= 0 {
		cfg.RetryBackoffMax = time.Minute
	}
	if cfg.RetryBackoffMax < cfg.RetryBackoff {
		cfg.RetryBackoffMax = cfg.RetryBackoff
	}

	store, err := newLocalJobStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}

	queue := &Queue{
		executor:     executor,
		cfg:          cfg,
		logger:       logger,
		store:        store,
		jobs:         make(map[string]*Job),
		activeByScan: make(map[string]string),
		enqueued:     make(map[string]struct{}),
		order:        make([]string, 0, cfg.JobHistoryLimit),
		work:         make(chan string, cfg.QueueSize),
		dispatch:     make(chan struct{}, 1),
		now: func() time.Time {
			return time.Now().UTC()
		},
	}

	if err := queue.loadPersistedJobs(); err != nil {
		return nil, err
	}
	return queue, nil
}

func (q *Queue) Start(ctx context.Context) {
	q.startOnce.Do(func() {
		go q.runDispatcher(ctx)
		for worker := 0; worker < q.cfg.WorkerCount; worker++ {
			go q.runWorker(ctx)
		}
		q.signalDispatch()
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
	if q.pendingCountLocked() >= q.cfg.QueueSize {
		q.mu.Unlock()
		return Job{}, ErrQueueFull
	}

	jobID, err := newJobID()
	if err != nil {
		q.mu.Unlock()
		return Job{}, err
	}
	job := Job{
		ID:          jobID,
		Status:      StatusPending,
		Request:     req,
		CreatedAt:   q.now(),
		MaxAttempts: q.maxAttempts(),
	}
	if err := q.saveJobLocked(job); err != nil {
		q.mu.Unlock()
		return Job{}, err
	}
	q.jobs[job.ID] = &job
	q.order = append(q.order, job.ID)
	q.activeByScan[targetKey] = job.ID
	if err := q.pruneLocked(); err != nil {
		q.mu.Unlock()
		return Job{}, err
	}
	stored := cloneJob(job)
	q.mu.Unlock()

	q.signalDispatch()
	return stored, nil
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

func (q *Queue) Stats() QueueStats {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var stats QueueStats
	for _, job := range q.jobs {
		switch job.Status {
		case StatusPending:
			stats.Pending++
		case StatusRunning:
			stats.Running++
		case StatusSucceeded:
			stats.Succeeded++
		case StatusFailed:
			stats.Failed++
		}
	}
	stats.QueueDepth = stats.Pending
	stats.ActiveTargets = len(q.activeByScan)
	return stats
}

func (q *Queue) runDispatcher(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		q.dispatchReadyJobs()

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-q.dispatch:
		}
	}
}

func (q *Queue) dispatchReadyJobs() {
	for {
		jobID, ok := q.nextReadyJobID()
		if !ok {
			return
		}

		select {
		case q.work <- jobID:
		default:
			q.mu.Lock()
			delete(q.enqueued, jobID)
			q.mu.Unlock()
			return
		}
	}
}

func (q *Queue) nextReadyJobID() (string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := q.now()
	for _, jobID := range q.order {
		job, ok := q.jobs[jobID]
		if !ok || job.Status != StatusPending {
			continue
		}
		if _, alreadyQueued := q.enqueued[jobID]; alreadyQueued {
			continue
		}
		if job.NextAttemptAt != nil && job.NextAttemptAt.After(now) {
			continue
		}
		q.enqueued[jobID] = struct{}{}
		return jobID, true
	}
	return "", false
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
			q.mu.Lock()
			delete(q.enqueued, jobID)
			q.mu.Unlock()
			q.executeJob(ctx, jobID)
		}
	}
}

func (q *Queue) executeJob(ctx context.Context, jobID string) {
	queuedJob, ok, err := q.markRunning(jobID)
	if err != nil {
		q.logger.Printf("persist running catalog scan %s: %v", jobID, err)
		return
	}
	if !ok {
		return
	}

	jobCtx := ctx
	cancel := func() {}
	if q.cfg.Timeout > 0 {
		jobCtx, cancel = context.WithTimeout(ctx, q.cfg.Timeout)
	}
	defer cancel()

	result, execErr := q.executor.ExecuteCatalogScan(jobCtx, queuedJob.Request)
	completedAt := q.now()

	q.mu.Lock()
	defer q.mu.Unlock()

	job, exists := q.jobs[jobID]
	if !exists {
		return
	}

	if execErr != nil {
		job.Result = nil
		job.Error = execErr.Error()
		job.CompletedAt = nil
		if job.Attempts < job.MaxAttempts {
			job.Status = StatusPending
			nextAttemptAt := completedAt.Add(q.retryDelay(job.Attempts))
			job.NextAttemptAt = &nextAttemptAt
			if err := q.saveJobLocked(*job); err != nil {
				q.logger.Printf("persist retryable catalog scan %s: %v", jobID, err)
				return
			}
			q.logger.Printf("catalog scan failed for %s, retrying attempt %d/%d: %v", queuedJob.Request.ImageName, job.Attempts, job.MaxAttempts, execErr)
			q.signalDispatch()
			return
		}

		job.Status = StatusFailed
		job.NextAttemptAt = nil
		job.CompletedAt = &completedAt
		delete(q.activeByScan, queuedJob.Request.TargetKey())
		if err := q.saveJobLocked(*job); err != nil {
			q.logger.Printf("persist failed catalog scan %s: %v", jobID, err)
			return
		}
		if err := q.pruneLocked(); err != nil {
			q.logger.Printf("prune catalog scan history after failure: %v", err)
		}
		q.logger.Printf("catalog scan failed for %s: %v", queuedJob.Request.ImageName, execErr)
		return
	}

	result.CompletedAt = completedAt
	job.Status = StatusSucceeded
	job.Result = &result
	job.Error = ""
	job.NextAttemptAt = nil
	job.CompletedAt = &completedAt
	delete(q.activeByScan, queuedJob.Request.TargetKey())
	if err := q.saveJobLocked(*job); err != nil {
		q.logger.Printf("persist completed catalog scan %s: %v", jobID, err)
		return
	}
	if err := q.pruneLocked(); err != nil {
		q.logger.Printf("prune catalog scan history after success: %v", err)
	}
}

func (q *Queue) markRunning(jobID string) (Job, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	job, exists := q.jobs[jobID]
	if !exists || job.Status != StatusPending {
		return Job{}, false, nil
	}

	startedAt := q.now()
	job.Status = StatusRunning
	job.StartedAt = &startedAt
	job.CompletedAt = nil
	job.NextAttemptAt = nil
	job.Error = ""
	job.Attempts++
	if job.MaxAttempts <= 0 {
		job.MaxAttempts = q.maxAttempts()
	}
	if err := q.saveJobLocked(*job); err != nil {
		return Job{}, false, err
	}
	return cloneJob(*job), true, nil
}

func (q *Queue) copyJobLocked(jobID string) Job {
	job, ok := q.jobs[jobID]
	if !ok {
		return Job{}
	}
	return cloneJob(*job)
}

func (q *Queue) loadPersistedJobs() error {
	jobs, err := q.store.List()
	if err != nil {
		return err
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	for _, job := range jobs {
		if job.MaxAttempts <= 0 {
			job.MaxAttempts = q.maxAttempts()
		}
		switch job.Status {
		case StatusPending:
		case StatusRunning:
			job.Status = StatusPending
			job.NextAttemptAt = nil
			job.CompletedAt = nil
		default:
			job.NextAttemptAt = nil
		}
		if err := q.saveJobLocked(job); err != nil {
			return err
		}
		jobCopy := job
		q.jobs[job.ID] = &jobCopy
		q.order = append(q.order, job.ID)
		if job.Status == StatusPending || job.Status == StatusRunning {
			q.activeByScan[job.Request.TargetKey()] = job.ID
		}
	}
	return q.pruneLocked()
}

func (q *Queue) saveJobLocked(job Job) error {
	if err := q.store.Save(job); err != nil {
		return err
	}
	jobCopy := job
	q.jobs[job.ID] = &jobCopy
	return nil
}

func (q *Queue) pruneLocked() error {
	for len(q.order) > q.cfg.JobHistoryLimit {
		pruned := false
		for index, jobID := range q.order {
			job, ok := q.jobs[jobID]
			if !ok {
				q.order = append(q.order[:index], q.order[index+1:]...)
				pruned = true
				break
			}
			if job.Status == StatusPending || job.Status == StatusRunning {
				continue
			}
			q.order = append(q.order[:index], q.order[index+1:]...)
			delete(q.jobs, jobID)
			delete(q.enqueued, jobID)
			if err := q.store.Delete(jobID); err != nil {
				return err
			}
			pruned = true
			break
		}
		if !pruned {
			return nil
		}
	}
	return nil
}

func (q *Queue) pendingCountLocked() int {
	count := 0
	for _, job := range q.jobs {
		if job.Status == StatusPending {
			count++
		}
	}
	return count
}

func (q *Queue) retryDelay(attempt int) time.Duration {
	delay := q.cfg.RetryBackoff
	for current := 1; current < attempt; current++ {
		if delay >= q.cfg.RetryBackoffMax {
			return q.cfg.RetryBackoffMax
		}
		delay *= 2
		if delay >= q.cfg.RetryBackoffMax {
			return q.cfg.RetryBackoffMax
		}
	}
	return delay
}

func (q *Queue) maxAttempts() int {
	return q.cfg.RetryLimit + 1
}

func (q *Queue) signalDispatch() {
	select {
	case q.dispatch <- struct{}{}:
	default:
	}
}

func cloneJob(job Job) Job {
	cloned := job
	if job.StartedAt != nil {
		startedAt := *job.StartedAt
		cloned.StartedAt = &startedAt
	}
	if job.CompletedAt != nil {
		completedAt := *job.CompletedAt
		cloned.CompletedAt = &completedAt
	}
	if job.NextAttemptAt != nil {
		nextAttemptAt := *job.NextAttemptAt
		cloned.NextAttemptAt = &nextAttemptAt
	}
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
