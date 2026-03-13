package catalogscan

import (
	"context"
	"log"
	"time"
)

type Scheduler struct {
	queue  *Queue
	config Config
	logger *log.Logger
}

func NewScheduler(queue *Queue, config Config, logger *log.Logger) *Scheduler {
	if logger == nil {
		logger = log.Default()
	}
	return &Scheduler{
		queue:  queue,
		config: config,
		logger: logger,
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	if s == nil || s.queue == nil || !s.config.Enabled {
		return
	}

	go func() {
		s.enqueueConfiguredScans()

		ticker := time.NewTicker(s.config.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.enqueueConfiguredScans()
			}
		}
	}()
}

func (s *Scheduler) enqueueConfiguredScans() {
	for _, request := range DefaultRequests(s.config) {
		job, err := s.queue.Enqueue(request)
		if err != nil {
			s.logger.Printf("enqueue catalog scan for %s: %v", request.ImageName, err)
			continue
		}
		s.logger.Printf("queued catalog scan %s for %s (%s)", job.ID, request.ImageName, request.Trigger)
	}
}
