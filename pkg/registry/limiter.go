package registry

import (
	"context"
	"sync"
	"time"
)

type pullLimiter struct {
	minInterval time.Duration
	mu          sync.Mutex
	nextByHost  map[string]time.Time
}

func newPullLimiter(minInterval time.Duration) *pullLimiter {
	return &pullLimiter{
		minInterval: minInterval,
		nextByHost:  make(map[string]time.Time),
	}
}

func (l *pullLimiter) Wait(ctx context.Context, host string) error {
	if l == nil || l.minInterval <= 0 {
		return nil
	}

	for {
		now := time.Now()
		l.mu.Lock()
		next := l.nextByHost[host]
		if next.IsZero() || !next.After(now) {
			l.nextByHost[host] = now.Add(l.minInterval)
			l.mu.Unlock()
			return nil
		}
		waitFor := time.Until(next)
		l.mu.Unlock()

		timer := time.NewTimer(waitFor)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
