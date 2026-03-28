package routes

import (
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultPerIPLimit = 10  // requests per minute per IP
	defaultGlobalLimit = 100 // requests per minute globally
)

type ipBucket struct {
	tokens    float64
	lastCheck time.Time
}

type rateLimiter struct {
	mu          sync.Mutex
	perIPLimit  float64
	globalLimit float64
	ipBuckets   map[string]*ipBucket
	globalBucket *ipBucket
}

func newRateLimiter(perIPLimit, globalLimit int) *rateLimiter {
	return &rateLimiter{
		perIPLimit:  float64(perIPLimit),
		globalLimit: float64(globalLimit),
		ipBuckets:   make(map[string]*ipBucket),
		globalBucket: &ipBucket{
			tokens:    float64(globalLimit),
			lastCheck: time.Now(),
		},
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Check global limit
	elapsed := now.Sub(rl.globalBucket.lastCheck).Seconds()
	rl.globalBucket.tokens += elapsed * (rl.globalLimit / 60.0)
	if rl.globalBucket.tokens > rl.globalLimit {
		rl.globalBucket.tokens = rl.globalLimit
	}
	rl.globalBucket.lastCheck = now

	if rl.globalBucket.tokens < 1 {
		return false
	}

	// Check per-IP limit
	bucket, ok := rl.ipBuckets[ip]
	if !ok {
		bucket = &ipBucket{
			tokens:    rl.perIPLimit,
			lastCheck: now,
		}
		rl.ipBuckets[ip] = bucket
	}

	elapsed = now.Sub(bucket.lastCheck).Seconds()
	bucket.tokens += elapsed * (rl.perIPLimit / 60.0)
	if bucket.tokens > rl.perIPLimit {
		bucket.tokens = rl.perIPLimit
	}
	bucket.lastCheck = now

	if bucket.tokens < 1 {
		return false
	}

	bucket.tokens--
	rl.globalBucket.tokens--
	return true
}

// RateLimitScans returns middleware that rate-limits scan endpoints.
// Limits are configurable via OTTER_RATE_LIMIT_SCANS_PER_MINUTE (per-IP)
// and OTTER_RATE_LIMIT_SCANS_GLOBAL (global).
func RateLimitScans() gin.HandlerFunc {
	perIP := defaultPerIPLimit
	global := defaultGlobalLimit

	if v := os.Getenv("OTTER_RATE_LIMIT_SCANS_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perIP = n
		}
	}
	if v := os.Getenv("OTTER_RATE_LIMIT_SCANS_GLOBAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			global = n
		}
	}

	limiter := newRateLimiter(perIP, global)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.allow(ip) {
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded, try again later",
			})
			return
		}
		c.Next()
	}
}
