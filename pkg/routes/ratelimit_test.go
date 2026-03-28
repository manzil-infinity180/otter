package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRateLimiterAllowsWithinLimit(t *testing.T) {
	limiter := newRateLimiter(5, 100)
	for i := 0; i < 5; i++ {
		if !limiter.allow("192.168.1.1") {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}
}

func TestRateLimiterBlocksExcessPerIP(t *testing.T) {
	limiter := newRateLimiter(3, 100)

	for i := 0; i < 3; i++ {
		limiter.allow("192.168.1.1")
	}

	if limiter.allow("192.168.1.1") {
		t.Fatal("4th request should have been rate limited")
	}

	// Different IP should still be allowed
	if !limiter.allow("192.168.1.2") {
		t.Fatal("different IP should not be rate limited")
	}
}

func TestRateLimiterBlocksExcessGlobal(t *testing.T) {
	limiter := newRateLimiter(100, 3)

	for i := 0; i < 3; i++ {
		limiter.allow("192.168.1." + string(rune('1'+i)))
	}

	if limiter.allow("192.168.1.99") {
		t.Fatal("global limit should have been reached")
	}
}

func TestRateLimitScansMiddleware429(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Setenv("OTTER_RATE_LIMIT_SCANS_PER_MINUTE", "2")
	t.Setenv("OTTER_RATE_LIMIT_SCANS_GLOBAL", "100")

	router := gin.New()
	router.POST("/api/v1/scans", RateLimitScans(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("{}"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "60" {
		t.Fatalf("expected Retry-After: 60, got %q", w.Header().Get("Retry-After"))
	}
}
