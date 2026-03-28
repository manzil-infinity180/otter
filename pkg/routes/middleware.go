package routes

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	defaultMaxBodySize int64 = 1 << 20 // 1MB default for general POST endpoints
)

// MaxBodySize returns a Gin middleware that limits the size of request bodies.
// It reads the limit from OTTER_MAX_REQUEST_BODY_SIZE (in bytes) or falls
// back to 1MB. Requests exceeding the limit receive a 413 response.
func MaxBodySize() gin.HandlerFunc {
	limit := defaultMaxBodySize
	if v := os.Getenv("OTTER_MAX_REQUEST_BODY_SIZE"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			limit = n
		}
	}

	return func(c *gin.Context) {
		if c.Request.Body == nil || c.Request.ContentLength == 0 {
			c.Next()
			return
		}

		if c.Request.ContentLength > limit {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large",
			})
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}
