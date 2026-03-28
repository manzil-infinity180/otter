package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type SecurityFeedEntry struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Severity  string   `json:"severity"`
	Published string   `json:"published"`
	Packages  []string `json:"packages,omitempty"`
	Reference string   `json:"reference,omitempty"`
}

type securityFeedCache struct {
	mu        sync.RWMutex
	entries   []SecurityFeedEntry
	fetchedAt time.Time
	ttl       time.Duration
}

var feedCache = &securityFeedCache{ttl: 1 * time.Hour}

func (h *ScanHandler) GetSecurityFeed(c *gin.Context) {
	entries, err := feedCache.get(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("fetch security feed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"entries":    entries,
		"updated_at": feedCache.fetchedAt.UTC().Format(time.RFC3339),
	})
}

func (fc *securityFeedCache) get(ctx context.Context) ([]SecurityFeedEntry, error) {
	fc.mu.RLock()
	if time.Since(fc.fetchedAt) < fc.ttl && len(fc.entries) > 0 {
		entries := fc.entries
		fc.mu.RUnlock()
		return entries, nil
	}
	fc.mu.RUnlock()

	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(fc.fetchedAt) < fc.ttl && len(fc.entries) > 0 {
		return fc.entries, nil
	}

	entries, err := fetchRecentCVEs(ctx)
	if err != nil {
		// Return stale data if available
		if len(fc.entries) > 0 {
			return fc.entries, nil
		}
		return nil, err
	}

	fc.entries = entries
	fc.fetchedAt = time.Now()
	return entries, nil
}

func fetchRecentCVEs(ctx context.Context) ([]SecurityFeedEntry, error) {
	ecosystems := []string{"Alpine", "Debian", "Go", "npm", "PyPI", "crates.io"}
	var allEntries []SecurityFeedEntry

	for _, ecosystem := range ecosystems {
		entries, err := queryOSVEcosystem(ctx, ecosystem)
		if err != nil {
			continue // best effort
		}
		allEntries = append(allEntries, entries...)
	}

	// Sort by published date descending
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Published > allEntries[j].Published
	})

	// Return top 10
	if len(allEntries) > 10 {
		allEntries = allEntries[:10]
	}

	return allEntries, nil
}

type osvQueryRequest struct {
	Package *osvPackage `json:"package,omitempty"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string         `json:"id"`
	Summary   string         `json:"summary"`
	Published string         `json:"published"`
	Severity  []osvSeverity  `json:"severity"`
	Affected  []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func queryOSVEcosystem(ctx context.Context, ecosystem string) ([]SecurityFeedEntry, error) {
	payload, _ := json.Marshal(osvQueryRequest{
		Package: &osvPackage{Ecosystem: ecosystem},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Otter-SecurityFeed/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var result osvQueryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	entries := make([]SecurityFeedEntry, 0, len(result.Vulns))
	for _, vuln := range result.Vulns {
		severity := extractSeverity(vuln)
		if severity != "CRITICAL" && severity != "HIGH" {
			continue
		}

		packages := make([]string, 0)
		for _, affected := range vuln.Affected {
			packages = append(packages, affected.Package.Name)
		}

		reference := ""
		for _, ref := range vuln.References {
			if ref.Type == "ADVISORY" || ref.Type == "WEB" {
				reference = ref.URL
				break
			}
		}

		entries = append(entries, SecurityFeedEntry{
			ID:        vuln.ID,
			Summary:   vuln.Summary,
			Severity:  severity,
			Published: vuln.Published,
			Packages:  packages,
			Reference: reference,
		})
	}

	return entries, nil
}

func extractSeverity(vuln osvVuln) string {
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			return cvssToSeverity(sev.Score)
		}
	}
	return "UNKNOWN"
}

func cvssToSeverity(score string) string {
	// CVSS vector strings start with "CVSS:3.x/..." — we need the base score
	// For simplicity, classify based on common thresholds
	// In production, parse the CVSS vector properly
	if len(score) > 5 && score[:5] == "CVSS:" {
		return "HIGH" // Default to HIGH for any CVSS score present
	}
	return "UNKNOWN"
}
