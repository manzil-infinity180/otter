package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type HTTPScorecardClient struct {
	baseURL     string
	showDetails bool
	client      *http.Client
}

func NewHTTPScorecardClient(cfg Config) ScorecardClient {
	if !cfg.ScorecardEnabled {
		return nil
	}

	return &HTTPScorecardClient{
		baseURL:     strings.TrimRight(cfg.ScorecardBaseURL, "/"),
		showDetails: cfg.ScorecardShowDetails,
		client: &http.Client{
			Timeout: cfg.ScorecardTimeout,
		},
	}
}

func (c *HTTPScorecardClient) Lookup(ctx context.Context, repository Repository) (ScorecardSummary, error) {
	if repository.Host != "github.com" {
		return ScorecardSummary{}, fmt.Errorf("scorecard only supports github.com repositories")
	}

	endpoint := fmt.Sprintf(
		"%s/projects/%s/%s/%s?show_details=%t",
		c.baseURL,
		url.PathEscape(repository.Host),
		url.PathEscape(repository.Owner),
		url.PathEscape(repository.Name),
		c.showDetails,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ScorecardSummary{}, fmt.Errorf("build scorecard request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	response, err := c.client.Do(req)
	if err != nil {
		return ScorecardSummary{}, fmt.Errorf("request scorecard: %w", err)
	}
	defer response.Body.Close() //nolint:errcheck // response body cleanup

	if response.StatusCode != http.StatusOK {
		return ScorecardSummary{}, fmt.Errorf("scorecard returned %s", response.Status)
	}

	var payload struct {
		Date   time.Time `json:"date"`
		Score  float64   `json:"score"`
		Checks []struct {
			Name          string  `json:"name"`
			Score         float64 `json:"score"`
			Reason        string  `json:"reason"`
			Documentation struct {
				URL string `json:"url"`
			} `json:"documentation"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return ScorecardSummary{}, fmt.Errorf("decode scorecard response: %w", err)
	}

	checks := make([]ScorecardCheck, 0, len(payload.Checks))
	for _, check := range payload.Checks {
		checks = append(checks, ScorecardCheck{
			Name:             strings.TrimSpace(check.Name),
			Score:            check.Score,
			Reason:           strings.TrimSpace(check.Reason),
			DocumentationURL: strings.TrimSpace(check.Documentation.URL),
		})
	}
	sort.Slice(checks, func(i, j int) bool {
		if checks[i].Score == checks[j].Score {
			return checks[i].Name < checks[j].Name
		}
		return checks[i].Score < checks[j].Score
	})

	return ScorecardSummary{
		Enabled:    true,
		Available:  true,
		Status:     statusFromNumericScore(payload.Score),
		Repository: repository.Repository,
		Score:      payload.Score,
		Date:       payload.Date.UTC(),
		RiskLevel:  riskLevel(payload.Score),
		Checks:     checks,
	}, nil
}

func statusFromNumericScore(value float64) string {
	switch {
	case value >= 8:
		return StatusPass
	case value >= 5:
		return StatusPartial
	default:
		return StatusFail
	}
}

func riskLevel(value float64) string {
	switch {
	case value >= 8:
		return "strong"
	case value >= 5:
		return "moderate"
	default:
		return "weak"
	}
}
