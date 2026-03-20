package compliance

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	ScorecardEnabled     bool
	ScorecardBaseURL     string
	ScorecardTimeout     time.Duration
	ScorecardShowDetails bool
}

func ConfigFromEnv() Config {
	enabled := true
	if raw := strings.TrimSpace(os.Getenv("OTTER_SCORECARD_ENABLED")); raw != "" {
		switch strings.ToLower(raw) {
		case "0", "false", "no", "off":
			enabled = false
		}
	}

	baseURL := strings.TrimSpace(os.Getenv("OTTER_SCORECARD_BASE_URL"))
	if baseURL == "" {
		baseURL = "https://api.scorecard.dev"
	}

	timeout := 3 * time.Second
	if raw := strings.TrimSpace(os.Getenv("OTTER_SCORECARD_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	showDetails := true
	if raw := strings.TrimSpace(os.Getenv("OTTER_SCORECARD_SHOW_DETAILS")); raw != "" {
		switch strings.ToLower(raw) {
		case "0", "false", "no", "off":
			showDetails = false
		}
	}

	return Config{
		ScorecardEnabled:     enabled,
		ScorecardBaseURL:     baseURL,
		ScorecardTimeout:     timeout,
		ScorecardShowDetails: showDetails,
	}
}
