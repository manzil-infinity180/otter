package compliance

import "testing"

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("OTTER_SCORECARD_ENABLED", "off")
	t.Setenv("OTTER_SCORECARD_BASE_URL", "https://scorecard.internal")
	t.Setenv("OTTER_SCORECARD_TIMEOUT", "9s")
	t.Setenv("OTTER_SCORECARD_SHOW_DETAILS", "no")

	cfg := ConfigFromEnv()

	if cfg.ScorecardEnabled {
		t.Fatal("expected scorecard integration to be disabled")
	}
	if got, want := cfg.ScorecardBaseURL, "https://scorecard.internal"; got != want {
		t.Fatalf("ScorecardBaseURL = %q, want %q", got, want)
	}
	if got, want := cfg.ScorecardTimeout.String(), "9s"; got != want {
		t.Fatalf("ScorecardTimeout = %q, want %q", got, want)
	}
	if cfg.ScorecardShowDetails {
		t.Fatal("expected scorecard detail rendering to be disabled")
	}
}
