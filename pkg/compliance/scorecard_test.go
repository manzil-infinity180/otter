package compliance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewHTTPScorecardClientDisabled(t *testing.T) {
	t.Parallel()

	if client := NewHTTPScorecardClient(Config{}); client != nil {
		t.Fatalf("NewHTTPScorecardClient() = %#v, want nil", client)
	}
}

func TestHTTPScorecardClientLookupParsesAndSortsChecks(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/projects/github.com/demo/project"; got != want {
			t.Fatalf("request path = %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("show_details"), "true"; got != want {
			t.Fatalf("show_details = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"date":"2026-03-14T00:00:00Z",
			"score":8.8,
			"checks":[
				{"name":"Pinned-Dependencies","score":8,"reason":"ok","documentation":{"url":"https://example.com/pinned"}},
				{"name":"Binary-Artifacts","score":2,"reason":"missing","documentation":{"url":"https://example.com/binary"}}
			]
		}`))
	}))
	t.Cleanup(server.Close)

	client := NewHTTPScorecardClient(Config{
		ScorecardEnabled:     true,
		ScorecardBaseURL:     server.URL,
		ScorecardShowDetails: true,
		ScorecardTimeout:     time.Second,
	}).(*HTTPScorecardClient)

	summary, err := client.Lookup(context.Background(), Repository{
		Host:       "github.com",
		Owner:      "demo",
		Name:       "project",
		Repository: "github.com/demo/project",
	})
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if got, want := summary.Status, StatusPass; got != want {
		t.Fatalf("summary.Status = %q, want %q", got, want)
	}
	if got, want := summary.RiskLevel, "strong"; got != want {
		t.Fatalf("summary.RiskLevel = %q, want %q", got, want)
	}
	if len(summary.Checks) != 2 || summary.Checks[0].Name != "Binary-Artifacts" {
		t.Fatalf("summary.Checks = %#v", summary.Checks)
	}
}

func TestHTTPScorecardClientLookupErrors(t *testing.T) {
	t.Parallel()

	client := &HTTPScorecardClient{baseURL: "http://example.com", client: &http.Client{Timeout: time.Second}}
	if _, err := client.Lookup(context.Background(), Repository{Host: "gitlab.com"}); err == nil {
		t.Fatal("expected Lookup() to reject unsupported hosts")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client.baseURL = server.URL
	if _, err := client.Lookup(context.Background(), Repository{
		Host:       "github.com",
		Owner:      "demo",
		Name:       "project",
		Repository: "github.com/demo/project",
	}); err == nil {
		t.Fatal("expected Lookup() to fail on non-200 response")
	}
}

func TestScorecardStatusHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		score      float64
		wantStatus string
		wantRisk   string
	}{
		{score: 9.1, wantStatus: StatusPass, wantRisk: "strong"},
		{score: 6.2, wantStatus: StatusPartial, wantRisk: "moderate"},
		{score: 3.5, wantStatus: StatusFail, wantRisk: "weak"},
	}

	for _, tt := range tests {
		if got := statusFromNumericScore(tt.score); got != tt.wantStatus {
			t.Fatalf("statusFromNumericScore(%v) = %q, want %q", tt.score, got, tt.wantStatus)
		}
		if got := riskLevel(tt.score); got != tt.wantRisk {
			t.Fatalf("riskLevel(%v) = %q, want %q", tt.score, got, tt.wantRisk)
		}
	}
}
