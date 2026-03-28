package vulnindex

import (
	"testing"
	"time"
)

func TestAnalyzeTrendImproving(t *testing.T) {
	trend := []TrendPoint{
		{ObservedAt: time.Now().Add(-48 * time.Hour), Summary: Summary{Total: 20, BySeverity: map[string]int{"CRITICAL": 5}}},
		{ObservedAt: time.Now().Add(-24 * time.Hour), Summary: Summary{Total: 15, BySeverity: map[string]int{"CRITICAL": 3}}},
		{ObservedAt: time.Now(), Summary: Summary{Total: 10, BySeverity: map[string]int{"CRITICAL": 1}}},
	}
	analysis := AnalyzeTrend(trend)
	if analysis.Direction != "improving" {
		t.Fatalf("expected improving, got %s", analysis.Direction)
	}
	if analysis.TotalChange != -10 {
		t.Fatalf("expected -10 change, got %d", analysis.TotalChange)
	}
}

func TestAnalyzeTrendWorsening(t *testing.T) {
	trend := []TrendPoint{
		{ObservedAt: time.Now().Add(-24 * time.Hour), Summary: Summary{Total: 5, BySeverity: map[string]int{"CRITICAL": 0}}},
		{ObservedAt: time.Now(), Summary: Summary{Total: 15, BySeverity: map[string]int{"CRITICAL": 3}}},
	}
	analysis := AnalyzeTrend(trend)
	if analysis.Direction != "worsening" {
		t.Fatalf("expected worsening, got %s", analysis.Direction)
	}
}

func TestAnalyzeTrendStable(t *testing.T) {
	trend := []TrendPoint{
		{ObservedAt: time.Now().Add(-24 * time.Hour), Summary: Summary{Total: 10, BySeverity: map[string]int{}}},
		{ObservedAt: time.Now(), Summary: Summary{Total: 11, BySeverity: map[string]int{}}},
	}
	analysis := AnalyzeTrend(trend)
	if analysis.Direction != "stable" {
		t.Fatalf("expected stable, got %s", analysis.Direction)
	}
}

func TestAnalyzeTrendSinglePoint(t *testing.T) {
	trend := []TrendPoint{{ObservedAt: time.Now(), Summary: Summary{Total: 5}}}
	analysis := AnalyzeTrend(trend)
	if analysis.Direction != "stable" {
		t.Fatalf("expected stable for single point, got %s", analysis.Direction)
	}
}
