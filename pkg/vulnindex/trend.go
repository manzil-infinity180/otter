package vulnindex

// TrendAnalysis provides computed insights from vulnerability trend data.
type TrendAnalysis struct {
	Points       []TrendPoint `json:"points"`
	Direction    string       `json:"direction"`     // "improving", "worsening", "stable"
	TotalChange  int          `json:"total_change"`  // delta between first and last
	CriticalDelta int        `json:"critical_delta"` // change in critical count
}

// AnalyzeTrend computes trend direction and deltas from trend points.
func AnalyzeTrend(trend []TrendPoint) TrendAnalysis {
	analysis := TrendAnalysis{
		Points:    trend,
		Direction: "stable",
	}

	if len(trend) < 2 {
		return analysis
	}

	first := trend[0].Summary
	last := trend[len(trend)-1].Summary

	analysis.TotalChange = last.Total - first.Total
	analysis.CriticalDelta = last.BySeverity["CRITICAL"] - first.BySeverity["CRITICAL"]

	if analysis.TotalChange < -2 {
		analysis.Direction = "improving"
	} else if analysis.TotalChange > 2 {
		analysis.Direction = "worsening"
	}

	return analysis
}
