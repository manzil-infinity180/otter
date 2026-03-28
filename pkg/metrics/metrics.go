package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ScansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "otter_scans_total",
		Help: "Total number of image scans by status.",
	}, []string{"status"})

	ScanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "otter_scan_duration_seconds",
		Help:    "Duration of image scans in seconds.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	})

	ScanQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "otter_scan_queue_depth",
		Help: "Number of scans currently queued.",
	})

	VulnerabilitiesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "otter_vulnerabilities_total",
		Help: "Total vulnerabilities found by severity.",
	}, []string{"severity"})

	ScannerAvailable = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "otter_scanner_available",
		Help: "Whether a scanner is available (1) or not (0).",
	}, []string{"scanner"})

	ImagesIndexedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "otter_images_indexed_total",
		Help: "Total number of images indexed.",
	})
)
