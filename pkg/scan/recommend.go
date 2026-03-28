package scan

// BaseImageRecommendation suggests an alternative base image with fewer vulnerabilities.
type BaseImageRecommendation struct {
	CurrentImage     string `json:"current_image"`
	RecommendedImage string `json:"recommended_image"`
	Reason           string `json:"reason"`
	EstimatedReduction int  `json:"estimated_reduction_pct"`
}

// Known secure base image alternatives.
var secureAlternatives = map[string][]BaseImageRecommendation{
	"ubuntu": {
		{RecommendedImage: "cgr.dev/chainguard/wolfi-base:latest", Reason: "Minimal distroless image with significantly fewer CVEs", EstimatedReduction: 80},
		{RecommendedImage: "ubuntu:24.04", Reason: "Latest LTS with most recent security patches", EstimatedReduction: 30},
	},
	"debian": {
		{RecommendedImage: "cgr.dev/chainguard/wolfi-base:latest", Reason: "Minimal distroless image with significantly fewer CVEs", EstimatedReduction: 80},
		{RecommendedImage: "debian:bookworm-slim", Reason: "Slim variant removes unnecessary packages", EstimatedReduction: 40},
	},
	"alpine": {
		{RecommendedImage: "cgr.dev/chainguard/static:latest", Reason: "Zero-CVE static base for compiled binaries", EstimatedReduction: 95},
		{RecommendedImage: "alpine:3.20", Reason: "Latest Alpine with most recent security patches", EstimatedReduction: 20},
	},
	"node": {
		{RecommendedImage: "node:22-alpine", Reason: "Alpine-based Node.js image with minimal attack surface", EstimatedReduction: 70},
		{RecommendedImage: "cgr.dev/chainguard/node:latest", Reason: "Chainguard hardened Node.js image", EstimatedReduction: 85},
	},
	"python": {
		{RecommendedImage: "python:3.12-slim", Reason: "Slim variant removes build tools and docs", EstimatedReduction: 50},
		{RecommendedImage: "cgr.dev/chainguard/python:latest", Reason: "Chainguard hardened Python image", EstimatedReduction: 85},
	},
	"golang": {
		{RecommendedImage: "cgr.dev/chainguard/go:latest", Reason: "Chainguard hardened Go builder", EstimatedReduction: 80},
		{RecommendedImage: "golang:1.23-alpine", Reason: "Alpine-based Go with minimal attack surface", EstimatedReduction: 60},
	},
	"nginx": {
		{RecommendedImage: "cgr.dev/chainguard/nginx:latest", Reason: "Chainguard hardened Nginx with near-zero CVEs", EstimatedReduction: 90},
		{RecommendedImage: "nginx:alpine", Reason: "Alpine-based Nginx with smaller attack surface", EstimatedReduction: 60},
	},
}

// RecommendBaseImage suggests alternative base images for a given image reference.
func RecommendBaseImage(imageRef string) []BaseImageRecommendation {
	for prefix, recommendations := range secureAlternatives {
		if matchesImagePrefix(imageRef, prefix) {
			result := make([]BaseImageRecommendation, len(recommendations))
			for i, rec := range recommendations {
				rec.CurrentImage = imageRef
				result[i] = rec
			}
			return result
		}
	}
	return nil
}

func matchesImagePrefix(imageRef, prefix string) bool {
	// Match "python:3.11", "docker.io/library/python:latest", "python"
	for i := 0; i < len(imageRef); i++ {
		if imageRef[i] == '/' {
			// Check the part after the last slash
			rest := imageRef[i+1:]
			return matchesImagePrefix(rest, prefix)
		}
	}
	// Now imageRef is just "python:3.11" or "python"
	if len(imageRef) < len(prefix) {
		return false
	}
	if imageRef[:len(prefix)] != prefix {
		return false
	}
	if len(imageRef) == len(prefix) {
		return true
	}
	next := imageRef[len(prefix)]
	return next == ':' || next == '-'
}
