package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type LearningPath struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Difficulty  string           `json:"difficulty"` // beginner, intermediate, advanced
	Topics      []LearningTopic  `json:"topics"`
}

type LearningTopic struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Content     string `json:"content"`
	ScanExample string `json:"scan_example,omitempty"` // image to scan as exercise
}

var learningPaths = []LearningPath{
	{
		ID:          "sbom-fundamentals",
		Title:       "SBOM Fundamentals",
		Description: "Learn what Software Bills of Materials are and why they matter for supply chain security.",
		Difficulty:  "beginner",
		Topics: []LearningTopic{
			{
				ID:          "what-is-sbom",
				Title:       "What is an SBOM?",
				Description: "A Software Bill of Materials is a complete inventory of components in a software artifact.",
				Content:     "An SBOM lists every package, library, and dependency in a container image — like a nutritional label for software. Standards include CycloneDX and SPDX.",
				ScanExample: "alpine:latest",
			},
			{
				ID:          "sbom-formats",
				Title:       "CycloneDX vs SPDX",
				Description: "Compare the two major SBOM standards.",
				Content:     "CycloneDX focuses on security use cases with vulnerability correlation. SPDX originated from license compliance. Both are supported by Otter.",
			},
			{
				ID:          "reading-sbom",
				Title:       "Reading an SBOM",
				Description: "How to interpret SBOM package data.",
				Content:     "Each package entry has a name, version, type (npm, pip, apk), PURL, and licenses. Try scanning nginx:latest to see a real SBOM.",
				ScanExample: "nginx:latest",
			},
		},
	},
	{
		ID:          "vulnerability-scanning",
		Title:       "Vulnerability Scanning",
		Description: "Understand how vulnerability scanners find security issues in container images.",
		Difficulty:  "beginner",
		Topics: []LearningTopic{
			{
				ID:          "how-scanners-work",
				Title:       "How Vulnerability Scanners Work",
				Description: "Scanners match package versions against known vulnerability databases.",
				Content:     "Grype, Trivy, and OSV Scanner each query different vulnerability databases. Otter runs them in parallel and merges findings to reduce false negatives.",
			},
			{
				ID:          "severity-levels",
				Title:       "Understanding Severity Levels",
				Description: "CVSS scores, CRITICAL vs HIGH vs MEDIUM vs LOW.",
				Content:     "CVSS (Common Vulnerability Scoring System) rates vulnerabilities 0-10. Critical (9.0-10.0) means remote code execution or full system compromise. Not all criticals are equally urgent — EPSS scores predict real-world exploitation.",
			},
			{
				ID:          "scanner-disagreement",
				Title:       "When Scanners Disagree",
				Description: "Why different scanners find different vulnerabilities.",
				Content:     "Scanner disagreement is a signal, not noise. When Grype finds a CVE that Trivy misses (or vice versa), it often means the databases haven't synced. Otter's multi-scanner approach catches more real vulnerabilities.",
				ScanExample: "python:3.11",
			},
		},
	},
	{
		ID:          "supply-chain-security",
		Title:       "Container Supply Chain Security",
		Description: "Advanced topics in securing the container supply chain.",
		Difficulty:  "intermediate",
		Topics: []LearningTopic{
			{
				ID:          "attestations",
				Title:       "Build Attestations & Provenance",
				Description: "Verify where and how an image was built.",
				Content:     "SLSA provenance attestations prove an image was built by a specific CI system from specific source code. Cosign signatures add cryptographic verification. Otter discovers and displays these automatically.",
				ScanExample: "cgr.dev/chainguard/static:latest",
			},
			{
				ID:          "license-compliance",
				Title:       "License Compliance in Containers",
				Description: "Identify copyleft licenses that could affect your software.",
				Content:     "GPL and AGPL licenses require derivative works to be open-sourced. Otter's license compliance checker flags these in your SBOM packages, helping legal teams assess risk.",
			},
			{
				ID:          "vex-documents",
				Title:       "VEX: Vulnerability Exploitability eXchange",
				Description: "Not all vulnerabilities are exploitable in your context.",
				Content:     "VEX documents let vendors declare that a CVE doesn't affect their product, even though the vulnerable package is present. Otter supports importing VEX documents to suppress false positives.",
			},
		},
	},
}

func (h *ScanHandler) GetLearningPaths(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"paths": learningPaths,
	})
}

func (h *ScanHandler) GetLearningTopic(c *gin.Context) {
	pathID := c.Param("path_id")
	topicID := c.Param("topic_id")

	for _, path := range learningPaths {
		if path.ID == pathID {
			for _, topic := range path.Topics {
				if topic.ID == topicID {
					c.JSON(http.StatusOK, gin.H{
						"path":  path.ID,
						"topic": topic,
					})
					return
				}
			}
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "topic not found"})
}
