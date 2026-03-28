package scan

import (
	"testing"
)

func TestRecommendBaseImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"python:3.11", true},
		{"docker.io/library/python:latest", true},
		{"nginx:latest", true},
		{"alpine:3.18", true},
		{"node:22", true},
		{"mycompany/custom-app:v1", false},
		{"unknown-image", false},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			recs := RecommendBaseImage(tt.image)
			if tt.want && len(recs) == 0 {
				t.Fatalf("expected recommendations for %s", tt.image)
			}
			if !tt.want && len(recs) > 0 {
				t.Fatalf("expected no recommendations for %s, got %d", tt.image, len(recs))
			}
			for _, rec := range recs {
				if rec.CurrentImage != tt.image {
					t.Fatalf("expected current_image=%s, got %s", tt.image, rec.CurrentImage)
				}
				if rec.RecommendedImage == "" {
					t.Fatal("recommended_image should not be empty")
				}
			}
		})
	}
}
