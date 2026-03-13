package attestation

import "testing"

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("OTTER_COSIGN_BINARY", "/usr/local/bin/cosign")
	t.Setenv("OTTER_COSIGN_TIMEOUT", "45s")
	t.Setenv("OTTER_COSIGN_PUBLIC_KEY", "/tmp/cosign.pub")
	t.Setenv("OTTER_COSIGN_IDENTITY_REGEXP", "^builder@example.com$")
	t.Setenv("OTTER_COSIGN_OIDC_ISSUER_REGEXP", "^https://token.actions.githubusercontent.com$")

	cfg := ConfigFromEnv()

	if got, want := cfg.CosignBinary, "/usr/local/bin/cosign"; got != want {
		t.Fatalf("CosignBinary = %q, want %q", got, want)
	}
	if got, want := cfg.CosignTimeout.String(), "45s"; got != want {
		t.Fatalf("CosignTimeout = %q, want %q", got, want)
	}
	if got, want := cfg.CosignPublicKey, "/tmp/cosign.pub"; got != want {
		t.Fatalf("CosignPublicKey = %q, want %q", got, want)
	}
	if got, want := cfg.CertificateIdentityRegex, "^builder@example.com$"; got != want {
		t.Fatalf("CertificateIdentityRegex = %q, want %q", got, want)
	}
	if got, want := cfg.OIDCIssuerRegex, "^https://token.actions.githubusercontent.com$"; got != want {
		t.Fatalf("OIDCIssuerRegex = %q, want %q", got, want)
	}
}
