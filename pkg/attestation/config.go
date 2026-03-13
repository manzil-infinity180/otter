package attestation

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	CosignBinary             string
	CosignTimeout            time.Duration
	CosignPublicKey          string
	CertificateIdentityRegex string
	OIDCIssuerRegex          string
}

func ConfigFromEnv() Config {
	binary := strings.TrimSpace(os.Getenv("OTTER_COSIGN_BINARY"))
	if binary == "" {
		binary = "cosign"
	}

	timeout := 2 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("OTTER_COSIGN_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	identityRegex := strings.TrimSpace(os.Getenv("OTTER_COSIGN_IDENTITY_REGEXP"))
	if identityRegex == "" {
		identityRegex = ".*"
	}

	issuerRegex := strings.TrimSpace(os.Getenv("OTTER_COSIGN_OIDC_ISSUER_REGEXP"))
	if issuerRegex == "" {
		issuerRegex = ".*"
	}

	return Config{
		CosignBinary:             binary,
		CosignTimeout:            timeout,
		CosignPublicKey:          strings.TrimSpace(os.Getenv("OTTER_COSIGN_PUBLIC_KEY")),
		CertificateIdentityRegex: identityRegex,
		OIDCIssuerRegex:          issuerRegex,
	}
}
