package registry

import (
	"testing"
)

func TestDetectOIDCEnvironmentGitHub(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.githubusercontent.com")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

	provider, token, ok := DetectOIDCEnvironment()
	if !ok {
		t.Fatal("expected OIDC environment to be detected")
	}
	if provider != OIDCProviderGitHub {
		t.Fatalf("expected GitHub provider, got %s", provider)
	}
	if token != "test-token" {
		t.Fatalf("expected test-token, got %s", token)
	}
}

func TestDetectOIDCEnvironmentAWS(t *testing.T) {
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/token")

	provider, _, ok := DetectOIDCEnvironment()
	if !ok {
		t.Fatal("expected OIDC environment to be detected")
	}
	if provider != OIDCProviderAWS {
		t.Fatalf("expected AWS provider, got %s", provider)
	}
}

func TestDetectOIDCEnvironmentNone(t *testing.T) {
	// Clear all OIDC-related env vars
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")

	_, _, ok := DetectOIDCEnvironment()
	if ok {
		t.Fatal("expected no OIDC environment")
	}
}

func TestExchangeOIDCTokenUnsupportedProvider(t *testing.T) {
	_, err := ExchangeOIDCToken(t.Context(), OIDCTokenExchangeRequest{
		Provider: "unknown",
	})
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}
