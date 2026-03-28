package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// OIDCProvider identifies the OIDC token source.
type OIDCProvider string

const (
	OIDCProviderGitHub OIDCProvider = "github"
	OIDCProviderGCP    OIDCProvider = "gcp"
	OIDCProviderAWS    OIDCProvider = "aws"
)

// OIDCTokenExchangeRequest contains the parameters for exchanging an OIDC token
// for short-lived registry credentials.
type OIDCTokenExchangeRequest struct {
	Provider  OIDCProvider
	Token     string // OIDC JWT token
	Registry  string // Target registry (e.g., ghcr.io, gcr.io)
	Audience  string // Optional audience override
}

// OIDCCredentials are short-lived credentials obtained via token exchange.
type OIDCCredentials struct {
	Username  string
	Password  string
	ExpiresAt time.Time
}

// ExchangeOIDCToken exchanges an OIDC token for registry credentials.
func ExchangeOIDCToken(ctx context.Context, req OIDCTokenExchangeRequest) (*OIDCCredentials, error) {
	switch req.Provider {
	case OIDCProviderGitHub:
		return exchangeGitHubOIDC(ctx, req)
	case OIDCProviderGCP:
		return exchangeGCPOIDC(ctx, req)
	case OIDCProviderAWS:
		return exchangeAWSOIDC(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported OIDC provider: %s", req.Provider)
	}
}

// DetectOIDCEnvironment checks if the current environment has OIDC tokens
// available (e.g., GitHub Actions, GKE workload identity).
func DetectOIDCEnvironment() (OIDCProvider, string, bool) {
	// GitHub Actions OIDC
	if tokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"); tokenURL != "" {
		if token := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); token != "" {
			return OIDCProviderGitHub, token, true
		}
	}

	// GCP Workload Identity (metadata server)
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" || isGCEEnvironment() {
		return OIDCProviderGCP, "", true
	}

	// AWS IRSA
	if os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "" {
		return OIDCProviderAWS, "", true
	}

	return "", "", false
}

func exchangeGitHubOIDC(ctx context.Context, req OIDCTokenExchangeRequest) (*OIDCCredentials, error) {
	tokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	bearerToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if tokenURL == "" || bearerToken == "" {
		return nil, fmt.Errorf("GitHub Actions OIDC environment not available")
	}

	audience := req.Audience
	if audience == "" {
		audience = "https://ghcr.io"
	}

	reqURL := fmt.Sprintf("%s&audience=%s", tokenURL, url.QueryEscape(audience))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	httpReq.Header.Set("Authorization", "bearer "+bearerToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OIDC token request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	// For ghcr.io, the OIDC token is used directly as a password with username "otter"
	return &OIDCCredentials{
		Username:  "otter",
		Password:  tokenResp.Value,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}, nil
}

func exchangeGCPOIDC(ctx context.Context, req OIDCTokenExchangeRequest) (*OIDCCredentials, error) {
	// Use GCP metadata server to get an access token
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create GCP metadata request: %w", err)
	}
	httpReq.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request GCP access token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCP metadata token request failed (status %d)", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode GCP token: %w", err)
	}

	return &OIDCCredentials{
		Username:  "oauth2accesstoken",
		Password:  tokenResp.AccessToken,
		ExpiresAt: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}, nil
}

func exchangeAWSOIDC(ctx context.Context, req OIDCTokenExchangeRequest) (*OIDCCredentials, error) {
	tokenFile := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if tokenFile == "" {
		return nil, fmt.Errorf("AWS_WEB_IDENTITY_TOKEN_FILE not set")
	}

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read AWS web identity token: %w", err)
	}

	// AWS ECR uses the web identity token for authentication.
	// The actual exchange with STS requires the AWS SDK, so we provide
	// the raw token for the caller to use with AWS ECR auth helpers.
	return &OIDCCredentials{
		Username:  "AWS",
		Password:  strings.TrimSpace(string(token)),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}, nil
}

func isGCEEnvironment() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://metadata.google.internal/")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.Header.Get("Metadata-Flavor") == "Google"
}
