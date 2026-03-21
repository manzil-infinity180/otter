package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/storage"
)

const (
	EnvEnabled    = "OTTER_AUTH_ENABLED"
	EnvTokens     = "OTTER_AUTH_TOKENS"
	EnvTokensFile = "OTTER_AUTH_TOKENS_FILE"

	HeaderAPIToken = "X-Otter-API-Token"
	CookieAPIToken = "otter_api_token"
)

const (
	contextKeyEnabled  = "otter.auth.enabled"
	contextKeyIdentity = "otter.auth.identity"
	contextKeyError    = "otter.auth.error"
)

var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrForbidden       = errors.New("forbidden")
)

type TokenRecord struct {
	Token   string   `json:"token"`
	Subject string   `json:"subject"`
	Orgs    []string `json:"orgs"`
	Admin   bool     `json:"admin"`
}

type Config struct {
	Enabled bool
	Tokens  []TokenRecord
}

type Identity struct {
	Subject string   `json:"subject"`
	Orgs    []string `json:"orgs,omitempty"`
	Admin   bool     `json:"admin"`
}

type Authenticator struct {
	enabled bool
	tokens  map[string]Identity
}

func ConfigFromEnv() (Config, error) {
	enabled := true
	if raw, ok := os.LookupEnv(EnvEnabled); ok {
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", EnvEnabled, err)
		}
		enabled = value
	}
	if !enabled {
		return Config{Enabled: false}, nil
	}

	var records []TokenRecord
	if path := strings.TrimSpace(os.Getenv(EnvTokensFile)); path != "" {
		payload, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read %s: %w", EnvTokensFile, err)
		}
		parsed, err := parseTokenRecords(payload)
		if err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", EnvTokensFile, err)
		}
		records = append(records, parsed...)
	}
	if raw := strings.TrimSpace(os.Getenv(EnvTokens)); raw != "" {
		parsed, err := parseTokenRecords([]byte(raw))
		if err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", EnvTokens, err)
		}
		records = append(records, parsed...)
	}

	return Config{
		Enabled: true,
		Tokens:  records,
	}, nil
}

func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if !cfg.Enabled {
		return &Authenticator{}, nil
	}
	if len(cfg.Tokens) == 0 {
		return nil, errors.New("authentication is enabled but no API tokens are configured")
	}

	tokens := make(map[string]Identity, len(cfg.Tokens))
	for index, record := range cfg.Tokens {
		token := strings.TrimSpace(record.Token)
		if token == "" {
			return nil, fmt.Errorf("token record %d is missing token", index)
		}
		if _, exists := tokens[token]; exists {
			return nil, fmt.Errorf("duplicate API token configured at index %d", index)
		}

		subject := strings.TrimSpace(record.Subject)
		if subject == "" {
			subject = fmt.Sprintf("token-%d", index+1)
		}

		orgs := make([]string, 0, len(record.Orgs))
		seen := make(map[string]struct{}, len(record.Orgs))
		for _, orgID := range record.Orgs {
			orgID = strings.TrimSpace(orgID)
			if orgID == "" {
				continue
			}
			if err := storage.ValidateSegment("org_id", orgID); err != nil {
				return nil, fmt.Errorf("token record %q: %w", subject, err)
			}
			if _, exists := seen[orgID]; exists {
				continue
			}
			seen[orgID] = struct{}{}
			orgs = append(orgs, orgID)
		}
		sort.Strings(orgs)

		if !record.Admin && len(orgs) == 0 {
			return nil, fmt.Errorf("token record %q must grant at least one org or be admin", subject)
		}

		tokens[token] = Identity{
			Subject: subject,
			Orgs:    orgs,
			Admin:   record.Admin,
		}
	}

	return &Authenticator{
		enabled: true,
		tokens:  tokens,
	}, nil
}

func NewDisabledAuthenticator() *Authenticator {
	return &Authenticator{}
}

func (a *Authenticator) Enabled() bool {
	return a != nil && a.enabled
}

func (a *Authenticator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		enabled := a != nil && a.enabled
		c.Set(contextKeyEnabled, enabled)
		if !enabled {
			c.Next()
			return
		}

		token, err := tokenFromRequest(c.Request)
		if err != nil {
			c.Set(contextKeyError, err.Error())
			c.Next()
			return
		}
		if token == "" {
			c.Next()
			return
		}

		identity, ok := a.tokens[token]
		if !ok {
			c.Set(contextKeyError, "invalid API token")
			c.Next()
			return
		}

		c.Set(contextKeyIdentity, identity)
		c.Next()
	}
}

func (a *Authenticator) RequireAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !Enabled(c) {
			c.Next()
			return
		}
		if _, ok := IdentityFromContext(c); !ok {
			AbortWithError(c, UnauthenticatedError(c))
			return
		}
		c.Next()
	}
}

func (a *Authenticator) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !Enabled(c) {
			c.Next()
			return
		}
		identity, ok := IdentityFromContext(c)
		if !ok {
			AbortWithError(c, UnauthenticatedError(c))
			return
		}
		if !identity.Admin {
			AbortWithError(c, fmt.Errorf("%w: admin access required", ErrForbidden))
			return
		}
		c.Next()
	}
}

func Enabled(c *gin.Context) bool {
	value, ok := c.Get(contextKeyEnabled)
	if !ok {
		return false
	}
	enabled, ok := value.(bool)
	return ok && enabled
}

func IdentityFromContext(c *gin.Context) (Identity, bool) {
	value, ok := c.Get(contextKeyIdentity)
	if !ok {
		return Identity{}, false
	}
	identity, ok := value.(Identity)
	return identity, ok
}

func RequireOrgAccess(c *gin.Context, orgID string) error {
	if !Enabled(c) {
		return nil
	}
	identity, ok := IdentityFromContext(c)
	if !ok {
		return UnauthenticatedError(c)
	}
	if identity.CanAccessOrg(orgID) {
		return nil
	}
	return fmt.Errorf("%w: org %q is not assigned to %q", ErrForbidden, orgID, identity.Subject)
}

func UnauthenticatedError(c *gin.Context) error {
	if !Enabled(c) {
		return nil
	}
	if value, ok := c.Get(contextKeyError); ok {
		if message, ok := value.(string); ok && strings.TrimSpace(message) != "" {
			return fmt.Errorf("%w: %s", ErrUnauthenticated, message)
		}
	}
	return ErrUnauthenticated
}

func AbortWithError(c *gin.Context, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, ErrUnauthenticated):
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case errors.Is(err, ErrForbidden):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
	default:
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}
}

func (i Identity) CanAccessOrg(orgID string) bool {
	if i.Admin {
		return true
	}
	for _, candidate := range i.Orgs {
		if candidate == orgID {
			return true
		}
	}
	return false
}

func parseTokenRecords(payload []byte) ([]TokenRecord, error) {
	var records []TokenRecord
	if err := json.Unmarshal(payload, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func tokenFromRequest(req *http.Request) (string, error) {
	authorization := strings.TrimSpace(req.Header.Get("Authorization"))
	if authorization != "" {
		parts := strings.SplitN(authorization, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			return "", errors.New("invalid Authorization header")
		}
		return strings.TrimSpace(parts[1]), nil
	}

	if token := strings.TrimSpace(req.Header.Get(HeaderAPIToken)); token != "" {
		return token, nil
	}

	cookie, err := req.Cookie(CookieAPIToken)
	switch {
	case err == nil:
		return strings.TrimSpace(cookie.Value), nil
	case errors.Is(err, http.ErrNoCookie):
		return "", nil
	default:
		return "", err
	}
}
