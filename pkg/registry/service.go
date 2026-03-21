package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1remote "github.com/google/go-containerregistry/pkg/v1/remote"
	v1transport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

type Manager struct {
	repo           Repository
	cfg            Config
	limiter        *pullLimiter
	tagCache       *remoteTagCache
	listRemoteTags func(context.Context, name.Repository, []v1remote.Option) ([]string, error)
	now            func() time.Time
}

func NewManager(repo Repository, cfg Config) *Manager {
	return &Manager{
		repo:     repo,
		cfg:      cfg,
		limiter:  newPullLimiter(cfg.MinPullInterval),
		tagCache: newRemoteTagCache(),
		listRemoteTags: func(ctx context.Context, repo name.Repository, options []v1remote.Option) ([]string, error) {
			return v1remote.List(repo, options...)
		},
		now: time.Now,
	}
}

func (m *Manager) Configure(ctx context.Context, req ConfigureRequest) (ConfigureResult, error) {
	record, err := validateConfigureRequest(req, m.cfg.DefaultDockerConfig)
	if err != nil {
		return ConfigureResult{}, err
	}
	if err := m.enforcePolicy(ctx, "configure", record); err != nil {
		return ConfigureResult{}, err
	}

	registryAPI, authSource, err := m.healthcheckRegistry(ctx, record)
	if err != nil {
		return ConfigureResult{}, err
	}

	now := time.Now().UTC()
	record.CreatedAt = now
	record.UpdatedAt = now
	saved, err := m.repo.Save(ctx, record)
	if err != nil {
		return ConfigureResult{}, fmt.Errorf("save registry configuration: %w", err)
	}

	return ConfigureResult{
		Summary:     summarize(saved),
		CheckedAt:   now,
		RegistryAPI: registryAPI,
		AuthSource:  authSource,
	}, nil
}

func (m *Manager) List(ctx context.Context) ([]Summary, error) {
	records, err := m.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list registry configurations: %w", err)
	}

	summaries := make([]Summary, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, summarize(record))
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Registry < summaries[j].Registry
	})
	return summaries, nil
}

func (m *Manager) PrepareImage(ctx context.Context, imageRef string) (ImageAccess, error) {
	ref, err := name.ParseReference(strings.TrimSpace(imageRef))
	if err != nil {
		return ImageAccess{}, fmt.Errorf("parse image reference: %w", err)
	}

	record, err := m.recordForRegistry(ctx, ref.Context().RegistryStr())
	if err != nil {
		return ImageAccess{}, err
	}
	if err := m.enforcePolicy(ctx, "prepare-image", record); err != nil {
		return ImageAccess{}, err
	}

	registryOptions, authSource, err := m.registryOptions(record)
	if err != nil {
		return ImageAccess{}, err
	}

	registryName := canonicalRegistry(record.Registry)
	if registryName == "" {
		registryName = canonicalRegistry(ref.Context().RegistryStr())
	}
	if err := m.limiter.Wait(ctx, registryName); err != nil {
		return ImageAccess{}, fmt.Errorf("wait for registry rate limit: %w", err)
	}

	refOptions := []name.Option{}
	if registryOptions != nil && registryOptions.InsecureUseHTTP {
		refOptions = append(refOptions, name.Insecure)
	}
	parsedRef, err := name.ParseReference(strings.TrimSpace(imageRef), refOptions...)
	if err != nil {
		return ImageAccess{}, fmt.Errorf("parse image reference for preflight: %w", err)
	}

	remoteOptions, err := remoteOptions(ctx, parsedRef, registryOptions)
	if err != nil {
		return ImageAccess{}, err
	}
	if _, err := v1remote.Head(parsedRef, remoteOptions...); err != nil {
		return ImageAccess{}, fmt.Errorf("registry preflight failed for %q: %w", imageRef, err)
	}

	return ImageAccess{
		Registry:        registryName,
		AuthSource:      authSource,
		RegistryOptions: registryOptions,
	}, nil
}

func (m *Manager) ListRepositoryTags(ctx context.Context, imageRef string) (RepositoryTagsResult, error) {
	ref, err := name.ParseReference(strings.TrimSpace(imageRef))
	if err != nil {
		return RepositoryTagsResult{}, fmt.Errorf("parse image reference: %w", err)
	}

	repository := ref.Context()
	record, err := m.recordForRegistry(ctx, repository.RegistryStr())
	if err != nil {
		return RepositoryTagsResult{}, err
	}
	if err := m.enforcePolicy(ctx, "list-repository-tags", record); err != nil {
		return RepositoryTagsResult{}, err
	}

	cacheKey := remoteTagCacheKey(repository, record)
	now := m.currentTime().UTC()
	if cached, ok := m.tagCache.Get(cacheKey, now); ok {
		return RepositoryTagsResult{
			Repository:     repository.Name(),
			Tags:           cached.Tags,
			Cached:         true,
			FetchedAt:      cached.FetchedAt,
			CacheExpiresAt: cached.ExpiresAt,
		}, nil
	}

	registryOptions, _, err := m.registryOptions(record)
	if err != nil {
		return RepositoryTagsResult{}, err
	}
	if err := m.limiter.Wait(ctx, canonicalRegistry(repository.RegistryStr())); err != nil {
		return RepositoryTagsResult{}, fmt.Errorf("wait for registry rate limit: %w", err)
	}

	options, err := remoteOptions(ctx, repository.Tag("latest"), registryOptions)
	if err != nil {
		return RepositoryTagsResult{}, err
	}
	tags, err := m.listRemoteTags(ctx, repository, options)
	if err != nil {
		return RepositoryTagsResult{}, fmt.Errorf("list repository tags for %q: %w", repository.Name(), err)
	}
	sort.Strings(tags)

	result := RepositoryTagsResult{
		Repository: repository.Name(),
		Tags:       append([]string(nil), tags...),
		FetchedAt:  now,
	}
	if expiresAt, ok := m.tagCache.Set(cacheKey, tags, now, m.cfg.RemoteTagCacheTTL); ok {
		result.CacheExpiresAt = expiresAt
	}
	return result, nil
}

func (m *Manager) recordForRegistry(ctx context.Context, registryName string) (Record, error) {
	registryName = canonicalRegistry(registryName)
	record, err := m.repo.Get(ctx, registryName)
	if err == nil {
		return record, nil
	}
	if errors.Is(err, ErrNotFound) {
		return Record{
			Registry:         registryName,
			AuthMode:         AuthModeDockerConfig,
			DockerConfigPath: strings.TrimSpace(m.cfg.DefaultDockerConfig),
		}, nil
	}
	return Record{}, fmt.Errorf("load registry configuration: %w", err)
}

func (m *Manager) healthcheckRegistry(ctx context.Context, record Record) (string, string, error) {
	timeout := m.cfg.HealthcheckTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	registryOptions, authSource, err := m.registryOptions(record)
	if err != nil {
		return "", "", err
	}
	registryName := canonicalRegistry(record.Registry)
	if err := m.limiter.Wait(checkCtx, registryName); err != nil {
		return "", "", fmt.Errorf("wait for registry rate limit: %w", err)
	}

	registry, scheme, err := parseRegistry(record.Registry, record.InsecureUseHTTP)
	if err != nil {
		return "", "", err
	}

	authenticator, hasAuth, err := resolveAuthenticator(checkCtx, registry, registryOptions)
	if err != nil {
		return "", "", fmt.Errorf("resolve registry authentication: %w", err)
	}
	transport, err := registryTransport(checkCtx, registry, authenticator, registryOptions)
	if err != nil {
		return "", "", err
	}

	request, err := http.NewRequestWithContext(checkCtx, http.MethodGet, scheme+"://"+registry.RegistryStr()+"/v2/", nil)
	if err != nil {
		return "", "", fmt.Errorf("create registry health request: %w", err)
	}

	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return "", "", fmt.Errorf("query registry api: %w", err)
	}
	defer response.Body.Close() //nolint:errcheck // response body cleanup

	switch {
	case response.StatusCode >= 200 && response.StatusCode < 400:
		return request.URL.String(), authSource, nil
	case response.StatusCode == http.StatusUnauthorized && !hasAuth:
		return "", "", fmt.Errorf("registry %q requires authentication", registryName)
	case response.StatusCode == http.StatusUnauthorized:
		return "", "", fmt.Errorf("registry %q rejected supplied credentials", registryName)
	default:
		return "", "", fmt.Errorf("registry %q healthcheck returned status %d", registryName, response.StatusCode)
	}
}

func (m *Manager) registryOptions(record Record) (*stereoscopeimage.RegistryOptions, string, error) {
	options := &stereoscopeimage.RegistryOptions{
		InsecureSkipTLSVerify: record.InsecureSkipTLSVerify,
		InsecureUseHTTP:       record.InsecureUseHTTP,
	}

	switch record.AuthMode {
	case AuthModeExplicit:
		options.Credentials = []stereoscopeimage.RegistryCredentials{{
			Authority: canonicalRegistry(record.Registry),
			Username:  record.Username,
			Password:  record.Password,
			Token:     record.Token,
		}}
		if record.Token != "" {
			return options, "explicit-token", nil
		}
		return options, "explicit-basic", nil
	case "", AuthModeDockerConfig:
		options.Keychain = keychainFromDockerConfig(firstNonEmpty(record.DockerConfigPath, m.cfg.DefaultDockerConfig))
		if strings.TrimSpace(record.DockerConfigPath) != "" {
			return options, "docker-config-path", nil
		}
		if strings.TrimSpace(m.cfg.DefaultDockerConfig) != "" {
			return options, "default-docker-config", nil
		}
		return options, "default-keychain", nil
	default:
		return nil, "", fmt.Errorf("unsupported registry auth_mode %q", record.AuthMode)
	}
}

func validateConfigureRequest(req ConfigureRequest, defaultDockerConfig string) (Record, error) {
	registryName, err := validateRegistryName(req.Registry)
	if err != nil {
		return Record{}, err
	}

	authMode := strings.TrimSpace(req.AuthMode)
	if authMode == "" {
		if strings.TrimSpace(req.Username) != "" || strings.TrimSpace(req.Password) != "" || strings.TrimSpace(req.Token) != "" {
			authMode = AuthModeExplicit
		} else {
			authMode = AuthModeDockerConfig
		}
	}

	record := Record{
		Registry:              registryName,
		AuthMode:              authMode,
		DockerConfigPath:      strings.TrimSpace(req.DockerConfigPath),
		Username:              strings.TrimSpace(req.Username),
		Password:              req.Password,
		Token:                 strings.TrimSpace(req.Token),
		InsecureSkipTLSVerify: req.InsecureSkipTLSVerify,
		InsecureUseHTTP:       req.InsecureUseHTTP,
	}

	switch authMode {
	case AuthModeExplicit:
		if record.Token != "" && (record.Username != "" || record.Password != "") {
			return Record{}, fmt.Errorf("explicit registry auth must use either token or username/password")
		}
		if record.Token == "" {
			if record.Username == "" || record.Password == "" {
				return Record{}, fmt.Errorf("explicit registry auth requires username/password or token")
			}
		}
	case AuthModeDockerConfig:
		record.Username = ""
		record.Password = ""
		record.Token = ""
		if record.DockerConfigPath == "" {
			record.DockerConfigPath = strings.TrimSpace(defaultDockerConfig)
		}
		if record.DockerConfigPath != "" {
			cleanPath := filepath.Clean(record.DockerConfigPath)
			if _, err := osStat(cleanPath); err != nil {
				return Record{}, fmt.Errorf("docker config path %q: %w", cleanPath, err)
			}
			record.DockerConfigPath = cleanPath
		}
	default:
		return Record{}, fmt.Errorf("unsupported auth_mode %q", authMode)
	}

	return record, nil
}

var osStat = func(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func validateRegistryName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("registry is required")
	}
	if strings.Contains(value, "://") || strings.Contains(value, "/") {
		return "", fmt.Errorf("registry must be a hostname, not a URL or repository path")
	}
	_, _, err := parseRegistry(value, false)
	if err != nil {
		return "", err
	}
	return canonicalRegistry(value), nil
}

func parseRegistry(value string, insecure bool) (name.Registry, string, error) {
	options := []name.Option{}
	scheme := "https"
	if insecure {
		options = append(options, name.Insecure)
		scheme = "http"
	}
	registry, err := name.NewRegistry(canonicalRegistry(value), options...)
	if err != nil {
		return name.Registry{}, "", fmt.Errorf("parse registry %q: %w", value, err)
	}
	return registry, scheme, nil
}

func remoteOptions(ctx context.Context, ref name.Reference, registryOptions *stereoscopeimage.RegistryOptions) ([]v1remote.Option, error) {
	options := []v1remote.Option{v1remote.WithContext(ctx)}

	registryName, _, err := parseRegistry(ref.Context().RegistryStr(), registryOptions != nil && registryOptions.InsecureUseHTTP)
	if err != nil {
		return nil, err
	}

	authenticator, _, err := resolveAuthenticator(ctx, registryName, registryOptions)
	if err != nil {
		return nil, fmt.Errorf("resolve registry authentication: %w", err)
	}
	switch {
	case authenticator != nil:
		options = append(options, v1remote.WithAuth(authenticator))
	case registryOptions != nil && registryOptions.Keychain != nil:
		options = append(options, v1remote.WithAuthFromKeychain(registryOptions.Keychain))
	default:
		options = append(options, v1remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	if registryOptions != nil {
		tlsConfig, err := registryOptions.TLSConfig(ref.Context().RegistryStr())
		if err != nil {
			return nil, fmt.Errorf("configure registry transport: %w", err)
		}
		if tlsConfig != nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = tlsConfig
			options = append(options, v1remote.WithTransport(transport))
		}
	}

	return options, nil
}

func registryTransport(ctx context.Context, registry name.Registry, authenticator authn.Authenticator, registryOptions *stereoscopeimage.RegistryOptions) (http.RoundTripper, error) {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	if registryOptions != nil {
		tlsConfig, err := registryOptions.TLSConfig(registry.RegistryStr())
		if err != nil {
			return nil, fmt.Errorf("configure registry tls: %w", err)
		}
		if tlsConfig != nil {
			baseTransport.TLSClientConfig = tlsConfig
		}
	}
	if authenticator == nil {
		authenticator = authn.Anonymous
	}
	transport, err := v1transport.NewWithContext(ctx, registry, authenticator, baseTransport, []string{})
	if err != nil {
		return nil, fmt.Errorf("build registry transport: %w", err)
	}
	return transport, nil
}

func resolveAuthenticator(ctx context.Context, registry name.Registry, registryOptions *stereoscopeimage.RegistryOptions) (authn.Authenticator, bool, error) {
	if registryOptions != nil {
		if authenticator := registryOptions.Authenticator(registry.RegistryStr()); authenticator != nil {
			if authenticator != authn.Anonymous {
				return authenticator, true, nil
			}
			return authenticator, false, nil
		}
		if registryOptions.Keychain != nil {
			authenticator, err := authn.Resolve(ctx, registryOptions.Keychain, registry)
			if err != nil {
				return nil, false, err
			}
			return authenticator, authenticator != authn.Anonymous, nil
		}
	}

	authenticator, err := authn.Resolve(ctx, authn.DefaultKeychain, registry)
	if err != nil {
		return nil, false, err
	}
	return authenticator, authenticator != authn.Anonymous, nil
}

func summarize(record Record) Summary {
	return Summary{
		Registry:              record.Registry,
		AuthMode:              record.AuthMode,
		HasCredentials:        record.Username != "" || record.Password != "" || record.Token != "",
		HasDockerConfigPath:   strings.TrimSpace(record.DockerConfigPath) != "",
		InsecureSkipTLSVerify: record.InsecureSkipTLSVerify,
		InsecureUseHTTP:       record.InsecureUseHTTP,
		CreatedAt:             record.CreatedAt,
		UpdatedAt:             record.UpdatedAt,
	}
}

func canonicalRegistry(value string) string {
	return NormalizeRegistry(value)
}

type remoteTagCache struct {
	mu      sync.RWMutex
	entries map[string]remoteTagCacheEntry
}

type remoteTagCacheEntry struct {
	Tags      []string
	FetchedAt time.Time
	ExpiresAt time.Time
}

func newRemoteTagCache() *remoteTagCache {
	return &remoteTagCache{entries: make(map[string]remoteTagCacheEntry)}
}

func (c *remoteTagCache) Get(key string, now time.Time) (remoteTagCacheEntry, bool) {
	if c == nil {
		return remoteTagCacheEntry{}, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return remoteTagCacheEntry{}, false
	}
	if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return remoteTagCacheEntry{}, false
	}

	entry.Tags = append([]string(nil), entry.Tags...)
	return entry, true
}

func (c *remoteTagCache) Set(key string, tags []string, now time.Time, ttl time.Duration) (time.Time, bool) {
	if c == nil || ttl <= 0 {
		return time.Time{}, false
	}

	entry := remoteTagCacheEntry{
		Tags:      append([]string(nil), tags...),
		FetchedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
	return entry.ExpiresAt, true
}

func remoteTagCacheKey(repository name.Repository, record Record) string {
	return strings.Join([]string{
		repository.Name(),
		record.AuthMode,
		record.DockerConfigPath,
		fmt.Sprintf("%t", record.InsecureUseHTTP),
		fmt.Sprintf("%t", record.InsecureSkipTLSVerify),
		record.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}, "|")
}

func (m *Manager) currentTime() time.Time {
	if m != nil && m.now != nil {
		return m.now()
	}
	return time.Now()
}

func NormalizeRegistry(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "docker.io", "registry-1.docker.io", "index.docker.io":
		return "index.docker.io"
	default:
		return value
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
