package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func keychainFromDockerConfig(path string) authn.Keychain {
	path = strings.TrimSpace(path)
	if path == "" {
		return authn.DefaultKeychain
	}
	return dockerConfigKeychain{path: path}
}

type dockerConfigKeychain struct {
	path string
}

func (k dockerConfigKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	return k.ResolveContext(context.Background(), target)
}

func (k dockerConfigKeychain) ResolveContext(_ context.Context, target authn.Resource) (authn.Authenticator, error) {
	cfg, err := loadDockerConfig(k.path)
	if err != nil {
		return nil, err
	}

	var authCfg types.AuthConfig
	for _, key := range []string{target.String(), target.RegistryStr()} {
		if key == name.DefaultRegistry {
			key = authn.DefaultAuthKey
		}
		authCfg, err = cfg.GetAuthConfig(key)
		if err != nil {
			return nil, fmt.Errorf("resolve docker config auth for %q: %w", key, err)
		}
		authCfg.ServerAddress = ""
		if authCfg != (types.AuthConfig{}) {
			break
		}
	}

	if authCfg == (types.AuthConfig{}) {
		return authn.Anonymous, nil
	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      authCfg.Username,
		Password:      authCfg.Password,
		Auth:          authCfg.Auth,
		IdentityToken: authCfg.IdentityToken,
		RegistryToken: authCfg.RegistryToken,
	}), nil
}

func loadDockerConfig(path string) (*configfile.ConfigFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat docker config: %w", err)
	}
	if info.IsDir() {
		return config.Load(path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open docker config: %w", err)
	}
	defer file.Close() //nolint:errcheck // file cleanup after parse

	cfg, err := config.LoadFromReader(file)
	if err != nil {
		return nil, fmt.Errorf("parse docker config %q: %w", path, err)
	}
	cfg.Filename = filepath.Base(path)
	return cfg, nil
}
