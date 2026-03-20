package registry

import (
	"context"
	"errors"
	"time"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
)

const (
	AuthModeDockerConfig = "docker_config"
	AuthModeExplicit     = "explicit"
)

var ErrNotFound = errors.New("registry configuration not found")

type Record struct {
	Registry              string    `json:"registry"`
	AuthMode              string    `json:"auth_mode"`
	DockerConfigPath      string    `json:"docker_config_path,omitempty"`
	Username              string    `json:"username,omitempty"`
	Password              string    `json:"password,omitempty"`
	Token                 string    `json:"token,omitempty"`
	InsecureSkipTLSVerify bool      `json:"insecure_skip_tls_verify,omitempty"`
	InsecureUseHTTP       bool      `json:"insecure_use_http,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type Summary struct {
	Registry              string    `json:"registry"`
	AuthMode              string    `json:"auth_mode"`
	HasCredentials        bool      `json:"has_credentials"`
	HasDockerConfigPath   bool      `json:"has_docker_config_path"`
	InsecureSkipTLSVerify bool      `json:"insecure_skip_tls_verify,omitempty"`
	InsecureUseHTTP       bool      `json:"insecure_use_http,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type ConfigureRequest struct {
	Registry              string `json:"registry"`
	AuthMode              string `json:"auth_mode"`
	DockerConfigPath      string `json:"docker_config_path"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	Token                 string `json:"token"`
	InsecureSkipTLSVerify bool   `json:"insecure_skip_tls_verify"`
	InsecureUseHTTP       bool   `json:"insecure_use_http"`
}

type ConfigureResult struct {
	Summary     Summary   `json:"summary"`
	CheckedAt   time.Time `json:"checked_at"`
	RegistryAPI string    `json:"registry_api"`
	AuthSource  string    `json:"auth_source"`
}

type ImageAccess struct {
	Registry        string
	AuthSource      string
	RegistryOptions *stereoscopeimage.RegistryOptions
}

type Service interface {
	Configure(context.Context, ConfigureRequest) (ConfigureResult, error)
	List(context.Context) ([]Summary, error)
	PrepareImage(context.Context, string) (ImageAccess, error)
	ListRepositoryTags(context.Context, string) ([]string, error)
}

type Repository interface {
	Save(context.Context, Record) (Record, error)
	Get(context.Context, string) (Record, error)
	List(context.Context) ([]Record, error)
}
