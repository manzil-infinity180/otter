package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type LocalRepository struct {
	path    string
	mu      sync.Mutex
	secrets *encryptedSecretStore
}

func NewLocalRepository(dataDir string) (*LocalRepository, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create registry data dir: %w", err)
	}
	secrets, err := newEncryptedSecretStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &LocalRepository{
		path:    filepath.Join(dataDir, "registries.json"),
		secrets: secrets,
	}, nil
}

func (r *LocalRepository) Save(_ context.Context, record Record) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.load()
	if err != nil {
		return Record{}, err
	}
	state, err = r.migrateLegacyState(state)
	if err != nil {
		return Record{}, err
	}

	updated := false
	storedRecord := storedRecordFromRecord(record)
	if hasStoredCredentials(record) {
		secretRef, err := r.secrets.Write(record.Registry, credentialSecret{
			Username: record.Username,
			Password: record.Password,
			Token:    record.Token,
		})
		if err != nil {
			return Record{}, fmt.Errorf("store registry secret: %w", err)
		}
		storedRecord.SecretRef = secretRef
		storedRecord.HasCredentials = true
	}

	var previousSecretRef string
	for idx := range state.Registries {
		if state.Registries[idx].Registry != record.Registry {
			continue
		}
		record.CreatedAt = state.Registries[idx].CreatedAt
		storedRecord.CreatedAt = record.CreatedAt
		previousSecretRef = state.Registries[idx].SecretRef
		state.Registries[idx] = storedRecord
		updated = true
		break
	}
	if !updated {
		state.Registries = append(state.Registries, storedRecord)
	}

	sort.Slice(state.Registries, func(i, j int) bool {
		return state.Registries[i].Registry < state.Registries[j].Registry
	})

	if err := r.store(state); err != nil {
		return Record{}, err
	}

	if previousSecretRef != "" && previousSecretRef != storedRecord.SecretRef {
		if err := r.secrets.Delete(previousSecretRef); err != nil {
			return Record{}, fmt.Errorf("delete registry secret: %w", err)
		}
	}
	return record, nil
}

func (r *LocalRepository) Get(_ context.Context, registry string) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.load()
	if err != nil {
		return Record{}, err
	}
	state, err = r.migrateLegacyState(state)
	if err != nil {
		return Record{}, err
	}

	for _, stored := range state.Registries {
		if stored.Registry == registry {
			return r.recordFromStored(stored)
		}
	}
	return Record{}, ErrNotFound
}

func (r *LocalRepository) List(_ context.Context) ([]Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.load()
	if err != nil {
		return nil, err
	}
	state, err = r.migrateLegacyState(state)
	if err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(state.Registries))
	for _, stored := range state.Registries {
		record, err := r.recordFromStored(stored)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

type localState struct {
	Registries []storedRecord `json:"registries"`
}

type storedRecord struct {
	Registry              string    `json:"registry"`
	AuthMode              string    `json:"auth_mode"`
	DockerConfigPath      string    `json:"docker_config_path,omitempty"`
	InsecureSkipTLSVerify bool      `json:"insecure_skip_tls_verify,omitempty"`
	InsecureUseHTTP       bool      `json:"insecure_use_http,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	SecretRef             string    `json:"secret_ref,omitempty"`
	HasCredentials        bool      `json:"has_credentials,omitempty"`

	// Legacy fields remain readable so plaintext registries.json files can be migrated in place.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

func (r *LocalRepository) load() (localState, error) {
	raw, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return localState{}, nil
		}
		return localState{}, fmt.Errorf("read registry repository: %w", err)
	}

	var state localState
	if err := json.Unmarshal(raw, &state); err != nil {
		return localState{}, fmt.Errorf("decode registry repository: %w", err)
	}
	return state, nil
}

func (r *LocalRepository) migrateLegacyState(state localState) (localState, error) {
	changed := false
	for idx := range state.Registries {
		migrated, wasChanged, err := r.migrateLegacyRecord(state.Registries[idx])
		if err != nil {
			return localState{}, err
		}
		if wasChanged {
			state.Registries[idx] = migrated
			changed = true
		}
	}
	if !changed {
		return state, nil
	}
	if err := r.store(state); err != nil {
		return localState{}, err
	}
	return state, nil
}

func (r *LocalRepository) migrateLegacyRecord(record storedRecord) (storedRecord, bool, error) {
	if !hasLegacyCredentials(record) {
		return record, false, nil
	}

	if record.AuthMode == AuthModeExplicit || record.AuthMode == "" {
		secretRef, err := r.secrets.Write(record.Registry, credentialSecret{
			Username: record.Username,
			Password: record.Password,
			Token:    record.Token,
		})
		if err != nil {
			return storedRecord{}, false, fmt.Errorf("migrate registry secret: %w", err)
		}
		record.SecretRef = secretRef
		record.HasCredentials = true
	}

	record.Username = ""
	record.Password = ""
	record.Token = ""
	return record, true, nil
}

func (r *LocalRepository) recordFromStored(stored storedRecord) (Record, error) {
	record := Record{
		Registry:              stored.Registry,
		AuthMode:              stored.AuthMode,
		DockerConfigPath:      stored.DockerConfigPath,
		InsecureSkipTLSVerify: stored.InsecureSkipTLSVerify,
		InsecureUseHTTP:       stored.InsecureUseHTTP,
		CreatedAt:             stored.CreatedAt,
		UpdatedAt:             stored.UpdatedAt,
		Username:              stored.Username,
		Password:              stored.Password,
		Token:                 stored.Token,
	}

	if stored.SecretRef == "" {
		if stored.HasCredentials && (stored.AuthMode == AuthModeExplicit || stored.AuthMode == "") {
			return Record{}, fmt.Errorf("registry %q credentials are missing secret storage", stored.Registry)
		}
		return record, nil
	}

	secret, err := r.secrets.Read(stored.Registry, stored.SecretRef)
	if err != nil {
		return Record{}, fmt.Errorf("read registry secret for %q: %w", stored.Registry, err)
	}
	record.Username = secret.Username
	record.Password = secret.Password
	record.Token = secret.Token
	return record, nil
}

func storedRecordFromRecord(record Record) storedRecord {
	return storedRecord{
		Registry:              record.Registry,
		AuthMode:              record.AuthMode,
		DockerConfigPath:      record.DockerConfigPath,
		InsecureSkipTLSVerify: record.InsecureSkipTLSVerify,
		InsecureUseHTTP:       record.InsecureUseHTTP,
		CreatedAt:             record.CreatedAt,
		UpdatedAt:             record.UpdatedAt,
	}
}

func hasStoredCredentials(record Record) bool {
	return strings.TrimSpace(record.Username) != "" || record.Password != "" || strings.TrimSpace(record.Token) != ""
}

func hasLegacyCredentials(record storedRecord) bool {
	return strings.TrimSpace(record.Username) != "" || record.Password != "" || strings.TrimSpace(record.Token) != ""
}

func (r *LocalRepository) store(state localState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode registry repository: %w", err)
	}

	tempPath := r.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return fmt.Errorf("write registry repository temp file: %w", err)
	}
	if err := os.Rename(tempPath, r.path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("replace registry repository: %w", err)
	}
	return nil
}
