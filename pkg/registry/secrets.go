package registry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	registrySecretDirName     = "registry-secrets"
	registrySecretKeyFileName = "registry-secrets.key"
	registrySecretEnvVar      = "OTTER_REGISTRY_SECRET_KEY"
	registrySecretFileEnvVar  = "OTTER_REGISTRY_SECRET_KEY_FILE"
	secretEnvelopeVersion     = 1
)

type encryptedSecretStore struct {
	dir string
	key []byte
}

type credentialSecret struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

type secretEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func newEncryptedSecretStore(dataDir string) (*encryptedSecretStore, error) {
	secretDir := filepath.Join(dataDir, registrySecretDirName)
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		return nil, fmt.Errorf("create registry secret dir: %w", err)
	}

	key, err := loadRegistrySecretKey(dataDir)
	if err != nil {
		return nil, err
	}
	return &encryptedSecretStore{dir: secretDir, key: key}, nil
}

func (s *encryptedSecretStore) Write(registry string, secret credentialSecret) (string, error) {
	ref := s.secretRef(registry)
	data, err := s.encrypt(registry, secret)
	if err != nil {
		return "", err
	}

	path := filepath.Join(s.dir, ref)
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return "", fmt.Errorf("write registry secret temp file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("replace registry secret: %w", err)
	}
	return ref, nil
}

func (s *encryptedSecretStore) Read(registry, ref string) (credentialSecret, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, ref))
	if err != nil {
		return credentialSecret{}, err
	}
	return s.decrypt(registry, data)
}

func (s *encryptedSecretStore) Delete(ref string) error {
	if ref == "" {
		return nil
	}
	if err := os.Remove(filepath.Join(s.dir, ref)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove registry secret: %w", err)
	}
	return nil
}

func (s *encryptedSecretStore) secretPathForRegistry(registry string) string {
	return filepath.Join(s.dir, s.secretRef(registry))
}

func (s *encryptedSecretStore) secretRef(registry string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(registry))))
	return hex.EncodeToString(digest[:]) + ".json"
}

func (s *encryptedSecretStore) encrypt(registry string, secret credentialSecret) ([]byte, error) {
	aead, err := newSecretAEAD(s.key)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(secret)
	if err != nil {
		return nil, fmt.Errorf("encode registry secret: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate registry secret nonce: %w", err)
	}

	envelope := secretEnvelope{
		Version:    secretEnvelopeVersion,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, []byte(strings.TrimSpace(registry)))),
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode registry secret envelope: %w", err)
	}
	return data, nil
}

func (s *encryptedSecretStore) decrypt(registry string, data []byte) (credentialSecret, error) {
	var envelope secretEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return credentialSecret{}, fmt.Errorf("decode registry secret envelope: %w", err)
	}
	if envelope.Version != secretEnvelopeVersion {
		return credentialSecret{}, fmt.Errorf("unsupported registry secret version %d", envelope.Version)
	}

	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return credentialSecret{}, fmt.Errorf("decode registry secret nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return credentialSecret{}, fmt.Errorf("decode registry secret ciphertext: %w", err)
	}

	aead, err := newSecretAEAD(s.key)
	if err != nil {
		return credentialSecret{}, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(strings.TrimSpace(registry)))
	if err != nil {
		return credentialSecret{}, fmt.Errorf("decrypt registry secret: %w", err)
	}

	var secret credentialSecret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return credentialSecret{}, fmt.Errorf("decode registry secret payload: %w", err)
	}
	return secret, nil
}

func newSecretAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build registry secret cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build registry secret aead: %w", err)
	}
	return aead, nil
}

func loadRegistrySecretKey(dataDir string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(registrySecretFileEnvVar)); raw != "" {
		keyData, err := os.ReadFile(filepath.Clean(raw))
		if err != nil {
			return nil, fmt.Errorf("read registry secret key file: %w", err)
		}
		key, err := parseRegistrySecretKey(string(keyData))
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	if raw := strings.TrimSpace(os.Getenv(registrySecretEnvVar)); raw != "" {
		key, err := parseRegistrySecretKey(raw)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	path := filepath.Join(dataDir, registrySecretKeyFileName)
	keyData, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, err := parseRegistrySecretKey(string(keyData))
		if err != nil {
			return nil, err
		}
		return key, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read registry secret key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate registry secret key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, fmt.Errorf("write registry secret key: %w", err)
	}
	return key, nil
}

func parseRegistrySecretKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("registry secret key is empty")
	}

	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	return nil, fmt.Errorf("registry secret key must decode to 32 bytes from base64 or hex")
}
