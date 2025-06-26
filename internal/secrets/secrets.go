package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SecretManager manages encrypted secrets
type SecretManager struct {
	key []byte
}

// NewSecretManager creates a new secret manager
func NewSecretManager() (*SecretManager, error) {
	key, err := getOrCreateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	return &SecretManager{key: key}, nil
}

// getOrCreateKey gets the encryption key from environment or creates a new one
func getOrCreateKey() ([]byte, error) {
	// First try to get key from environment variable
	envKey := os.Getenv("MCP_GATEWAY_SECRET_KEY")
	if envKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(envKey)
		if err != nil {
			return nil, fmt.Errorf("invalid secret key in environment: %w", err)
		}
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("secret key must be 32 bytes")
		}
		return keyBytes, nil
	}

	// Try to read from key file
	keyPath := getKeyPath()
	if keyBytes, err := os.ReadFile(keyPath); err == nil {
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("stored key file has wrong size")
		}
		return keyBytes, nil
	}

	// Generate new key and save it
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Save key to file
	if err := saveKeyToFile(key, keyPath); err != nil {
		return nil, fmt.Errorf("failed to save encryption key: %w", err)
	}

	return key, nil
}

// getKeyPath returns the path where the encryption key should be stored
func getKeyPath() string {
	// Store in user's config directory or current directory
	if homeDir, err := os.UserHomeDir(); err == nil {
		configDir := filepath.Join(homeDir, ".config", "mcp-gateway")
		os.MkdirAll(configDir, 0700)
		return filepath.Join(configDir, "secret.key")
	}
	return "secret.key"
}

// saveKeyToFile saves the encryption key to a file with restricted permissions
func saveKeyToFile(key []byte, path string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	// Write key with restricted permissions
	return os.WriteFile(path, key, 0600)
}

// Encrypt encrypts a plaintext string and returns base64 encoded ciphertext
func (sm *SecretManager) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(sm.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	
	// Return base64 encoded result
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64 encoded ciphertext and returns plaintext
func (sm *SecretManager) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(sm.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// HashSecret creates a SHA256 hash of a secret for comparison purposes
func (sm *SecretManager) HashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// GenerateSecretID generates a unique ID for a secret based on its hash
func (sm *SecretManager) GenerateSecretID(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	// Return first 16 characters of the hash as ID
	return base64.StdEncoding.EncodeToString(hash[:])[:16]
}
