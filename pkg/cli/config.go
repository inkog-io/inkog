package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config stores persistent CLI configuration.
type Config struct {
	APIKey string `json:"api_key,omitempty"`
}

// ConfigDir returns the Inkog config directory (~/.inkog/), creating it if needed.
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".inkog")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func configFilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// GetSavedAPIKey reads the API key from ~/.inkog/config.json.
// Returns empty string if the file doesn't exist or can't be read.
func GetSavedAPIKey() string {
	path, err := configFilePath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return cfg.APIKey
}

// SaveAPIKey writes the API key to ~/.inkog/config.json with restrictive permissions.
func SaveAPIKey(key string) error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	cfg := Config{APIKey: key}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
