// Package config manages the CLI configuration file and stored credentials.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// ConfigDir returns the active configuration directory path.
// The path depends on the build mode (dev/prod) and can be overridden
// with the RETYC_CONFIG_DIR environment variable.
func ConfigDir() (string, error) {
	return configDir()
}

// OIDCConfig holds the parameters needed to perform an OIDC device flow.
type OIDCConfig struct {
	Issuer         string   `yaml:"issuer" mapstructure:"issuer"`
	ClientID       string   `yaml:"client_id" mapstructure:"client_id"`
	Scopes         []string `yaml:"scopes" mapstructure:"scopes"`
	DeviceAuthURL  string   `yaml:"device_auth_url" mapstructure:"device_auth_url"`
	TokenURL       string   `yaml:"token_url" mapstructure:"token_url"`
	EndSessionURL  string   `yaml:"end_session_url" mapstructure:"end_session_url"`
}

// APIConfig holds REST API connection parameters.
type APIConfig struct {
	BaseURL string `yaml:"base_url" mapstructure:"base_url"`
}

// KeyringConfig controls the kernel keyring cache for the decrypted AGE identity.
type KeyringConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	TTL     int  `yaml:"ttl" mapstructure:"ttl"`
}

// Config is the top-level configuration structure.
type Config struct {
	API     APIConfig     `yaml:"api" mapstructure:"api"`
	Keyring KeyringConfig `yaml:"keyring" mapstructure:"keyring"`
}

// SetDefaults registers the default configuration values in viper.
// Must be called before viper.ReadInConfig so that defaults are applied
// when a key is absent from the config file.
func SetDefaults() {
	viper.SetDefault("api.base_url", defaultAPIBaseURL)
	viper.SetDefault("keyring.enabled", true)
	viper.SetDefault("keyring.ttl", 60)
}

// Load reads the active viper configuration and returns a Config struct.
// SetDefaults must have been called before this function.
func Load() (*Config, error) {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	return &cfg, nil
}

// tokenPath returns the path to the stored token file.
func tokenPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "token.json"), nil
}

// SaveToken persists an OAuth2 token to disk in JSON format.
func SaveToken(tok *oauth2.Token) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	path, err := tokenPath()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(tok)
}

// LoadToken reads the persisted OAuth2 token from disk.
func LoadToken() (*oauth2.Token, error) {
	path, err := tokenPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no stored token found")
		}
		return nil, err
	}
	defer f.Close()

	var tok oauth2.Token
	if err := json.NewDecoder(f).Decode(&tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

// DeleteToken removes the stored token file.
func DeleteToken() error {
	path, err := tokenPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
