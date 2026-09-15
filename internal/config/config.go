// Package config manages the CLI configuration file and stored credentials.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	Issuer        string   `yaml:"issuer" mapstructure:"issuer"`
	ClientID      string   `yaml:"client_id" mapstructure:"client_id"`
	Scopes        []string `yaml:"scopes" mapstructure:"scopes"`
	DeviceAuthURL string   `yaml:"device_auth_url" mapstructure:"device_auth_url"`
	TokenURL      string   `yaml:"token_url" mapstructure:"token_url"`
	EndSessionURL string   `yaml:"end_session_url" mapstructure:"end_session_url"`
}

// APIConfig holds REST API connection parameters.
type APIConfig struct {
	BaseURL     string            `yaml:"base_url" mapstructure:"base_url"`
	Concurrency ConcurrencyConfig `yaml:"concurrency" mapstructure:"concurrency"`
}

// DefaultConcurrency is the default of every api.concurrency.* key.
const DefaultConcurrency = 4

// MaxConcurrency is the largest value every api.concurrency.* key accepts.
// Higher would flood the API — well before HTTP/2's 250 streams per
// connection, one request per page or per chunk is already a lot — and a
// download holds up to twice its value in decrypted 8 MB chunks.
const MaxConcurrency = 32

// ConcurrencyConfig bounds the API requests a single operation runs at once.
// The API is served over HTTP/2, so they share one multiplexed connection:
// these values bound the load put on the backend, not a connection pool.
type ConcurrencyConfig struct {
	// List is the listing pages fetched at once after the first.
	List int `yaml:"list" mapstructure:"list"`
	// Upload is the chunks uploaded at once per file.
	Upload int `yaml:"upload" mapstructure:"upload"`
	// Download is the chunks downloaded at once per file.
	Download int `yaml:"download" mapstructure:"download"`
}

// KeyringConfig controls the kernel keyring cache for the decrypted AGE identity.
type KeyringConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	TTL     int  `yaml:"ttl" mapstructure:"ttl"`
}

// AdminConfig holds the admin (organization public API) parameters.
// The API key authenticates as a bearer token; the private key file holds the
// organization AGE identity, kept outside the platform.
type AdminConfig struct {
	APIKey         string `yaml:"api_key" mapstructure:"api_key"`
	PrivateKeyFile string `yaml:"private_key_file" mapstructure:"private_key_file"`
	BaseURL        string `yaml:"base_url" mapstructure:"base_url"`
}

// WebdavMetricsConfig controls the observability listener of `webdav serve`
// (Prometheus metrics and health probes). An empty address disables it.
// Runtime toggles the go_* and process_* collectors on /metrics: a parent
// process that aggregates several instances and already exposes its own
// runtime metrics turns it off. Labels are constant "key=value" pairs added
// to every series, so such a parent can tell its instances apart.
type WebdavMetricsConfig struct {
	Addr    string   `yaml:"addr" mapstructure:"addr"`
	Runtime bool     `yaml:"runtime" mapstructure:"runtime"`
	Labels  []string `yaml:"labels" mapstructure:"labels"`
}

// WebdavConfig holds the `webdav serve` settings. Addr is the host:port the
// server binds; loopback by default since the tree is served in cleartext.
type WebdavConfig struct {
	Addr    string              `yaml:"addr" mapstructure:"addr"`
	Metrics WebdavMetricsConfig `yaml:"metrics" mapstructure:"metrics"`
}

// Config is the top-level configuration structure.
type Config struct {
	API     APIConfig     `yaml:"api" mapstructure:"api"`
	Keyring KeyringConfig `yaml:"keyring" mapstructure:"keyring"`
	Admin   AdminConfig   `yaml:"admin" mapstructure:"admin"`
	Webdav  WebdavConfig  `yaml:"webdav" mapstructure:"webdav"`
}

// defaultWebdavAddr is the bind address of `webdav serve`: local only, the
// WebDAV tree is served in cleartext.
const defaultWebdavAddr = "127.0.0.1:8888"

// envPrefix is the prefix of every environment variable that maps to a
// configuration key: the key "a.b" is read from RETYC_A_B.
//
// The prefix is not cosmetic. Without it, viper.AutomaticEnv resolved
// "insecure" from a bare INSECURE variable, so an unrelated environment
// variable could disable TLS certificate verification.
const envPrefix = "RETYC"

// SetDefaults registers the default configuration values in viper and binds
// the environment. Must be called before viper.ReadInConfig so that defaults
// are applied when a key is absent from the config file.
//
// Every key registered here is settable from the environment as
// RETYC_<KEY_WITH_UNDERSCORES>. Secrets are deliberately not registered here:
// see env.go.
func SetDefaults() {
	viper.SetDefault("api.base_url", defaultAPIBaseURL)
	viper.SetDefault("api.concurrency.list", DefaultConcurrency)
	viper.SetDefault("api.concurrency.upload", DefaultConcurrency)
	viper.SetDefault("api.concurrency.download", DefaultConcurrency)
	// Dev builds only (see cmd/insecure_dev.go). Registered unconditionally so
	// that the key appears in viper.AllKeys() and stays documented.
	viper.SetDefault("insecure", false)
	viper.SetDefault("keyring.enabled", true)
	viper.SetDefault("keyring.ttl", 60)
	viper.SetDefault("admin.base_url", "")
	viper.SetDefault("admin.api_key", "")
	viper.SetDefault("admin.private_key_file", "")
	viper.SetDefault("webdav.addr", defaultWebdavAddr)
	// Empty means no metrics/probes listener (see cmd/webdav_metrics.go).
	viper.SetDefault("webdav.metrics.addr", "")
	viper.SetDefault("webdav.metrics.runtime", true)
	// "key=value" items; from the environment, separated by spaces.
	viper.SetDefault("webdav.metrics.labels", []string{})

	viper.SetEnvPrefix(envPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
}

// Load reads the active viper configuration and returns a Config struct.
// SetDefaults must have been called before this function.
func Load() (*Config, error) {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	// Unmarshal keeps an environment value as a single item; GetStringSlice
	// splits it on spaces, which is the documented environment syntax.
	cfg.Webdav.Metrics.Labels = viper.GetStringSlice("webdav.metrics.labels")

	// A bound below 1 leaves the workers without a single slot, and one above
	// MaxConcurrency is more than the API or this process should take on.
	for _, c := range []struct {
		key   string
		value int
	}{
		{"api.concurrency.list", cfg.API.Concurrency.List},
		{"api.concurrency.upload", cfg.API.Concurrency.Upload},
		{"api.concurrency.download", cfg.API.Concurrency.Download},
	} {
		if c.value < 1 || c.value > MaxConcurrency {
			return nil, fmt.Errorf("%s must be between 1 and %d, got %d", c.key, MaxConcurrency, c.value)
		}
	}

	return &cfg, nil
}

// AdminBaseURL returns the admin API base URL. When not explicitly configured,
// it is derived from the member API base URL by appending the /v1 prefix.
func (c *Config) AdminBaseURL() string {
	if c.Admin.BaseURL != "" {
		return strings.TrimRight(c.Admin.BaseURL, "/")
	}

	return strings.TrimRight(c.API.BaseURL, "/") + "/v1"
}

// TokenPath returns the path to the stored token file.
func TokenPath() (string, error) {
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

	path, err := TokenPath()
	if err != nil {
		return err
	}

	//nolint:gosec // G304: path is computed internally from configDir
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	return json.NewEncoder(f).Encode(tok) //nolint:gosec // G117: token storage is intentional
}

// LoadToken reads the persisted OAuth2 token from disk.
func LoadToken() (*oauth2.Token, error) {
	path, err := TokenPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path) //nolint:gosec // G304: path is computed internally from configDir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no stored token found: %w", os.ErrNotExist)
		}

		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var tok oauth2.Token
	if err := json.NewDecoder(f).Decode(&tok); err != nil {
		return nil, err
	}

	return &tok, nil
}

// DeleteToken removes the stored token file.
func DeleteToken() error {
	path, err := TokenPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}
