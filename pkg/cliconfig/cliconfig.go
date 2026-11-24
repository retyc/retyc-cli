// Package cliconfig is the CLI's side of the configuration: the viper
// binding (SetDefaults), the decoding and validation of config.Config (Load),
// the build defaults (paths_dev.go / paths_prod.go: config directory, API
// URL) and token.json in the config directory. It is for cmd only: the core
// (core/config and the packages that import it) never imports viper, nor reads
// the config directory or the working directory.
package cliconfig

import (
	"errors"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/core/config"
)

// Dir returns the active configuration directory path.
// The path depends on the build mode (dev/prod) and can be overridden
// with the RETYC_CONFIG_DIR environment variable.
func Dir() (string, error) {
	return configDir()
}

// localFilePatterns reads mount.local_files: glob patterns in the syntax of
// path.Match, matched against the name of a file. The empty items are
// dropped, and the single item config.MountLocalFilesNone is the empty list.
func localFilePatterns(items []string) ([]string, error) {
	patterns := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			patterns = append(patterns, item)
		}
	}
	if len(patterns) == 1 && patterns[0] == config.MountLocalFilesNone {
		return []string{}, nil
	}
	for _, pattern := range patterns {
		if strings.Contains(pattern, "/") {
			return nil, fmt.Errorf(
				"mount.local_files: %q holds a \"/\": a pattern is matched against the name of a file, not its path",
				pattern)
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("mount.local_files: %q is not a valid pattern (%w)", pattern, err)
		}
	}

	return patterns, nil
}

// defaultWebdavAddr is the bind address of `webdav serve`: local only, the
// WebDAV tree is served in cleartext.
const defaultWebdavAddr = "127.0.0.1:8888"

// removedKeys maps a configuration key that no longer exists to the one that
// replaced it. Load refuses a config file or an environment variable that
// still carries one: silently ignoring it would run with the default in place
// of the value the operator asked for.
var removedKeys = [][2]string{
	{"webdav.cache.ttl", "cache.ttl"},
	{"webdav.cache.max_stale", "cache.max_stale"},
}

// validateCacheStore checks cache.store and, for Redis, the shape of its URL.
// No message quotes the URL: it holds the password.
func validateCacheStore(c *config.CacheConfig) error {
	switch c.Store {
	case config.CacheStoreMemory:
		return nil
	case config.CacheStoreRedis:
	default:
		return fmt.Errorf("cache.store must be %q or %q, got %q", config.CacheStoreMemory, config.CacheStoreRedis, c.Store)
	}
	if c.Redis.URL == "" {
		return fmt.Errorf("cache.store is %q but cache.redis.url is not set", config.CacheStoreRedis)
	}
	scheme, _, found := strings.Cut(c.Redis.URL, "://")
	if !found || (scheme != "redis" && scheme != "rediss") {
		return errors.New("cache.redis.url must be a redis:// or rediss:// URL")
	}

	return nil
}

// envName returns the environment variable a configuration key is read from.
func envName(key string) string {
	return envPrefix + "_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}

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
	viper.SetDefault("api.concurrency.list", config.DefaultConcurrency)
	viper.SetDefault("api.concurrency.upload", config.DefaultConcurrency)
	viper.SetDefault("api.concurrency.download", config.DefaultConcurrency)
	viper.SetDefault("api.unsafe_write", false)
	viper.SetDefault("api.retry.max_wait", config.DefaultRetryMaxWait)
	viper.SetDefault("api.retry.max_attempts", config.DefaultRetryMaxAttempts)
	setBuildDefaults()
	viper.SetDefault("keyring.enabled", true)
	viper.SetDefault("keyring.ttl", 60)
	viper.SetDefault("admin.base_url", "")
	viper.SetDefault("admin.api_key", "")
	viper.SetDefault("admin.private_key_file", "")
	viper.SetDefault("cache.ttl", config.DefaultCacheTTL)
	viper.SetDefault("cache.max_stale", config.DefaultCacheMaxStale)
	viper.SetDefault("cache.negative_ttl", config.DefaultCacheNegativeTTL)
	viper.SetDefault("cache.store", config.CacheStoreMemory)
	viper.SetDefault("cache.redis.url", "")
	viper.SetDefault("cache.redis.high_confidentiality", false)
	viper.SetDefault("webdav.addr", defaultWebdavAddr)
	// Zero: each follows cache.ttl (see config.Config.KernelTTLs).
	viper.SetDefault("mount.entry_ttl", time.Duration(0))
	viper.SetDefault("mount.attr_ttl", time.Duration(0))
	viper.SetDefault("mount.kernel_cache", true)
	// Off: a folder listed gives an inode to no entry (see retycfs.Options).
	viper.SetDefault("mount.readdir_plus", false)
	// Empty: the temporary directory of the system.
	viper.SetDefault("mount.spool_dir", "")
	viper.SetDefault("mount.allow_other", false)
	viper.SetDefault("mount.uid", config.MountProcessID)
	viper.SetDefault("mount.gid", config.MountProcessID)
	viper.SetDefault("mount.file_mode", config.DefaultMountFileMode)
	viper.SetDefault("mount.dir_mode", config.DefaultMountDirMode)
	viper.SetDefault("mount.read_only", false)
	viper.SetDefault("mount.drain_timeout", config.DefaultMountDrainTimeout)
	viper.SetDefault("mount.mirror_locks", false)
	viper.SetDefault("mount.background_delete", false)
	viper.SetDefault("mount.warmup", false)
	viper.SetDefault("mount.warmup_depth", 0)
	// Glob patterns; from the environment, separated by spaces.
	viper.SetDefault("mount.local_files", config.DefaultMountLocalFiles())
	// Empty means no metrics/probes listener (see cmd/observability.go).
	// Labels are "key=value" items; from the environment, separated by spaces.
	viper.SetDefault("mount.metrics.addr", "")
	viper.SetDefault("mount.metrics.labels", []string{})

	viper.SetEnvPrefix(envPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
}

// Load reads the active viper configuration and returns a config.Config struct.
// SetDefaults must have been called before this function.
func Load() (*config.Config, error) {
	// A removed key has no default, so it is set only when a config file or
	// the environment carries it.
	for _, k := range removedKeys {
		if viper.IsSet(k[0]) {
			return nil, fmt.Errorf("%s was replaced by %s (%s by %s): rename it in the config file or the environment",
				k[0], k[1], envName(k[0]), envName(k[1]))
		}
	}

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	// Unmarshal keeps an environment value as a single item; GetStringSlice
	// splits it on spaces, which is the documented environment syntax.
	cfg.Mount.Metrics.Labels = viper.GetStringSlice("mount.metrics.labels")
	// Same for the patterns of the local files.
	var err error
	if cfg.Mount.LocalFiles, err = localFilePatterns(viper.GetStringSlice("mount.local_files")); err != nil {
		return nil, err
	}

	// A bound below 1 leaves the workers without a single slot, and one above
	// config.MaxConcurrency is more than the API or this process should take on.
	for _, c := range []struct {
		key   string
		value int
	}{
		{"api.concurrency.list", cfg.API.Concurrency.List},
		{"api.concurrency.upload", cfg.API.Concurrency.Upload},
		{"api.concurrency.download", cfg.API.Concurrency.Download},
	} {
		if c.value < 1 || c.value > config.MaxConcurrency {
			return nil, fmt.Errorf("%s must be between 1 and %d, got %d", c.key, config.MaxConcurrency, c.value)
		}
	}

	// 1 attempt means no retry on a 429; the request is still sent.
	if n := cfg.API.Retry.MaxAttempts; n < 1 || n > config.MaxRetryAttempts {
		return nil, fmt.Errorf("api.retry.max_attempts must be between 1 and %d, got %d", config.MaxRetryAttempts, n)
	}
	// Same trap as the cache durations below: a bare number is nanoseconds.
	if d := cfg.API.Retry.MaxWait; d < time.Second || d > config.MaxRetryMaxWait {
		return nil, fmt.Errorf("api.retry.max_wait must be between 1s and %s, with a unit (e.g. 30s), got %s",
			config.MaxRetryMaxWait, d)
	}

	// A bare number in config.yaml decodes as nanoseconds (only strings go
	// through the duration parser), so "ttl: 60" would silently disable the
	// cache: anything under a second is taken for a missing unit.
	if cfg.Cache.TTL < time.Second {
		return nil, fmt.Errorf("cache.ttl must be at least 1s, with a unit (e.g. 60s), got %s",
			cfg.Cache.TTL)
	}
	if cfg.Cache.MaxStale != 0 && cfg.Cache.MaxStale < time.Second {
		return nil, fmt.Errorf("cache.max_stale must be 0 or at least 1s, with a unit (e.g. 5m), got %s",
			cfg.Cache.MaxStale)
	}
	// Sub-second values are legitimate here, hence the lower floor; it still
	// catches a bare number.
	if cfg.Cache.NegativeTTL != 0 && cfg.Cache.NegativeTTL < time.Millisecond {
		return nil, fmt.Errorf("cache.negative_ttl must be 0 or at least 1ms, with a unit (e.g. 1s), got %s",
			cfg.Cache.NegativeTTL)
	}

	if err := validateCacheStore(&cfg.Cache); err != nil {
		return nil, err
	}

	if err := validateMount(&cfg.Mount); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateMount checks the mount.* keys.
func validateMount(m *config.MountConfig) error {
	// Same trap as the cache durations: a bare number is nanoseconds.
	for _, d := range []struct {
		key   string
		value time.Duration
	}{
		{"mount.entry_ttl", m.EntryTTL},
		{"mount.attr_ttl", m.AttrTTL},
	} {
		if d.value != 0 && d.value < time.Millisecond {
			return fmt.Errorf("%s must be 0 (follow cache.ttl) or at least 1ms, with a unit (e.g. 30s), got %s",
				d.key, d.value)
		}
	}
	if m.DrainTimeout != 0 && m.DrainTimeout < time.Second {
		return fmt.Errorf("mount.drain_timeout must be 0 or at least 1s, with a unit (e.g. 30s), got %s",
			m.DrainTimeout)
	}
	for _, id := range []struct {
		key   string
		value int64
	}{
		{"mount.uid", m.UID},
		{"mount.gid", m.GID},
	} {
		// The last 32-bit value is the "no change" ID of chown(2), not an owner.
		if id.value < config.MountProcessID || id.value >= math.MaxUint32 {
			return fmt.Errorf("%s must be -1 (the process's own) or an ID between 0 and %d, got %d",
				id.key, uint32(math.MaxUint32-1), id.value)
		}
	}
	if m.WarmupDepth < 0 {
		return fmt.Errorf("mount.warmup_depth must be 0 (every level) or more, got %d", m.WarmupDepth)
	}
	for _, mode := range []struct {
		key   string
		value string
	}{
		{"mount.file_mode", m.FileMode},
		{"mount.dir_mode", m.DirMode},
	} {
		// YAML reads an unquoted 0644 as the number 420, and 644 as 644: the
		// digits written are lost, so only a string is taken.
		if _, quoted := viper.Get(mode.key).(string); !quoted {
			return fmt.Errorf("%s must be a quoted octal string (e.g. \"0644\")", mode.key)
		}
		if _, err := config.ParseMountMode(mode.value); err != nil {
			return fmt.Errorf("%s: %w", mode.key, err)
		}
	}

	return nil
}

// TokenPath returns the path to the stored token file.
func TokenPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "token.json"), nil
}

// tokenFile returns the store of token.json in the config directory.
func tokenFile() (config.TokenFileStore, error) {
	path, err := TokenPath()

	return config.TokenFileStore{Path: path}, err
}

// SaveToken persists an OAuth2 token to token.json (mode 0600).
func SaveToken(tok *oauth2.Token) error {
	f, err := tokenFile()
	if err != nil {
		return err
	}

	return f.Save(tok)
}

// LoadToken reads token.json; a missing file wraps os.ErrNotExist.
func LoadToken() (*oauth2.Token, error) {
	f, err := tokenFile()
	if err != nil {
		return nil, err
	}

	return f.Load()
}

// DeleteToken removes token.json; a missing file is no error.
func DeleteToken() error {
	f, err := tokenFile()
	if err != nil {
		return err
	}

	return f.Delete()
}

// TokenFile is the token store of the CLI (auth.TokenStore): token.json in
// the config directory, resolved at each call (RETYC_CONFIG_DIR may come from
// the environment file).
type TokenFile struct{}

// Load reads token.json (LoadToken).
func (TokenFile) Load() (*oauth2.Token, error) { return LoadToken() }

// Save writes token.json (SaveToken).
func (TokenFile) Save(tok *oauth2.Token) error { return SaveToken(tok) }

// Delete removes token.json (DeleteToken).
func (TokenFile) Delete() error { return DeleteToken() }
