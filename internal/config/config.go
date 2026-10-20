// Package config manages the CLI configuration file and stored credentials.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	// UnsafeWrite lets the API acknowledge an uploaded chunk before it reaches
	// the object store (unsafe_write): faster, but a failure of the background
	// store goes unreported and leaves the version incomplete.
	UnsafeWrite bool        `yaml:"unsafe_write" mapstructure:"unsafe_write"`
	Retry       RetryConfig `yaml:"retry" mapstructure:"retry"`
}

// RetryConfig is the budget of a request the API answers 429 (rate limit):
// it is sent again, after the pause the server asks for, until it has been
// held back for MaxWait in total or sent MaxAttempts times. With MaxAttempts
// 1 a request is never replayed; the client still pauses after its refusal.
type RetryConfig struct {
	MaxWait     time.Duration `yaml:"max_wait" mapstructure:"max_wait"`
	MaxAttempts int           `yaml:"max_attempts" mapstructure:"max_attempts"`
}

// Defaults and bound of the api.retry.* keys (see RetryConfig).
const (
	DefaultRetryMaxWait     = 30 * time.Second
	DefaultRetryMaxAttempts = 10
	// MaxRetryAttempts is the largest api.retry.max_attempts accepted.
	MaxRetryAttempts = 100
	// MaxRetryMaxWait is the largest api.retry.max_wait accepted: it is also
	// the longest a refusal keeps every request of the client waiting.
	MaxRetryMaxWait = 10 * time.Minute
)

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

// MetricsConfig controls the observability listener of `fs mount`
// (Prometheus metrics and health probes, mount.metrics.*). An empty address
// disables it. /metrics always carries the go_* and process_* collectors.
// Labels are constant "key=value" pairs added to every series, so a parent
// aggregating several instances can tell them apart.
type MetricsConfig struct {
	Addr   string   `yaml:"addr" mapstructure:"addr"`
	Labels []string `yaml:"labels" mapstructure:"labels"`
}

// CacheConfig controls the caches of the tree both filesystem front ends
// (`fs webdav serve`, `fs mount`) are built on: folder listings, the dataroom
// list and the names looked up one by one. A listing younger than TTL is
// served as is. Once expired, it is still served for MaxStale more while a
// single background fetch replaces it, so a client walking a tree it has not
// touched for a while is answered from memory instead of waiting for one API
// round trip per folder. Past TTL+MaxStale the request waits for a fresh
// listing. MaxStale 0 disables stale serving: an expired listing waits for
// its refresh. `fs mount` never serves an expired listing, whatever MaxStale.
// NegativeTTL is how long a name looked up and found missing is answered
// missing without asking again; 0 disables that negative cache.
//
// Store is where the listings and the names looked up are kept: CacheStoreMemory
// (the process, the default) or CacheStoreRedis (a Redis several instances
// share, see Redis).
type CacheConfig struct {
	TTL         time.Duration    `yaml:"ttl" mapstructure:"ttl"`
	MaxStale    time.Duration    `yaml:"max_stale" mapstructure:"max_stale"`
	NegativeTTL time.Duration    `yaml:"negative_ttl" mapstructure:"negative_ttl"`
	Store       string           `yaml:"store" mapstructure:"store"`
	Redis       CacheRedisConfig `yaml:"redis" mapstructure:"redis"`
}

// CacheRedisConfig is the Redis of `cache.store: redis`. URL is a redis:// or
// rediss:// URL, password included: it is a secret, never printed nor part of
// an error. HighConfidentiality makes this instance store the encrypted
// fields the API answered in place of the decrypted names; what an instance
// reads does not depend on it.
type CacheRedisConfig struct {
	URL                 string `yaml:"url" mapstructure:"url"`
	HighConfidentiality bool   `yaml:"high_confidentiality" mapstructure:"high_confidentiality"`
}

// WebdavConfig holds the `webdav serve` settings. Addr is the host:port the
// server binds; loopback by default since the tree is served in cleartext.
type WebdavConfig struct {
	Addr string `yaml:"addr" mapstructure:"addr"`
}

// MountConfig holds the `fs mount` settings (the FUSE mount).
//
// EntryTTL and AttrTTL are how long the kernel keeps a name and the
// attributes of an inode without asking again; zero follows cache.ttl (see
// KernelTTLs). KernelCache lets the kernel keep the pages of a file between
// two opens of one version. ReadDirPlus lets a listing carry the attributes of
// its entries (FUSE READDIRPLUS), which gives every entry listed an inode.
// SpoolDir is where a file being written is kept
// until it is sent, the temporary directory of the system when empty. UID and
// GID are the owner every file is presented with, -1 meaning those of the
// process. FileMode and DirMode are octal strings: the permissions presented
// for a node the API stores no mode for. DrainTimeout is what the uploads in
// progress are given to end when the mount is stopped. MirrorLocks takes an
// API lock on a file for as long as it is open for writing. LocalFiles are the
// glob patterns of the names kept local (see DefaultMountLocalFiles and
// localFilePatterns). Metrics is the observability listener of the mount, off
// while its address is empty.
type MountConfig struct {
	EntryTTL     time.Duration `yaml:"entry_ttl" mapstructure:"entry_ttl"`
	AttrTTL      time.Duration `yaml:"attr_ttl" mapstructure:"attr_ttl"`
	KernelCache  bool          `yaml:"kernel_cache" mapstructure:"kernel_cache"`
	ReadDirPlus  bool          `yaml:"readdir_plus" mapstructure:"readdir_plus"`
	SpoolDir     string        `yaml:"spool_dir" mapstructure:"spool_dir"`
	AllowOther   bool          `yaml:"allow_other" mapstructure:"allow_other"`
	UID          int64         `yaml:"uid" mapstructure:"uid"`
	GID          int64         `yaml:"gid" mapstructure:"gid"`
	FileMode     string        `yaml:"file_mode" mapstructure:"file_mode"`
	DirMode      string        `yaml:"dir_mode" mapstructure:"dir_mode"`
	ReadOnly     bool          `yaml:"read_only" mapstructure:"read_only"`
	DrainTimeout time.Duration `yaml:"drain_timeout" mapstructure:"drain_timeout"`
	MirrorLocks  bool          `yaml:"mirror_locks" mapstructure:"mirror_locks"`
	// BackgroundDelete makes unlink answer before the API has deleted the
	// file (see retycfs.Options.BackgroundDelete).
	BackgroundDelete bool          `yaml:"background_delete" mapstructure:"background_delete"`
	LocalFiles       []string      `yaml:"local_files" mapstructure:"local_files"`
	// Warmup lists the whole tree in the background once mounted, to fill
	// the listing cache; WarmupDepth bounds the levels listed, 0 for all
	// (see vfs.FS.Warmup).
	Warmup      bool          `yaml:"warmup" mapstructure:"warmup"`
	WarmupDepth int           `yaml:"warmup_depth" mapstructure:"warmup_depth"`
	Metrics     MetricsConfig `yaml:"metrics" mapstructure:"metrics"`
}

// Defaults of the mount (see MountConfig).
const (
	DefaultMountFileMode     = "0644"
	DefaultMountDirMode      = "0755"
	DefaultMountDrainTimeout = 5 * time.Minute
	// MountProcessID is the value of mount.uid and mount.gid that stands for
	// the user or the group of the process.
	MountProcessID = -1
)

// MountLocalFilesNone is the value of mount.local_files that stands for an
// empty list where one cannot be written: an environment variable (viper
// ignores an empty one) or a flag.
const MountLocalFilesNone = "none"

// DefaultMountLocalFiles returns the default of mount.local_files: the files
// an editor creates next to the one it edits, for itself alone. Vim's swap
// files and the name it probes a folder with, and the backup files of vim,
// Emacs and others.
//
// The lock files of office suites (".~lock.name#", "~$name") are left out on
// purpose: they are how two users of one dataroom learn that the other has
// the document open, which only works when the file reaches the dataroom.
func DefaultMountLocalFiles() []string {
	return []string{".*.swp", ".*.swx", "*~", "4913"}
}

// localFilePatterns reads mount.local_files: glob patterns in the syntax of
// path.Match, matched against the name of a file. The empty items are
// dropped, and the single item MountLocalFilesNone is the empty list.
func localFilePatterns(items []string) ([]string, error) {
	patterns := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			patterns = append(patterns, item)
		}
	}
	if len(patterns) == 1 && patterns[0] == MountLocalFilesNone {
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

// ParseMountMode reads the permission bits of mount.file_mode and
// mount.dir_mode: an octal string of three or four digits, without setuid,
// setgid nor sticky.
func ParseMountMode(value string) (os.FileMode, error) {
	if len(value) < 3 || len(value) > 4 {
		return 0, fmt.Errorf("%q is not an octal mode (e.g. \"0644\")", value)
	}
	bits, err := strconv.ParseUint(value, 8, 32)
	if err != nil || bits == 0 || bits > 0o777 {
		return 0, fmt.Errorf("%q is not an octal mode between 0001 and 0777 (e.g. \"0644\")", value)
	}

	return os.FileMode(bits), nil
}

// KernelTTLs returns the entry and attribute timeouts of the mount: the ones
// configured, each following cache.ttl when it is zero.
func (c *Config) KernelTTLs() (entry, attr time.Duration) {
	entry, attr = c.Mount.EntryTTL, c.Mount.AttrTTL
	if entry == 0 {
		entry = c.Cache.TTL
	}
	if attr == 0 {
		attr = c.Cache.TTL
	}

	return entry, attr
}

// Config is the top-level configuration structure.
type Config struct {
	API     APIConfig     `yaml:"api" mapstructure:"api"`
	Keyring KeyringConfig `yaml:"keyring" mapstructure:"keyring"`
	Admin   AdminConfig   `yaml:"admin" mapstructure:"admin"`
	Cache   CacheConfig   `yaml:"cache" mapstructure:"cache"`
	Webdav  WebdavConfig  `yaml:"webdav" mapstructure:"webdav"`
	Mount   MountConfig   `yaml:"mount" mapstructure:"mount"`
}

// defaultWebdavAddr is the bind address of `webdav serve`: local only, the
// WebDAV tree is served in cleartext.
const defaultWebdavAddr = "127.0.0.1:8888"

// Defaults of the tree caches (see CacheConfig).
const (
	DefaultCacheTTL         = time.Minute
	DefaultCacheMaxStale    = 5 * time.Minute
	DefaultCacheNegativeTTL = time.Second
)

// Values of cache.store.
const (
	CacheStoreMemory = "memory"
	CacheStoreRedis  = "redis"
)

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
func validateCacheStore(c *CacheConfig) error {
	switch c.Store {
	case CacheStoreMemory:
		return nil
	case CacheStoreRedis:
	default:
		return fmt.Errorf("cache.store must be %q or %q, got %q", CacheStoreMemory, CacheStoreRedis, c.Store)
	}
	if c.Redis.URL == "" {
		return fmt.Errorf("cache.store is %q but cache.redis.url is not set", CacheStoreRedis)
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
	viper.SetDefault("api.concurrency.list", DefaultConcurrency)
	viper.SetDefault("api.concurrency.upload", DefaultConcurrency)
	viper.SetDefault("api.concurrency.download", DefaultConcurrency)
	viper.SetDefault("api.unsafe_write", false)
	viper.SetDefault("api.retry.max_wait", DefaultRetryMaxWait)
	viper.SetDefault("api.retry.max_attempts", DefaultRetryMaxAttempts)
	setBuildDefaults()
	viper.SetDefault("keyring.enabled", true)
	viper.SetDefault("keyring.ttl", 60)
	viper.SetDefault("admin.base_url", "")
	viper.SetDefault("admin.api_key", "")
	viper.SetDefault("admin.private_key_file", "")
	viper.SetDefault("cache.ttl", DefaultCacheTTL)
	viper.SetDefault("cache.max_stale", DefaultCacheMaxStale)
	viper.SetDefault("cache.negative_ttl", DefaultCacheNegativeTTL)
	viper.SetDefault("cache.store", CacheStoreMemory)
	viper.SetDefault("cache.redis.url", "")
	viper.SetDefault("cache.redis.high_confidentiality", false)
	viper.SetDefault("webdav.addr", defaultWebdavAddr)
	// Zero: each follows cache.ttl (see Config.KernelTTLs).
	viper.SetDefault("mount.entry_ttl", time.Duration(0))
	viper.SetDefault("mount.attr_ttl", time.Duration(0))
	viper.SetDefault("mount.kernel_cache", true)
	// Off: a folder listed gives an inode to no entry (see retycfs.Options).
	viper.SetDefault("mount.readdir_plus", false)
	// Empty: the temporary directory of the system.
	viper.SetDefault("mount.spool_dir", "")
	viper.SetDefault("mount.allow_other", false)
	viper.SetDefault("mount.uid", MountProcessID)
	viper.SetDefault("mount.gid", MountProcessID)
	viper.SetDefault("mount.file_mode", DefaultMountFileMode)
	viper.SetDefault("mount.dir_mode", DefaultMountDirMode)
	viper.SetDefault("mount.read_only", false)
	viper.SetDefault("mount.drain_timeout", DefaultMountDrainTimeout)
	viper.SetDefault("mount.mirror_locks", false)
	viper.SetDefault("mount.background_delete", false)
	viper.SetDefault("mount.warmup", true)
	viper.SetDefault("mount.warmup_depth", 0)
	// Glob patterns; from the environment, separated by spaces.
	viper.SetDefault("mount.local_files", DefaultMountLocalFiles())
	// Empty means no metrics/probes listener (see cmd/observability.go).
	// Labels are "key=value" items; from the environment, separated by spaces.
	viper.SetDefault("mount.metrics.addr", "")
	viper.SetDefault("mount.metrics.labels", []string{})

	viper.SetEnvPrefix(envPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
}

// Load reads the active viper configuration and returns a Config struct.
// SetDefaults must have been called before this function.
func Load() (*Config, error) {
	// A removed key has no default, so it is set only when a config file or
	// the environment carries it.
	for _, k := range removedKeys {
		if viper.IsSet(k[0]) {
			return nil, fmt.Errorf("%s was replaced by %s (%s by %s): rename it in the config file or the environment",
				k[0], k[1], envName(k[0]), envName(k[1]))
		}
	}

	var cfg Config
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

	// 1 attempt means no retry on a 429; the request is still sent.
	if n := cfg.API.Retry.MaxAttempts; n < 1 || n > MaxRetryAttempts {
		return nil, fmt.Errorf("api.retry.max_attempts must be between 1 and %d, got %d", MaxRetryAttempts, n)
	}
	// Same trap as the cache durations below: a bare number is nanoseconds.
	if d := cfg.API.Retry.MaxWait; d < time.Second || d > MaxRetryMaxWait {
		return nil, fmt.Errorf("api.retry.max_wait must be between 1s and %s, with a unit (e.g. 30s), got %s",
			MaxRetryMaxWait, d)
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
func validateMount(m *MountConfig) error {
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
		if id.value < MountProcessID || id.value >= math.MaxUint32 {
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
		if _, err := ParseMountMode(mode.value); err != nil {
			return fmt.Errorf("%s: %w", mode.key, err)
		}
	}

	return nil
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
