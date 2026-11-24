// Package config holds the settings of the core as plain values: the Config
// structs (decoded by the CLI from viper, see pkg/cliconfig), their defaults
// and bounds, and the environment-only settings (env.go, machine.go, the
// environment file). It imports no configuration library and never reads the
// config directory nor the working directory: the CLI's binding, validation
// and build defaults live in pkg/cliconfig.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

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
	BackgroundDelete bool     `yaml:"background_delete" mapstructure:"background_delete"`
	LocalFiles       []string `yaml:"local_files" mapstructure:"local_files"`
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
// configured, each half of cache.ttl when it is zero. Half, so that a name or
// a file in use is asked of the mount again before its listing expires, and
// the mount renews that listing in the background (see vfs revalidateLocked).
func (c *Config) KernelTTLs() (entry, attr time.Duration) {
	entry, attr = c.Mount.EntryTTL, c.Mount.AttrTTL
	if entry == 0 {
		entry = c.Cache.TTL / 2
	}
	if attr == 0 {
		attr = c.Cache.TTL / 2
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

// AdminBaseURL returns the admin API base URL. When not explicitly configured,
// it is derived from the member API base URL by appending the /v1 prefix.
func (c *Config) AdminBaseURL() string {
	if c.Admin.BaseURL != "" {
		return strings.TrimRight(c.Admin.BaseURL, "/")
	}

	return strings.TrimRight(c.API.BaseURL, "/") + "/v1"
}
