package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// resetViper isolates a test from the viper global state and from the
// developer's shell: SetDefaults binds the environment, so an exported
// RETYC_API_BASE_URL or RETYC_INSECURE would otherwise leak into assertions
// about defaults. Every inherited RETYC_ variable is unset for the duration of
// the test and restored afterwards.
func resetViper(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if name, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(name, "RETYC_") {
			t.Setenv(name, "") // registers the restore
			_ = os.Unsetenv(name)
		}
	}
	viper.Reset()
	t.Cleanup(func() { viper.Reset() })
}

func TestSetDefaults(t *testing.T) {
	resetViper(t)
	SetDefaults()

	if got := viper.GetString("api.base_url"); got != defaultAPIBaseURL {
		t.Errorf("api.base_url = %q, want %q", got, defaultAPIBaseURL)
	}

	if got := viper.GetBool("keyring.enabled"); !got {
		t.Error("keyring.enabled should be true by default")
	}

	if got := viper.GetInt("keyring.ttl"); got != 60 {
		t.Errorf("keyring.ttl = %d, want 60", got)
	}
}

func TestLoad_Defaults(t *testing.T) {
	resetViper(t)
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.API.BaseURL != defaultAPIBaseURL {
		t.Errorf("API.BaseURL = %q, want %q", cfg.API.BaseURL, defaultAPIBaseURL)
	}

	if !cfg.Keyring.Enabled {
		t.Error("Keyring.Enabled should be true by default")
	}

	if cfg.Keyring.TTL != 60 {
		t.Errorf("Keyring.TTL = %d, want 60", cfg.Keyring.TTL)
	}
}

func TestSaveToken_LoadToken_RoundTrip(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())

	tok := &oauth2.Token{
		AccessToken:  "access-token-value",
		TokenType:    "Bearer",
		RefreshToken: "refresh-token-value",
		Expiry:       time.Now().Add(time.Hour),
	}

	if err := SaveToken(tok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	got, err := LoadToken()
	if err != nil {
		t.Fatalf("LoadToken() error = %v", err)
	}

	if got.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, tok.AccessToken)
	}

	if got.RefreshToken != tok.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, tok.RefreshToken)
	}
}

func TestSaveToken_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RETYC_CONFIG_DIR", dir)

	if err := SaveToken(&oauth2.Token{AccessToken: "test"}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "token.json"))
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("token.json permissions = %04o, want 0600", perm)
	}
}

func TestLoadToken_NoFile(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())

	_, err := LoadToken()
	if err == nil {
		t.Fatal("LoadToken() should return error when no token file exists")
	}

	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadToken() error = %v, want errors.Is(err, os.ErrNotExist) to be true", err)
	}
}

func TestLoadToken_CorruptJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RETYC_CONFIG_DIR", dir)

	if err := os.WriteFile(filepath.Join(dir, "token.json"), []byte("not valid json {{{"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadToken()
	if err == nil {
		t.Error("LoadToken() should return error for corrupt JSON")
	}
}

func TestDeleteToken(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())

	if err := SaveToken(&oauth2.Token{AccessToken: "test"}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken() error = %v", err)
	}

	_, err := LoadToken()
	if err == nil {
		t.Error("LoadToken() should fail after DeleteToken()")
	}
}

func TestDeleteToken_NoFile(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())

	if err := DeleteToken(); err != nil {
		t.Errorf("DeleteToken() should not error when no file exists, got: %v", err)
	}
}

func TestConfigDir_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RETYC_CONFIG_DIR", dir)

	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir() error = %v", err)
	}

	if got != dir {
		t.Errorf("ConfigDir() = %q, want %q", got, dir)
	}
}

func TestAdminBaseURL_Derived(t *testing.T) {
	cfg := &Config{API: APIConfig{BaseURL: "https://api.example.com"}}
	if got := cfg.AdminBaseURL(); got != "https://api.example.com/v1" {
		t.Errorf("AdminBaseURL() = %q, want %q", got, "https://api.example.com/v1")
	}
}

func TestAdminBaseURL_DerivedTrailingSlash(t *testing.T) {
	cfg := &Config{API: APIConfig{BaseURL: "https://api.example.com/"}}
	if got := cfg.AdminBaseURL(); got != "https://api.example.com/v1" {
		t.Errorf("AdminBaseURL() = %q, want %q", got, "https://api.example.com/v1")
	}
}

func TestAdminBaseURL_Explicit(t *testing.T) {
	cfg := &Config{
		API:   APIConfig{BaseURL: "https://api.example.com"},
		Admin: AdminConfig{BaseURL: "https://other.example.com/v2"},
	}
	if got := cfg.AdminBaseURL(); got != "https://other.example.com/v2" {
		t.Errorf("AdminBaseURL() = %q, want %q", got, "https://other.example.com/v2")
	}
}

func TestAdminBaseURL_ExplicitTrailingSlash(t *testing.T) {
	cfg := &Config{
		API:   APIConfig{BaseURL: "https://api.example.com"},
		Admin: AdminConfig{BaseURL: "https://other.example.com/v2/"},
	}
	if got := cfg.AdminBaseURL(); got != "https://other.example.com/v2" {
		t.Errorf("AdminBaseURL() = %q, want %q", got, "https://other.example.com/v2")
	}
}

func TestAdminEnvBinding(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_ADMIN_API_KEY", "ryc_test123")
	t.Setenv("RETYC_ADMIN_PRIVATE_KEY_FILE", "/tmp/key.txt")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Admin.APIKey != "ryc_test123" {
		t.Errorf("Admin.APIKey = %q, want ryc_test123", cfg.Admin.APIKey)
	}
	if cfg.Admin.PrivateKeyFile != "/tmp/key.txt" {
		t.Errorf("Admin.PrivateKeyFile = %q, want /tmp/key.txt", cfg.Admin.PrivateKeyFile)
	}
}

func TestSetDefaults_PrefixedEnv(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_API_BASE_URL", "https://api.env.example")
	t.Setenv("RETYC_KEYRING_TTL", "900")
	t.Setenv("RETYC_KEYRING_ENABLED", "false")
	t.Setenv("RETYC_ADMIN_BASE_URL", "https://admin.env.example/v9")
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.API.BaseURL != "https://api.env.example" {
		t.Errorf("API.BaseURL = %q, want the RETYC_API_BASE_URL value", cfg.API.BaseURL)
	}

	if cfg.Keyring.TTL != 900 {
		t.Errorf("Keyring.TTL = %d, want 900", cfg.Keyring.TTL)
	}

	if cfg.Keyring.Enabled {
		t.Error("Keyring.Enabled = true, want false from RETYC_KEYRING_ENABLED")
	}

	if cfg.Admin.BaseURL != "https://admin.env.example/v9" {
		t.Errorf("Admin.BaseURL = %q, want the RETYC_ADMIN_BASE_URL value", cfg.Admin.BaseURL)
	}
}

// TestSetDefaults_IgnoresUnprefixedEnv is the regression test for the reason
// this whole change exists: without SetEnvPrefix, viper resolved "insecure"
// from a bare INSECURE variable, so an unrelated environment variable could
// disable TLS verification.
func TestSetDefaults_IgnoresUnprefixedEnv(t *testing.T) {
	resetViper(t)
	t.Setenv("INSECURE", "true")
	t.Setenv("API.BASE_URL", "https://hijacked.example")
	t.Setenv("KEYRING.TTL", "999")
	SetDefaults()

	if viper.GetBool("insecure") {
		t.Error("a bare INSECURE variable must not disable TLS verification")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.API.BaseURL != defaultAPIBaseURL {
		t.Errorf("API.BaseURL = %q, want the default %q", cfg.API.BaseURL, defaultAPIBaseURL)
	}

	if cfg.Keyring.TTL != 60 {
		t.Errorf("Keyring.TTL = %d, want the default 60", cfg.Keyring.TTL)
	}
}

func TestSetDefaults_InsecureFromPrefixedEnv(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_INSECURE", "true")
	SetDefaults()

	if !viper.GetBool("insecure") {
		t.Error("insecure = false, want true from RETYC_INSECURE")
	}
}

func TestSetDefaults_InsecureDefaultsToFalse(t *testing.T) {
	resetViper(t)
	SetDefaults()

	if viper.GetBool("insecure") {
		t.Error("insecure must default to false")
	}
}

// TestEnvVarsDocumented fails when a configuration key has no documented
// environment variable. doc/configuration.md is the public contract for the
// environment: it must not drift from SetDefaults().
func TestEnvVarsDocumented(t *testing.T) {
	resetViper(t)
	SetDefaults()

	doc, err := os.ReadFile(filepath.Join("..", "..", "doc", "configuration.md"))
	if err != nil {
		t.Fatalf("reading doc/configuration.md: %v", err)
	}
	text := string(doc)

	var missing []string

	// The name is looked up backquoted, as it appears in a doc table cell.
	// A bare substring search would accept a passing mention in prose, and
	// would let RETYC_TOKEN be satisfied by a longer name containing it.
	documented := func(name string) bool {
		return strings.Contains(text, "`"+name+"`")
	}

	for _, key := range viper.AllKeys() {
		name := envPrefix + "_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		if !documented(name) {
			missing = append(missing, name)
		}
	}

	// The env-only settings, which have no viper key by design: every RETYC_
	// constant declared in env.go.
	for _, name := range declaredEnvNames(t) {
		if !documented(name) {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Errorf("undocumented in doc/configuration.md: %v", missing)
	}
}

func TestMountMetricsAddr_DefaultDisabled(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mount.Metrics.Addr != "" {
		t.Errorf("Mount.Metrics.Addr = %q, want empty (disabled)", cfg.Mount.Metrics.Addr)
	}
}

func TestMountMetricsAddr_EnvBinding(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_MOUNT_METRICS_ADDR", "127.0.0.1:9090")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mount.Metrics.Addr != "127.0.0.1:9090" {
		t.Errorf("Mount.Metrics.Addr = %q, want 127.0.0.1:9090", cfg.Mount.Metrics.Addr)
	}
}

func TestMountMetricsLabels_DefaultEmpty(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Mount.Metrics.Labels) != 0 {
		t.Errorf("Mount.Metrics.Labels = %v, want empty", cfg.Mount.Metrics.Labels)
	}
}

func TestMountMetricsLabels_EnvBindingSplitsOnSpaces(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_MOUNT_METRICS_LABELS", "identity=abc pod=x")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"identity=abc", "pod=x"}
	if got := cfg.Mount.Metrics.Labels; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Mount.Metrics.Labels = %v, want %v", got, want)
	}
}

func TestWebdavAddr_Default(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Webdav.Addr != "127.0.0.1:8888" {
		t.Errorf("Webdav.Addr = %q, want 127.0.0.1:8888", cfg.Webdav.Addr)
	}
}

func TestWebdavAddr_EnvBinding(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_WEBDAV_ADDR", "0.0.0.0:9000")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Webdav.Addr != "0.0.0.0:9000" {
		t.Errorf("Webdav.Addr = %q, want 0.0.0.0:9000", cfg.Webdav.Addr)
	}
}

func TestAPIConcurrency_Defaults(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := ConcurrencyConfig{List: DefaultConcurrency, Upload: DefaultConcurrency, Download: DefaultConcurrency}
	if cfg.API.Concurrency != want {
		t.Errorf("API.Concurrency = %+v, want %+v", cfg.API.Concurrency, want)
	}
}

func TestAPIConcurrency_EnvBinding(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_API_CONCURRENCY_LIST", "8")
	t.Setenv("RETYC_API_CONCURRENCY_UPLOAD", "2")
	t.Setenv("RETYC_API_CONCURRENCY_DOWNLOAD", "6")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := ConcurrencyConfig{List: 8, Upload: 2, Download: 6}
	if cfg.API.Concurrency != want {
		t.Errorf("API.Concurrency = %+v, want %+v", cfg.API.Concurrency, want)
	}
}

// A concurrency below 1 would deadlock the bounded workers (no slot ever
// free), and one above MaxConcurrency would flood the API and hold far too
// many decrypted chunks: Load refuses both and names the key.
func TestAPIConcurrency_RejectsOutOfRange(t *testing.T) {
	for _, key := range []string{"LIST", "UPLOAD", "DOWNLOAD"} {
		for _, value := range []string{"0", "-1", strconv.Itoa(MaxConcurrency + 1), "4611686018427387905"} {
			t.Run(key+"="+value, func(t *testing.T) {
				resetViper(t)
				t.Setenv("RETYC_API_CONCURRENCY_"+key, value)
				SetDefaults()
				_, err := Load()
				if err == nil {
					t.Fatalf("Load() accepted a concurrency of %s", value)
				}
				if want := "api.concurrency." + strings.ToLower(key); !strings.Contains(err.Error(), want) {
					t.Errorf("Load() error = %q, want it to name %s", err, want)
				}
			})
		}
	}
}

// The bounds themselves are accepted.
func TestAPIConcurrency_AcceptsTheBounds(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_API_CONCURRENCY_LIST", "1")
	t.Setenv("RETYC_API_CONCURRENCY_UPLOAD", strconv.Itoa(MaxConcurrency))
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.API.Concurrency.List != 1 || cfg.API.Concurrency.Upload != MaxConcurrency {
		t.Errorf("API.Concurrency = %+v, want list 1 and upload %d", cfg.API.Concurrency, MaxConcurrency)
	}
}

// The retry budget of a rate-limited request: 30 s and 10 attempts unless
// set, from the environment like any key.
func TestAPIRetry_DefaultsAndEnv(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.API.Retry.MaxWait != 30*time.Second || cfg.API.Retry.MaxAttempts != 10 {
		t.Errorf("API.Retry = %+v, want 30s and 10", cfg.API.Retry)
	}

	t.Setenv("RETYC_API_RETRY_MAX_WAIT", "10m") // the upper bound
	t.Setenv("RETYC_API_RETRY_MAX_ATTEMPTS", "1")
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.API.Retry.MaxWait != MaxRetryMaxWait || cfg.API.Retry.MaxAttempts != 1 {
		t.Errorf("API.Retry = %+v, want 10m and 1", cfg.API.Retry)
	}
}

// A bare number is nanoseconds, so a max_wait under a second is a missing
// unit; above MaxRetryMaxWait a single refusal would freeze the client for
// too long; attempts outside 1..MaxRetryAttempts make no sense.
func TestAPIRetry_RejectsOutOfRange(t *testing.T) {
	for _, tc := range []struct{ env, value, key string }{
		{"RETYC_API_RETRY_MAX_WAIT", "30", "api.retry.max_wait"},
		{"RETYC_API_RETRY_MAX_WAIT", "0", "api.retry.max_wait"},
		{"RETYC_API_RETRY_MAX_WAIT", "-5s", "api.retry.max_wait"},
		{"RETYC_API_RETRY_MAX_WAIT", "10m1s", "api.retry.max_wait"},
		{"RETYC_API_RETRY_MAX_ATTEMPTS", "0", "api.retry.max_attempts"},
		{"RETYC_API_RETRY_MAX_ATTEMPTS", strconv.Itoa(MaxRetryAttempts + 1), "api.retry.max_attempts"},
	} {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			resetViper(t)
			t.Setenv(tc.env, tc.value)
			SetDefaults()
			_, err := Load()
			if err == nil {
				t.Fatalf("Load() accepted %s=%s", tc.env, tc.value)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("Load() error = %q, want it to name %s", err, tc.key)
			}
		})
	}
}

func TestAPIUnsafeWrite_DefaultFalse(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.API.UnsafeWrite {
		t.Error("API.UnsafeWrite should be false by default: an upload must be stored before it is acknowledged")
	}
}

func TestAPIUnsafeWrite_EnvBinding(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_API_UNSAFE_WRITE", "true")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.API.UnsafeWrite {
		t.Error("API.UnsafeWrite = false, want true from env")
	}
}

func TestCache_Defaults(t *testing.T) {
	resetViper(t)
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Cache.TTL != time.Minute {
		t.Errorf("Cache.TTL = %s, want 1m", cfg.Cache.TTL)
	}
	if cfg.Cache.MaxStale != 5*time.Minute {
		t.Errorf("Cache.MaxStale = %s, want 5m", cfg.Cache.MaxStale)
	}
	if cfg.Cache.NegativeTTL != time.Second {
		t.Errorf("Cache.NegativeTTL = %s, want 1s", cfg.Cache.NegativeTTL)
	}
}

// Durations come as strings from the environment (and from config.yaml).
func TestCache_FromEnv(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_CACHE_TTL", "90s")
	t.Setenv("RETYC_CACHE_MAX_STALE", "0")
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Cache.TTL != 90*time.Second {
		t.Errorf("Cache.TTL = %s, want 1m30s", cfg.Cache.TTL)
	}
	if cfg.Cache.MaxStale != 0 {
		t.Errorf("Cache.MaxStale = %s, want 0 (stale serving disabled)", cfg.Cache.MaxStale)
	}
}

func TestCache_Invalid(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"RETYC_CACHE_TTL", "0"},
		{"RETYC_CACHE_TTL", "-1s"},
		{"RETYC_CACHE_MAX_STALE", "-1s"},
		{"RETYC_CACHE_TTL", "soon"},
		{"RETYC_CACHE_TTL", "500ms"},
		{"RETYC_CACHE_MAX_STALE", "10ms"},
		{"RETYC_CACHE_NEGATIVE_TTL", "-1s"},
		{"RETYC_CACHE_NEGATIVE_TTL", "500"},
		{"RETYC_CACHE_NEGATIVE_TTL", "soon"},
	} {
		t.Run(c.name+"="+c.value, func(t *testing.T) {
			resetViper(t)
			t.Setenv(c.name, c.value)
			SetDefaults()

			if _, err := Load(); err == nil {
				t.Errorf("Load() accepted %s=%s", c.name, c.value)
			}
		})
	}
}

// cache.store is memory unless asked otherwise, and a Redis store needs a
// redis:// or rediss:// URL. No refusal quotes the URL: it holds the password.
func TestCacheStore(t *testing.T) {
	const password = "s3cr3t-pw"
	for label, c := range map[string]struct {
		env     map[string]string
		want    CacheConfig
		wantErr string
	}{
		"default": {want: CacheConfig{Store: CacheStoreMemory}},
		"a URL alone changes nothing": {
			env:  map[string]string{"RETYC_CACHE_REDIS_URL": "redis://h:6379"},
			want: CacheConfig{Store: CacheStoreMemory, Redis: CacheRedisConfig{URL: "redis://h:6379"}},
		},
		"redis": {
			env: map[string]string{
				"RETYC_CACHE_STORE": "redis", "RETYC_CACHE_REDIS_URL": "rediss://u:" + password + "@h:6380/3",
				"RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY": "true",
			},
			want: CacheConfig{Store: CacheStoreRedis, Redis: CacheRedisConfig{
				URL: "rediss://u:" + password + "@h:6380/3", HighConfidentiality: true,
			}},
		},
		"unknown store": {
			env:     map[string]string{"RETYC_CACHE_STORE": "memcached"},
			wantErr: "cache.store must be",
		},
		"redis without a URL": {
			env:     map[string]string{"RETYC_CACHE_STORE": "redis"},
			wantErr: "cache.redis.url is not set",
		},
		"another scheme": {
			env: map[string]string{
				"RETYC_CACHE_STORE": "redis", "RETYC_CACHE_REDIS_URL": "https://u:" + password + "@h:6379",
			},
			wantErr: "cache.redis.url must be a redis:// or rediss:// URL",
		},
		"no scheme": {
			env:     map[string]string{"RETYC_CACHE_STORE": "redis", "RETYC_CACHE_REDIS_URL": password + "@h:6379"},
			wantErr: "cache.redis.url must be a redis:// or rediss:// URL",
		},
	} {
		t.Run(label, func(t *testing.T) {
			resetViper(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			SetDefaults()

			cfg, err := Load()
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("Load() error = %v, want one containing %q", err, c.wantErr)
				}
				if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "h:6379") {
					t.Errorf("the error quotes the URL: %v", err)
				}

				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.Cache.Store != c.want.Store || cfg.Cache.Redis != c.want.Redis {
				t.Errorf("Cache = %+v, want store %q and redis %+v", cfg.Cache, c.want.Store, c.want.Redis)
			}
		})
	}
}

// A bare number in config.yaml decodes as nanoseconds: "ttl: 60" must be
// rejected, not silently turn the cache off.
func TestCache_BareNumberRejected(t *testing.T) {
	resetViper(t)
	SetDefaults()
	viper.Set("cache.ttl", 60)

	if _, err := Load(); err == nil {
		t.Error("Load() accepted cache.ttl: 60 (60ns)")
	}
}

// The negative cache takes sub-second values, and 0 turns it off.
func TestCache_NegativeTTL(t *testing.T) {
	for value, want := range map[string]time.Duration{"0": 0, "250ms": 250 * time.Millisecond, "5s": 5 * time.Second} {
		t.Run(value, func(t *testing.T) {
			resetViper(t)
			t.Setenv("RETYC_CACHE_NEGATIVE_TTL", value)
			SetDefaults()

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.Cache.NegativeTTL != want {
				t.Errorf("Cache.NegativeTTL = %s, want %s", cfg.Cache.NegativeTTL, want)
			}
		})
	}
}

// The keys of the former webdav.cache section are refused, from the
// environment and from a config file, with the name of their replacement.
func TestCache_RemovedKeysRefused(t *testing.T) {
	for _, c := range []struct{ key, env, want string }{
		{"webdav.cache.ttl", "RETYC_WEBDAV_CACHE_TTL", "webdav.cache.ttl was replaced by cache.ttl"},
		{"webdav.cache.max_stale", "RETYC_WEBDAV_CACHE_MAX_STALE", "webdav.cache.max_stale was replaced by cache.max_stale"},
	} {
		t.Run(c.env, func(t *testing.T) {
			resetViper(t)
			t.Setenv(c.env, "90s")
			SetDefaults()

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, c.want)
			}
		})
		t.Run(c.key, func(t *testing.T) {
			resetViper(t)
			SetDefaults()
			viper.SetConfigType("yaml")
			section, leaf, _ := strings.Cut(strings.TrimPrefix(c.key, "webdav."), ".")
			yaml := "webdav:\n  " + section + ":\n    " + leaf + ": 90s\n"
			if err := viper.ReadConfig(strings.NewReader(yaml)); err != nil {
				t.Fatalf("ReadConfig() error = %v", err)
			}

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Load() error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestMount_Defaults(t *testing.T) {
	resetViper(t)
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := MountConfig{
		KernelCache: true, UID: MountProcessID, GID: MountProcessID,
		FileMode: "0644", DirMode: "0755", DrainTimeout: 5 * time.Minute,
		LocalFiles: []string{".*.swp", ".*.swx", "*~", "4913"},
		Warmup:     true,
		Metrics:    MetricsConfig{Labels: []string{}},
	}
	if !reflect.DeepEqual(cfg.Mount, want) {
		t.Errorf("Mount = %+v, want %+v", cfg.Mount, want)
	}
	// Left at zero, the kernel timeouts follow cache.ttl.
	if entry, attr := cfg.KernelTTLs(); entry != DefaultCacheTTL || attr != DefaultCacheTTL {
		t.Errorf("KernelTTLs() = %s, %s, want cache.ttl", entry, attr)
	}
}

func TestMount_FromEnv(t *testing.T) {
	resetViper(t)
	for name, value := range map[string]string{
		"RETYC_CACHE_TTL": "20s", "RETYC_MOUNT_ENTRY_TTL": "5s", "RETYC_MOUNT_KERNEL_CACHE": "false",
		"RETYC_MOUNT_READDIR_PLUS": "true", "RETYC_MOUNT_SPOOL_DIR": "/var/spool/retyc", "RETYC_MOUNT_ALLOW_OTHER": "true",
		"RETYC_MOUNT_UID": "0", "RETYC_MOUNT_GID": "1000", "RETYC_MOUNT_FILE_MODE": "0600",
		"RETYC_MOUNT_DIR_MODE": "700", "RETYC_MOUNT_READ_ONLY": "true", "RETYC_MOUNT_DRAIN_TIMEOUT": "2m",
		"RETYC_MOUNT_MIRROR_LOCKS": "true", "RETYC_MOUNT_METRICS_ADDR": "127.0.0.1:9091",
		"RETYC_MOUNT_METRICS_LABELS": "pod=a volume=b",
		"RETYC_MOUNT_LOCAL_FILES":    ".*.swp  *.tmp",
		"RETYC_MOUNT_WARMUP":         "false", "RETYC_MOUNT_WARMUP_DEPTH": "2",
	} {
		t.Setenv(name, value)
	}
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := MountConfig{
		EntryTTL: 5 * time.Second, ReadDirPlus: true, SpoolDir: "/var/spool/retyc", AllowOther: true,
		UID: 0, GID: 1000,
		FileMode: "0600", DirMode: "700", ReadOnly: true, DrainTimeout: 2 * time.Minute,
		MirrorLocks: true,
		LocalFiles:  []string{".*.swp", "*.tmp"},
		WarmupDepth: 2,
		Metrics:     MetricsConfig{Addr: "127.0.0.1:9091", Labels: []string{"pod=a", "volume=b"}},
	}
	if !reflect.DeepEqual(cfg.Mount, want) {
		t.Errorf("Mount = %+v, want %+v", cfg.Mount, want)
	}
	// entry_ttl is set, attr_ttl follows cache.ttl.
	if entry, attr := cfg.KernelTTLs(); entry != 5*time.Second || attr != 20*time.Second {
		t.Errorf("KernelTTLs() = %s, %s, want 5s and 20s", entry, attr)
	}
}

// mount.background_delete is off unless asked for, from the environment or
// from the file.
func TestMount_BackgroundDelete(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mount.BackgroundDelete {
		t.Error("mount.background_delete is on by default")
	}

	resetViper(t)
	t.Setenv("RETYC_MOUNT_BACKGROUND_DELETE", "true")
	SetDefaults()
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Mount.BackgroundDelete {
		t.Error("RETYC_MOUNT_BACKGROUND_DELETE=true is ignored")
	}
}

func TestMount_Invalid(t *testing.T) {
	for label, c := range map[string]struct {
		key   string
		value any
	}{
		"entry_ttl without a unit":     {"mount.entry_ttl", 60},
		"attr_ttl without a unit":      {"mount.attr_ttl", 60},
		"drain_timeout without a unit": {"mount.drain_timeout", 30},
		"drain_timeout under a second": {"mount.drain_timeout", "200ms"},
		"uid below -1":                 {"mount.uid", -2},
		"warmup_depth below 0":         {"mount.warmup_depth", -1},
		"gid past 32 bits":             {"mount.gid", int64(1) << 32},
		"uid that is the chown no-op":  {"mount.uid", int64(1)<<32 - 1},
		// YAML reads 0644 as 420 and 644 as 644: neither is what was written.
		"file_mode unquoted (0644)": {"mount.file_mode", 420},
		"dir_mode unquoted (755)":   {"mount.dir_mode", 755},
		"file_mode not octal":       {"mount.file_mode", "0689"},
		"file_mode with setuid":     {"mount.file_mode", "4755"},
		"dir_mode empty":            {"mount.dir_mode", ""},
		"dir_mode zero":             {"mount.dir_mode", "000"},
	} {
		t.Run(label, func(t *testing.T) {
			resetViper(t)
			SetDefaults()
			viper.Set(c.key, c.value)

			if _, err := Load(); err == nil || !strings.Contains(err.Error(), c.key) {
				t.Errorf("Load() = %v, want an error naming %s", err, c.key)
			}
		})
	}
}

func TestMount_AcceptsTheBounds(t *testing.T) {
	resetViper(t)
	SetDefaults()
	viper.Set("mount.uid", int64(1)<<32-2)
	viper.Set("mount.gid", 0)
	viper.Set("mount.drain_timeout", "0")
	viper.Set("mount.entry_ttl", "1ms")
	viper.Set("mount.file_mode", "400")
	viper.Set("mount.dir_mode", "0777")

	if _, err := Load(); err != nil {
		t.Errorf("Load() error = %v", err)
	}
}

func TestParseMountMode(t *testing.T) {
	for value, want := range map[string]os.FileMode{"0644": 0o644, "755": 0o755, "0001": 0o001, "0777": 0o777} {
		if got, err := ParseMountMode(value); err != nil || got != want {
			t.Errorf("ParseMountMode(%q) = %o, %v, want %o", value, got, err, want)
		}
	}
	for _, value := range []string{"", "0", "64", "00644", "0o644", "rwx", "1777", "-644", "0000"} {
		if got, err := ParseMountMode(value); err == nil {
			t.Errorf("ParseMountMode(%q) = %o, want an error", value, got)
		}
	}
}

// mount.local_files can be emptied from each source: an empty list in the
// file, and the word "none" where an empty value cannot be written.
func TestMountLocalFiles_Emptied(t *testing.T) {
	for label, set := range map[string]func(t *testing.T){
		"an empty list in the file": func(*testing.T) { viper.Set("mount.local_files", []string{}) },
		"none in the file":          func(*testing.T) { viper.Set("mount.local_files", []string{"none"}) },
		"an empty item":             func(*testing.T) { viper.Set("mount.local_files", []string{""}) },
		"none in the environment":   func(t *testing.T) { t.Setenv("RETYC_MOUNT_LOCAL_FILES", "none") },
		"a blank environment":       func(t *testing.T) { t.Setenv("RETYC_MOUNT_LOCAL_FILES", " ") },
	} {
		t.Run(label, func(t *testing.T) {
			resetViper(t)
			set(t)
			SetDefaults()
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := cfg.Mount.LocalFiles; got == nil || len(got) != 0 {
				t.Errorf("Mount.LocalFiles = %#v, want an empty list", got)
			}
		})
	}
}

// A YAML file is read like the other sources: a list replaces the default,
// an empty one empties it.
func TestMountLocalFiles_FromFile(t *testing.T) {
	for content, want := range map[string][]string{
		"mount:\n  local_files: []\n":                      {},
		"mount:\n  local_files: [\"*.bak\", \"[a-c]~\"]\n": {"*.bak", "[a-c]~"},
		"mount:\n  read_only: true\n":                      DefaultMountLocalFiles(),
	} {
		resetViper(t)
		SetDefaults()
		viper.SetConfigType("yaml")
		if err := viper.ReadConfig(strings.NewReader(content)); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if got := cfg.Mount.LocalFiles; !reflect.DeepEqual(got, want) {
			t.Errorf("%q: Mount.LocalFiles = %#v, want %#v", content, got, want)
		}
	}
}

func TestMountLocalFiles_Invalid(t *testing.T) {
	for label, patterns := range map[string][]string{
		"an open class":      {"*~", "[a-"},
		"a trailing escape":  {"a\\"},
		"a path, not a name": {"build/*.o"},
	} {
		t.Run(label, func(t *testing.T) {
			resetViper(t)
			SetDefaults()
			viper.Set("mount.local_files", patterns)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "mount.local_files") {
				t.Errorf("Load() error = %v, want one naming mount.local_files", err)
			}
		})
	}
}
