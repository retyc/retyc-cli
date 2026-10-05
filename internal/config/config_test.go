package config

import (
	"errors"
	"os"
	"path/filepath"
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

func TestWebdavMetricsAddr_DefaultDisabled(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Webdav.Metrics.Addr != "" {
		t.Errorf("Webdav.Metrics.Addr = %q, want empty (disabled)", cfg.Webdav.Metrics.Addr)
	}
}

func TestWebdavMetricsAddr_EnvBinding(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_WEBDAV_METRICS_ADDR", "127.0.0.1:9090")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Webdav.Metrics.Addr != "127.0.0.1:9090" {
		t.Errorf("Webdav.Metrics.Addr = %q, want 127.0.0.1:9090", cfg.Webdav.Metrics.Addr)
	}
}

func TestWebdavMetricsRuntime_DefaultEnabled(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Webdav.Metrics.Runtime {
		t.Error("Webdav.Metrics.Runtime should be true by default")
	}
}

func TestWebdavMetricsRuntime_EnvBinding(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_WEBDAV_METRICS_RUNTIME", "false")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Webdav.Metrics.Runtime {
		t.Error("Webdav.Metrics.Runtime = true, want false from env")
	}
}

func TestWebdavMetricsLabels_DefaultEmpty(t *testing.T) {
	resetViper(t)
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Webdav.Metrics.Labels) != 0 {
		t.Errorf("Webdav.Metrics.Labels = %v, want empty", cfg.Webdav.Metrics.Labels)
	}
}

func TestWebdavMetricsLabels_EnvBindingSplitsOnSpaces(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_WEBDAV_METRICS_LABELS", "identity=abc pod=x")
	SetDefaults()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"identity=abc", "pod=x"}
	if got := cfg.Webdav.Metrics.Labels; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Webdav.Metrics.Labels = %v, want %v", got, want)
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

func TestWebdavCache_Defaults(t *testing.T) {
	resetViper(t)
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Webdav.Cache.TTL != time.Minute {
		t.Errorf("Webdav.Cache.TTL = %s, want 1m", cfg.Webdav.Cache.TTL)
	}
	if cfg.Webdav.Cache.MaxStale != 5*time.Minute {
		t.Errorf("Webdav.Cache.MaxStale = %s, want 5m", cfg.Webdav.Cache.MaxStale)
	}
}

// Durations come as strings from the environment (and from config.yaml).
func TestWebdavCache_FromEnv(t *testing.T) {
	resetViper(t)
	t.Setenv("RETYC_WEBDAV_CACHE_TTL", "90s")
	t.Setenv("RETYC_WEBDAV_CACHE_MAX_STALE", "0")
	SetDefaults()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Webdav.Cache.TTL != 90*time.Second {
		t.Errorf("Webdav.Cache.TTL = %s, want 1m30s", cfg.Webdav.Cache.TTL)
	}
	if cfg.Webdav.Cache.MaxStale != 0 {
		t.Errorf("Webdav.Cache.MaxStale = %s, want 0 (stale serving disabled)", cfg.Webdav.Cache.MaxStale)
	}
}

func TestWebdavCache_Invalid(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"RETYC_WEBDAV_CACHE_TTL", "0"},
		{"RETYC_WEBDAV_CACHE_TTL", "-1s"},
		{"RETYC_WEBDAV_CACHE_MAX_STALE", "-1s"},
		{"RETYC_WEBDAV_CACHE_TTL", "soon"},
		{"RETYC_WEBDAV_CACHE_TTL", "500ms"},
		{"RETYC_WEBDAV_CACHE_MAX_STALE", "10ms"},
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

// A bare number in config.yaml decodes as nanoseconds: "ttl: 60" must be
// rejected, not silently turn the cache off.
func TestWebdavCache_BareNumberRejected(t *testing.T) {
	resetViper(t)
	SetDefaults()
	viper.Set("webdav.cache.ttl", 60)

	if _, err := Load(); err == nil {
		t.Error("Load() accepted webdav.cache.ttl: 60 (60ns)")
	}
}
