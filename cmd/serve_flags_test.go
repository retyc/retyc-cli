package cmd

import (
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestResolveWebdavAddr_FlagOverridesEnv(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_WEBDAV_ADDR", "0.0.0.0:9000")
	config.SetDefaults()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("addr", "127.0.0.1:8888", "")
	if got, err := resolveWebdavAddr(flags); err != nil || got != "0.0.0.0:9000" {
		t.Errorf("without flag: got %q (%v), want env value 0.0.0.0:9000", got, err)
	}
	if err := flags.Set("addr", "127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveWebdavAddr(flags); err != nil || got != "127.0.0.1:9999" {
		t.Errorf("with flag: got %q (%v), want flag value 127.0.0.1:9999", got, err)
	}
}

func TestResolveWebdavAddr_Default(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("addr", "127.0.0.1:8888", "")
	if got, err := resolveWebdavAddr(flags); err != nil || got != "127.0.0.1:8888" {
		t.Errorf("got %q (%v), want 127.0.0.1:8888", got, err)
	}
}

func TestResolveWebdavAddr_RejectsMissingPort(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "localhost", "127.0.0.1:", ""} {
		t.Run(addr, func(t *testing.T) {
			isolateConfig(t)
			config.SetDefaults()
			flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
			flags.String("addr", "127.0.0.1:8888", "")
			if err := flags.Set("addr", addr); err != nil {
				t.Fatal(err)
			}
			if _, err := resolveWebdavAddr(flags); err == nil {
				t.Errorf("--addr %q: expected an error", addr)
			}
		})
	}
}

func TestResolveUnsafeWrite(t *testing.T) {
	cases := map[string]struct {
		env  string // "" = unset
		flag string // "" = not passed
		want bool
	}{
		"default":            {want: false},
		"env without flag":   {env: "true", want: true},
		"flag overrides env": {env: "true", flag: "false", want: false},
		"flag without env":   {flag: "true", want: true},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			isolateConfig(t)
			if tc.env != "" {
				t.Setenv("RETYC_API_UNSAFE_WRITE", tc.env)
			}
			config.SetDefaults()
			flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
			flags.Bool("unsafe-write", false, "")
			if tc.flag != "" {
				if err := flags.Set("unsafe-write", tc.flag); err != nil {
					t.Fatal(err)
				}
			}
			bindUnsafeWrite(flags)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.API.UnsafeWrite != tc.want {
				t.Errorf("API.UnsafeWrite = %v, want %v", cfg.API.UnsafeWrite, tc.want)
			}
		})
	}
}

// The cache flags of the fs front ends land in the common cache section with
// the usual precedence, and go through the validation of config.Load.
func TestResolveCacheFlags(t *testing.T) {
	cases := map[string]struct {
		env, flags map[string]string
		want       config.CacheConfig
		wantErr    bool
	}{
		"defaults": {
			want: config.CacheConfig{TTL: time.Minute, MaxStale: 5 * time.Minute, NegativeTTL: time.Second, Store: "memory"},
		},
		"env without flag": {
			env:  map[string]string{"RETYC_CACHE_TTL": "90s", "RETYC_CACHE_NEGATIVE_TTL": "0"},
			want: config.CacheConfig{TTL: 90 * time.Second, MaxStale: 5 * time.Minute, Store: "memory"},
		},
		"flags override env": {
			env:   map[string]string{"RETYC_CACHE_TTL": "90s", "RETYC_CACHE_MAX_STALE": "1m"},
			flags: map[string]string{"cache-ttl": "10s", "cache-max-stale": "0s", "cache-negative-ttl": "250ms"},
			want:  config.CacheConfig{TTL: 10 * time.Second, NegativeTTL: 250 * time.Millisecond, Store: "memory"},
		},
		"redis from the flags": {
			env: map[string]string{"RETYC_CACHE_REDIS_URL": "redis://env.example:6379"},
			flags: map[string]string{
				"cache-store": "redis", "cache-redis-url": "rediss://:pw@flag.example:6380/2",
				"cache-redis-high-confidentiality": "true",
			},
			want: config.CacheConfig{
				TTL: time.Minute, MaxStale: 5 * time.Minute, NegativeTTL: time.Second, Store: "redis",
				Redis: config.CacheRedisConfig{URL: "rediss://:pw@flag.example:6380/2", HighConfidentiality: true},
			},
		},
		"redis from the environment": {
			env: map[string]string{
				"RETYC_CACHE_STORE": "redis", "RETYC_CACHE_REDIS_URL": "redis://env.example:6379",
				"RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY": "true",
			},
			want: config.CacheConfig{
				TTL: time.Minute, MaxStale: 5 * time.Minute, NegativeTTL: time.Second, Store: "redis",
				Redis: config.CacheRedisConfig{URL: "redis://env.example:6379", HighConfidentiality: true},
			},
		},
		"redis without a URL": {
			flags:   map[string]string{"cache-store": "redis"},
			wantErr: true,
		},
		"flag value is validated": {
			flags:   map[string]string{"cache-ttl": "10ms"},
			wantErr: true,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			isolateConfig(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			config.SetDefaults()
			cmd := &cobra.Command{Use: "serve"}
			addCacheFlags(cmd, true)
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			resolveCacheFlags(cmd.Flags())
			cfg, err := config.Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() accepted %v", tc.flags)
				}

				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cache != tc.want {
				t.Errorf("Cache = %+v, want %+v", cfg.Cache, tc.want)
			}
		})
	}
}

// A front end that declares no --cache-max-stale still binds the others.
func TestResolveCacheFlags_WithoutMaxStale(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	cmd := &cobra.Command{Use: "mount"}
	addCacheFlags(cmd, false)
	if err := cmd.Flags().Set("cache-ttl", "30s"); err != nil {
		t.Fatal(err)
	}
	resolveCacheFlags(cmd.Flags())
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cache.TTL != 30*time.Second || cfg.Cache.MaxStale != config.DefaultCacheMaxStale {
		t.Errorf("Cache = %+v, want ttl 30s and the default max_stale", cfg.Cache)
	}
}

// The serve command offers the three cache flags and none of the old names.
func TestWebdavServeCacheFlags(t *testing.T) {
	for _, name := range []string{"cache-ttl", "cache-max-stale", "cache-negative-ttl"} {
		if webdavServeCmd.Flags().Lookup(name) == nil {
			t.Errorf("fs webdav serve has no --%s", name)
		}
	}
}
