package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/viper"
)

func TestConfigEntries_MasksSecrets(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })
	viper.Reset()
	t.Setenv("RETYC_ADMIN_API_KEY", "ryc_supersecret")
	t.Setenv("RETYC_API_BASE_URL", "https://api.env.example")
	config.SetDefaults()

	entries := configEntries()

	var sawKey, sawURL bool
	for _, e := range entries {
		if strings.Contains(e.Value, "supersecret") {
			t.Fatalf("entry %q leaked the secret value", e.Key)
		}
		if e.Key == "admin.api_key" {
			sawKey = true
			if !e.Secret {
				t.Error("admin.api_key must be flagged as a secret")
			}
			if e.Value == "" {
				t.Error("admin.api_key is set, its masked value must not be empty")
			}
		}
		if e.Key == "api.base_url" {
			sawURL = true
			if e.Value != "https://api.env.example" {
				t.Errorf("api.base_url = %q, want the env value", e.Value)
			}
		}
	}

	if !sawKey || !sawURL {
		t.Fatalf("configEntries() = %+v, want both admin.api_key and api.base_url", entries)
	}
}

func TestConfigEntries_UnsetSecretIsEmpty(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })
	viper.Reset()
	t.Setenv("RETYC_ADMIN_API_KEY", "")
	config.SetDefaults()

	for _, e := range configEntries() {
		if e.Key == "admin.api_key" && e.Value != "" {
			t.Errorf("unset admin.api_key = %q, want \"\"", e.Value)
		}
	}
}

func TestConfigEntries_Sorted(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })
	viper.Reset()
	config.SetDefaults()

	entries := configEntries()
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Key > entries[i].Key {
			t.Fatalf("entries are not sorted: %q before %q", entries[i-1].Key, entries[i].Key)
		}
	}
}

// TestConfigFileLoaded_UnreadableFile is the regression test for `config path`
// reporting a file it never read: viper.ConfigFileUsed() returns the path
// requested with --config even when reading it failed.
func TestConfigFileLoaded_UnreadableFile(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
		cfgFile = ""
		configFileLoaded = ""
	})
	viper.Reset()
	configFileLoaded = ""
	cfgFile = filepath.Join(t.TempDir(), "absent.yaml")

	initConfig()

	if configFileLoaded != "" {
		t.Errorf("configFileLoaded = %q, want \"\" when the config file could not be read", configFileLoaded)
	}
}

func TestConfigFileLoaded_ReadableFile(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
		cfgFile = ""
		configFileLoaded = ""
	})
	viper.Reset()
	configFileLoaded = ""
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("api:\n  base_url: https://api.file.example\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfgFile = path

	initConfig()

	if configFileLoaded != path {
		t.Errorf("configFileLoaded = %q, want %q", configFileLoaded, path)
	}
}
