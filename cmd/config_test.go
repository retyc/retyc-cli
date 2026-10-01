package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/viper"
)

// isolateConfig resets the configuration state that initConfig and
// configEntries share through package variables and the viper global, and
// unsets every RETYC_ variable inherited from the developer's shell, so that a
// test only sees what it sets itself. Everything is restored afterwards.
func isolateConfig(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if name, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(name, "RETYC_") {
			t.Setenv(name, "") // registers the restore
			_ = os.Unsetenv(name)
		}
	}
	reset := func() {
		viper.Reset()
		cfgFile = ""
		configFileLoaded = ""
		configFileErr = nil
	}
	reset()
	t.Cleanup(reset)
}

func TestConfigEntries_MasksSecrets(t *testing.T) {
	isolateConfig(t)
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
	isolateConfig(t)
	config.SetDefaults()

	for _, e := range configEntries() {
		if e.Key == "admin.api_key" && e.Value != "" {
			t.Errorf("unset admin.api_key = %q, want \"\"", e.Value)
		}
	}
}

func TestConfigEntries_Sorted(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()

	entries := configEntries()
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Key > entries[i].Key {
			t.Fatalf("entries are not sorted: %q before %q", entries[i-1].Key, entries[i].Key)
		}
	}
}

// entryFor returns the configEntries entry for key, failing the test when the
// key is absent.
func entryFor(t *testing.T, key string) configEntryJSON {
	t.Helper()
	for _, e := range configEntries() {
		if e.Key == key {
			return e
		}
	}
	t.Fatalf("configEntries() has no %q entry", key)

	return configEntryJSON{}
}

// TestConfigFileLoaded_UnreadableFile is the regression test for `config path`
// reporting a file it never read: viper.ConfigFileUsed() returns the path
// requested with --config even when reading it failed.
func TestConfigFileLoaded_UnreadableFile(t *testing.T) {
	isolateConfig(t)
	cfgFile = filepath.Join(t.TempDir(), "absent.yaml")

	initConfig()

	if configFileLoaded != "" {
		t.Errorf("configFileLoaded = %q, want \"\" when the config file could not be read", configFileLoaded)
	}
	if configFileErr == nil {
		t.Error("configFileErr = nil, want the read error for a --config file that does not exist")
	}
}

// A config file with a YAML syntax error used to be skipped without a trace:
// every command silently ran on defaults.
func TestConfigFileLoaded_MalformedFile(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDirName, dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("api:\n  base_url: [\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	initConfig()

	if configFileLoaded != "" {
		t.Errorf("configFileLoaded = %q, want \"\" for a malformed file", configFileLoaded)
	}
	if configFileErr == nil {
		t.Error("configFileErr = nil, want the parse error")
	}
}

// Having no config file at all is the normal case, not an error.
func TestConfigFileLoaded_NoFileInSearchPath(t *testing.T) {
	isolateConfig(t)
	t.Setenv(config.EnvConfigDirName, t.TempDir())

	initConfig()

	if configFileLoaded != "" || configFileErr != nil {
		t.Errorf("configFileLoaded = %q, configFileErr = %v, want both empty when no config file exists",
			configFileLoaded, configFileErr)
	}
}

func TestConfigFileLoaded_ReadableFile(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("api:\n  base_url: https://api.file.example\n"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfgFile = path

	initConfig()

	if configFileLoaded != path {
		t.Errorf("configFileLoaded = %q, want %q", configFileLoaded, path)
	}
	if configFileErr != nil {
		t.Errorf("configFileErr = %v, want nil", configFileErr)
	}
}

func TestEffectiveValue_JoinsYAMLLists(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "webdav:\n  metrics:\n    labels:\n      - identity=abc\n      - pod=x\n"
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfgFile = path

	initConfig()

	if got := effectiveValue("webdav.metrics.labels"); got != "identity=abc pod=x" {
		t.Errorf("effectiveValue = %q, want %q", got, "identity=abc pod=x")
	}
}

func TestEffectiveValue_JoinsLists(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_WEBDAV_METRICS_LABELS", "identity=abc pod=x")
	config.SetDefaults()
	if got := effectiveValue("webdav.metrics.labels"); got != "identity=abc pod=x" {
		t.Errorf("effectiveValue = %q, want %q", got, "identity=abc pod=x")
	}
}
