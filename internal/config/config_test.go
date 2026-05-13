package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// resetViper resets viper global state after the test to avoid cross-test pollution.
func resetViper(t *testing.T) {
	t.Helper()
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
