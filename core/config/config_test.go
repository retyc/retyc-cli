package config

import (
	"os"
	"testing"
)

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
