package config

import (
	"errors"
	"testing"
)

// TestToken verifies that an unsubstituted MCPB user_config placeholder
// (injected by older MCPB clients when the optional token is left empty) is
// treated as unset, while a value that merely contains "${" is kept.
func TestToken(t *testing.T) {
	cases := []struct {
		name, value, want string
	}{
		{"unset", "", ""},
		{"real token", "abc123", "abc123"},
		{"mcpb placeholder", "${user_config.token}", ""},
		{"contains a brace but is not a placeholder", "x${y}", "x${y}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvTokenName, tc.value)
			if got := Token(); got != tc.want {
				t.Errorf("Token() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKeyPassphrase_PlaceholderTreatedAsUnset(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "${user_config.key_passphrase}")
	if got := KeyPassphrase(); got != "" {
		t.Errorf("KeyPassphrase() = %q, want \"\"", got)
	}
}

// A passphrase is user-chosen text: "${" in it must not be mistaken for an
// MCPB placeholder.
func TestKeyPassphrase_KeepsDollarBrace(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "a${b}c")
	if got := KeyPassphrase(); got != "a${b}c" {
		t.Errorf("KeyPassphrase() = %q, want %q", got, "a${b}c")
	}
}

func TestRequireKeyPassphrase(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "s3cret")
	got, err := RequireKeyPassphrase()
	if err != nil {
		t.Fatalf("RequireKeyPassphrase() error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("RequireKeyPassphrase() = %q, want %q", got, "s3cret")
	}
}

func TestRequireKeyPassphrase_Unset(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "")
	_, err := RequireKeyPassphrase()
	if !errors.Is(err, ErrNoKeyPassphrase) {
		t.Errorf("error = %v, want ErrNoKeyPassphrase", err)
	}
}

func TestWebdavPassword(t *testing.T) {
	t.Setenv(EnvWebdavPasswordName, "hunter2")
	if got := WebdavPassword(); got != "hunter2" {
		t.Errorf("WebdavPassword() = %q, want %q", got, "hunter2")
	}
}
