package cmd

import (
	"testing"
)

func TestPtrOr_Nil(t *testing.T) {
	got := ptrOr(nil, "fallback")
	if got != "fallback" {
		t.Errorf("ptrOr(nil) = %q, want fallback", got)
	}
}

func TestPtrOr_NonNil(t *testing.T) {
	s := "actual value"

	got := ptrOr(&s, "fallback")
	if got != "actual value" {
		t.Errorf("ptrOr(&s) = %q, want actual value", got)
	}
}

func TestFormatExpiry(t *testing.T) {
	tests := []struct {
		seconds  int
		expected string
	}{
		{0, "never"},
		{60, "in 1m"},
		{300, "in 5m"},
		{3599, "in 59m"},
		{3600, "in 1h"},
		{3601, "in 1h"},
		{7200, "in 2h"},
		{86399, "in 23h"},
		{86400, "in 1d"},
		{172800, "in 2d"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatExpiry(tt.seconds)
			if got != tt.expected {
				t.Errorf("formatExpiry(%d) = %q, want %q", tt.seconds, got, tt.expected)
			}
		})
	}
}

func TestGenerateTransferPassphrase_Length(t *testing.T) {
	p, err := generateTransferPassphrase()
	if err != nil {
		t.Fatalf("generateTransferPassphrase() error = %v", err)
	}

	if len(p) != 32 {
		t.Errorf("passphrase length = %d, want 32", len(p))
	}
}

func TestGenerateTransferPassphrase_Charset(t *testing.T) {
	p, err := generateTransferPassphrase()
	if err != nil {
		t.Fatalf("generateTransferPassphrase() error = %v", err)
	}

	for i, c := range p {
		if c < 0x21 || c > 0x7e {
			t.Errorf("passphrase[%d] = %q (0x%02x), want printable ASCII (0x21–0x7e)", i, c, c)
		}
	}
}

func TestGenerateTransferPassphrase_Unique(t *testing.T) {
	p1, err := generateTransferPassphrase()
	if err != nil {
		t.Fatal(err)
	}

	p2, err := generateTransferPassphrase()
	if err != nil {
		t.Fatal(err)
	}

	if p1 == p2 {
		t.Error("generateTransferPassphrase() returned identical passphrases on two consecutive calls")
	}
}

func TestRandomLetters_Length(t *testing.T) {
	for _, n := range []int{0, 1, 8, 16, 32} {
		got := randomLetters(n)
		if len(got) != n {
			t.Errorf("randomLetters(%d) length = %d, want %d", n, len(got), n)
		}
	}
}

func TestRandomLetters_Charset(t *testing.T) {
	s := randomLetters(64)
	for i, c := range s {
		if c < 'a' || c > 'z' {
			t.Errorf("randomLetters[%d] = %q, want lowercase a-z", i, c)
		}
	}
}

func TestRandomLetters_Unique(t *testing.T) {
	a := randomLetters(16)
	b := randomLetters(16)

	if a == b {
		t.Error("randomLetters() returned identical strings on two consecutive calls")
	}
}

func TestIsOfflineToken_Valid(t *testing.T) {
	// Manually crafted JWT with payload {"typ":"Offline"} (base64url-encoded).
	// header.payload.signature — signature is irrelevant for this check.
	//nolint:gosec // G101: test fixture JWT, not a real credential
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJ0eXAiOiJPZmZsaW5lIn0.signature"

	if !isOfflineToken(jwt) {
		t.Error("isOfflineToken() = false, want true for Offline typ")
	}
}

func TestIsOfflineToken_Regular(t *testing.T) {
	// JWT payload {"typ":"Bearer"}.
	//nolint:gosec // G101: test fixture JWT, not a real credential
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJ0eXAiOiJCZWFyZXIifQ.signature"

	if isOfflineToken(jwt) {
		t.Error("isOfflineToken() = true, want false for Bearer typ")
	}
}

func TestIsOfflineToken_NotJWT(t *testing.T) {
	if isOfflineToken("not.a.jwt.at.all.parts") {
		t.Error("isOfflineToken() = true, want false for non-JWT string")
	}
}

func TestIsOfflineToken_Empty(t *testing.T) {
	if isOfflineToken("") {
		t.Error("isOfflineToken() = true, want false for empty string")
	}
}

func TestIsOfflineToken_InvalidBase64(t *testing.T) {
	// Three parts but invalid base64 in the payload segment.
	if isOfflineToken("header.!!!invalid!!!.signature") {
		t.Error("isOfflineToken() = true, want false for invalid base64 payload")
	}
}
