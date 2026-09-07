package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
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
	p, err := service.GenerateTransferPassphrase()
	if err != nil {
		t.Fatalf("service.GenerateTransferPassphrase() error = %v", err)
	}

	if len(p) != 32 {
		t.Errorf("passphrase length = %d, want 32", len(p))
	}
}

func TestGenerateTransferPassphrase_Charset(t *testing.T) {
	p, err := service.GenerateTransferPassphrase()
	if err != nil {
		t.Fatalf("service.GenerateTransferPassphrase() error = %v", err)
	}

	for i, c := range p {
		if c < 0x21 || c > 0x7e {
			t.Errorf("passphrase[%d] = %q (0x%02x), want printable ASCII (0x21–0x7e)", i, c, c)
		}
	}
}

func TestGenerateTransferPassphrase_Unique(t *testing.T) {
	p1, err := service.GenerateTransferPassphrase()
	if err != nil {
		t.Fatal(err)
	}

	p2, err := service.GenerateTransferPassphrase()
	if err != nil {
		t.Fatal(err)
	}

	if p1 == p2 {
		t.Error("service.GenerateTransferPassphrase() returned identical passphrases on two consecutive calls")
	}
}

func TestRandomLetters_Length(t *testing.T) {
	for _, n := range []int{0, 1, 8, 16, 32} {
		got := service.RandomLetters(n)
		if len(got) != n {
			t.Errorf("service.RandomLetters(%d) length = %d, want %d", n, len(got), n)
		}
	}
}

func TestRandomLetters_Charset(t *testing.T) {
	s := service.RandomLetters(64)
	for i, c := range s {
		if c < 'a' || c > 'z' {
			t.Errorf("randomLetters[%d] = %q, want lowercase a-z", i, c)
		}
	}
}

func TestRandomLetters_Unique(t *testing.T) {
	a := service.RandomLetters(16)
	b := service.RandomLetters(16)

	if a == b {
		t.Error("service.RandomLetters() returned identical strings on two consecutive calls")
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

func TestNewHTTPClient_UsesEnvironmentProxy(t *testing.T) {
	client := newHTTPClient(false, false)

	ua, ok := client.Transport.(*api.UserAgentTransport)
	if !ok {
		t.Fatalf("transport = %T, want *api.UserAgentTransport", client.Transport)
	}

	inner, ok := ua.Base.(*http.Transport)
	if !ok {
		t.Fatalf("UserAgentTransport.Base = %T, want *http.Transport", ua.Base)
	}

	if inner.Proxy == nil {
		t.Error("Proxy = nil — the auth client would ignore HTTP_PROXY/HTTPS_PROXY/NO_PROXY")
	}
}

// testCAPEM is a self-signed CA used only to check that a custom bundle
// reaches the transport; it never validates a real connection.
const testCAPEM = `-----BEGIN CERTIFICATE-----
MIIBjjCCATWgAwIBAgIUKKEEmOjoXxzDTiOGz7lA63l93e8wCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRcmV0eWMtY2xpIHRlc3QgQ0EwIBcNMjYwOTA3MDc0OTQ4WhgP
MjEyNjA4MTQwNzQ5NDhaMBwxGjAYBgNVBAMMEXJldHljLWNsaSB0ZXN0IENBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmjUA9f9d1jIj9oGm0zOJP35IxhxrkadI
feFXknCJzdjT/5qqZlZkl2GZkE6Q/RGmm0dD8LlhM/RYjBXGX5kCN6NTMFEwHQYD
VR0OBBYEFHAqOtICMvL0oshcA1mqlW8r4xl8MB8GA1UdIwQYMBaAFHAqOtICMvL0
oshcA1mqlW8r4xl8MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIg
POkYyvcZYqG0F+lqTxf+AQHms0Hw1YaaB/qtDS2uQAECIEWvQU6UtEG9zPgwdNnz
5/hHTP/iFZbVtcTXBbyBJVNg
-----END CERTIFICATE-----
`

func TestNewHTTPClient_UsesCustomRootCAs(t *testing.T) {
	// Registered before t.Setenv so it runs after the environment is restored.
	t.Cleanup(func() { _, _ = api.InitTLSRoots() })

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte(testCAPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SSL_CERT_FILE", path)
	t.Setenv("SSL_CERT_DIR", "")

	if _, err := api.InitTLSRoots(); err != nil {
		t.Fatalf("InitTLSRoots() error = %v", err)
	}

	ua, ok := newHTTPClient(false, false).Transport.(*api.UserAgentTransport)
	if !ok {
		t.Fatal("unexpected transport type")
	}

	inner, ok := ua.Base.(*http.Transport)
	if !ok {
		t.Fatalf("UserAgentTransport.Base = %T, want *http.Transport", ua.Base)
	}

	if inner.TLSClientConfig.RootCAs == nil {
		t.Error("RootCAs = nil — newHTTPClient dropped the CAs loaded from SSL_CERT_FILE")
	}
}
