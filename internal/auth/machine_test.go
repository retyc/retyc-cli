package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/machinekey"
)

const testClientID = "machine-abc"

// newTestMachineSource writes a fresh signing key and returns a source posting
// to handler, with a controllable clock.
func newTestMachineSource(t *testing.T, handler http.HandlerFunc) (*MachineTokenSource, *httptest.Server, *time.Time) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	key, err := machinekey.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := machinekey.MarshalSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}

	src, err := NewMachineTokenSource(&config.Machine{
		ClientID: testClientID, TokenEndpoint: srv.URL, ClientKeyFile: path,
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_800_000_000, 0)
	src.now = func() time.Time { return clock }

	return src, srv, &clock
}

func okHandler(count *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-secret","token_type":"Bearer","expires_in":300}`))
	}
}

func TestMachineTokenRequest(t *testing.T) {
	var form map[string][]string
	var srvURL string
	src, srv, clock := newTestMachineSource(t, func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		_ = r.ParseForm()
		form = r.PostForm
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":300}`))
	})
	srvURL = srv.URL

	tok, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if got := form["grant_type"]; len(got) != 1 || got[0] != "client_credentials" {
		t.Errorf("grant_type = %v", got)
	}
	if got := form["client_assertion_type"]; len(got) != 1 ||
		got[0] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %v", got)
	}
	parts := strings.Split(form["client_assertion"][0], ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != srvURL || claims["iss"] != testClientID || claims["sub"] != testClientID {
		t.Errorf("claims = %v", claims)
	}
	if want := clock.Add(300 * time.Second); !tok.Expiry.Equal(want) {
		t.Errorf("expiry = %v, want %v", tok.Expiry, want)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access token = %q", tok.AccessToken)
	}
}

func TestMachineTokenCached(t *testing.T) {
	var n atomic.Int32
	src, _, clock := newTestMachineSource(t, okHandler(&n))

	for range 2 {
		if _, err := src.Token(); err != nil {
			t.Fatal(err)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("requests = %d, want 1", n.Load())
	}
	*clock = clock.Add(280 * time.Second)
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 {
		t.Fatalf("requests = %d after 280s, want 2", n.Load())
	}
	src.Expire()
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 3 {
		t.Fatalf("requests = %d after Expire, want 3", n.Load())
	}
}

func TestMachineTokenRevoked(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		for _, code := range []string{"invalid_client", "unauthorized_client", "invalid_grant"} {
			src, _, _ := newTestMachineSource(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"nope"}`))
			})
			_, err := src.Token()
			if !errors.Is(err, ErrMachineRevoked) {
				t.Errorf("%d %s: not ErrMachineRevoked: %v", status, code, err)
			}
			if !IsPermanent(err) {
				t.Errorf("%d %s: not permanent", status, code)
			}
		}
	}
}

func TestMachineTokenOtherClientError(t *testing.T) {
	src, _, _ := newTestMachineSource(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	})
	_, err := src.Token()
	if errors.Is(err, ErrMachineRevoked) || !IsPermanent(err) {
		t.Errorf("err = %v, want permanent non-revoked", err)
	}
}

func TestMachineTokenTransient(t *testing.T) {
	src, _, _ := newTestMachineSource(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	_, err := src.Token()
	if err == nil || errors.Is(err, ErrMachineRevoked) || IsPermanent(err) {
		t.Errorf("503: err = %v", err)
	}

	src, srv, _ := newTestMachineSource(t, nil)
	srv.Close()
	_, err = src.Token()
	if err == nil || errors.Is(err, ErrMachineRevoked) || IsPermanent(err) {
		t.Errorf("network: err = %v", err)
	}
}

func TestMachineTokenNoSecretInError(t *testing.T) {
	var assertion string
	src, _, _ := newTestMachineSource(t, func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		_ = r.ParseForm()
		assertion = r.PostForm.Get("client_assertion")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"bad"}`))
	})
	_, err := src.Token()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), assertion) || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("error leaks a secret: %v", err)
	}
}

func TestNewMachineTokenSourceBadKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewMachineTokenSource(&config.Machine{ClientID: "c", TokenEndpoint: "http://x", ClientKeyFile: path}, nil)
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Errorf("err = %v, want ErrMachineConfig", err)
	}
}

// An answer without expires_in still gets a 300 s expiry, so the token is
// cached.
func TestMachineTokenDefaultLifetime(t *testing.T) {
	var n atomic.Int32
	src, _, clock := newTestMachineSource(t, func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	})
	tok, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if want := clock.Add(machineDefaultLifetime); !tok.Expiry.Equal(want) {
		t.Errorf("expiry = %v, want %v", tok.Expiry, want)
	}
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 1 {
		t.Errorf("requests = %d, want 1", n.Load())
	}
}
