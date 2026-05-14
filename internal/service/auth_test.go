package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"golang.org/x/oauth2"
)

// oidcTestServer creates a test server that handles the two OIDC discovery
// endpoints required by FetchOIDCConfig, plus a /token endpoint driven by
// tokenHandler. It also handles /device (device auth) and /logout.
func oidcTestServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/config/public":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":    srv.URL,
				"client_id": "test",
				"scopes":    []string{"openid"},
			})
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_authorization_endpoint": srv.URL + "/device",
				"token_endpoint":                srv.URL + "/token",
				"end_session_endpoint":          srv.URL + "/logout",
			})
		case "/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "test-device-code",
				"user_code":                 "ABCD-1234",
				"verification_uri":          srv.URL + "/activate",
				"verification_uri_complete": srv.URL + "/activate?code=ABCD-1234",
				"expires_in":                300,
				"interval":                  5,
			})
		case "/token":
			tokenHandler(w, r)
		case "/logout":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	// Reset the OIDC cache so each test starts clean.
	oidcCache.Lock()
	oidcCache.entries = nil
	oidcCache.Unlock()
	t.Cleanup(func() {
		srv.Close()
		oidcCache.Lock()
		oidcCache.entries = nil
		oidcCache.Unlock()
	})

	return srv
}

// — LoginPoll ————————————————————————————————————————————————————————————————

func TestLoginPoll_Pending(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	srv := oidcTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
	})

	result, err := LoginPoll(context.Background(), srv.URL, "code", http.DefaultClient)
	if err != nil {
		t.Fatalf("LoginPoll() error = %v", err)
	}
	if result.Status != PollPending {
		t.Errorf("Status = %q, want %q", result.Status, PollPending)
	}
}

func TestLoginPoll_Expired(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	srv := oidcTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
	})

	result, err := LoginPoll(context.Background(), srv.URL, "code", http.DefaultClient)
	if err != nil {
		t.Fatalf("LoginPoll() error = %v", err)
	}
	if result.Status != PollExpired {
		t.Errorf("Status = %q, want %q", result.Status, PollExpired)
	}
}

func TestLoginPoll_Denied(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	srv := oidcTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	})

	result, err := LoginPoll(context.Background(), srv.URL, "code", http.DefaultClient)
	if err != nil {
		t.Fatalf("LoginPoll() error = %v", err)
	}
	if result.Status != PollDenied {
		t.Errorf("Status = %q, want %q", result.Status, PollDenied)
	}
}

func TestLoginPoll_SlowDown(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	srv := oidcTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
	})

	result, err := LoginPoll(context.Background(), srv.URL, "code", http.DefaultClient)
	if err != nil {
		t.Fatalf("LoginPoll() error = %v", err)
	}
	if result.Status != PollSlowDown {
		t.Errorf("Status = %q, want %q", result.Status, PollSlowDown)
	}
	if result.ExtraDelaySecs != 5 {
		t.Errorf("ExtraDelaySecs = %d, want 5", result.ExtraDelaySecs)
	}
}

func TestLoginPoll_Done(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")
	srv := oidcTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G117: test fixture, not real credentials
			"access_token":  "new-access",
			"token_type":    "Bearer",
			"refresh_token": "new-refresh",
			"expires_in":    3600,
		})
	})

	result, err := LoginPoll(context.Background(), srv.URL, "code", http.DefaultClient)
	if err != nil {
		t.Fatalf("LoginPoll() error = %v", err)
	}
	if result.Status != PollDone {
		t.Errorf("Status = %q, want %q", result.Status, PollDone)
	}
	if result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set on PollDone")
	}

	// Verify token was saved to disk.
	tok, err := config.LoadToken()
	if err != nil {
		t.Fatalf("LoadToken() after poll error = %v", err)
	}
	if tok.AccessToken != "new-access" {
		t.Errorf("saved AccessToken = %q, want new-access", tok.AccessToken)
	}
}

// — LoginStart ———————————————————————————————————————————————————————————————

func TestLoginStart_AlreadyAuthenticated(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")
	srv := oidcTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("token endpoint should not be called when already authenticated")
	})

	validTok := &oauth2.Token{
		AccessToken: "valid",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	if err := config.SaveToken(validTok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	result, err := LoginStart(context.Background(), srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("LoginStart() error = %v", err)
	}
	if !result.AlreadyAuthenticated {
		t.Error("AlreadyAuthenticated should be true")
	}
	if result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
}

func TestLoginStart_StartsDeviceFlow(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")
	srv := oidcTestServer(t, nil)

	result, err := LoginStart(context.Background(), srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("LoginStart() error = %v", err)
	}
	if result.AlreadyAuthenticated {
		t.Error("AlreadyAuthenticated should be false")
	}
	if result.DeviceCode != "test-device-code" {
		t.Errorf("DeviceCode = %q, want test-device-code", result.DeviceCode)
	}
	if result.Interval != 5 {
		t.Errorf("Interval = %d, want 5", result.Interval)
	}
	if result.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want 300", result.ExpiresIn)
	}
}

// — Logout ————————————————————————————————————————————————————————————————————

func TestLogout_Success(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")
	srv := oidcTestServer(t, nil)

	tok := &oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(time.Hour),
	}
	if err := config.SaveToken(tok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	warnings, err := Logout(context.Background(), srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}

	// Token file should be gone.
	if _, lerr := config.LoadToken(); lerr == nil {
		t.Error("token should have been deleted")
	}
}

func TestLogout_RevocationWarning(t *testing.T) {
	// Unreachable base URL → FetchOIDCConfig fails → warning, not error.
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")
	// Reset cache so the bad URL doesn't interfere with other tests.
	oidcCache.Lock()
	oidcCache.entries = nil
	oidcCache.Unlock()

	tok := &oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(time.Hour),
	}
	if err := config.SaveToken(tok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	warnings, err := Logout(context.Background(), "http://127.0.0.1:0", http.DefaultClient)
	if err != nil {
		t.Fatalf("Logout() should succeed even when revocation fails, got error = %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected at least one warning for failed revocation")
	}

	// Local token must still be deleted despite the warning.
	if _, lerr := config.LoadToken(); lerr == nil {
		t.Error("token should have been deleted even when revocation failed")
	}
}
