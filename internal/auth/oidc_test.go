package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"golang.org/x/oauth2"
)

func TestTokenFromResponse_WithExpiry(t *testing.T) {
	tr := TokenResponse{
		AccessToken:  "access",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		ExpiresIn:    3600,
	}

	before := time.Now()
	tok := tokenFromResponse(tr)
	after := time.Now()

	if tok.AccessToken != "access" {
		t.Errorf("AccessToken = %q, want access", tok.AccessToken)
	}

	if tok.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", tok.TokenType)
	}

	if tok.RefreshToken != "refresh" {
		t.Errorf("RefreshToken = %q, want refresh", tok.RefreshToken)
	}

	low := before.Add(3600 * time.Second)
	high := after.Add(3600 * time.Second)

	if tok.Expiry.Before(low) || tok.Expiry.After(high) {
		t.Errorf("Expiry = %v, want between %v and %v", tok.Expiry, low, high)
	}
}

func TestTokenFromResponse_ZeroExpiry(t *testing.T) {
	tr := TokenResponse{AccessToken: "access", ExpiresIn: 0}

	tok := tokenFromResponse(tr)
	if !tok.Expiry.IsZero() {
		t.Errorf("Expiry should be zero when ExpiresIn=0, got %v", tok.Expiry)
	}
}

func TestRequestDeviceCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DeviceAuthResponse{
			DeviceCode:              "dev-code-123",
			UserCode:                "ABCD-1234",
			VerificationURIComplete: "https://example.com/activate?code=ABCD-1234",
			ExpiresIn:               300,
			Interval:                5,
		})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test-client", Scopes: []string{"openid"}, DeviceAuthURL: srv.URL}

	resp, err := RequestDeviceCode(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("RequestDeviceCode() error = %v", err)
	}

	if resp.DeviceCode != "dev-code-123" {
		t.Errorf("DeviceCode = %q, want dev-code-123", resp.DeviceCode)
	}

	if resp.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want ABCD-1234", resp.UserCode)
	}
}

func TestRequestDeviceCode_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{DeviceAuthURL: srv.URL}

	_, err := RequestDeviceCode(cfg, http.DefaultClient)
	if err == nil {
		t.Error("RequestDeviceCode() should return error for non-2xx status")
	}
}

func TestRequestDeviceCode_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not valid json")
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{DeviceAuthURL: srv.URL}

	_, err := RequestDeviceCode(cfg, http.DefaultClient)
	if err == nil {
		t.Error("RequestDeviceCode() should return error for invalid JSON")
	}
}

func TestPollToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenResponse{ //nolint:gosec // G117: test fixture, not real credentials
			AccessToken:  "new-access-token",
			TokenType:    "Bearer",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := PollToken(cfg, "device-code", http.DefaultClient)
	if err != nil {
		t.Fatalf("PollToken() error = %v", err)
	}

	if tok == nil {
		t.Fatal("PollToken() returned nil token")
	}

	if tok.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want new-access-token", tok.AccessToken)
	}
}

func TestPollToken_AuthorizationPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := PollToken(cfg, "device-code", http.DefaultClient)
	if err != nil {
		t.Errorf("PollToken() error = %v, want nil for authorization_pending", err)
	}

	if tok != nil {
		t.Error("PollToken() should return nil token for authorization_pending")
	}
}

func TestPollToken_SlowDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := PollToken(cfg, "device-code", http.DefaultClient)
	if !errors.Is(err, ErrSlowDown) || tok != nil {
		t.Errorf("PollToken() = (%v, %v), want (nil, ErrSlowDown) for slow_down", tok, err)
	}
}

func TestPollToken_ExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	_, err := PollToken(cfg, "device-code", http.DefaultClient)
	if err == nil {
		t.Error("PollToken() should return error for expired_token")
	}
}

func TestPollToken_AccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	_, err := PollToken(cfg, "device-code", http.DefaultClient)
	if err == nil {
		t.Error("PollToken() should return error for access_denied")
	}
}

func TestPollToken_UnknownError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "custom_error",
			"error_description": "something went wrong",
		})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	_, err := PollToken(cfg, "device-code", http.DefaultClient)
	if err == nil {
		t.Error("PollToken() should return error for unknown error field")
	}
}

func TestPollToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json at all")
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	_, err := PollToken(cfg, "device-code", http.DefaultClient)
	if err == nil {
		t.Error("PollToken() should return error for invalid JSON response")
	}
}

func TestRefresh_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenResponse{ //nolint:gosec // G117: test fixture, not real credentials
			AccessToken:  "fresh-access",
			TokenType:    "Bearer",
			RefreshToken: "new-refresh",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := Refresh(context.Background(), cfg, "old-refresh-token", http.DefaultClient)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if tok.AccessToken != "fresh-access" {
		t.Errorf("AccessToken = %q, want fresh-access", tok.AccessToken)
	}

	if tok.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want new-refresh", tok.RefreshToken)
	}
}

func TestRefresh_PreservesRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server omits refresh_token — the original must be preserved.
		_ = json.NewEncoder(w).Encode(TokenResponse{ //nolint:gosec // G117: test fixture, not real credentials
			AccessToken: "fresh-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := Refresh(context.Background(), cfg, "original-refresh", http.DefaultClient)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if tok.RefreshToken != "original-refresh" {
		t.Errorf("RefreshToken = %q, want original-refresh (should be preserved)", tok.RefreshToken)
	}
}

func TestRefresh_InvalidGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "token expired",
		})
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	_, err := Refresh(context.Background(), cfg, "bad-token", http.DefaultClient)
	if err == nil {
		t.Fatal("Refresh() should return error for invalid_grant")
	}

	if !errors.Is(err, ErrNoRefreshToken) {
		t.Errorf("Refresh() error = %v, want errors.Is(err, ErrNoRefreshToken) to be true", err)
	}
}

func TestGetValidToken_EnvToken_InvalidGrant_NoDiskToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Invalid refresh token",
		})
	}))
	defer srv.Close()

	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "expired-offline-token")

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	_, err := GetValidToken(context.Background(), cfg, http.DefaultClient)
	if err == nil {
		t.Fatal("GetValidToken() should return error when RETYC_TOKEN fails and no disk token exists")
	}

	if !errors.Is(err, ErrNoToken) {
		t.Errorf("GetValidToken() error = %v, want errors.Is(err, ErrNoToken) to be true", err)
	}
}

func TestGetValidToken_EnvToken_InvalidGrant_FallbackToDisk(t *testing.T) {
	// RETYC_TOKEN is set but expired; a valid token was saved to disk (e.g. via
	// MCP device flow). GetValidToken should fall through to the disk token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Invalid refresh token",
		})
	}))
	defer srv.Close()

	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "expired-offline-token")

	diskTok := &oauth2.Token{
		AccessToken:  "disk-access-token",
		TokenType:    "Bearer",
		RefreshToken: "disk-refresh",
		Expiry:       time.Now().Add(time.Hour),
	}
	if err := config.SaveToken(diskTok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := GetValidToken(context.Background(), cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("GetValidToken() should fall back to disk token, got error: %v", err)
	}

	if tok.AccessToken != "disk-access-token" {
		t.Errorf("AccessToken = %q, want disk-access-token", tok.AccessToken)
	}
}

func TestRevoke_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", EndSessionURL: srv.URL}

	if err := Revoke(context.Background(), cfg, "refresh-token", http.DefaultClient); err != nil {
		t.Errorf("Revoke() error = %v", err)
	}
}

func TestRevoke_NoEndpointURL(t *testing.T) {
	cfg := config.OIDCConfig{EndSessionURL: ""}

	err := Revoke(context.Background(), cfg, "token", http.DefaultClient)
	if err == nil {
		t.Error("Revoke() should return error when EndSessionURL is empty")
	}
}

func TestRevoke_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	cfg := config.OIDCConfig{ClientID: "test", EndSessionURL: srv.URL}

	if err := Revoke(context.Background(), cfg, "refresh-token", http.DefaultClient); err == nil {
		t.Error("Revoke() should return error for non-2xx status")
	}
}

func TestRefreshingTokenSource_ValidToken(t *testing.T) {
	validTok := &oauth2.Token{
		AccessToken:  "valid-access",
		TokenType:    "Bearer",
		RefreshToken: "some-refresh",
		Expiry:       time.Now().Add(time.Hour),
	}

	src := NewRefreshingTokenSource(validTok, config.OIDCConfig{}, http.DefaultClient, false)

	got, err := src.Token()
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if got.AccessToken != "valid-access" {
		t.Errorf("AccessToken = %q, want valid-access", got.AccessToken)
	}
}

func TestRefreshingTokenSource_ExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenResponse{ //nolint:gosec // G117: test fixture, not real credentials
			AccessToken:  "refreshed-access",
			TokenType:    "Bearer",
			RefreshToken: "new-refresh",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())

	expiredTok := &oauth2.Token{
		AccessToken:  "expired-access",
		RefreshToken: "valid-refresh",
		Expiry:       time.Now().Add(-time.Hour),
	}

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}
	src := NewRefreshingTokenSource(expiredTok, cfg, http.DefaultClient, true)

	got, err := src.Token()
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if got.AccessToken != "refreshed-access" {
		t.Errorf("AccessToken = %q, want refreshed-access", got.AccessToken)
	}
}

func TestRefreshingTokenSource_NoRefreshToken(t *testing.T) {
	expiredTok := &oauth2.Token{
		AccessToken: "expired",
		Expiry:      time.Now().Add(-time.Hour),
	}

	src := NewRefreshingTokenSource(expiredTok, config.OIDCConfig{}, http.DefaultClient, false)

	_, err := src.Token()
	if err == nil {
		t.Fatal("Token() should return error when token expired and no refresh token available")
	}

	if err != ErrNoRefreshToken {
		t.Errorf("error = %v, want ErrNoRefreshToken", err)
	}
}

func TestGetValidToken_EnvToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenResponse{ //nolint:gosec // G117: test fixture, not real credentials
			AccessToken: "env-refreshed-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	t.Setenv("RETYC_TOKEN", "offline-token")

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := GetValidToken(context.Background(), cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("GetValidToken() error = %v", err)
	}

	if tok.AccessToken != "env-refreshed-token" {
		t.Errorf("AccessToken = %q, want env-refreshed-token", tok.AccessToken)
	}
}

func TestGetValidToken_ValidStored(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")

	validTok := &oauth2.Token{
		AccessToken:  "stored-valid-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(time.Hour),
	}

	if err := config.SaveToken(validTok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	tok, err := GetValidToken(context.Background(), config.OIDCConfig{}, http.DefaultClient)
	if err != nil {
		t.Fatalf("GetValidToken() error = %v", err)
	}

	if tok.AccessToken != "stored-valid-token" {
		t.Errorf("AccessToken = %q, want stored-valid-token", tok.AccessToken)
	}
}

func TestGetValidToken_ExpiredWithRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenResponse{ //nolint:gosec // G117: test fixture, not real credentials
			AccessToken:  "refreshed-token",
			TokenType:    "Bearer",
			RefreshToken: "new-refresh",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")

	expiredTok := &oauth2.Token{
		AccessToken:  "expired",
		RefreshToken: "valid-refresh",
		Expiry:       time.Now().Add(-time.Hour),
	}

	if err := config.SaveToken(expiredTok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	cfg := config.OIDCConfig{ClientID: "test", TokenURL: srv.URL}

	tok, err := GetValidToken(context.Background(), cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("GetValidToken() error = %v", err)
	}

	if tok.AccessToken != "refreshed-token" {
		t.Errorf("AccessToken = %q, want refreshed-token", tok.AccessToken)
	}
}

func TestGetValidToken_ExpiredNoRefresh(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")

	expiredTok := &oauth2.Token{
		AccessToken: "expired",
		Expiry:      time.Now().Add(-time.Hour),
	}

	if err := config.SaveToken(expiredTok); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	_, err := GetValidToken(context.Background(), config.OIDCConfig{}, http.DefaultClient)
	if err == nil {
		t.Fatal("GetValidToken() should return error when token expired and no refresh token")
	}

	if err != ErrNoRefreshToken {
		t.Errorf("error = %v, want ErrNoRefreshToken", err)
	}
}

func TestGetValidToken_NoToken(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")

	_, err := GetValidToken(context.Background(), config.OIDCConfig{}, http.DefaultClient)
	if err == nil {
		t.Fatal("GetValidToken() should return error when no token stored")
	}

	if err != ErrNoToken {
		t.Errorf("error = %v, want ErrNoToken", err)
	}
}
