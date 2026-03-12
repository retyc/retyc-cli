package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchOIDCConfig_Success(t *testing.T) {
	// srv is referenced inside the handler to build the issuer URL dynamically.
	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/config/public":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":    srv.URL,
				"client_id": "device",
				"scopes":    []string{"openid", "offline_access"},
			})

		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"device_authorization_endpoint": srv.URL + "/device",
				"token_endpoint":                srv.URL + "/token",
				"end_session_endpoint":          srv.URL + "/logout",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg, err := FetchOIDCConfig(context.Background(), srv.URL, http.DefaultClient)
	if err != nil {
		t.Fatalf("FetchOIDCConfig() error = %v", err)
	}

	if cfg.Issuer != srv.URL {
		t.Errorf("Issuer = %q, want %q", cfg.Issuer, srv.URL)
	}

	if cfg.ClientID != "device" {
		t.Errorf("ClientID = %q, want device", cfg.ClientID)
	}

	if cfg.DeviceAuthURL != srv.URL+"/device" {
		t.Errorf("DeviceAuthURL = %q, want %q", cfg.DeviceAuthURL, srv.URL+"/device")
	}

	if cfg.TokenURL != srv.URL+"/token" {
		t.Errorf("TokenURL = %q, want %q", cfg.TokenURL, srv.URL+"/token")
	}

	if cfg.EndSessionURL != srv.URL+"/logout" {
		t.Errorf("EndSessionURL = %q, want %q", cfg.EndSessionURL, srv.URL+"/logout")
	}
}

func TestFetchOIDCConfig_LoginEndpointError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchOIDCConfig(context.Background(), srv.URL, http.DefaultClient)
	if err == nil {
		t.Error("FetchOIDCConfig() should return error when login endpoint returns 500")
	}
}

func TestFetchOIDCConfig_InvalidLoginJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	_, err := FetchOIDCConfig(context.Background(), srv.URL, http.DefaultClient)
	if err == nil {
		t.Error("FetchOIDCConfig() should return error for invalid login config JSON")
	}
}

func TestFetchOIDCConfig_DiscoveryError(t *testing.T) {
	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/config/public":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":    srv.URL,
				"client_id": "device",
				"scopes":    []string{"openid"},
			})

		default:
			http.Error(w, "discovery unavailable", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	_, err := FetchOIDCConfig(context.Background(), srv.URL, http.DefaultClient)
	if err == nil {
		t.Error("FetchOIDCConfig() should return error when OIDC discovery returns 500")
	}
}

func TestFetchOIDCConfig_InvalidDiscoveryJSON(t *testing.T) {
	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/config/public":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":    srv.URL,
				"client_id": "device",
				"scopes":    []string{"openid"},
			})

		default:
			fmt.Fprint(w, "not valid json {{")
		}
	}))
	defer srv.Close()

	_, err := FetchOIDCConfig(context.Background(), srv.URL, http.DefaultClient)
	if err == nil {
		t.Error("FetchOIDCConfig() should return error for invalid discovery JSON")
	}
}
