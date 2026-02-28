// Package api — login/OIDC configuration.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/retyc/retyc-cli/internal/config"
)

// publicLoginConfig is the response from POST /login/config/public.
type publicLoginConfig struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// oidcDiscovery holds the relevant fields from the OIDC discovery document.
type oidcDiscovery struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	EndSessionEndpoint          string `json:"end_session_endpoint"`
}

// FetchOIDCConfig retrieves the public OIDC configuration from POST /login/config/public
// and completes it with endpoint URLs from the OIDC discovery document.
// No authentication is required.
func FetchOIDCConfig(ctx context.Context, baseURL string, httpClient *http.Client) (*config.OIDCConfig, error) {
	// Step 1: retrieve issuer, client_id and scopes from the API.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/login/config/public", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching public login config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("public login config: API error %d: %s", resp.StatusCode, string(body))
	}

	var pub publicLoginConfig
	if err := json.NewDecoder(resp.Body).Decode(&pub); err != nil {
		return nil, fmt.Errorf("decoding public login config: %w", err)
	}

	// Step 2: complete with device_authorization_endpoint and token_endpoint
	// from the standard OIDC discovery document.
	discoveryURL := strings.TrimRight(pub.Issuer, "/") + "/.well-known/openid-configuration"
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	resp2, err := httpClient.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		body, _ := io.ReadAll(resp2.Body)
		return nil, fmt.Errorf("OIDC discovery: API error %d: %s", resp2.StatusCode, string(body))
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(resp2.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery: %w", err)
	}

	return &config.OIDCConfig{
		Issuer:        pub.Issuer,
		ClientID:      pub.ClientID,
		Scopes:        pub.Scopes,
		DeviceAuthURL: disc.DeviceAuthorizationEndpoint,
		TokenURL:      disc.TokenEndpoint,
		EndSessionURL: disc.EndSessionEndpoint,
	}, nil
}
