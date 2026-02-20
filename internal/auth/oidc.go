// Package auth provides OIDC authentication via the device authorization flow.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/ui"
	"golang.org/x/oauth2"
)

// ErrNoToken is returned when no token is stored on disk.
var ErrNoToken = errors.New("no stored token")

// ErrNoRefreshToken is returned when the stored token is expired and has no
// refresh token to attempt a silent renewal.
var ErrNoRefreshToken = errors.New("token expired and no refresh token available")

// DeviceAuthResponse holds the response from the device authorization endpoint.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse holds the token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// DeviceFlow performs OIDC authentication using the RFC 8628 device authorization grant.
// It prints the user code and verification URI, then polls until the user authenticates
// or the code expires.
//
// httpClient is used for all requests; pass an insecure client to accept self-signed
// TLS certificates (e.g. in development environments).
func DeviceFlow(ctx context.Context, cfg config.OIDCConfig, httpClient *http.Client) (*oauth2.Token, error) {
	// Step 1: request a device code
	devResp, err := requestDeviceCode(cfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}

	// Prompt the user to visit the verification URI
	fmt.Printf("\nOpen the following URL in your browser:\n\n  %s\n\n", devResp.VerificationURIComplete)
	fmt.Printf("Enter code: %s\n\n", devResp.UserCode)

	spinner := ui.New("Waiting for authentication…")
	spinner.Start()
	defer spinner.Stop()

	// Step 2: poll the token endpoint
	interval := time.Duration(devResp.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}
	expiresIn := devResp.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 300 // default to 5 minutes if the server did not specify
	}
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Poll first, then wait: RFC 8628 requires waiting between *subsequent*
	// requests, so the initial poll can happen immediately. This makes the
	// response feel instantaneous when the user authenticates right away.
	for time.Now().Before(deadline) {
		tok, err := pollToken(cfg, devResp.DeviceCode, httpClient)
		if err != nil {
			return nil, err
		}
		if tok != nil {
			return tok, nil
		}

		// authorization_pending — wait before next poll
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}

	return nil, fmt.Errorf("device code expired")
}

// requestDeviceCode calls the device authorization endpoint.
func requestDeviceCode(cfg config.OIDCConfig, httpClient *http.Client) (*DeviceAuthResponse, error) {
	data := url.Values{
		"client_id": {cfg.ClientID},
		"scope":     {strings.Join(cfg.Scopes, " ")},
	}

	resp, err := httpClient.PostForm(cfg.DeviceAuthURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("device authorization endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var dar DeviceAuthResponse
	if err := json.Unmarshal(body, &dar); err != nil {
		return nil, fmt.Errorf("decoding device auth response: %w", err)
	}
	return &dar, nil
}

// pollToken exchanges a device code for tokens at the token endpoint.
// Returns nil, nil when the authorization is still pending.
func pollToken(cfg config.OIDCConfig, deviceCode string, httpClient *http.Client) (*oauth2.Token, error) {
	data := url.Values{
		"client_id":   {cfg.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	resp, err := httpClient.PostForm(cfg.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response body: %w", err)
	}

	// A non-2xx status that carries no recognised error field is unexpected.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to decode anyway — RFC 8628 errors (authorization_pending, etc.)
		// are returned as 4xx with a JSON body; fall through to the switch below.
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decoding token response (status %d): %w — body: %s", resp.StatusCode, err, string(body))
	}

	switch tr.Error {
	case "":
		return tokenFromResponse(tr), nil
	case "authorization_pending", "slow_down":
		return nil, nil
	case "expired_token":
		return nil, fmt.Errorf("device code expired")
	case "access_denied":
		return nil, fmt.Errorf("access denied by user")
	default:
		return nil, fmt.Errorf("token error %s: %s", tr.Error, tr.ErrorDesc)
	}
}

// tokenFromResponse converts a TokenResponse into an *oauth2.Token.
func tokenFromResponse(tr TokenResponse) *oauth2.Token {
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tok
}

// Refresh exchanges a refresh token for a new set of tokens.
// If the server does not return a new refresh token, the original one is
// preserved so that subsequent refreshes remain possible.
func Refresh(ctx context.Context, cfg config.OIDCConfig, refreshToken string, httpClient *http.Client) (*oauth2.Token, error) {
	data := url.Values{
		"client_id":     {cfg.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	resp, err := httpClient.PostForm(cfg.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading refresh response body: %w", err)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decoding refresh response (status %d): %w — body: %s", resp.StatusCode, err, string(body))
	}

	if tr.Error != "" {
		return nil, fmt.Errorf("refresh error %s: %s", tr.Error, tr.ErrorDesc)
	}

	tok := tokenFromResponse(tr)

	// Some servers omit the refresh token in the response when it has not been
	// rotated; carry the original forward so it remains usable.
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}

	return tok, nil
}

// GetValidToken returns a valid token for the current session.
//
// It loads the stored token from disk and returns it immediately if it is
// still valid. If it has expired and a refresh token is available, it
// attempts a silent refresh and persists the new token before returning it.
//
// Callers should handle ErrNoToken (not authenticated) and ErrNoRefreshToken
// (expired, must re-authenticate via DeviceFlow) as non-fatal states.
func GetValidToken(ctx context.Context, cfg config.OIDCConfig, httpClient *http.Client) (*oauth2.Token, error) {
	tok, err := config.LoadToken()
	if err != nil {
		return nil, ErrNoToken
	}

	if tok.Valid() {
		return tok, nil
	}

	// Token is expired — attempt a silent refresh.
	if tok.RefreshToken == "" {
		return nil, ErrNoRefreshToken
	}

	newTok, err := Refresh(ctx, cfg, tok.RefreshToken, httpClient)
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}

	if err := config.SaveToken(newTok); err != nil {
		return nil, fmt.Errorf("saving refreshed token: %w", err)
	}

	return newTok, nil
}
