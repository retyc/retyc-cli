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
	"os"
	"strings"
	"sync"
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

// ErrDeviceCodeExpired is returned by PollToken when the device code has expired.
var ErrDeviceCodeExpired = errors.New("device code expired")

// ErrAccessDenied is returned by PollToken when the user explicitly denied access.
var ErrAccessDenied = errors.New("access denied by user")

// ErrSlowDown is returned by PollToken when the server requests a slower polling rate.
var ErrSlowDown = errors.New("slow down: poll less frequently")

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
	devResp, err := RequestDeviceCode(cfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}

	// Prompt the user to visit the verification URI
	fmt.Printf("\nOpen the following URL in your browser:\n\n  %s\n\n", devResp.VerificationURIComplete)
	fmt.Printf("Enter code: %s\n\n", devResp.UserCode)

	spinner := ui.NewSpinner("Waiting for authentication…")
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
		tok, err := PollToken(cfg, devResp.DeviceCode, httpClient)
		if err != nil {
			if !errors.Is(err, ErrSlowDown) {
				return nil, err
			}
			// RFC 8628 §3.5: slow_down requires increasing the polling interval by 5s.
			interval += 5 * time.Second
		}
		if tok != nil {
			return tok, nil
		}

		// authorization_pending or slow_down — wait before next poll
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}

	return nil, ErrDeviceCodeExpired
}

// RequestDeviceCode calls the device authorization endpoint.
func RequestDeviceCode(cfg config.OIDCConfig, httpClient *http.Client) (*DeviceAuthResponse, error) {
	data := url.Values{
		"client_id": {cfg.ClientID},
		"scope":     {strings.Join(cfg.Scopes, " ")},
	}

	resp, err := httpClient.PostForm(cfg.DeviceAuthURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

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

// PollToken exchanges a device code for tokens at the token endpoint.
// Returns (token, nil) on success, (nil, nil) when authorization is pending,
// ErrSlowDown when the server requests a reduced polling rate,
// ErrDeviceCodeExpired when the code has expired, ErrAccessDenied when the
// user denied access, or a non-nil error for unexpected failures.
func PollToken(cfg config.OIDCConfig, deviceCode string, httpClient *http.Client) (*oauth2.Token, error) {
	data := url.Values{
		"client_id":   {cfg.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	resp, err := httpClient.PostForm(cfg.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response body: %w", err)
	}

	// A non-2xx status that carries no recognised error field is unexpected.
	// Try to decode anyway — RFC 8628 errors (authorization_pending, etc.)
	// are returned as 4xx with a JSON body; fall through to the switch below.
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decoding token response (status %d): %w — body: %s", resp.StatusCode, err, string(body))
	}

	switch tr.Error {
	case "":
		return tokenFromResponse(tr), nil
	case "authorization_pending":
		return nil, nil
	case "slow_down":
		return nil, ErrSlowDown
	case "expired_token":
		return nil, ErrDeviceCodeExpired
	case "access_denied":
		return nil, ErrAccessDenied
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
func Refresh(
	ctx context.Context, cfg config.OIDCConfig, refreshToken string, httpClient *http.Client,
) (*oauth2.Token, error) {
	data := url.Values{
		"client_id":     {cfg.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading refresh response body: %w", err)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decoding refresh response (status %d): %w — body: %s", resp.StatusCode, err, string(body))
	}

	if tr.Error != "" {
		if tr.Error == "invalid_grant" {
			// Refresh token is expired or revoked — caller must re-authenticate.
			return nil, fmt.Errorf("refresh token invalid or expired (%s): %w", tr.ErrorDesc, ErrNoRefreshToken)
		}

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

// Revoke terminates the server-side session by calling the OIDC end_session
// endpoint with the refresh token (Keycloak backchannel logout).
// Unlike RFC 7009 token revocation, this actually closes the session visible
// in the identity provider's admin panel.
func Revoke(ctx context.Context, cfg config.OIDCConfig, refreshToken string, httpClient *http.Client) error {
	if cfg.EndSessionURL == "" {
		return fmt.Errorf("OIDC end_session endpoint not available")
	}

	data := url.Values{
		"client_id":     {cfg.ClientID},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EndSessionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("end_session endpoint returned %d (could not read body: %w)", resp.StatusCode, readErr)
		}

		return fmt.Errorf("end_session endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RefreshingTokenSource is an oauth2.TokenSource that transparently refreshes
// the access token when it expires. It is safe for concurrent use.
// When persist is true, a successfully refreshed token is saved to disk so
// that the next invocation of the CLI does not need to re-authenticate.
type RefreshingTokenSource struct {
	mu         sync.Mutex
	tok        *oauth2.Token
	cfg        config.OIDCConfig
	httpClient *http.Client
	persist    bool
}

// NewRefreshingTokenSource returns a TokenSource that refreshes tok automatically.
// Set persist to true when the token was loaded from disk (interactive sessions);
// set it to false for the RETYC_TOKEN env-var path (CI/CD, no disk state).
func NewRefreshingTokenSource(
	tok *oauth2.Token,
	cfg config.OIDCConfig,
	httpClient *http.Client,
	persist bool,
) oauth2.TokenSource {
	return &RefreshingTokenSource{tok: tok, cfg: cfg, httpClient: httpClient, persist: persist}
}

// Token returns a valid access token, refreshing it if necessary.
func (s *RefreshingTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tok.Valid() {
		return s.tok, nil
	}
	if s.tok.RefreshToken == "" {
		return nil, ErrNoRefreshToken
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	newTok, err := Refresh(ctx, s.cfg, s.tok.RefreshToken, s.httpClient)
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}

	if s.persist {
		if err := config.SaveToken(newTok); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving refreshed token: %v\n", err)
		}
	}

	s.tok = newTok

	return newTok, nil
}

// GetValidToken returns a valid token for the current session.
//
// If the RETYC_TOKEN environment variable is set, it is treated as an offline
// refresh token: it is exchanged for a fresh access token without reading from
// or writing to disk. This is the intended path for non-interactive CI/CD use.
//
// Otherwise it loads the stored token from disk and returns it immediately if
// it is still valid. If it has expired and a refresh token is available, it
// attempts a silent refresh and persists the new token before returning it.
//
// Callers should handle ErrNoToken (not authenticated) and ErrNoRefreshToken
// (expired, must re-authenticate via DeviceFlow) as non-fatal states.
func GetValidToken(ctx context.Context, cfg config.OIDCConfig, httpClient *http.Client) (*oauth2.Token, error) {
	// CI/CD path: RETYC_TOKEN holds an offline refresh token.
	// Exchange it for a fresh access token without touching disk.
	// If the env token is expired or revoked (ErrNoRefreshToken / invalid_grant),
	// fall through to the disk token so that users who logged in interactively
	// via the MCP device flow are not locked out when RETYC_TOKEN is also set.
	if envToken := os.Getenv("RETYC_TOKEN"); envToken != "" {
		tok, err := Refresh(ctx, cfg, envToken, httpClient)
		if err != nil {
			if !errors.Is(err, ErrNoRefreshToken) {
				return nil, fmt.Errorf("RETYC_TOKEN refresh failed: %w", err)
			}
			// ErrNoRefreshToken (invalid_grant): fall through to disk token.
		} else {
			return tok, nil
		}
	}

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
