package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication",
}

var offlineLogin bool

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate using OIDC device flow",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		ctx := context.Background()
		httpClient := newHTTPClient(insecure, debug)

		oidcCfg, err := api.FetchOIDCConfig(ctx, cfg.API.BaseURL, httpClient)
		if err != nil {
			return fmt.Errorf("fetching OIDC config: %w", err)
		}

		// In offline mode, request a long-lived offline token (refresh token)
		// suitable for non-interactive use in CI/CD pipelines.
		if offlineLogin {
			oidcCfg.Scopes = append(oidcCfg.Scopes, "offline_access")
		}

		token, err := auth.DeviceFlow(ctx, *oidcCfg, httpClient)
		if err != nil {
			return fmt.Errorf("device flow: %w", err)
		}

		if offlineLogin {
			if token.RefreshToken == "" {
				return fmt.Errorf("server did not return an offline token (check that offline_access scope is supported)")
			}
			// Do not persist to disk: the offline token is intended to be copied
			// into RETYC_TOKEN and used non-interactively in CI/CD pipelines.
			fmt.Println("Authentication successful.")
			fmt.Println()
			fmt.Println("Offline token (set as RETYC_TOKEN in CI):")
			fmt.Println(token.RefreshToken)
			return nil
		}

		if err := config.SaveToken(token); err != nil {
			return fmt.Errorf("saving token: %w", err)
		}

		fmt.Println("Authentication successful.")
		return nil
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke server-side token and remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Attempt server-side revocation before deleting the local token.
		// Failures are non-fatal: local credentials are always cleaned up.
		tok, err := config.LoadToken()
		if err == nil && tok.RefreshToken != "" {
			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: loading config: %v\n", err)
			} else {
				ctx := context.Background()
				httpClient := newHTTPClient(insecure, debug)
				oidcCfg, err := api.FetchOIDCConfig(ctx, cfg.API.BaseURL, httpClient)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: fetching OIDC config: %v\n", err)
				} else if err := auth.Revoke(ctx, *oidcCfg, tok.RefreshToken, httpClient); err != nil {
					fmt.Fprintf(os.Stderr, "warning: revoking token: %v\n", err)
				}
			}
		}

		if err := config.DeleteToken(); err != nil {
			return fmt.Errorf("removing token: %w", err)
		}
		fmt.Println("Logged out.")
		return nil
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		envToken := os.Getenv("RETYC_TOKEN")

		// Load the stored token from disk to detect silent refreshes and token type.
		// Skipped when RETYC_TOKEN is set (no local credentials in that mode).
		var stored *oauth2.Token
		if envToken == "" {
			stored, err = config.LoadToken()
			if err != nil {
				fmt.Println("Not authenticated. Run `retyc auth login`.")
				return nil
			}
		}

		ctx := context.Background()
		httpClient := newHTTPClient(insecure, debug)

		oidcCfg, err := api.FetchOIDCConfig(ctx, cfg.API.BaseURL, httpClient)
		if err != nil {
			return fmt.Errorf("fetching OIDC config: %w", err)
		}

		tok, err := auth.GetValidToken(ctx, *oidcCfg, httpClient)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrNoToken):
				fmt.Println("Not authenticated. Run `retyc auth login`.")
			case errors.Is(err, auth.ErrNoRefreshToken):
				fmt.Println("Token expired and no refresh token available. Run `retyc auth login`.")
			default:
				fmt.Printf("Token expired and refresh failed: %v\nRun `retyc auth login`.\n", err)
			}
			return nil
		}

		// Inform the user when a silent refresh happened (disk token path only).
		if stored != nil && !stored.Valid() {
			fmt.Println("Token was expired and has been refreshed silently.")
		}

		// Determine the refresh token to inspect: disk token or RETYC_TOKEN env var.
		refreshToken := envToken
		if stored != nil {
			refreshToken = stored.RefreshToken
		}

		if isOfflineToken(refreshToken) {
			fmt.Printf("Authenticated — offline token (expires: %s)\n", tok.Expiry.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("Authenticated (expires: %s)\n", tok.Expiry.Format("2006-01-02 15:04:05"))
		}
		return nil
	},
}

// newHTTPClient returns an HTTP client configured according to the insecure and debug flags.
// When insecure is true, TLS certificate verification is disabled to allow
// connections to servers using self-signed certificates.
// When debug is true, all requests and responses are printed to stderr.
func newHTTPClient(insecure, debug bool) *http.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 — intentional, controlled by --insecure flag
	}
	var transport http.RoundTripper = &http.Transport{TLSClientConfig: tlsCfg}
	if debug {
		transport = &debugTransport{wrapped: transport}
	}
	transport = &api.UserAgentTransport{UserAgent: cliUserAgent(), Base: transport}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// debugTransport is an http.RoundTripper that logs requests and responses to stderr.
type debugTransport struct {
	wrapped http.RoundTripper
}

func (t *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Fprintf(os.Stderr, "> %s %s\n", req.Method, req.URL)

	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	fmt.Fprintf(os.Stderr, "< %s\n", resp.Status)
	if len(body) > 0 {
		var buf bytes.Buffer
		if json.Indent(&buf, body, "  ", "  ") == nil {
			fmt.Fprintf(os.Stderr, "  %s\n", buf.String())
		} else {
			fmt.Fprintf(os.Stderr, "  (%d bytes, binary)\n", len(body))
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// isOfflineToken reports whether the given JWT refresh token is a Keycloak
// offline token by decoding its payload and checking for typ == "Offline".
// Returns false on any parse error.
func isOfflineToken(refreshToken string) bool {
	parts := strings.SplitN(refreshToken, ".", 3)
	if len(parts) != 3 {
		return false
	}
	// base64url → base64 standard, add padding
	payload := parts[1]
	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var claims struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return false
	}
	return strings.EqualFold(claims.Typ, "Offline")
}

func init() {
	authLoginCmd.Flags().BoolVar(&offlineLogin, "offline", false, "Request an offline token for non-interactive use (CI/CD)")
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.AddCommand(authStatusCmd)
	rootCmd.AddCommand(authCmd)
}
