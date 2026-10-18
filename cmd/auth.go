package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication",
}

var offlineLogin bool

// refuseInMachineMode fails, before any network call, a command that only makes
// sense for an interactive login.
func refuseInMachineMode() error {
	if config.MachineMode() {
		return fmt.Errorf("%w: machine account mode: no interactive login", config.ErrMachineConfig)
	}

	return nil
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate using OIDC device flow",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := refuseInMachineMode(); err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		ctx := cmd.Context()
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
			if jsonOutput {
				return printJSON(authLoginJSON{Authenticated: true, OfflineToken: token.RefreshToken})
			}
			fmt.Println("Authentication successful.")
			fmt.Println()
			fmt.Println("Offline token (set as RETYC_TOKEN in CI):")
			fmt.Println(token.RefreshToken)

			return nil
		}

		if err := config.SaveToken(token); err != nil {
			return fmt.Errorf("saving token: %w", err)
		}

		if jsonOutput {
			return printJSON(authLoginJSON{Authenticated: true})
		}
		fmt.Println("Authentication successful.")

		return nil
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke server-side token and remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := refuseInMachineMode(); err != nil {
			return err
		}
		var baseURL string
		if cfg, err := config.Load(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: loading config: %v\n", err)
		} else {
			baseURL = cfg.API.BaseURL
		}
		warnings, err := service.Logout(cmd.Context(), baseURL, newHTTPClient(insecure, debug))
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "warning: %v\n", w)
		}
		if err != nil {
			return err
		}
		if jsonOutput {
			return printJSON(struct {
				LoggedOut bool `json:"logged_out"`
			}{true})
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

		if config.MachineMode() {
			return machineAuthStatus(cmd.Context(), cfg)
		}

		envToken := config.Token()

		// notAuthenticated reports a non-authenticated state: JSON on stdout
		// with --json, otherwise the human message. Exit code stays 0 — this
		// is a status report, not a failure.
		notAuthenticated := func(reason, msg string) error {
			if jsonOutput {
				return printJSON(authStatusJSON{Authenticated: false, Reason: reason})
			}
			fmt.Println(msg)

			return nil
		}

		// Load the stored token from disk to detect silent refreshes and token type.
		// Skipped when RETYC_TOKEN is set (no local credentials in that mode).
		var stored *oauth2.Token
		if envToken == "" {
			stored, err = config.LoadToken()
			if err != nil {
				return notAuthenticated("no_token", "Not authenticated. Run `retyc auth login`.")
			}
		}

		ctx := cmd.Context()
		httpClient := newHTTPClient(insecure, debug)

		oidcCfg, err := api.FetchOIDCConfig(ctx, cfg.API.BaseURL, httpClient)
		if err != nil {
			return fmt.Errorf("fetching OIDC config: %w", err)
		}

		tok, err := auth.GetValidToken(ctx, *oidcCfg, httpClient)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrNoToken):
				return notAuthenticated("no_token", "Not authenticated. Run `retyc auth login`.")
			case errors.Is(err, auth.ErrNoRefreshToken):
				return notAuthenticated("no_refresh_token",
					"Token expired and no refresh token available. Run `retyc auth login`.")
			default:
				return notAuthenticated("refresh_failed: "+err.Error(),
					fmt.Sprintf("Token expired and refresh failed: %v\nRun `retyc auth login`.", err))
			}
		}

		// A silent refresh happened when the disk token was expired (disk token path only).
		refreshed := stored != nil && !stored.Valid()

		// Determine the refresh token to inspect: disk token or RETYC_TOKEN env var.
		refreshToken := envToken
		if stored != nil {
			refreshToken = stored.RefreshToken
		}
		offline := isOfflineToken(refreshToken)

		if jsonOutput {
			expiry := tok.Expiry

			return printJSON(authStatusJSON{
				Authenticated: true, Offline: offline, Refreshed: refreshed, ExpiresAt: &expiry,
			})
		}

		if refreshed {
			fmt.Println("Token was expired and has been refreshed silently.")
		}
		if offline {
			fmt.Printf("Authenticated — offline token (expires: %s)\n", tok.Expiry.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("Authenticated (expires: %s)\n", tok.Expiry.Format("2006-01-02 15:04:05"))
		}

		return nil
	},
}

// machineAuthStatus reports the status of a machine account: the token
// endpoint must hand out a token and the API's active key must be the one of
// age.key. token.json and the OIDC discovery are never touched.
// machineRevokedStatus reports a machine account refused by the identity
// provider or the API: a status, not a failure (exit code 0).
func machineRevokedStatus() error {
	if jsonOutput {
		return printJSON(authStatusJSON{Authenticated: false, Reason: "machine_revoked"})
	}
	fmt.Println("Machine account refused (disabled or deleted?): ask an organization admin to enable it again.")

	return nil
}

func machineAuthStatus(ctx context.Context, cfg *config.Config) error {
	m, err := config.LoadMachine()
	if err != nil {
		return err
	}
	src, err := mustGetToken(ctx, cfg)
	if err != nil {
		return err
	}
	tok, err := src.Token()
	if err != nil {
		if errors.Is(err, auth.ErrMachineRevoked) {
			return machineRevokedStatus()
		}

		return err
	}

	client := api.New(cfg.API.BaseURL, cliUserAgent(), src, insecure, debug,
		apiRetry(cfg), api.WithUnsafeWrite(cfg.API.UnsafeWrite))
	userKey, err := client.GetActiveKey(ctx)
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusUnauthorized {
		// A token was issued but the API refuses the account (disabled).
		return machineRevokedStatus()
	}
	if err != nil {
		return fmt.Errorf("fetching active key: %w", err)
	}
	if _, err := service.MachineIdentity(ctx, userKey); err != nil {
		return err
	}

	if jsonOutput {
		expiry := tok.Expiry

		return printJSON(authStatusJSON{
			Authenticated: true, ExpiresAt: &expiry,
			Mode: "machine", ClientID: m.ClientID, MachineID: m.MachineID,
		})
	}
	fmt.Printf("Authenticated — machine account %s (expires: %s)\n",
		m.ClientID, tok.Expiry.Format("2006-01-02 15:04:05"))

	return nil
}

// newHTTPClient returns an HTTP client configured according to the insecure and debug flags.
// Proxy settings and custom root CAs come from the environment through
// api.BaseTransport.
// When insecure is true, TLS certificate verification is disabled to allow
// connections to servers using self-signed certificates.
// When debug is true, all requests and responses are printed to stderr.
func newHTTPClient(insecure, debug bool) *http.Client {
	var transport http.RoundTripper = api.BaseTransport(insecure)
	if debug {
		transport = &debugTransport{wrapped: transport}
	}
	// One CLIENT span per OIDC round trip (discovery, token refresh, device
	// flow), so the time spent authenticating shows up in the trace.
	transport = telemetry.RoundTripper(transport)
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
	fmt.Fprintf(os.Stderr, "> %s %s%s\n", req.Method, req.URL, api.ProxyLabel(req))

	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // G104: body already fully read, close error irrelevant
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	fmt.Fprintf(os.Stderr, "< %s\n", resp.Status)
	if len(body) > 0 {
		var buf bytes.Buffer
		if json.Indent(&buf, redactDebugBody(body), "  ", "  ") == nil {
			fmt.Fprintf(os.Stderr, "  %s\n", buf.String())
		} else {
			fmt.Fprintf(os.Stderr, "  (%d bytes, binary)\n", len(body))
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))

	return resp, nil
}

// accessTokenField matches the access_token member of a JSON token response.
var accessTokenField = regexp.MustCompile(`("access_token"\s*:\s*)"[^"]*"`)

// clientAssertionField matches the client_assertion field of a form body.
var clientAssertionField = regexp.MustCompile(`(client_assertion=)[^&\s]*`)

// redactDebugBody hides what --debug must never print: the access token of a
// token response and the signed assertion of a machine token request.
func redactDebugBody(body []byte) []byte {
	body = accessTokenField.ReplaceAll(body, []byte(`${1}"[redacted]"`))

	return clientAssertionField.ReplaceAll(body, []byte("${1}[redacted]"))
}

// isOfflineToken reports whether the given JWT refresh token is a Keycloak
// offline token by decoding its payload and checking for typ == "Offline".
// Returns false on any parse error.
func isOfflineToken(refreshToken string) bool {
	parts := strings.SplitN(refreshToken, ".", 3)
	if len(parts) != 3 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
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
	authLoginCmd.Flags().BoolVar(&offlineLogin, "offline", false,
		"Request an offline token for non-interactive use (CI/CD)")
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.AddCommand(authStatusCmd)
	rootCmd.AddCommand(authCmd)
}
