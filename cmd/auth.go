package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate using OIDC device flow",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		ctx := context.Background()
		httpClient := newHTTPClient(insecure)

		oidcCfg, err := api.FetchOIDCConfig(ctx, cfg.API.BaseURL, httpClient)
		if err != nil {
			return fmt.Errorf("fetching OIDC config: %w", err)
		}

		token, err := auth.DeviceFlow(ctx, *oidcCfg, httpClient)
		if err != nil {
			return fmt.Errorf("device flow: %w", err)
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
	Short: "Remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
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

		// Load the raw token first to detect whether a refresh occurred.
		stored, err := config.LoadToken()
		if err != nil {
			fmt.Println("Not authenticated. Run `retyc auth login`.")
			return nil
		}

		ctx := context.Background()
		httpClient := newHTTPClient(insecure)

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

		// Inform the user when a silent refresh happened.
		if !stored.Valid() {
			fmt.Println("Token was expired and has been refreshed silently.")
		}

		fmt.Printf("Authenticated (expires: %s)\n", tok.Expiry.Format("2006-01-02 15:04:05"))
		return nil
	},
}

// newHTTPClient returns an HTTP client configured according to the insecure flag.
// When insecure is true, TLS certificate verification is disabled to allow
// connections to servers using self-signed certificates.
func newHTTPClient(insecure bool) *http.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 — intentional, controlled by --insecure flag
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
}

func init() {
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authLogoutCmd)
	authCmd.AddCommand(authStatusCmd)
	rootCmd.AddCommand(authCmd)
}
