// Package cmd — admin command group (organization public API).
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Organization administration (API key required)",
	Long: `Administer the organization through the Retyc public API.

Authentication uses an organization API key (ryc_...) created from the
dashboard, configured as admin.api_key or RETYC_ADMIN_API_KEY. Commands that
decrypt content additionally need the organization private key file
(admin.private_key_file or RETYC_ADMIN_PRIVATE_KEY_FILE).`,
}

// newAdminClient loads the config and returns an API client authenticated
// with the organization API key.
func newAdminClient() (*config.Config, *api.Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}
	if cfg.Admin.APIKey == "" {
		return nil, nil, fmt.Errorf(
			"no admin API key configured: create one from the dashboard, then set " +
				"admin.api_key in the config file or the RETYC_ADMIN_API_KEY environment variable")
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Admin.APIKey, TokenType: "Bearer"})

	return cfg, api.New(cfg.AdminBaseURL(), cliUserAgent(), ts, insecure, debug), nil
}

// adminIdentity loads the organization AGE identity from the
// configured key file.
func adminIdentity(cfg *config.Config) (*age.HybridIdentity, error) {
	if cfg.Admin.PrivateKeyFile == "" {
		return nil, fmt.Errorf(
			"this command needs the organization key: set admin.private_key_file " +
				"in the config file or the RETYC_ADMIN_PRIVATE_KEY_FILE environment variable")
	}

	return service.LoadAdminIdentity(cfg.Admin.PrivateKeyFile)
}

// adminErrHint enriches API auth errors with actionable hints.
func adminErrHint(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "API error 401"):
		return fmt.Errorf("%w\nHint: the admin API key is invalid or revoked", err)
	case strings.Contains(msg, "API error 403"):
		return fmt.Errorf("%w\nHint: the API key lacks a required scope — check with 'retyc admin org scopes'", err)
	}

	return err
}

// askConfirm prints prompt on stderr and returns true when the user answers y.
func askConfirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')

	return strings.ToLower(strings.TrimSpace(answer)) == "y"
}

func init() {
	rootCmd.AddCommand(adminCmd)
}
