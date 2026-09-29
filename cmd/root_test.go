package cmd

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
)

func TestRootPersistentPreRunE_FailsOnUnreadableCABundle(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", filepath.Join(t.TempDir(), "absent.pem"))
	t.Setenv("SSL_CERT_DIR", "")

	if rootCmd.PersistentPreRunE == nil {
		t.Fatal("rootCmd.PersistentPreRunE = nil, want the CA bundle to be validated at startup")
	}

	// authStatusCmd talks to the API, so a broken bundle must stop it.
	if err := rootCmd.PersistentPreRunE(authStatusCmd, nil); err == nil {
		t.Error("PersistentPreRunE() error = nil, want an error for an unreadable SSL_CERT_FILE")
	}
}

func TestRootPersistentPreRunE_SkipsOfflineCommands(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", filepath.Join(t.TempDir(), "absent.pem"))
	t.Setenv("SSL_CERT_DIR", "")

	// These commands open no connection: a CA bundle they never use must not
	// stop them. The release CI runs `retyc mcp manifest`.
	for _, cmd := range []*cobra.Command{versionCmd, mcpManifestCmd} {
		if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
			t.Errorf("%q needs no CA bundle but failed: %v", cmd.Name(), err)
		}
	}
}

// The api.concurrency.* settings reach the service, which reads them from a
// process-wide value rather than from each command's configuration.
func TestApplyServiceConfig_SetsConcurrency(t *testing.T) {
	isolateConfig(t)
	t.Cleanup(func() { service.SetConcurrency(defaultServiceConcurrency()) })
	t.Setenv("RETYC_API_CONCURRENCY_LIST", "7")
	t.Setenv("RETYC_API_CONCURRENCY_UPLOAD", "3")
	t.Setenv("RETYC_API_CONCURRENCY_DOWNLOAD", "5")
	initConfig()

	applyServiceConfig()

	want := config.ConcurrencyConfig{List: 7, Upload: 3, Download: 5}
	if got := service.Concurrency(); got != want {
		t.Errorf("service.Concurrency() = %+v, want %+v", got, want)
	}
}

// A configuration that does not load must not stop the command here: each
// command reports it through its own config.Load, and some deliberately
// tolerate it (auth logout). The service keeps its previous bounds.
func TestApplyServiceConfig_IgnoresInvalidConfig(t *testing.T) {
	isolateConfig(t)
	t.Cleanup(func() { service.SetConcurrency(defaultServiceConcurrency()) })
	service.SetConcurrency(defaultServiceConcurrency())
	t.Setenv("RETYC_API_CONCURRENCY_LIST", "0")
	initConfig()

	applyServiceConfig()

	if got := service.Concurrency(); got != defaultServiceConcurrency() {
		t.Errorf("service.Concurrency() = %+v, want the defaults kept", got)
	}
}

func defaultServiceConcurrency() config.ConcurrencyConfig {
	return config.ConcurrencyConfig{
		List: config.DefaultConcurrency, Upload: config.DefaultConcurrency, Download: config.DefaultConcurrency,
	}
}

// A login that cannot come back without a new token exits with
// exitAuthRequired, a missing or wrong key passphrase with exitConfig, so a
// supervisor stops restarting the process; anything else, transient failures
// included, keeps the generic exit code.
func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"no stored token", fmt.Errorf("not authenticated: %w", auth.ErrNoToken), exitAuthRequired},
		{"revoked refresh token", fmt.Errorf("authentication expired: %w",
			fmt.Errorf("refreshing token: %w", auth.ErrNoRefreshToken)), exitAuthRequired},
		{"missing key passphrase", config.ErrNoKeyPassphrase, exitConfig},
		{"no TTY for the key passphrase", fmt.Errorf("no TTY detected: %w", config.ErrNoKeyPassphrase), exitConfig},
		{"wrong key passphrase", fmt.Errorf("key passphrase check failed: %w",
			fmt.Errorf("%w: no identity matched", service.ErrWrongKeyPassphrase)), exitConfig},
		{"unreachable identity provider", errors.New("fetching OIDC config: connection refused"), 1},
		{"other failure", errors.New("WebDAV server: address already in use"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.err); got != tt.want {
				t.Errorf("exitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
