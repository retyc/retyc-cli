package cmd

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
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
