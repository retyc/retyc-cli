package service

import (
	"fmt"
	"os"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/keyring"
)

// ResolveUserIdentity decrypts the user's AGE private key using the passphrase.
// It checks the keyring cache first (when enabled), falling back to reader().
func ResolveUserIdentity(cfg *config.Config, userKey *api.UserKey, reader PassphraseReader) (
	*age.HybridIdentity, error,
) {
	var identityStr string
	fromKeyring := false

	if cfg.Keyring.Enabled {
		var err error
		identityStr, err = keyring.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: keyring load: %v\n", err)
		} else if identityStr != "" {
			fromKeyring = true
		}
	}

	if identityStr == "" {
		passphrase, err := reader()
		if err != nil {
			return nil, err
		}
		identityStr, err = crypto.DecryptToStringWithPassphrase(userKey.PrivateKeyEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("wrong key passphrase: %w", err)
		}
	}

	identity, err := crypto.ParseIdentity(identityStr)
	if err != nil {
		return nil, fmt.Errorf("parsing AGE identity: %w", err)
	}

	if cfg.Keyring.Enabled && !fromKeyring {
		if err := keyring.Store(identityStr, cfg.Keyring.TTL); err != nil {
			fmt.Fprintf(os.Stderr, "warning: keyring store: %v\n", err)
		}
	}

	return identity, nil
}
