package service

import (
	"context"
	"fmt"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// rekeyKeyHolder is one holder (dataroom member or transfer recipient) whose
// access must survive a rekey.
type rekeyKeyHolder struct {
	Label             string
	PublicKey         *string
	ExpectedPublicKey *string
}

// rekeyRecipientKeys returns the deduplicated public keys to re-encrypt a
// session key for. The expected (active profile) key wins over the currently
// encrypted-for key, so a rekey also repairs key_mismatch entries after a user
// key rotation. Holders with no key at all are reported in skipped: external
// passphrase-only recipients keep their ephemeral-key access path, untouched
// by a rekey.
func rekeyRecipientKeys(holders []rekeyKeyHolder) (keys []string, skipped []string) {
	seen := make(map[string]bool)
	for _, h := range holders {
		key := ""
		switch {
		case h.ExpectedPublicKey != nil && *h.ExpectedPublicKey != "":
			key = *h.ExpectedPublicKey
		case h.PublicKey != nil && *h.PublicKey != "":
			key = *h.PublicKey
		}
		if key == "" {
			skipped = append(skipped, h.Label)

			continue
		}
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}

	return keys, skipped
}

// AdminRekeyResult summarizes a rekey operation.
type AdminRekeyResult struct {
	Reencrypted int
	Skipped     []string
}

// AdminRekeyDataroom decrypts the dataroom session key with the organization
// identity, re-encrypts it for the active keys of all current members (the
// service account included), and pushes the blob.
func AdminRekeyDataroom(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity, dataroomID string,
) (*AdminRekeyResult, error) {
	sess, err := ResolveAdminDataroomSession(ctx, client, orgKey, dataroomID)
	if err != nil {
		return nil, err
	}

	users, err := client.AdminListDataroomUsers(ctx, dataroomID)
	if err != nil {
		return nil, fmt.Errorf("listing dataroom users: %w", err)
	}

	holders := make([]rekeyKeyHolder, 0, len(users))
	for _, u := range users {
		holders = append(holders, rekeyKeyHolder{
			Label:             u.Email,
			PublicKey:         u.PublicKey,
			ExpectedPublicKey: u.ExpectedPublicKey,
		})
	}

	return pushRekey(ctx, sess.PrivateKey, holders, func(blob string) error {
		return client.AdminRekeyDataroom(ctx, dataroomID, blob)
	})
}

// AdminRekeyTransfer decrypts the transfer session key with the organization
// identity, re-encrypts it for the active keys of all current recipients (the
// service account included), and pushes the blob.
func AdminRekeyTransfer(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity, transferID string,
) (*AdminRekeyResult, error) {
	tr, err := client.AdminGetTransfer(ctx, transferID)
	if err != nil {
		return nil, fmt.Errorf("fetching transfer: %w", err)
	}
	if tr.SessionPrivateKeyEnc == nil {
		return nil, fmt.Errorf("the organization key was not enabled when this transfer was created: nothing to decrypt")
	}

	sessionPrivKey, err := crypto.DecryptToString(*tr.SessionPrivateKeyEnc, orgKey)
	if err != nil {
		return nil, ErrOrgKeyNoAccess
	}

	holders := make([]rekeyKeyHolder, 0, len(tr.Recipients))
	for _, r := range tr.Recipients {
		label := "(unknown)"
		if r.Email != nil {
			label = *r.Email
		}
		holders = append(holders, rekeyKeyHolder{
			Label:             label,
			PublicKey:         r.PublicKey,
			ExpectedPublicKey: r.ExpectedPublicKey,
		})
	}

	return pushRekey(ctx, sessionPrivKey, holders, func(blob string) error {
		return client.AdminRekeyTransfer(ctx, transferID, blob)
	})
}

// pushRekey re-encrypts sessionPrivKey for the holders' keys and pushes the
// blob through pushFn.
func pushRekey(
	_ context.Context, sessionPrivKey string, holders []rekeyKeyHolder, pushFn func(blob string) error,
) (*AdminRekeyResult, error) {
	keys, skipped := rekeyRecipientKeys(holders)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no recipient with a public key: refusing to push an undecryptable blob")
	}

	blob, err := crypto.EncryptStringForKeys(sessionPrivKey, keys)
	if err != nil {
		return nil, fmt.Errorf("re-encrypting session key: %w", err)
	}

	if err := pushFn(blob); err != nil {
		return nil, fmt.Errorf("pushing rekeyed session key: %w", err)
	}

	return &AdminRekeyResult{Reencrypted: len(keys), Skipped: skipped}, nil
}
