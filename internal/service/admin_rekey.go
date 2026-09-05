package service

import (
	"context"
	"fmt"
	"slices"

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

	return rekeyDataroomWithSession(ctx, client, orgKey, dataroomID, sess)
}

// AdminRemoveDataroomUser removes a member from a dataroom and rekeys it so
// the removal also takes effect cryptographically. The session key is
// decrypted BEFORE the removal: the DELETE is irreversible from the CLI (there
// is no admin "add user"), so a dataroom the organization key cannot open must
// be refused up front rather than left half-done with the old blob in place.
func AdminRemoveDataroomUser(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity, dataroomID, userID string,
) (*AdminRekeyResult, error) {
	sess, err := ResolveAdminDataroomSession(ctx, client, orgKey, dataroomID)
	if err != nil {
		return nil, err
	}

	if err := client.AdminRemoveDataroomUser(ctx, dataroomID, userID); err != nil {
		return nil, fmt.Errorf("removing user: %w", err)
	}

	result, err := rekeyDataroomWithSession(ctx, client, orgKey, dataroomID, sess)
	if err != nil {
		return nil, fmt.Errorf("user removed but rekey FAILED (the user may still decrypt): %w", err)
	}

	return result, nil
}

// rekeyDataroomWithSession re-encrypts an already decrypted dataroom session
// key for the current members and pushes it.
func rekeyDataroomWithSession(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity, dataroomID string, sess *DataroomSession,
) (*AdminRekeyResult, error) {
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

	return pushRekey(ctx, sess.PrivateKey, orgKey, holders, func(blob string) error {
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

	return pushRekey(ctx, sessionPrivKey, orgKey, holders, func(blob string) error {
		return client.AdminRekeyTransfer(ctx, transferID, blob)
	})
}

// pushRekey re-encrypts sessionPrivKey for the holders' keys plus the
// organization key itself, and pushes the blob through pushFn. The
// organization recipient is always added, whatever the holder list says: the
// service account may be listed without a key (rotation in progress, stale
// membership), and a blob the organization key cannot open would make every
// later admin operation on the dataroom/transfer fail with no way to repair it.
func pushRekey(
	_ context.Context, sessionPrivKey string, orgKey *age.HybridIdentity, holders []rekeyKeyHolder,
	pushFn func(blob string) error,
) (*AdminRekeyResult, error) {
	keys, skipped := rekeyRecipientKeys(holders)
	orgRecipient := orgKey.Recipient().String()
	if !slices.Contains(keys, orgRecipient) {
		keys = append(keys, orgRecipient)
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
