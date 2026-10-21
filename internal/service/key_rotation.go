package service

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/keyring"
)

// ErrKeyRotationIncomplete is returned when a rotation finished with errors:
// the old key is kept and the command can be run again.
var ErrKeyRotationIncomplete = errors.New("key rotation incomplete")

// errRotationIncomplete is the error of a rotation that kept the previous key
// after n rekey failures; user and machine rotations share it.
func errRotationIncomplete(n int) error {
	return fmt.Errorf("%w: %d error(s), the previous key is kept: run the command again",
		ErrKeyRotationIncomplete, n)
}

// RekeyOutcome counts the objects of one kind handled by a rotation. Skipped
// and Failed entries read "<id>: <reason>" and never carry a title or name.
type RekeyOutcome struct {
	Rekeyed int
	Skipped []string
	Failed  []string
}

// KeyRotationResult summarizes a user or machine key rotation.
type KeyRotationResult struct {
	Machine     bool
	Resumed     bool
	KeyID       string
	PublicKey   string
	Fingerprint string
	Datarooms   RekeyOutcome
	Transfers   RekeyOutcome
	Revoked     []string
	OldKeyKept  bool
}

// orgRecipient returns the public key of the organization service account, or
// "" when there is none (no account, or an account without key).
func orgRecipient(ctx context.Context, client *api.Client) (string, error) {
	sa, err := client.GetOrganizationServiceAccount(ctx)
	if err != nil {
		return "", fmt.Errorf("reading the organization key: %w", err)
	}
	if sa == nil || sa.PublicKey == nil {
		return "", nil
	}

	return *sa.PublicKey, nil
}

// withOrgKey returns keys with org appended when org is set and absent (also
// used to add the caller's new key).
func withOrgKey(keys []string, org string) []string {
	if org == "" || slices.Contains(keys, org) {
		return keys
	}

	return append(slices.Clone(keys), org)
}

// decryptWithAny opens an armored AGE blob with the first identity that can.
func decryptWithAny(blob string, identities []*age.HybridIdentity) (string, bool) {
	for _, id := range identities {
		if plain, err := crypto.DecryptToString(blob, id); err == nil {
			return plain, true
		}
	}

	return "", false
}

// rekeyPendingDatarooms rekeys every dataroom whose link is still encrypted
// for a previous key, for the members listed by the API plus newPub (the
// caller's new key, which the listing may omit) and the organization key. keys
// maps a public key to its identity. Failures are counted, never returned: the
// caller decides whether to revoke the old key.
func rekeyPendingDatarooms(
	ctx context.Context, client *api.Client, keys map[string]*age.HybridIdentity, newPub, org string,
) RekeyOutcome {
	var out RekeyOutcome

	pending, err := client.ListPendingRekeyDatarooms(ctx)
	if err != nil {
		out.Failed = append(out.Failed, fmt.Sprintf("list: %v", err))

		return out
	}

	for _, entry := range pending {
		id := keys[entry.PublicKey]
		if id == nil {
			out.Skipped = append(out.Skipped, entry.DataroomID+": no key available for this dataroom")

			continue
		}

		sessionKey, err := crypto.DecryptToString(entry.SessionPrivateKeyEnc, id)
		if err != nil {
			out.Failed = append(out.Failed, entry.DataroomID+": cannot decrypt the session key")

			continue
		}

		blob, err := crypto.EncryptStringForKeys(sessionKey, withOrgKey(withOrgKey(entry.UserPublicKeys, newPub), org))
		if err != nil {
			out.Failed = append(out.Failed, fmt.Sprintf("%s: encrypting: %v", entry.DataroomID, err))

			continue
		}

		if err := client.RekeyDataroom(ctx, entry.DataroomID, blob); err != nil {
			out.Failed = append(out.Failed, fmt.Sprintf("%s: %v", entry.DataroomID, err))

			continue
		}

		out.Rekeyed++
	}

	return out
}

// rekeySentTransfers rekeys the active and expired transfers the caller sent,
// for newPub, the current key of each recipient and the organization key.
// Other statuses are ignored silently (the API refuses them).
func rekeySentTransfers(
	ctx context.Context, client *api.Client, identities []*age.HybridIdentity, newPub, org string,
) RekeyOutcome {
	var out RekeyOutcome

	for page := 1; ; page++ {
		list, err := client.ListTransfers(ctx, "sent", page)
		if err != nil {
			out.Failed = append(out.Failed, fmt.Sprintf("list: %v", err))

			return out
		}

		for _, tr := range list.Items {
			if tr.Status != "active" && tr.Status != "expired" {
				continue
			}
			rekeyOneTransfer(ctx, client, identities, newPub, org, tr.ID, &out)
		}

		if page >= list.Pages {
			return out
		}
	}
}

func rekeyOneTransfer(
	ctx context.Context, client *api.Client, identities []*age.HybridIdentity,
	newPub, org, id string, out *RekeyOutcome,
) {
	details, err := client.GetTransferDetails(ctx, id)
	if err != nil {
		out.Failed = append(out.Failed, fmt.Sprintf("%s: %v", id, err))

		return
	}

	if details.SessionPrivateKeyEnc == nil {
		out.Skipped = append(out.Skipped, id+": no session key to decrypt")

		return
	}

	sessionKey, ok := decryptWithAny(*details.SessionPrivateKeyEnc, identities)
	if !ok {
		out.Skipped = append(out.Skipped, id+": no available key can decrypt it")

		return
	}

	holders := make([]rekeyKeyHolder, 0, len(details.Recipients))
	for _, r := range details.Recipients {
		holders = append(holders, rekeyKeyHolder{
			Label: id, PublicKey: r.PublicKey, ExpectedPublicKey: r.ExpectedPublicKey,
		})
	}
	recipients, _ := rekeyRecipientKeys(holders)

	blob, err := crypto.EncryptStringForKeys(sessionKey, withOrgKey(dedupe(append([]string{newPub}, recipients...)), org))
	if err != nil {
		out.Failed = append(out.Failed, fmt.Sprintf("%s: encrypting: %v", id, err))

		return
	}

	if err := client.RekeyTransfer(ctx, id, blob); err != nil {
		out.Failed = append(out.Failed, fmt.Sprintf("%s: %v", id, err))

		return
	}

	out.Rekeyed++
}

// dedupe removes duplicates, keeping the first occurrence.
func dedupe(keys []string) []string {
	seen := make(map[string]bool, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}

	return out
}

// clearKeyring drops the cached identity once the active key changed. A
// variable so that tests leave the developer's session keyring alone.
var clearKeyring = keyring.Clear

// RotateUserKey rotates the key of a human user: it registers a new key
// encrypted with the same passphrase (unless a rotation is already pending),
// rekeys the datarooms and sent transfers still bound to a previous key, then
// revokes the pending keys. When a rekey failed, nothing is revoked and the
// result comes back with an error wrapping ErrKeyRotationIncomplete: running
// it again resumes. progress receives short messages, never a key or a title.
func RotateUserKey(
	ctx context.Context, client *api.Client, reader PassphraseReader, progress func(string),
) (*KeyRotationResult, error) {
	org, err := orgRecipient(ctx, client)
	if err != nil {
		return nil, err
	}

	keys, err := client.ListUserKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing keys: %w", err)
	}
	active, err := activeUserKey(keys)
	if err != nil {
		return nil, err
	}

	passphrase, err := reader()
	if err != nil {
		return nil, err
	}

	// unlocked caches the identities by ciphertext: each scrypt costs about a
	// second and 256 MiB, and the same blobs come back on the second listing.
	unlocked := map[string]*age.HybridIdentity{}
	if _, err := unlockUserKey(ctx, active, passphrase, unlocked); err != nil {
		return nil, err
	}

	res := &KeyRotationResult{}
	created := false
	// Once a key was created or revoked the cached identity is stale,
	// whatever happens next.
	defer func() {
		if created || len(res.Revoked) > 0 {
			clearUserKeyring(progress)
		}
	}()

	if !slices.ContainsFunc(keys, isPendingUserKey) {
		progress("Generating the new key")
		created, err = createUserKey(ctx, client, passphrase, unlocked)
		if err != nil {
			return nil, err
		}
		res.Resumed = !created
		if !created {
			progress("A rotation is already in progress, resuming it")
		}
	} else {
		res.Resumed = true
		progress("Resuming the rotation in progress")
	}

	keys, err = client.ListUserKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing keys: %w", err)
	}
	active, err = activeUserKey(keys)
	if err != nil {
		return nil, err
	}
	newID, err := unlockUserKey(ctx, active, passphrase, unlocked)
	if err != nil {
		return nil, err
	}

	byPub := map[string]*age.HybridIdentity{active.PublicKey: newID}
	identities := []*age.HybridIdentity{newID}
	var pendingIDs []string
	for i := range keys {
		if !isPendingUserKey(keys[i]) {
			continue
		}
		id, err := unlockUserKey(ctx, &keys[i], passphrase, unlocked)
		if err != nil {
			return nil, err
		}
		byPub[keys[i].PublicKey] = id
		identities = append(identities, id)
		pendingIDs = append(pendingIDs, keys[i].ID)
	}

	res.KeyID = active.ID
	res.PublicKey = active.PublicKey

	progress("Rekeying the datarooms")
	res.Datarooms = rekeyPendingDatarooms(ctx, client, byPub, active.PublicKey, org)
	progress("Rekeying the sent transfers")
	res.Transfers = rekeySentTransfers(ctx, client, identities, active.PublicKey, org)

	if failed := len(res.Datarooms.Failed) + len(res.Transfers.Failed); failed > 0 {
		res.OldKeyKept = true

		return res, errRotationIncomplete(failed)
	}

	if len(pendingIDs) > 0 {
		progress("Revoking the previous key")
	}
	for _, id := range pendingIDs {
		if err := client.RevokeUserKey(ctx, id); err != nil {
			res.OldKeyKept = true

			// The API error stays in the chain for its kind and status.
			return res, fmt.Errorf("%w: revoking key %s, the previous key is kept: run the command again: %w",
				ErrKeyRotationIncomplete, id, err)
		}
		res.Revoked = append(res.Revoked, id)
	}

	return res, nil
}

func isPendingUserKey(k api.UserKeyInfo) bool { return k.Status == api.UserKeyPending }

// activeUserKey returns the active key of a listing.
func activeUserKey(keys []api.UserKeyInfo) (*api.UserKeyInfo, error) {
	for i := range keys {
		if keys[i].Status == api.UserKeyActive {
			if keys[i].PrivateKeyEnc == nil {
				return nil, fmt.Errorf("key %s: the server holds no private key", keys[i].ID)
			}

			return &keys[i], nil
		}
	}

	return nil, errors.New("no active encryption key - set up your key in the web interface first")
}

// unlockUserKey decrypts a key with the passphrase, through the cache. The
// identity must match the public key the server lists for it.
func unlockUserKey(
	ctx context.Context, key *api.UserKeyInfo, passphrase string, cache map[string]*age.HybridIdentity,
) (*age.HybridIdentity, error) {
	if key.PrivateKeyEnc == nil {
		return nil, fmt.Errorf("key %s: the server holds no private key", key.ID)
	}
	id := cache[*key.PrivateKeyEnc]
	if id == nil {
		plain, err := decryptKeyWithPassphrase(ctx, "user", *key.PrivateKeyEnc, passphrase)
		// Release the ~256 MiB scrypt buffer now, as ResolveUserIdentity does.
		debug.FreeOSMemory()
		if err != nil {
			return nil, fmt.Errorf("%w: key %s does not open with this passphrase", ErrWrongKeyPassphrase, key.ID)
		}
		if id, err = crypto.ParseIdentity(plain); err != nil {
			return nil, fmt.Errorf("key %s: invalid AGE identity", key.ID)
		}
		cache[*key.PrivateKeyEnc] = id
	}
	if id.Recipient().String() != key.PublicKey {
		return nil, fmt.Errorf("key %s: the private key does not match its public key", key.ID)
	}

	return id, nil
}

// createUserKey generates a key, encrypts it with passphrase and registers it.
// It reports false, without error, when another rotation won the race.
func createUserKey(
	ctx context.Context, client *api.Client, passphrase string, cache map[string]*age.HybridIdentity,
) (bool, error) {
	id, err := crypto.GenerateKeyPair()
	if err != nil {
		return false, fmt.Errorf("generating the key: %w", err)
	}
	privEnc, err := crypto.EncryptWithPassphrase([]byte(id.String()), passphrase)
	debug.FreeOSMemory()
	if err != nil {
		return false, fmt.Errorf("encrypting the key: %w", err)
	}

	if err := client.CreateUserKey(ctx, id.Recipient().String(), privEnc); err != nil {
		if errors.Is(err, api.ErrKeyRotationInProgress) {
			return false, nil
		}

		return false, fmt.Errorf("registering the key: %w", err)
	}
	cache[privEnc] = id

	return true, nil
}

// clearUserKeyring drops the cached identity; a failure is only a warning.
func clearUserKeyring(progress func(string)) {
	if err := clearKeyring(); err != nil {
		progress(fmt.Sprintf("warning: clearing the keyring: %v", err))
	}
}
