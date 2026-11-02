package service

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/machinekey"
)

// machineRotationStep is what RotateMachineKey does from the state of the key
// files and the active key of the server.
type machineRotationStep int

const (
	machineStepUnknown machineRotationStep = iota
	machineStepRotate                      // POST a new key (fresh or the existing .new)
	machineStepSwap                        // POST done: swap .new into age.key, then rekey
	machineStepFinish                      // swap interrupted: .new to age.key, then rekey
	machineStepDropNew                     // stale .new beside .old: remove it, then rekey
	machineStepRekey                       // rekey with .old
)

// machineRotationPlan maps the state table of the design (key files present,
// active key of the server) to a step. Anything else is unknown: the active
// key is in no local file, or the files are inconsistent.
func machineRotationPlan(f machineKeyFiles, active string) machineRotationStep {
	is := func(id *age.HybridIdentity) bool { return id != nil && id.Recipient().String() == active }

	switch {
	case f.cur == nil:
		if f.old != nil && is(f.next) {
			return machineStepFinish
		}
	case is(f.cur) && f.old == nil && f.next == nil:
		return machineStepRotate
	case is(f.cur) && f.old == nil && f.next != nil && f.next.Recipient().String() != active:
		return machineStepRotate
	case is(f.next) && f.old == nil && !is(f.cur):
		return machineStepSwap
	case is(f.cur) && f.old != nil && f.next == nil:
		return machineStepRekey
	case is(f.cur) && f.old != nil:
		return machineStepDropNew
	}

	return machineStepUnknown
}

// RotateMachineKey rotates the AGE key of a machine account, or resumes an
// interrupted rotation from the key files beside m.AgeKeyFile (see the state
// table of the design): POST of the new key with a proof signed by client.key,
// swap of the files, rekey of the datarooms the machine administers, removal
// of age.key.old once nothing is encrypted for it any more. A rekey failure
// keeps age.key.old and returns the result with ErrKeyRotationIncomplete.
func RotateMachineKey(
	ctx context.Context, client *api.Client, m *config.Machine, now func() time.Time, progress func(string),
) (*KeyRotationResult, error) {
	say := func(msg string) {
		if progress != nil {
			progress(msg)
		}
	}

	org, err := orgRecipient(ctx, client)
	if err != nil {
		return nil, err
	}

	signer, err := readMachineSigningKey(m.ClientKeyFile)
	if err != nil {
		return nil, err
	}
	kid := machinekey.Thumbprint(&signer.PublicKey)

	activeKey, err := client.GetActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the active key: %w", err)
	}
	if activeKey == nil {
		return nil, fmt.Errorf("%w: the server has no active key for this machine", config.ErrMachineConfig)
	}

	path := m.AgeKeyFile
	files, err := readMachineKeyFiles(path)
	if err != nil {
		return nil, err
	}

	res := &KeyRotationResult{Machine: true, Resumed: true}

	switch machineRotationPlan(files, activeKey.PublicKey) {
	case machineStepRotate:
		res.Resumed = files.next != nil
		fp, err := postMachineKey(ctx, client, m, signer, kid, &files, now, say)
		if err != nil {
			return nil, err
		}
		res.Fingerprint = fp
	case machineStepSwap:
		say("The new key is already active: finishing the swap of the key files")
		if err := swapMachineKeys(path); err != nil {
			return nil, err
		}
		files.cur, files.old, files.next = files.next, files.cur, nil
	case machineStepFinish:
		say("Finishing an interrupted swap of the key files")
		if err := renameSync(path+machineKeyNewSuffix, path); err != nil {
			return nil, err
		}
		files.cur, files.next = files.next, nil
	case machineStepDropNew:
		say("Removing a key left by a refused rotation")
		if err := removeMachineKey(path, machineKeyNewSuffix); err != nil {
			return nil, err
		}
		files.next = nil
	case machineStepRekey:
		say("Resuming the rekey of the previous rotation")
	default:
		return nil, fmt.Errorf("%w: the key files are inconsistent or hold no copy of the server's active key (%s)",
			config.ErrMachineConfig, path)
	}

	newPub := files.cur.Recipient().String()
	res.PublicKey = newPub
	if res.Fingerprint == "" {
		res.Fingerprint = machinekey.Fingerprint(kid, newPub)
	}

	return finishMachineRotation(ctx, client, path, files, org, res, say)
}

// readMachineSigningKey reads and parses client.key without quoting it.
func readMachineSigningKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := config.ReadMachineFile(path)
	if err != nil {
		return nil, err
	}
	k, err := machinekey.ParseSigningKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a valid signing key", config.ErrMachineConfig, path)
	}

	return k, nil
}

// postMachineKey sends the new key (the existing .new, or a fresh one written
// to .new first) with a proof signed just before the call, then swaps the key
// files. It updates files and returns the fingerprint answered by the API.
func postMachineKey(
	ctx context.Context, client *api.Client, m *config.Machine, signer *ecdsa.PrivateKey, kid string,
	files *machineKeyFiles, now func() time.Time, say func(string),
) (string, error) {
	path := m.AgeKeyFile
	next := files.next
	if next == nil {
		id, err := crypto.GenerateKeyPair()
		if err != nil {
			return "", fmt.Errorf("generating the new key: %w", err)
		}
		if err := writeMachineKey(path, machineKeyNewSuffix, id); err != nil {
			return "", err
		}
		next = id
	} else {
		say("Sending again the key of an interrupted rotation")
	}
	newPub := next.Recipient().String()

	proof, err := machinekey.SignRotationProof(signer, kid, m.ClientID, newPub, now())
	if err != nil {
		return "", fmt.Errorf("signing the rotation proof: %w", err)
	}

	say("Registering the new key")
	var fingerprint string
	out, err := client.RotateMachineKey(ctx, proof)
	switch {
	case err == nil:
		fingerprint = out.Fingerprint
	case errors.Is(err, api.ErrMachineKeyAlreadyActive):
	case unsupportedRoute(err):
		// An API that predates machine key rotation: the key cannot be active.
		if rmErr := removeMachineKey(path, machineKeyNewSuffix); rmErr != nil {
			return "", rmErr
		}

		return "", fmt.Errorf("the API does not support machine key rotation (too old): %w", err)
	default:
		// Keep .new unless the server certainly does not hold it as the
		// active key: after a transport error or a 5xx, or when the active
		// key cannot be re-read, .new may be the only copy of the active key.
		if !refused(err) {
			return "", fmt.Errorf("registering the new key: %w", err)
		}
		active, readErr := client.GetActiveKey(ctx)
		if readErr != nil {
			return "", fmt.Errorf("registering the new key: %w (the active key cannot be re-read: %v)", err, readErr)
		}
		if active == nil || active.PublicKey != newPub {
			if rmErr := removeMachineKey(path, machineKeyNewSuffix); rmErr != nil {
				return "", rmErr
			}
			if errors.Is(err, api.ErrMachineRotationUnfinished) {
				return "", fmt.Errorf("datarooms where this machine is only editor or viewer "+
					"wait for a human admin to rekey them: %w", err)
			}

			return "", fmt.Errorf("registering the new key: %w", err)
		}
		// The refusal hides an accepted rotation: carry on with the swap.
	}

	if err := swapMachineKeys(path); err != nil {
		return "", err
	}
	files.cur, files.old, files.next = next, files.cur, nil

	return fingerprint, nil
}

// unsupportedRoute reports whether err is the 404 or 405 of an API that has no
// machine key rotation route.
func unsupportedRoute(err error) bool {
	var httpErr *api.HTTPError

	return errors.As(err, &httpErr) &&
		(httpErr.Status == http.StatusNotFound || httpErr.Status == http.StatusMethodNotAllowed)
}

// refused reports whether err is an HTTP refusal (a 4xx), after which the
// active key is checked before .new is dropped.
func refused(err error) bool {
	var httpErr *api.HTTPError

	return errors.As(err, &httpErr) && httpErr.Status >= http.StatusBadRequest &&
		httpErr.Status < http.StatusInternalServerError
}

// finishMachineRotation rekeys the datarooms still encrypted for .old and
// removes .old once the server lists none.
func finishMachineRotation(
	ctx context.Context, client *api.Client, path string, files machineKeyFiles,
	org string, res *KeyRotationResult, say func(string),
) (*KeyRotationResult, error) {
	newPub := files.cur.Recipient().String()
	keys := map[string]*age.HybridIdentity{newPub: files.cur}
	var oldPub string
	if files.old != nil {
		oldPub = files.old.Recipient().String()
		keys[oldPub] = files.old
	}

	say("Rekeying the datarooms")
	res.Datarooms = rekeyPendingDatarooms(ctx, client, keys, newPub, org)

	if files.old == nil {
		return res, nil
	}

	if len(res.Datarooms.Failed) == 0 {
		pending, err := client.ListPendingRekeyDatarooms(ctx)
		if err != nil {
			res.Datarooms.Failed = append(res.Datarooms.Failed, fmt.Sprintf("list: %v", err))
		} else if !anyEncryptedFor(pending, oldPub) {
			if err := removeMachineKey(path, machineKeyOldSuffix); err != nil {
				return res, err
			}

			return res, nil
		}
	}

	res.OldKeyKept = true
	if len(res.Datarooms.Failed) > 0 {
		return res, errRotationIncomplete(len(res.Datarooms.Failed))
	}

	return res, nil
}

// anyEncryptedFor reports whether a pending entry is still encrypted for pub.
func anyEncryptedFor(pending []api.PendingRekeyDataroom, pub string) bool {
	for _, p := range pending {
		if p.PublicKey == pub {
			return true
		}
	}

	return false
}
