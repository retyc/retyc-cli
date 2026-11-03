// Package cryptotest holds crypto helpers for tests only.
package cryptotest

import (
	"fmt"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/crypto"
)

// ScryptWorkFactor is the scrypt work factor (log2) of EncryptWithPassphrase.
// age uses 18 (~256 MiB, about a second, much more under -race); the decryption
// reads the factor from the header, so a fixture encrypted at 10 decrypts in
// about a millisecond through the production code.
const ScryptWorkFactor = 10

// EncryptWithPassphrase is crypto.EncryptWithPassphrase with a cheap work
// factor. Never use it outside tests.
func EncryptWithPassphrase(plaintext []byte, passphrase string) (string, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", fmt.Errorf("creating scrypt recipient: %w", err)
	}
	recipient.SetWorkFactor(ScryptWorkFactor)

	return crypto.Encrypt(plaintext, recipient)
}
