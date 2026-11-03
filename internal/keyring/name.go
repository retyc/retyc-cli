package keyring

import (
	"errors"
	"regexp"
)

// namePrefix starts the name of every cached identity, followed by the ID of
// its user key.
const namePrefix = "retyc:identity:"

// ErrBadKeyID is returned for a key ID that cannot name a keyring entry. The
// ID comes from the API: it is checked before it reaches the kernel.
var ErrBadKeyID = errors.New("keyring: invalid key ID")

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// keyName returns the keyring entry name of the identity of key keyID.
func keyName(keyID string) (string, error) {
	if !keyIDPattern.MatchString(keyID) {
		return "", ErrBadKeyID
	}

	return namePrefix + keyID, nil
}
