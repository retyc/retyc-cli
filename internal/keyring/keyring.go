//go:build linux

// Package keyring caches the decrypted AGE identity in the Linux kernel session keyring.
// The key lives only in kernel memory, is shared across all processes in the same
// terminal session, and is automatically wiped after TTL seconds.
package keyring

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	keyType = "user"
	keyName = "retyc:identity"
)

// Store saves the decrypted AGE identity string in the session keyring with the
// given TTL (in seconds). It overwrites any existing entry and resets the TTL.
func Store(identity string, ttl int) error {
	id, err := unix.AddKey(keyType, keyName, []byte(identity), unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		return fmt.Errorf("add_key: %w", err)
	}
	if _, err = unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, id, ttl, 0, 0); err != nil {
		return fmt.Errorf("set_timeout: %w", err)
	}
	return nil
}

// Load retrieves the cached AGE identity from the user keyring.
// Returns ("", nil) if the key does not exist or has expired.
func Load() (string, error) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, keyType, keyName, 0)
	if err != nil {
		if isAbsent(err) {
			return "", nil
		}
		return "", fmt.Errorf("search: %w", err)
	}

	// First call with empty buffer to obtain the actual payload size.
	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
	if err != nil {
		return "", fmt.Errorf("read (size): %w", err)
	}
	if size <= 0 {
		return "", nil
	}

	buf := make([]byte, size)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	// n is the total payload length; clamp to allocated buffer.
	if n > size {
		n = size
	}
	return string(buf[:n]), nil
}

// isAbsent reports whether err means the key was not found or is no longer valid.
func isAbsent(err error) bool {
	return errors.Is(err, unix.ENOKEY) ||
		errors.Is(err, unix.EKEYEXPIRED) ||
		errors.Is(err, unix.EKEYREVOKED)
}
