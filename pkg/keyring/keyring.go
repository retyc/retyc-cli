//go:build linux

// Package keyring caches the decrypted AGE identity in the Linux kernel session keyring.
// The key lives only in kernel memory, is shared across all processes in the same
// terminal session, and is automatically wiped after TTL seconds.
//
// Each identity is stored under the ID of its user key ("retyc:identity:<key id>"),
// so that two accounts (or the dev and prod builds) used in the same session do
// not overwrite each other's cache.
package keyring

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

const keyType = "user"

// Store saves the decrypted AGE identity of key keyID in the session keyring
// with the given TTL (in seconds). It overwrites any existing entry and resets
// the TTL.
func Store(keyID, identity string, ttl int) error {
	name, err := keyName(keyID)
	if err != nil {
		return err
	}
	id, err := unix.AddKey(keyType, name, []byte(identity), unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		return fmt.Errorf("add_key: %w", err)
	}
	if _, err = unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, id, ttl, 0, 0); err != nil {
		return fmt.Errorf("set_timeout: %w", err)
	}

	return nil
}

// Load retrieves the cached AGE identity of key keyID from the session keyring.
// Returns ("", nil) if the key does not exist or has expired.
func Load(keyID string) (string, error) {
	name, err := keyName(keyID)
	if err != nil {
		return "", err
	}
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, keyType, name, 0)
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

// HasAny reports whether the session keyring caches an identity, whatever its
// key, without reading it. It lets a command check, before it knows the active
// key, that it may not need a passphrase. Any error (keyring unavailable,
// blocked by seccomp…) reads as "nothing cached".
func HasAny() bool {
	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, unix.KEY_SPEC_SESSION_KEYRING, nil, 0)
	if err != nil || size <= 0 {
		return false
	}
	// The payload of a keyring is the list of its key serials (native int32 each).
	buf := make([]byte, size)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, unix.KEY_SPEC_SESSION_KEYRING, buf, 0)
	if err != nil {
		return false
	}
	n = min(n, size)
	for i := 0; i+4 <= n; i += 4 {
		serial := int(int32(binary.NativeEndian.Uint32(buf[i:]))) //nolint:gosec // G115: a key serial is an int32
		// "type;uid;gid;perm;description"
		desc, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, serial)
		if err != nil {
			continue
		}
		parts := strings.SplitN(desc, ";", 5)
		if len(parts) == 5 && parts[0] == keyType && strings.HasPrefix(parts[4], namePrefix) {
			return true
		}
	}

	return false
}

// isAbsent reports whether err means the key was not found or is no longer valid.
func isAbsent(err error) bool {
	return errors.Is(err, unix.ENOKEY) ||
		errors.Is(err, unix.EKEYEXPIRED) ||
		errors.Is(err, unix.EKEYREVOKED)
}
