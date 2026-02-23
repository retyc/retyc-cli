//go:build !linux

// Package keyring provides a no-op implementation for non-Linux platforms.
// The Linux kernel session keyring is not available on macOS or Windows;
// the passphrase will be re-prompted every time instead of being cached.
package keyring

// Store is a no-op on non-Linux platforms.
func Store(_ string, _ int) error { return nil }

// Load always returns an empty string on non-Linux platforms.
func Load() (string, error) { return "", nil }
