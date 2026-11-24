//go:build !plan9

package vfs

import (
	"errors"
	"syscall"
)

// isNoSpace reports whether err says the file system has no room left, or the
// user no quota.
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
