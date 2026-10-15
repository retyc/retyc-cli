//go:build !linux

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// runMount is the FUSE driver's entry point, which exists on Linux only
// (internal/retycfs). Elsewhere the command is still there, so that the help
// and the error are the same on every platform.
func runMount(*cobra.Command, mountTarget) error {
	return errors.New("retyc fs mount is available on Linux only; `retyc fs webdav serve` works on every platform")
}
