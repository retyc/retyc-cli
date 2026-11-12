package mcpsetup

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// BinaryPath is where InstallBinary puts the binary the clients launch:
// outside of the npx cache (which may be cleaned) and reachable without PATH
// (GUI clients on macOS do not see the shell's PATH).
//
//	Linux    $XDG_DATA_HOME/retyc/bin/retyc (~/.local/share/…)
//	macOS    ~/Library/Application Support/retyc/bin/retyc
//	Windows  %LOCALAPPDATA%\retyc\bin\retyc.exe
func BinaryPath(e Env) string {
	switch e.GOOS {
	case "windows":
		base := e.Getenv("LOCALAPPDATA")
		if base == "" {
			base = filepath.Join(e.Home, "AppData", "Local")
		}

		return filepath.Join(base, "retyc", "bin", "retyc.exe")
	case "darwin":
		return filepath.Join(e.ConfigDir, "retyc", "bin", "retyc")
	default:
		base := e.Getenv("XDG_DATA_HOME")
		if base == "" {
			base = filepath.Join(e.Home, ".local", "share")
		}

		return filepath.Join(base, "retyc", "bin", "retyc")
	}
}

// InstallBinary copies src to BinaryPath (mode 0755) through a temporary file
// renamed over the previous binary, and returns the path. Copying a binary
// onto itself does nothing.
func InstallBinary(e Env, src string) (string, error) {
	dst := BinaryPath(e)
	if same(src, dst) {
		return dst, nil
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: a bin directory
		return "", err
	}

	in, err := os.Open(src) //nolint:gosec // G304: our own executable
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(dir, ".retyc-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()

		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()

		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		// Windows refuses to replace an executable a running client holds.
		if runtime.GOOS == "windows" && errors.Is(err, fs.ErrPermission) {
			return "", fmt.Errorf("%w: %s", ErrBinaryInUse, dst)
		}

		return "", err
	}

	return dst, nil
}

func same(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)

	return err == nil && os.SameFile(sa, sb)
}
