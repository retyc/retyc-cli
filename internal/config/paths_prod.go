//go:build prod

// This file is compiled for production builds (-tags prod).
// Config follows the XDG Base Directory specification and is stored under
// $XDG_CONFIG_HOME/retyc (typically ~/.config/retyc on Linux).
// Override the directory with RETYC_CONFIG_DIR.

package config

import (
	"os"
	"path/filepath"
)

// BuildMode identifies the active build configuration.
const BuildMode = "prod"

// defaultAPIBaseURL is the default REST API base URL for production builds.
const defaultAPIBaseURL = "https://api.retyc.com"

// configDir returns the config directory for production builds.
func configDir() (string, error) {
	if dir := os.Getenv("RETYC_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "retyc"), nil
}
