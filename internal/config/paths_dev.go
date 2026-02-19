//go:build !prod

// This file is compiled for development builds (default).
// Config is stored in .retyc/ relative to the current working directory so
// that multiple project checkouts can coexist without interfering with each
// other. Override the directory with RETYC_CONFIG_DIR.

package config

import "os"

// BuildMode identifies the active build configuration.
const BuildMode = "dev"

// configDir returns the config directory for development builds.
func configDir() (string, error) {
	if dir := os.Getenv("RETYC_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	return ".retyc", nil
}
