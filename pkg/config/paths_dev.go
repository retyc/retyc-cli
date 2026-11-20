//go:build !prod

// This file is compiled for development builds (default).
// Config is stored in .retyc/ relative to the current working directory so
// that multiple project checkouts can coexist without interfering with each
// other. Override the directory with RETYC_CONFIG_DIR.

package config

import "github.com/spf13/viper"

// BuildMode identifies the active build configuration.
const BuildMode = "dev"

// defaultAPIBaseURL is the default REST API base URL for development builds.
const defaultAPIBaseURL = "https://api.triplesfer.traefik.me"

// configDir returns the config directory for development builds.
func configDir() (string, error) {
	if dir := fromEnv(EnvConfigDirName); dir != "" {
		return dir, nil
	}

	return ".retyc", nil
}

// setBuildDefaults registers the keys that only a development build acts on.
// The default is what makes "insecure" appear in viper.AllKeys(), hence in
// `retyc config show` and in the documentation check.
func setBuildDefaults() {
	viper.SetDefault("insecure", false)
}
