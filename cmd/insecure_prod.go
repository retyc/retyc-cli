//go:build prod

// This file is compiled for production builds only.
// TLS certificate verification is always enforced in production;
// the --insecure flag is not available.

package cmd

const insecure = false

// hiddenConfigKey reports whether `config show` leaves key out. "insecure" is
// not a setting of a production build: it has no default there, but viper
// still lists it when a config file carries it.
func hiddenConfigKey(key string) bool { return key == "insecure" }

func setInsecureFromConfig() {}
