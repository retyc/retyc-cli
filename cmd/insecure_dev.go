//go:build !prod

// This file is compiled for development builds only.
// The --insecure / -k flag is intentionally restricted to dev builds;
// it must not be available in production binaries.

package cmd

import "github.com/spf13/viper"

var insecure bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "k", false,
		"skip TLS certificate verification (useful for self-signed certificates)")
}

// setInsecureFromConfig applies the "insecure" value from the config file or
// environment variable when the flag was not explicitly provided on the command line.
func setInsecureFromConfig() {
	if !rootCmd.PersistentFlags().Changed("insecure") {
		insecure = viper.GetBool("insecure")
	}
}
