//go:build !prod

// This file is compiled for development builds only.
// The --insecure / -k flag is intentionally restricted to dev builds;
// it must not be available in production binaries.

package cmd

var insecure bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "k", false,
		"skip TLS certificate verification (useful for self-signed certificates)")
}
