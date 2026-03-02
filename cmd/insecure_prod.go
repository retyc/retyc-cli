//go:build prod

// This file is compiled for production builds only.
// TLS certificate verification is always enforced in production;
// the --insecure flag is not available.

package cmd

const insecure = false
