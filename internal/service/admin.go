// Package service — admin (organization public API) helpers.
package service

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// LoadAdminIdentity reads the organization AGE identity from a local
// key file (as downloaded from the dashboard or produced by age-keygen).
// Blank lines and lines starting with '#' are ignored. The identity must be a
// hybrid post-quantum one (AGE-SECRET-KEY-PQ-1...): every key in the product
// is post-quantum, a legacy X25519 identity is rejected explicitly.
func LoadAdminIdentity(path string) (*age.HybridIdentity, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the user's own config
	if err != nil {
		return nil, fmt.Errorf("reading organization key file: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
			return nil, fmt.Errorf(
				"organization key in %s is a legacy X25519 identity: "+
					"a post-quantum key (AGE-SECRET-KEY-PQ-1...) is required", path)
		}
		id, err := crypto.ParseIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("parsing organization key from %s: %w", path, err)
		}

		return id, nil
	}

	return nil, fmt.Errorf("no AGE identity found in %s", path)
}
