package config

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/core/machinekey"
)

// classicAgeKeyPrefix starts an X25519 identity, which is never accepted.
const classicAgeKeyPrefix = "AGE-SECRET-KEY-1"

// MachineIdentity is the parsed identity of a machine account: what the core
// needs to obtain its tokens (client_credentials with a signed assertion) and
// to decrypt its keys (the AGE identity, no passphrase). It is set in
// Config.Machine by the caller; a nil Config.Machine means a user account.
// It is read-only once built and can be shared between goroutines.
type MachineIdentity struct {
	ClientID      string
	TokenEndpoint string
	// MachineID and OrganizationID are informational (machine.json); they may
	// be empty.
	MachineID      string
	OrganizationID string
	// SigningKey signs the client assertion; KeyID is its kid (the JWK
	// thumbprint of its public key).
	SigningKey *ecdsa.PrivateKey
	KeyID      string
	// AgeIdentity is the post-quantum private half of the account's active key.
	AgeIdentity *age.HybridIdentity
}

// NewMachineIdentity parses a machine identity from the contents of its keys:
// signingKeyPEM is the PKCS#8 PEM of client.key (EC P-256), ageKey the content
// of age.key (comment lines allowed, one post-quantum identity). MachineID
// and OrganizationID can be set on the result. Errors wrap ErrMachineConfig
// and never quote the keys.
func NewMachineIdentity(clientID, tokenEndpoint string, signingKeyPEM, ageKey []byte) (*MachineIdentity, error) {
	return newMachineIdentity(clientID, tokenEndpoint, signingKeyPEM, "the signing key", ageKey, "the AGE key")
}

// LoadMachineIdentity reads and parses the key files of m (see LoadMachine):
// each must exist and not be accessible to others. Errors wrap
// ErrMachineConfig, name the files and never quote their content.
func LoadMachineIdentity(m *Machine) (*MachineIdentity, error) {
	sig, err := ReadMachineFile(m.ClientKeyFile)
	if err != nil {
		return nil, err
	}
	ageKey, err := ReadMachineFile(m.AgeKeyFile)
	if err != nil {
		return nil, err
	}
	id, err := newMachineIdentity(m.ClientID, m.TokenEndpoint, sig, m.ClientKeyFile, ageKey, m.AgeKeyFile)
	if err != nil {
		return nil, err
	}
	id.MachineID, id.OrganizationID = m.MachineID, m.OrganizationID

	return id, nil
}

func newMachineIdentity(
	clientID, tokenEndpoint string, signingKeyPEM []byte, sigName string, ageKey []byte, ageName string,
) (*MachineIdentity, error) {
	if clientID == "" || tokenEndpoint == "" {
		return nil, fmt.Errorf("%w: the client ID and the token endpoint are required", ErrMachineConfig)
	}
	key, err := machinekey.ParseSigningKey(signingKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrMachineConfig, sigName, err)
	}
	identity, err := ParseMachineAgeKey(ageKey, ageName)
	if err != nil {
		return nil, err
	}

	return &MachineIdentity{
		ClientID:      clientID,
		TokenEndpoint: tokenEndpoint,
		SigningKey:    key,
		KeyID:         machinekey.Thumbprint(&key.PublicKey),
		AgeIdentity:   identity,
	}, nil
}

// ParseMachineAgeKey parses the content of a machine age.key: comment lines
// and blank lines are skipped, exactly one post-quantum identity must remain.
// name designates the key in errors, which wrap ErrMachineConfig and never
// quote the content.
func ParseMachineAgeKey(data []byte, name string) (*age.HybridIdentity, error) {
	// The standard age-keygen format puts comment lines before the key.
	var keyLines []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyLines = append(keyLines, line)
	}
	if len(keyLines) != 1 {
		return nil, fmt.Errorf("%w: %s must hold exactly one identity (expected one identity, found %d)",
			ErrMachineConfig, name, len(keyLines))
	}
	content := keyLines[0]
	if strings.HasPrefix(content, classicAgeKeyPrefix) {
		return nil, fmt.Errorf("%w: %s holds a classic X25519 key, a post-quantum key is required",
			ErrMachineConfig, name)
	}
	identity, err := age.ParseHybridIdentity(content)
	if err != nil {
		// The parse error is dropped on purpose: it could quote the key.
		return nil, fmt.Errorf("%w: %s is not a valid post-quantum AGE identity", ErrMachineConfig, name)
	}

	return identity, nil
}
