package service

import (
	"context"
	"testing"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
)

// fakeKeyring replaces the session keyring for one test.
type fakeKeyring struct {
	entries map[string]string
	stored  []string // key IDs written, in order
}

func stubKeyring(t *testing.T) *fakeKeyring {
	t.Helper()
	k := &fakeKeyring{entries: map[string]string{}}
	prevLoad, prevStore := keyringLoad, keyringStore
	t.Cleanup(func() { keyringLoad, keyringStore = prevLoad, prevStore })
	keyringLoad = func(keyID string) (string, error) { return k.entries[keyID], nil }
	keyringStore = func(keyID, identity string, _ int) error {
		k.entries[keyID] = identity
		k.stored = append(k.stored, keyID)

		return nil
	}

	return k
}

// passphraseKey returns a user key encrypted under passphrase, and its identity.
func passphraseKey(t *testing.T, id, passphrase string) (*api.UserKey, *age.HybridIdentity) {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.EncryptWithPassphrase([]byte(identity.String()), passphrase)
	if err != nil {
		t.Fatal(err)
	}

	return &api.UserKey{ID: id, PublicKey: identity.Recipient().String(), PrivateKeyEnc: enc}, identity
}

func keyringConfig() *config.Config {
	return &config.Config{Keyring: config.KeyringConfig{Enabled: true, TTL: 60}}
}

// The identity cached for the active key is used: no passphrase is asked.
func TestResolveUserIdentity_KeyringHit(t *testing.T) {
	k := stubKeyring(t)
	userKey, identity := passphraseKey(t, "key-1", "pw")
	k.entries["key-1"] = identity.String()

	got, err := ResolveUserIdentity(context.Background(), keyringConfig(), userKey, failingReader(t))
	if err != nil {
		t.Fatalf("ResolveUserIdentity() error = %v", err)
	}
	if got.Recipient().String() != userKey.PublicKey {
		t.Fatal("ResolveUserIdentity() returned another identity")
	}
	if len(k.stored) != 0 {
		t.Fatalf("keyring written on a hit: %v", k.stored)
	}
}

// An identity cached under the active key ID but for another public key reads
// as a miss: the passphrase is asked and the entry overwritten.
func TestResolveUserIdentity_KeyringMismatch(t *testing.T) {
	k := stubKeyring(t)
	userKey, _ := passphraseKey(t, "key-1", "pw")
	_, other := passphraseKey(t, "key-2", "other")
	k.entries["key-1"] = other.String()
	asked := 0

	got, err := ResolveUserIdentity(context.Background(), keyringConfig(), userKey, func() (string, error) {
		asked++

		return "pw", nil
	})
	if err != nil {
		t.Fatalf("ResolveUserIdentity() error = %v", err)
	}
	if asked != 1 || got.Recipient().String() != userKey.PublicKey {
		t.Fatalf("asked %d times, got the active key: %v; want 1, true", asked,
			got.Recipient().String() == userKey.PublicKey)
	}
	if k.entries["key-1"] == other.String() {
		t.Fatal("the mismatched entry was not overwritten")
	}
}

// Identities are cached per key ID: the entry of another key is neither read
// nor overwritten.
func TestResolveUserIdentity_KeyringPerKeyID(t *testing.T) {
	k := stubKeyring(t)
	_, other := passphraseKey(t, "key-2", "other")
	k.entries["key-2"] = other.String()
	userKey, _ := passphraseKey(t, "key-1", "pw")

	if _, err := ResolveUserIdentity(context.Background(), keyringConfig(), userKey, func() (string, error) {
		return "pw", nil
	}); err != nil {
		t.Fatalf("ResolveUserIdentity() error = %v", err)
	}
	if len(k.stored) != 1 || k.stored[0] != "key-1" {
		t.Fatalf("stored under %v, want [key-1]", k.stored)
	}
	if k.entries["key-2"] != other.String() {
		t.Fatal("the entry of another key was overwritten")
	}
}

// The keyring lookup is one crypto.unlock_key span (source keyring) whose
// cache hit tells whether the scrypt was avoided: a mismatched entry is no hit.
func TestResolveUserIdentity_KeyringSpanCacheHit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		matches bool
	}{{"hit", true}, {"mismatch", false}} {
		t.Run(tc.name, func(t *testing.T) {
			exp := telemetrytest.Install(t)
			k := stubKeyring(t)
			userKey, identity := passphraseKey(t, "key-1", "pw")
			if !tc.matches {
				_, identity = passphraseKey(t, "key-2", "other")
			}
			k.entries["key-1"] = identity.String()
			if _, err := ResolveUserIdentity(context.Background(), keyringConfig(), userKey, func() (string, error) {
				return "pw", nil
			}); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, s := range exp.GetSpans() {
				if _, source := keyAttrs(s); s.Name != "crypto.unlock_key" || source != "keyring" {
					continue
				}
				found = true
				for _, kv := range s.Attributes {
					if kv.Key == telemetry.AttrCacheHit && kv.Value.AsBool() != tc.matches {
						t.Errorf("cache hit = %v, want %v", kv.Value.AsBool(), tc.matches)
					}
				}
			}
			if !found {
				t.Fatal("no crypto.unlock_key span with source keyring")
			}
		})
	}
}
