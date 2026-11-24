package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/core/machinekey"
)

// machineKeys returns a fresh signing key (PEM) and post-quantum identity.
func machineKeys(t *testing.T) ([]byte, *age.HybridIdentity) {
	t.Helper()
	key, err := machinekey.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := machinekey.MarshalSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}

	return pemData, id
}

func TestNewMachineIdentity(t *testing.T) {
	sig, id := machineKeys(t)
	m, err := NewMachineIdentity("c1", "https://iss/token", sig,
		[]byte("# created: now\n# public key: "+id.Recipient().String()+"\n\n"+id.String()+"\n"))
	if err != nil {
		t.Fatalf("NewMachineIdentity() error = %v", err)
	}
	if m.ClientID != "c1" || m.TokenEndpoint != "https://iss/token" || m.MachineID != "" || m.OrganizationID != "" {
		t.Errorf("unexpected identity %+v", m)
	}
	if m.SigningKey == nil || m.KeyID != machinekey.Thumbprint(&m.SigningKey.PublicKey) {
		t.Error("signing key or kid not set")
	}
	if m.AgeIdentity.Recipient().String() != id.Recipient().String() {
		t.Error("AGE identity mismatch")
	}
}

func TestNewMachineIdentityErrors(t *testing.T) {
	sig, id := machineKeys(t)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, clientID, endpoint string
		sig, age                 []byte
		want                     string
	}{
		{"no client", "", "e", sig, []byte(id.String()), "client ID"},
		{"no endpoint", "c", "", sig, []byte(id.String()), "token endpoint"},
		{"bad signing key", "c", "e", []byte("SECRETCONTENT"), []byte(id.String()), "signing key"},
		{"x25519", "c", "e", sig, []byte(x.String()), "post-quantum key is required"},
		{"garbage", "c", "e", sig, []byte("not a key SECRETCONTENT"), "not a valid post-quantum"},
		{"two keys", "c", "e", sig, []byte(id.String() + "\n" + id.String()), "expected one identity"},
		{"empty", "c", "e", sig, []byte("# only a comment\n"), "expected one identity, found 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewMachineIdentity(tc.clientID, tc.endpoint, tc.sig, tc.age)
			if !errors.Is(err, ErrMachineConfig) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrMachineConfig mentioning %q", err, tc.want)
			}
			for _, secret := range []string{"SECRETCONTENT", x.String(), id.String(), string(sig)} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaks a key: %v", err)
				}
			}
		})
	}
}

// writeMachineKeys writes valid key files and returns the Machine naming them.
func writeMachineKeys(t *testing.T) (*Machine, *age.HybridIdentity) {
	t.Helper()
	sig, id := machineKeys(t)
	dir := t.TempDir()
	m := &Machine{ //nolint:gosec // G101: test fixture, no credential
		ClientID: "c1", TokenEndpoint: "https://iss/token", MachineID: "m1", OrganizationID: "o1",
		ClientKeyFile: filepath.Join(dir, MachineSigningKeyFile), AgeKeyFile: filepath.Join(dir, MachineAgeKeyFile),
	}
	for path, data := range map[string][]byte{m.ClientKeyFile: sig, m.AgeKeyFile: []byte(id.String() + "\n")} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return m, id
}

func TestLoadMachineIdentity(t *testing.T) {
	m, id := writeMachineKeys(t)
	got, err := LoadMachineIdentity(m)
	if err != nil {
		t.Fatalf("LoadMachineIdentity() error = %v", err)
	}
	if got.ClientID != "c1" || got.TokenEndpoint != "https://iss/token" || got.MachineID != "m1" ||
		got.OrganizationID != "o1" || got.AgeIdentity.Recipient().String() != id.Recipient().String() {
		t.Errorf("unexpected identity %+v", got)
	}
}

func TestLoadMachineIdentityErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, m *Machine)
		want  func(m *Machine) string
	}{
		{"missing age.key", func(t *testing.T, m *Machine) {
			t.Helper()
			if err := os.Remove(m.AgeKeyFile); err != nil {
				t.Fatal(err)
			}
		}, func(m *Machine) string { return m.AgeKeyFile }},
		{"world readable client.key", func(t *testing.T, m *Machine) {
			t.Helper()
			if err := os.Chmod(m.ClientKeyFile, 0o644); err != nil { //nolint:gosec // G302: test fixture
				t.Fatal(err)
			}
		}, func(m *Machine) string { return m.ClientKeyFile + " has mode 0644" }},
		{"bad client.key", func(t *testing.T, m *Machine) {
			t.Helper()
			if err := os.WriteFile(m.ClientKeyFile, []byte("SECRETCONTENT"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, func(m *Machine) string { return m.ClientKeyFile }},
		{"bad age.key", func(t *testing.T, m *Machine) {
			t.Helper()
			if err := os.WriteFile(m.AgeKeyFile, []byte("SECRETCONTENT"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, func(m *Machine) string { return m.AgeKeyFile + " is not a valid post-quantum AGE identity" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := writeMachineKeys(t)
			tc.setup(t, m)
			_, err := LoadMachineIdentity(m)
			if !errors.Is(err, ErrMachineConfig) || !strings.Contains(err.Error(), tc.want(m)) {
				t.Fatalf("err = %v, want ErrMachineConfig mentioning %q", err, tc.want(m))
			}
			if strings.Contains(err.Error(), "SECRETCONTENT") {
				t.Errorf("error leaks the file content: %v", err)
			}
		})
	}
}
