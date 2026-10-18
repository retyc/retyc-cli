package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// machineEnv puts the process in machine mode with age.key holding content.
func machineEnv(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{"client.key": "x", "age.key": content} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(config.EnvClientIDName, "c1")
	t.Setenv(config.EnvTokenEndpointName, "https://idp.example/token")
	t.Setenv(config.EnvClientKeyFileName, filepath.Join(dir, "client.key"))
	t.Setenv(config.EnvAgeKeyFileName, filepath.Join(dir, "age.key"))
}

func failingReader(t *testing.T) PassphraseReader {
	t.Helper()

	return func() (string, error) {
		t.Error("passphrase reader called in machine mode")

		return "", errors.New("unexpected")
	}
}

func TestResolveUserIdentityMachine(t *testing.T) {
	id, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	machineEnv(t, id.String()+"\n")
	cfg := &config.Config{}
	cfg.Keyring.Enabled = true // must not be consulted

	got, err := ResolveUserIdentity(context.Background(), cfg,
		&api.UserKey{PublicKey: id.Recipient().String()}, failingReader(t))
	if err != nil {
		t.Fatalf("ResolveUserIdentity() error = %v", err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Error("identity does not match the age.key")
	}
}

func TestMachineIdentityMismatch(t *testing.T) {
	id, _ := crypto.GenerateKeyPair()
	other, _ := crypto.GenerateKeyPair()
	machineEnv(t, id.String())

	_, err := MachineIdentity(context.Background(), &api.UserKey{PublicKey: other.Recipient().String()})
	if !errors.Is(err, ErrAgeKeyMismatch) || !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrAgeKeyMismatch and ErrMachineConfig", err)
	}
}

func TestMachineIdentityNoActiveKey(t *testing.T) {
	id, _ := crypto.GenerateKeyPair()
	machineEnv(t, id.String())

	_, err := MachineIdentity(context.Background(), nil)
	if !errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "no active key") {
		t.Fatalf("err = %v", err)
	}
}

func TestMachineIdentityRejectsX25519(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	machineEnv(t, x.String())

	_, err = MachineIdentity(context.Background(), &api.UserKey{PublicKey: x.Recipient().String()})
	if !errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "post-quantum") {
		t.Fatalf("err = %v, want ErrMachineConfig mentioning post-quantum", err)
	}
	if strings.Contains(err.Error(), x.String()) {
		t.Error("error leaks the key")
	}
}

func TestMachineIdentityGarbage(t *testing.T) {
	machineEnv(t, "not a key SECRETCONTENT")

	_, err := MachineIdentity(context.Background(), &api.UserKey{PublicKey: "age1pq1x"})
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
	if strings.Contains(err.Error(), "SECRETCONTENT") {
		t.Error("error leaks the file content")
	}
}

func TestUnlockUserIdentityMachine(t *testing.T) {
	id, _ := crypto.GenerateKeyPair()
	machineEnv(t, id.String())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"k1","public_key":"` + id.Recipient().String() + `","private_key_enc":null}`))
	}))
	defer srv.Close()

	got, err := UnlockUserIdentity(context.Background(), newKeyTestClient(srv), failingReader(t))
	if err != nil {
		t.Fatalf("UnlockUserIdentity() error = %v", err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Error("identity mismatch")
	}
}

func TestUnlockUserIdentityMachineNoActiveKey(t *testing.T) {
	id, _ := crypto.GenerateKeyPair()
	machineEnv(t, id.String())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(nil)
	}))
	defer srv.Close()

	_, err := UnlockUserIdentity(context.Background(), newKeyTestClient(srv), failingReader(t))
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
}

func TestMachineIdentityAcceptsKeygenComments(t *testing.T) {
	id, _ := crypto.GenerateKeyPair()
	machineEnv(t, "# created: 2026-10-17T00:00:00Z\n# public key: "+id.Recipient().String()+"\n\n"+id.String()+"\n")

	got, err := MachineIdentity(context.Background(), &api.UserKey{PublicKey: id.Recipient().String()})
	if err != nil || got.Recipient().String() != id.Recipient().String() {
		t.Fatalf("err = %v", err)
	}
}

func TestMachineIdentityCommentsThenX25519(t *testing.T) {
	x, _ := age.GenerateX25519Identity()
	machineEnv(t, "# created: now\n# public key: "+x.Recipient().String()+"\n"+x.String()+"\n")

	_, err := MachineIdentity(context.Background(), &api.UserKey{PublicKey: x.Recipient().String()})
	if !errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "post-quantum") {
		t.Fatalf("err = %v", err)
	}
}

func TestMachineIdentityTwoKeys(t *testing.T) {
	a, _ := crypto.GenerateKeyPair()
	b, _ := crypto.GenerateKeyPair()
	machineEnv(t, a.String()+"\n"+b.String()+"\n")

	_, err := MachineIdentity(context.Background(), &api.UserKey{PublicKey: a.Recipient().String()})
	if !errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "expected one identity") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnlockUserIdentityMachineMismatch(t *testing.T) {
	id, _ := crypto.GenerateKeyPair()
	other, _ := crypto.GenerateKeyPair()
	machineEnv(t, id.String())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"k1","public_key":"` + other.Recipient().String() + `","private_key_enc":null}`))
	}))
	defer srv.Close()

	_, err := UnlockUserIdentity(context.Background(), newKeyTestClient(srv), failingReader(t))
	if !errors.Is(err, ErrAgeKeyMismatch) || !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrAgeKeyMismatch and ErrMachineConfig", err)
	}
}
