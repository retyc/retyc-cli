package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/crypto"
)

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "organization-key.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestLoadAdminIdentity_Valid(t *testing.T) {
	id, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	path := writeKeyFile(t, "# created: today\n# public key: "+id.Recipient().String()+"\n"+id.String()+"\n")
	got, err := LoadAdminIdentity(path)
	if err != nil {
		t.Fatalf("LoadAdminIdentity() error = %v", err)
	}
	if got.String() != id.String() {
		t.Error("loaded identity does not match the one written")
	}
}

func TestLoadAdminIdentity_Missing(t *testing.T) {
	_, err := LoadAdminIdentity(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAdminIdentity_LegacyKeyRejected(t *testing.T) {
	path := writeKeyFile(t, "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n")
	_, err := LoadAdminIdentity(path)
	if err == nil || !strings.Contains(err.Error(), "post-quantum") {
		t.Fatalf("expected post-quantum rejection, got %v", err)
	}
}

func TestLoadAdminIdentity_NoKey(t *testing.T) {
	path := writeKeyFile(t, "# just a comment\n\n")
	_, err := LoadAdminIdentity(path)
	if err == nil {
		t.Fatal("expected error for file without identity")
	}
}

func TestLoadAdminIdentity_Garbage(t *testing.T) {
	path := writeKeyFile(t, "not a key at all\n")
	_, err := LoadAdminIdentity(path)
	if err == nil {
		t.Fatal("expected error for garbage content")
	}
}
