package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

func keyfilesDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

func newKeyString(t *testing.T) string {
	t.Helper()
	id, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	return id.String()
}

func existsPath(p string) bool {
	_, err := os.Lstat(p)

	return err == nil
}

func readTrim(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: test path
	if err != nil {
		t.Fatal(err)
	}

	return strings.TrimSpace(string(b))
}

func TestFinishMachineKeySwap(t *testing.T) {
	oldK, newK := newKeyString(t), newKeyString(t)
	for _, tc := range []struct {
		name      string
		files     map[string]string
		wantKey   string
		wantNew   bool
		wantOld   bool
		wantKeyEx bool
	}{
		{"crash during swap", map[string]string{"age.key.old": oldK, "age.key.new": newK}, newK, false, true, true},
		{"new beside current", map[string]string{"age.key": oldK, "age.key.new": newK}, oldK, true, false, true},
		{
			"all three present",
			map[string]string{"age.key": oldK, "age.key.old": oldK, "age.key.new": newK},
			oldK, true, true, true,
		},
		{"current alone", map[string]string{"age.key": oldK}, oldK, false, false, true},
		{"nothing", map[string]string{}, "", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := keyfilesDir(t, tc.files)
			p := filepath.Join(dir, "age.key")
			if err := FinishMachineKeySwap(p); err != nil {
				t.Fatal(err)
			}
			if existsPath(p) != tc.wantKeyEx || existsPath(p+".new") != tc.wantNew || existsPath(p+".old") != tc.wantOld {
				t.Fatalf("unexpected file set in %v", dirNames(t, dir))
			}
			if tc.wantKeyEx && readTrim(t, p) != tc.wantKey {
				t.Fatal("age.key has the wrong content")
			}
		})
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}

	return out
}

func TestSwapMachineKeys(t *testing.T) {
	oldK, newK := newKeyString(t), newKeyString(t)
	dir := keyfilesDir(t, map[string]string{"age.key": oldK, "age.key.new": newK})
	p := filepath.Join(dir, "age.key")
	if err := swapMachineKeys(p); err != nil {
		t.Fatal(err)
	}
	if readTrim(t, p) != newK || readTrim(t, p+".old") != oldK || existsPath(p+".new") {
		t.Fatalf("unexpected state: %v", dirNames(t, dir))
	}
	for _, f := range []string{p, p + ".old"} {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", f, fi.Mode().Perm())
		}
	}
}

func TestWriteReadRemoveMachineKey(t *testing.T) {
	dir := keyfilesDir(t, map[string]string{"age.key": newKeyString(t)})
	p := filepath.Join(dir, "age.key")
	id, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMachineKey(p, machineKeyNewSuffix, id); err != nil {
		t.Fatal(err)
	}
	if err := writeMachineKey(p, machineKeyNewSuffix, id); err == nil {
		t.Fatal("second write must refuse to overwrite")
	}
	files, err := readMachineKeyFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	if files.cur == nil || files.old != nil || files.next == nil ||
		files.next.Recipient().String() != id.Recipient().String() {
		t.Fatalf("unexpected files: %+v", files)
	}
	if err := removeMachineKey(p, machineKeyNewSuffix); err != nil || existsPath(p+".new") {
		t.Fatalf("remove: %v", err)
	}
	if err := removeMachineKey(p, machineKeyOldSuffix); err != nil {
		t.Fatalf("absent remove: %v", err)
	}
}

func TestReadMachineKeyFiles_NoContentInErrors(t *testing.T) {
	dir := keyfilesDir(t, map[string]string{"age.key": newKeyString(t), "age.key.new": "SECRET-MARKER"})
	_, err := readMachineKeyFiles(filepath.Join(dir, "age.key"))
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatal("error quotes the file content")
	}
}
