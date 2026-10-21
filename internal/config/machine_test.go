package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// machineDir builds a directory shaped like an enrollment output.
func machineDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	meta := `{"version":1,"machine_id":"m1","organization_id":"o1","client_id":"c1",` +
		`"issuer":"https://iss","token_endpoint":"https://iss/token"}`
	for name, data := range map[string]string{
		MachineFile: meta, MachineSigningKeyFile: "k", MachineAgeKeyFile: "a",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

func TestLoadMachineOff(t *testing.T) {
	resetViper(t)
	m, err := LoadMachine()
	if m != nil || err != nil {
		t.Fatalf("LoadMachine() = %v, %v; want nil, nil", m, err)
	}
	if MachineMode() {
		t.Fatal("MachineMode() = true without variables")
	}
}

func TestLoadMachineFromDir(t *testing.T) {
	resetViper(t)
	dir := machineDir(t)
	t.Setenv(EnvMachineDirName, dir)
	m, err := LoadMachine()
	if err != nil {
		t.Fatal(err)
	}
	if m.ClientID != "c1" || m.TokenEndpoint != "https://iss/token" || m.MachineID != "m1" ||
		m.OrganizationID != "o1" || m.ClientKeyFile != filepath.Join(dir, "client.key") ||
		m.AgeKeyFile != filepath.Join(dir, "age.key") {
		t.Fatalf("unexpected machine %+v", m)
	}
}

func TestLoadMachineOverrides(t *testing.T) {
	resetViper(t)
	t.Setenv(EnvMachineDirName, machineDir(t))
	t.Setenv(EnvTokenEndpointName, "https://other/token")
	m, err := LoadMachine()
	if err != nil {
		t.Fatal(err)
	}
	if m.TokenEndpoint != "https://other/token" {
		t.Fatalf("TokenEndpoint = %q", m.TokenEndpoint)
	}
}

func TestLoadMachineUnitVarsOnly(t *testing.T) {
	resetViper(t)
	dir := machineDir(t)
	t.Setenv(EnvClientIDName, "c2")
	t.Setenv(EnvTokenEndpointName, "https://t")
	t.Setenv(EnvClientKeyFileName, filepath.Join(dir, "client.key"))
	t.Setenv(EnvAgeKeyFileName, filepath.Join(dir, "age.key"))
	m, err := LoadMachine()
	if err != nil || m.ClientID != "c2" {
		t.Fatalf("LoadMachine() = %+v, %v", m, err)
	}
}

func TestLoadMachineIncomplete(t *testing.T) {
	resetViper(t)
	t.Setenv(EnvClientIDName, "c1")
	_, err := LoadMachine()
	if !errors.Is(err, ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
	if !strings.Contains(err.Error(), EnvTokenEndpointName) {
		t.Fatalf("error %q does not name the missing variable", err)
	}
}

func TestLoadMachineBadKeyMode(t *testing.T) {
	resetViper(t)
	dir := machineDir(t)
	if err := os.Chmod(filepath.Join(dir, "age.key"), 0o644); err != nil { //nolint:gosec // G302: test fixture
		t.Fatal(err)
	}
	t.Setenv(EnvMachineDirName, dir)
	if _, err := LoadMachine(); !errors.Is(err, ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
}

func TestLoadMachineExclusive(t *testing.T) {
	for _, name := range []string{EnvTokenName, EnvKeyPassphraseName} {
		t.Run(name, func(t *testing.T) {
			resetViper(t)
			t.Setenv(EnvMachineDirName, machineDir(t))
			t.Setenv(name, "x")
			_, err := LoadMachine()
			if !errors.Is(err, ErrMachineConfig) || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want ErrMachineConfig naming %s", err, name)
			}
		})
	}
}

func TestReadMachineFileSymlink0440(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "..2026_01_01")
	if err := os.Mkdir(data, 0o755); err != nil { //nolint:gosec // G301: test fixture
		t.Fatal(err)
	}
	p := filepath.Join(data, "age.key")
	if err := os.WriteFile(p, []byte("secret"), 0o440); err != nil { //nolint:gosec // G306: fixture
		t.Fatal(err)
	}
	if err := os.Symlink("..2026_01_01", filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "age.key"), filepath.Join(root, "age.key")); err != nil {
		t.Fatal(err)
	}
	b, err := ReadMachineFile(filepath.Join(root, "age.key"))
	if err != nil || string(b) != "secret" {
		t.Fatalf("ReadMachineFile = %q, %v", b, err)
	}
}

func TestReadMachineFileWorldReadable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(p, []byte("secret"), 0o644); err != nil { //nolint:gosec // G306: test fixture
		t.Fatal(err)
	}
	_, err := ReadMachineFile(p)
	if !errors.Is(err, ErrMachineConfig) || !strings.Contains(err.Error(), p) ||
		strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestMachineInfoUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, MachineFile), []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMachineInfo(dir); !errors.Is(err, ErrMachineConfig) {
		t.Fatalf("err = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, MachineEnrollmentFile), []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnrollmentInfo(dir); !errors.Is(err, ErrMachineConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestMachineInfoAbsent(t *testing.T) {
	dir := t.TempDir()
	if i, err := ReadMachineInfo(dir); i != nil || err != nil {
		t.Fatalf("got %v, %v", i, err)
	}
	if i, err := ReadEnrollmentInfo(dir); i != nil || err != nil {
		t.Fatalf("got %v, %v", i, err)
	}
}

func TestEnrollmentInfoRead(t *testing.T) {
	dir := t.TempDir()
	js := `{"version":1,"enrollment_id":"e1","organization_id":"o1","expires_at":"2026-10-17T10:00:00Z"}`
	if err := WriteMachineFile(dir, MachineEnrollmentFile, []byte(js)); err != nil {
		t.Fatal(err)
	}
	e, err := ReadEnrollmentInfo(dir)
	if err != nil || e.EnrollmentID != "e1" || e.ExpiresAt.Year() != 2026 {
		t.Fatalf("got %+v, %v", e, err)
	}
}

func TestWriteMachineFileNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMachineFile(dir, MachineAgeKeyFile, []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := WriteMachineFile(dir, MachineAgeKeyFile, []byte("2")); err == nil {
		t.Fatal("second write of age.key succeeded")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, MachineAgeKeyFile)); string(b) != "1" { //nolint:gosec // G304: test path
		t.Fatalf("age.key overwritten: %q", b)
	}
	for _, v := range []string{"1", "2"} {
		if err := WriteMachineFile(dir, MachineEnrollmentFile, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{MachineAgeKeyFile, MachineEnrollmentFile} {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, %v", n, st, err)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatalf("temp files left: %v", ents)
	}
}

func TestMachineAgeKeyPath(t *testing.T) {
	t.Run("file variable wins", func(t *testing.T) {
		t.Setenv(EnvMachineDirName, "/some/dir")
		t.Setenv(EnvAgeKeyFileName, "/elsewhere/my.key")
		got, err := MachineAgeKeyPath()
		if err != nil || got != "/elsewhere/my.key" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		t.Setenv(EnvMachineDirName, "/some/dir")
		t.Setenv(EnvAgeKeyFileName, "")
		got, err := MachineAgeKeyPath()
		if err != nil || got != filepath.Join("/some/dir", MachineAgeKeyFile) {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("nothing set", func(t *testing.T) {
		t.Setenv(EnvMachineDirName, "")
		t.Setenv(EnvAgeKeyFileName, "")
		if _, err := MachineAgeKeyPath(); !errors.Is(err, ErrMachineConfig) {
			t.Fatalf("err = %v, want ErrMachineConfig", err)
		}
	})
	t.Run("absent file is not an error", func(t *testing.T) {
		t.Setenv(EnvMachineDirName, "")
		t.Setenv(EnvAgeKeyFileName, filepath.Join(t.TempDir(), "missing"))
		if _, err := MachineAgeKeyPath(); err != nil {
			t.Fatal(err)
		}
	})
}
