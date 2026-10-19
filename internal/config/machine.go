package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ErrMachineConfig is wrapped by every failure to configure a machine account:
// a missing variable, an unreadable or too permissive key file, an unknown
// file version. It maps to the configuration exit code (78). Messages carry
// paths and variable names, never file contents.
var ErrMachineConfig = errors.New("machine account configuration")

// Names of the files of an enrollment directory.
const (
	MachineSigningKeyFile = "client.key"
	MachineAgeKeyFile     = "age.key"
	MachineEnrollmentFile = "enrollment.json"
	MachineFile           = "machine.json"
)

// machineFileVersion is the only format version of the JSON files.
const machineFileVersion = 1

// MachineInfo is the content of machine.json.
type MachineInfo struct {
	Version        int    `json:"version"`
	MachineID      string `json:"machine_id"`
	OrganizationID string `json:"organization_id"`
	ClientID       string `json:"client_id"`
	Issuer         string `json:"issuer"`
	TokenEndpoint  string `json:"token_endpoint"`
}

// EnrollmentInfo is the content of enrollment.json.
type EnrollmentInfo struct {
	Version        int       `json:"version"`
	EnrollmentID   string    `json:"enrollment_id"`
	OrganizationID string    `json:"organization_id"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Machine is the resolved configuration of a machine account.
type Machine struct {
	ClientID       string
	TokenEndpoint  string
	ClientKeyFile  string
	AgeKeyFile     string
	MachineID      string
	OrganizationID string
}

// MachineMode reports whether the environment designates a machine account.
func MachineMode() bool {
	return fromEnv(EnvMachineDirName) != "" || fromEnv(EnvClientIDName) != ""
}

// LoadMachine resolves the machine account configuration. It returns nil, nil
// outside machine mode. The values of RETYC_MACHINE_DIR/machine.json come
// first; each non-empty unit variable then overrides its value. Both key files
// must exist and not be accessible to others (stat only, nothing is parsed).
func LoadMachine() (*Machine, error) {
	if !MachineMode() {
		return nil, nil //nolint:nilnil // not in machine mode is not an error
	}
	for _, name := range []string{EnvTokenName, EnvKeyPassphraseName} {
		if fromEnv(name) != "" {
			return nil, fmt.Errorf("%w: %s cannot be set with a machine account", ErrMachineConfig, name)
		}
	}

	m := &Machine{}
	if dir := fromEnv(EnvMachineDirName); dir != "" {
		info, err := ReadMachineInfo(dir)
		if err != nil {
			return nil, err
		}
		if info != nil {
			m.ClientID, m.TokenEndpoint = info.ClientID, info.TokenEndpoint
			m.MachineID, m.OrganizationID = info.MachineID, info.OrganizationID
		}
		m.ClientKeyFile = filepath.Join(dir, MachineSigningKeyFile)
		m.AgeKeyFile = filepath.Join(dir, MachineAgeKeyFile)
	}
	for _, o := range []struct {
		env string
		dst *string
	}{
		{EnvClientIDName, &m.ClientID},
		{EnvTokenEndpointName, &m.TokenEndpoint},
		{EnvClientKeyFileName, &m.ClientKeyFile},
		{EnvAgeKeyFileName, &m.AgeKeyFile},
	} {
		if v := fromEnv(o.env); v != "" {
			*o.dst = v
		}
	}

	for _, r := range []struct {
		env string
		val string
	}{
		{EnvClientIDName, m.ClientID},
		{EnvTokenEndpointName, m.TokenEndpoint},
		{EnvClientKeyFileName, m.ClientKeyFile},
		{EnvAgeKeyFileName, m.AgeKeyFile},
	} {
		if r.val == "" {
			return nil, fmt.Errorf("%w: %s is not set", ErrMachineConfig, r.env)
		}
	}
	for _, p := range []string{m.ClientKeyFile, m.AgeKeyFile} {
		if err := checkMachineFile(p); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// checkMachineFile stats path (following symlinks) and refuses a file that
// others can access. Group read is tolerated: a mounted Secret is 0440.
func checkMachineFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %s", ErrMachineConfig, path, errReason(err))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrMachineConfig, path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("%w: %s has mode %04o, expected 0600 or 0440", ErrMachineConfig, path, info.Mode().Perm())
	}

	return nil
}

// errReason is the short reason of a file system error, without the path
// (the caller already names it).
func errReason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}

	return err.Error()
}

// ReadMachineFile reads a machine file, following symlinks, and refuses one
// whose mode gives access to others (mode&0o007 != 0).
func ReadMachineFile(path string) ([]byte, error) {
	if err := checkMachineFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-designated key file
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %s", ErrMachineConfig, path, errReason(err))
	}

	return data, nil
}

// WriteMachineFile atomically writes dir/name with mode 0600 (temp file in the
// same directory, then rename). It refuses to replace an existing file, except
// the enrollment record, which is rewritten as the enrollment progresses.
func WriteMachineFile(dir, name string, data []byte) error {
	target := filepath.Join(dir, name)
	if name != MachineEnrollmentFile {
		if _, err := os.Lstat(target); err == nil {
			return fmt.Errorf("%w: %s already exists, not overwriting", ErrMachineConfig, target)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s: %s", ErrMachineConfig, target, errReason(err))
		}
	}

	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("creating %s: %w", target, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()

		return fmt.Errorf("writing %s: %w", target, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()

		return fmt.Errorf("writing %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()

		return fmt.Errorf("writing %s: %w", target, err)
	}
	if name != MachineEnrollmentFile {
		// A hard link fails if the target appeared meanwhile, so a concurrent
		// writer never loses its file.
		defer cleanup()
		if err := os.Link(tmpName, target); err != nil {
			return fmt.Errorf("writing %s: %w", target, err)
		}

		return nil
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()

		return fmt.Errorf("writing %s: %w", target, err)
	}

	return nil
}

// readMachineJSON decodes dir/name into v. It returns false, nil when the file
// is absent. The error never quotes the file.
func readMachineJSON(dir, name string, v any, version func() int) (bool, error) {
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	data, err := ReadMachineFile(path)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("%w: %s is not valid JSON", ErrMachineConfig, path)
	}
	if got := version(); got != machineFileVersion {
		return false, fmt.Errorf("%w: %s has unsupported version %d", ErrMachineConfig, path, got)
	}

	return true, nil
}

// ReadMachineInfo reads dir/machine.json. It returns nil, nil when absent.
func ReadMachineInfo(dir string) (*MachineInfo, error) {
	var info MachineInfo
	ok, err := readMachineJSON(dir, MachineFile, &info, func() int { return info.Version })
	if err != nil || !ok {
		return nil, err
	}

	return &info, nil
}

// ReadEnrollmentInfo reads dir/enrollment.json. It returns nil, nil when absent.
func ReadEnrollmentInfo(dir string) (*EnrollmentInfo, error) {
	var info EnrollmentInfo
	ok, err := readMachineJSON(dir, MachineEnrollmentFile, &info, func() int { return info.Version })
	if err != nil || !ok {
		return nil, err
	}

	return &info, nil
}
