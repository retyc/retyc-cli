package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/config"
)

// Neighbours of age.key used by a machine key rotation. At every instant the
// key active on the server is in age.key or in age.key.new (see the state
// table of the design): the swap order below preserves that.
const (
	machineKeyNewSuffix = ".new"
	machineKeyOldSuffix = ".old"
)

// machineKeyFiles holds the identities of age.key (cur), age.key.new (next)
// and age.key.old (old); a nil field means the file is absent.
type machineKeyFiles struct {
	cur, next, old *age.HybridIdentity
}

// renameSync renames from to to, then syncs the directory.
func renameSync(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("%w: renaming %s: %s", config.ErrMachineConfig, filepath.Base(from), config.ErrReason(err))
	}

	return config.SyncDir(filepath.Dir(to))
}

// FinishMachineKeySwap completes a swap interrupted between its two renames:
// age.key absent with both .old and .new present means .new is the active key
// and must become age.key. Every other state is left untouched. It must run
// before the machine configuration is loaded, which requires age.key.
func FinishMachineKeySwap(ageKeyPath string) error {
	cur, err := fileExists(ageKeyPath)
	if err != nil || cur {
		return err
	}
	old, err := fileExists(ageKeyPath + machineKeyOldSuffix)
	if err != nil || !old {
		return err
	}
	next, err := fileExists(ageKeyPath + machineKeyNewSuffix)
	if err != nil || !next {
		return err
	}

	return renameSync(ageKeyPath+machineKeyNewSuffix, ageKeyPath)
}

// readMachineKeyFiles reads age.key and its optional neighbours. Errors wrap
// config.ErrMachineConfig and never quote a file.
func readMachineKeyFiles(ageKeyPath string) (machineKeyFiles, error) {
	var out machineKeyFiles
	for _, f := range []struct {
		path string
		dst  **age.HybridIdentity
	}{
		{ageKeyPath, &out.cur},
		{ageKeyPath + machineKeyNewSuffix, &out.next},
		{ageKeyPath + machineKeyOldSuffix, &out.old},
	} {
		ok, err := fileExists(f.path)
		if err != nil {
			return machineKeyFiles{}, err
		}
		if !ok {
			continue
		}
		data, err := config.ReadMachineFile(f.path)
		if err != nil {
			return machineKeyFiles{}, err
		}
		id, err := parseMachineAgeKey(data, filepath.Base(f.path))
		if err != nil {
			return machineKeyFiles{}, err
		}
		*f.dst = id
	}

	return out, nil
}

// writeMachineKey writes id to ageKeyPath+suffix (0600, atomic, never
// overwriting).
func writeMachineKey(ageKeyPath, suffix string, id *age.HybridIdentity) error {
	return config.WriteMachineFile(filepath.Dir(ageKeyPath), filepath.Base(ageKeyPath)+suffix,
		[]byte(id.String()+"\n"))
}

// swapMachineKeys makes .new the active age.key and keeps the previous one as
// .old: age.key to .old, then .new to age.key. A crash between the two renames
// is repaired by FinishMachineKeySwap.
func swapMachineKeys(ageKeyPath string) error {
	if err := renameSync(ageKeyPath, ageKeyPath+machineKeyOldSuffix); err != nil {
		return err
	}

	return renameSync(ageKeyPath+machineKeyNewSuffix, ageKeyPath)
}

// removeMachineKey deletes ageKeyPath+suffix; an absent file is not an error.
func removeMachineKey(ageKeyPath, suffix string) error {
	err := os.Remove(ageKeyPath + suffix)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: removing %s: %s", config.ErrMachineConfig,
			filepath.Base(ageKeyPath)+suffix, config.ErrReason(err))
	}
	if err != nil {
		return nil
	}

	return config.SyncDir(filepath.Dir(ageKeyPath))
}
