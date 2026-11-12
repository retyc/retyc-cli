package mcpsetup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// readOptional returns the content of path, or nil when it does not exist.
func readOptional(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: client configuration path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	return b, err
}

// writeFileAtomic replaces path with data: the previous content is saved as
// path.bak (mode 0600, it may hold secrets), then path is replaced. A missing
// directory is created (0700).
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if old, err := readOptional(path); err != nil {
		return err
	} else if old != nil {
		// Replaced, not rewritten: an existing .bak may be readable by others.
		if err := replaceFile(path+".bak", old, 0o600); err != nil {
			return fmt.Errorf("backing up %s: %w", path, err)
		}
	}

	return replaceFile(path, data, perm)
}

// replaceFile writes data to a temporary file of path's directory with mode
// perm, then renames it over path: path never holds partial content, and its
// mode is perm whatever it was before.
func replaceFile(path string, data []byte, perm fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}

// dotenvValue quotes v for a .env line, read the same way by python-dotenv
// (Hermes) and Node's dotenv (OpenClaw). Single quotes keep everything literal
// in Node's dotenv, but python-dotenv still unescapes \\ and \' and expands
// ${VAR} in them, so a backslash or "${" is never accepted; double quotes are
// used only when v has no character either parser would interpret. Anything
// else is refused rather than silently altered.
func dotenvValue(v string) (string, error) {
	if strings.ContainsAny(v, "\n\r\x00\\") || strings.Contains(v, "${") {
		return "", ErrUnsupportedValue
	}
	if !strings.Contains(v, "'") {
		return "'" + v + "'", nil
	}
	if !strings.ContainsAny(v, "\"\\$") {
		return `"` + v + `"`, nil
	}

	return "", ErrUnsupportedValue
}

// upsertDotEnv sets keys in the .env file at path (mode 0600): an existing
// KEY= or export KEY= line is replaced in place, later duplicates are dropped,
// missing keys are appended in order. Other lines are kept as they are.
func upsertDotEnv(path string, keys []string, values map[string]string) error {
	quoted := make(map[string]string, len(keys))
	for _, k := range keys {
		q, err := dotenvValue(values[k])
		if err != nil {
			return fmt.Errorf("%s: %w", k, err) // never the value itself
		}
		quoted[k] = q
	}

	old, err := readOptional(path)
	if err != nil {
		return err
	}
	var lines []string
	if s := strings.TrimRight(string(old), "\n"); s != "" {
		lines = strings.Split(s, "\n")
	}

	done := map[string]bool{}
	out := make([]string, 0, len(lines)+len(keys))
	for _, line := range lines {
		k := dotenvKey(line)
		if _, ours := quoted[k]; !ours {
			out = append(out, line)

			continue
		}
		if !done[k] {
			out = append(out, k+"="+quoted[k])
			done[k] = true
		}
	}
	for _, k := range keys {
		if !done[k] {
			out = append(out, k+"="+quoted[k])
		}
	}

	return writeFileAtomic(path, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

// dotenvKey returns the key a .env line assigns, "" for anything else.
func dotenvKey(line string) string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "export ")
	k, _, ok := strings.Cut(s, "=")
	if !ok {
		return ""
	}

	return strings.TrimSpace(k)
}
