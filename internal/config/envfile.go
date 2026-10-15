package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
)

// ErrEnvFile is wrapped by every failure to load the environment file: a file
// that is missing, unreadable, readable by others, or malformed. It maps to
// the configuration exit code, since a restart with the same file fails again.
var ErrEnvFile = errors.New("environment file")

// envFileMaxSize bounds what is read from an environment file. It holds a
// handful of short lines; anything larger is not one.
const envFileMaxSize = 1 << 20

// envVarPrefix is the only namespace an environment file may set. The file is
// a source of CLI settings, not a way to change the proxy, the trusted CAs or
// the loader of the process.
const envVarPrefix = envPrefix + "_"

// EnvFile describes the environment file a process loaded.
type EnvFile struct {
	// Path is the file as it was designated (flag or RETYC_ENV_FILE).
	Path string
	// Applied lists the variables set from the file, sorted.
	Applied []string
	// Kept lists the variables the file carries but the environment already
	// had: the environment wins. Sorted.
	Kept []string
}

// envFileApplied holds the variables the last LoadEnvFile set, so that a new
// load (or UnloadEnvFile) can take them back. Startup only: not synchronised.
var envFileApplied []string

// envVar is one assignment of an environment file.
type envVar struct {
	name, value string
	line        int
}

// LoadEnvFile reads the environment file designated by flagPath, or by
// RETYC_ENV_FILE when flagPath is empty, and sets its variables in the process
// environment. A variable the environment already holds, even empty, is left
// alone: the real environment wins over the file. It returns nil, nil when no
// file is designated.
//
// It must run before viper is initialised and before any RETYC_ variable is
// read. Nothing is applied when the file fails to load. No error ever carries
// a value, nor any text of an offending line: only its number.
func LoadEnvFile(flagPath string) (*EnvFile, error) {
	UnloadEnvFile()

	path := flagPath
	if path == "" {
		path = envFilePath()
	}
	if path == "" {
		return nil, nil //nolint:nilnil // no file designated is not an error
	}

	vars, err := readEnvFile(path)
	if err != nil {
		return nil, err
	}

	loaded := &EnvFile{Path: path}
	seen := make(map[string]bool, len(vars))
	// Decide against the environment as it is before the file touches it, so
	// a name assigned twice in the file takes its last value.
	inherited := make(map[string]bool, len(vars))
	for _, v := range vars {
		if _, done := inherited[v.name]; !done {
			_, present := os.LookupEnv(v.name)
			inherited[v.name] = present
		}
	}
	for _, v := range vars {
		if inherited[v.name] {
			if !seen[v.name] {
				loaded.Kept = append(loaded.Kept, v.name)
			}
			seen[v.name] = true

			continue
		}
		if err := os.Setenv(v.name, v.value); err != nil {
			UnloadEnvFile()

			return nil, fmt.Errorf("%w %s: line %d: value cannot be set in the environment", ErrEnvFile, path, v.line)
		}
		if !seen[v.name] {
			loaded.Applied = append(loaded.Applied, v.name)
			envFileApplied = append(envFileApplied, v.name)
		}
		seen[v.name] = true
	}
	sort.Strings(loaded.Applied)
	sort.Strings(loaded.Kept)

	return loaded, nil
}

// UnloadEnvFile removes from the environment the variables the last
// LoadEnvFile set. Tests use it to leave the environment as they found it.
func UnloadEnvFile() {
	for _, name := range envFileApplied {
		_ = os.Unsetenv(name)
	}
	envFileApplied = nil
}

// readEnvFile opens path, checks its permissions and parses it.
func readEnvFile(path string) ([]envVar, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator designates the file
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvFile, err)
	}
	defer func() { _ = f.Close() }()

	// Checked on the open file, not on the path: what is read is what was
	// checked.
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvFile, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%w %s: is a directory", ErrEnvFile, path)
	}
	// Like ssh for a private key: a file of secrets others can read is
	// refused. Windows has no mode bits to check (ACLs, not handled yet).
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"%w %s: permissions %#o are too open, it must not be accessible by group or others; run: chmod 600 %s",
			ErrEnvFile, path, info.Mode().Perm(), path)
	}

	data, err := io.ReadAll(io.LimitReader(f, envFileMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvFile, err)
	}
	if len(data) > envFileMaxSize {
		return nil, fmt.Errorf("%w %s: larger than %d bytes", ErrEnvFile, path, envFileMaxSize)
	}

	vars, err := parseEnvFile(string(data))
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrEnvFile, path, err)
	}

	return vars, nil
}

// parseEnvFile parses the content of an environment file:
//
//	# comment
//	RETYC_NAME=value
//	export RETYC_NAME="value with spaces"
//	RETYC_NAME='taken as it is'
//
// A value is the rest of the line, surrounding blanks removed, or the content
// of a pair of quotes, which may be followed by a comment. Nothing is expanded.
// Between double quotes \" and \\ stand for the character; every other
// backslash, and everything between single quotes, is literal. An unquoted
// value keeps its '#': a passphrase may hold one.
//
// Errors name the line number and never quote the line.
func parseEnvFile(content string) ([]envVar, error) {
	content = strings.TrimPrefix(content, "\xef\xbb\xbf") // UTF-8 byte order mark

	var vars []envVar
	for i, line := range strings.Split(content, "\n") {
		name, value, ok, err := parseEnvLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if ok {
			vars = append(vars, envVar{name: name, value: value, line: i + 1})
		}
	}

	return vars, nil
}

// parseEnvLine parses one line; ok is false for a blank line or a comment.
func parseEnvLine(line string) (name, value string, ok bool, err error) {
	line = strings.TrimSpace(line) // also drops the \r of a CRLF file
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, nil
	}
	if rest, found := strings.CutPrefix(line, "export"); found && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
		line = strings.TrimSpace(rest)
	}

	name, raw, found := strings.Cut(line, "=")
	if !found || !validEnvName(name) {
		return "", "", false, errors.New("expected RETYC_NAME=value")
	}
	if !strings.HasPrefix(name, envVarPrefix) {
		return "", "", false, errors.New("only " + envVarPrefix + "* variables are accepted")
	}
	if name == EnvFileName {
		return "", "", false, errors.New(EnvFileName + " cannot be set from the environment file")
	}

	value, err = envValue(raw)
	if err != nil {
		return "", "", false, err
	}
	if strings.ContainsRune(value, 0) {
		return "", "", false, errors.New("value holds a NUL byte")
	}

	return name, value, true, nil
}

// validEnvName reports whether s is a shell variable name.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}

	return true
}

// envValue returns the value written after the '=' of a line.
func envValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || (raw[0] != '"' && raw[0] != '\'') {
		return raw, nil
	}

	quote := raw[0]
	var b strings.Builder
	for i := 1; i < len(raw); i++ {
		c := raw[i]
		switch {
		case quote == '"' && c == '\\' && i+1 < len(raw) && (raw[i+1] == '"' || raw[i+1] == '\\'):
			i++
			b.WriteByte(raw[i])
		case c == quote:
			if rest := strings.TrimSpace(raw[i+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
				return "", errors.New("unexpected text after the closing quote")
			}

			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}

	return "", errors.New("missing closing quote")
}
