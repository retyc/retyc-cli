// Package mcpsetup writes the MCP server entry of retyc into the configuration
// of AI clients (Claude Desktop, Hermes, OpenClaw) and installs the binary
// they launch at a stable path. It backs `retyc mcp setup`.
//
// The package works on files only (plus the OpenClaw CLI, which owns its
// configuration): it knows nothing about login, the API or cobra, and takes
// every host detail through Env so that tests run against a temporary home.
//
// Rules shared by every client:
//   - the user's configuration is preserved: only the `retyc` entry is
//     added or replaced, and the previous file is kept as <file>.bak;
//   - every file that receives a secret is written atomically with mode 0600;
//   - secrets never appear in errors, nor on a command line.
package mcpsetup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ServerName is the name of the entry written into every client.
const ServerName = "retyc"

// Environment variables the server reads its secrets from.
const (
	EnvToken      = "RETYC_TOKEN"
	EnvPassphrase = "RETYC_KEY_PASSPHRASE" //nolint:gosec // G101: variable name, not a credential
)

// ServeArgs are the arguments every client passes to the binary.
var ServeArgs = []string{"mcp", "serve"}

var (
	// ErrBinaryInUse reports that the stable binary could not be replaced
	// because a running client holds it (Windows).
	ErrBinaryInUse = errors.New("mcpsetup: binary in use")
	// ErrUnsupportedValue reports a secret that cannot be written to a .env
	// file without being altered by the client's dotenv parser.
	ErrUnsupportedValue = errors.New("mcpsetup: value cannot be stored in a .env file")
)

// ManualStepError reports a client that could only be partly configured: the
// user has to run Command. Command never contains a secret.
type ManualStepError struct {
	Client  string
	Command string
}

func (e *ManualStepError) Error() string {
	return fmt.Sprintf("%s: run this command to finish: %s", e.Client, e.Command)
}

// Env is the host as seen by this package. DefaultEnv returns the real one.
type Env struct {
	GOOS      string // runtime.GOOS, overridable in tests
	Home      string // os.UserHomeDir
	ConfigDir string // os.UserConfigDir (~/.config, ~/Library/Application Support, %AppData%)
	Getenv    func(string) string
	LookPath  func(string) (string, error)
	// Run runs a command and returns an error carrying its output on failure.
	Run func(name string, args ...string) error
}

// DefaultEnv returns the Env of the running process; Run is bound to ctx.
func DefaultEnv(ctx context.Context) (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return Env{}, err
	}

	return Env{
		GOOS:      runtime.GOOS,
		Home:      home,
		ConfigDir: cfg,
		Getenv:    os.Getenv,
		LookPath:  exec.LookPath,
		Run: func(name string, args ...string) error {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: fixed client CLI
			if err != nil {
				return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
			}

			return nil
		},
	}, nil
}

// Server is the entry written into the clients.
type Server struct {
	Command    string // absolute path of the binary (BinaryPath)
	Token      string // offline refresh token (RETYC_TOKEN)
	Passphrase string // key passphrase (RETYC_KEY_PASSPHRASE)
}

// Client is an AI client this package can configure.
type Client interface {
	Name() string
	// Detected reports whether the client seems installed for this user.
	Detected(e Env) bool
	// Configure adds or replaces the retyc entry; it returns the files written.
	Configure(e Env, s Server) (changed []string, err error)
}

// Clients returns every supported client, in display order.
func Clients() []Client {
	return []Client{claudeDesktop{}, hermes{}, openClaw{}}
}

// expandHome expands a leading "~" (alone or followed by a separator) to Home.
func expandHome(e Env, path string) string {
	if path == "~" {
		return e.Home
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return filepath.Join(e.Home, rest)
	}
	if rest, ok := strings.CutPrefix(path, `~\`); ok {
		return filepath.Join(e.Home, rest)
	}

	return path
}

func isDir(path string) bool {
	st, err := os.Stat(path)

	return err == nil && st.IsDir()
}
