package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/mcpsetup"
	"github.com/retyc/retyc-cli/internal/service"
)

const (
	setupTestToken = "offline-SECRET-token"
	setupGoodPass  = "good SECRET pass"
)

type setupFixture struct {
	deps       setupDeps
	out        *bytes.Buffer
	env        mcpsetup.Env
	loginCalls int
}

// newSetupFixture returns fake dependencies over a temporary home where the
// named clients ("claude", "hermes", "openclaw") are installed.
func newSetupFixture(t *testing.T, passphrases, lines []string, clients ...string) *setupFixture {
	t.Helper()
	home := t.TempDir()
	e := mcpsetup.Env{
		GOOS:      "linux",
		Home:      home,
		ConfigDir: filepath.Join(home, ".config"),
		Getenv:    func(string) string { return "" },
		LookPath:  func(string) (string, error) { return "", exec.ErrNotFound },
		Run:       func(string, ...string) error { return nil },
	}
	dirs := map[string]string{
		"claude":   filepath.Join(e.ConfigDir, "Claude"),
		"hermes":   filepath.Join(home, ".hermes"),
		"openclaw": filepath.Join(home, ".openclaw"),
	}
	for _, c := range clients {
		if err := os.MkdirAll(dirs[c], 0o700); err != nil {
			t.Fatal(err)
		}
	}

	f := &setupFixture{out: &bytes.Buffer{}, env: e}
	f.deps = setupDeps{
		login: func(context.Context) (*oauth2.Token, error) {
			f.loginCalls++

			return &oauth2.Token{AccessToken: "access", RefreshToken: setupTestToken}, nil
		},
		verify: func(_ context.Context, tok *oauth2.Token, pass string) error {
			if tok.AccessToken != "access" {
				t.Errorf("verify got token %q", tok.AccessToken)
			}
			if pass != setupGoodPass {
				return fmt.Errorf("%w: decrypt failed", service.ErrWrongKeyPassphrase)
			}

			return nil
		},
		readSecret: func(string) (string, error) {
			if len(passphrases) == 0 {
				return "", errors.New("no more passphrases")
			}
			p := passphrases[0]
			passphrases = passphrases[1:]

			return p, nil
		},
		readLine: func(string) (string, error) {
			if len(lines) == 0 {
				return "", nil
			}
			l := lines[0]
			lines = lines[1:]

			return l, nil
		},
		env:     e,
		exe:     "/npx-cache/retyc",
		install: func(mcpsetup.Env, string) (string, error) { return "/stable/retyc", nil },
		out:     f.out,
	}

	return f
}

func (f *setupFixture) claudeConfig() string {
	return filepath.Join(f.env.ConfigDir, "Claude", "claude_desktop_config.json")
}

func (f *setupFixture) hermesConfig() string {
	return filepath.Join(f.env.Home, ".hermes", "config.yaml")
}

func exists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

func TestMCPSetup_WritesSelectedClients(t *testing.T) {
	f := newSetupFixture(t, []string{setupGoodPass}, []string{"1"}, "claude", "hermes")
	if err := runMCPSetup(context.Background(), f.deps); err != nil {
		t.Fatalf("err = %v\n%s", err, f.out)
	}
	if !exists(f.claudeConfig()) {
		t.Error("Claude Desktop not configured")
	}
	if exists(f.hermesConfig()) {
		t.Error("Hermes configured although not selected")
	}
	content, _ := os.ReadFile(f.claudeConfig())
	if !strings.Contains(string(content), "/stable/retyc") || !strings.Contains(string(content), setupTestToken) {
		t.Errorf("claude config:\n%s", content)
	}
	if !strings.Contains(f.out.String(), "Restart Claude Desktop") {
		t.Errorf("no restart hint:\n%s", f.out)
	}
}

func TestMCPSetup_DefaultSelectsAll(t *testing.T) {
	f := newSetupFixture(t, []string{setupGoodPass}, []string{""}, "claude", "hermes")
	if err := runMCPSetup(context.Background(), f.deps); err != nil {
		t.Fatalf("err = %v\n%s", err, f.out)
	}
	if !exists(f.claudeConfig()) || !exists(f.hermesConfig()) {
		t.Error("Enter should configure every detected client")
	}
}

func TestMCPSetup_WrongPassphraseThreeTimes(t *testing.T) {
	f := newSetupFixture(t, []string{"a", "b", "c"}, nil, "claude")
	err := runMCPSetup(context.Background(), f.deps)
	if !errors.Is(err, service.ErrWrongKeyPassphrase) {
		t.Fatalf("err = %v, want ErrWrongKeyPassphrase", err)
	}
	if got := exitCode(err); got != exitConfig {
		t.Errorf("exit code %d, want %d", got, exitConfig)
	}
	if exists(f.claudeConfig()) {
		t.Error("config written after a failed setup")
	}
}

func TestMCPSetup_RetryThenGoodPassphrase(t *testing.T) {
	f := newSetupFixture(t, []string{"a", "b", setupGoodPass}, nil, "claude")
	if err := runMCPSetup(context.Background(), f.deps); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !exists(f.claudeConfig()) {
		t.Error("Claude Desktop not configured")
	}
}

func TestMCPSetup_NeverPrintsSecrets(t *testing.T) {
	f := newSetupFixture(t, []string{"wrong SECRET", setupGoodPass}, nil, "claude", "hermes", "openclaw")
	_ = runMCPSetup(context.Background(), f.deps)
	if strings.Contains(f.out.String(), "SECRET") {
		t.Errorf("secret printed:\n%s", f.out)
	}
}

func TestMCPSetup_LoginFailsWritesNothing(t *testing.T) {
	f := newSetupFixture(t, nil, nil, "claude")
	f.deps.login = func(context.Context) (*oauth2.Token, error) { return nil, errors.New("device code expired") }
	if err := runMCPSetup(context.Background(), f.deps); err == nil {
		t.Fatal("expected an error")
	}
	if exists(f.claudeConfig()) {
		t.Error("config written after a failed login")
	}
}

func TestMCPSetup_BinaryInUse(t *testing.T) {
	f := newSetupFixture(t, []string{setupGoodPass}, nil, "claude")
	f.deps.install = func(mcpsetup.Env, string) (string, error) {
		return "", fmt.Errorf("%w: C:\\retyc.exe", mcpsetup.ErrBinaryInUse)
	}
	err := runMCPSetup(context.Background(), f.deps)
	if err == nil || !strings.Contains(err.Error(), "Quit") {
		t.Fatalf("err = %v, want a message asking to quit the clients", err)
	}
	if exists(f.claudeConfig()) {
		t.Error("config written although the binary was not installed")
	}
}

func TestMCPSetup_NoClientDetected(t *testing.T) {
	f := newSetupFixture(t, nil, nil)
	if err := runMCPSetup(context.Background(), f.deps); err != nil {
		t.Fatalf("err = %v", err)
	}
	if f.loginCalls != 0 {
		t.Error("login run although no client can be configured")
	}
	out := f.out.String()
	if !strings.Contains(out, `"mcpServers"`) || !strings.Contains(out, "npx") {
		t.Errorf("no manual configuration shown:\n%s", out)
	}
}

func TestMCPSetup_PrintsManualStep(t *testing.T) {
	f := newSetupFixture(t, []string{setupGoodPass}, nil, "openclaw")
	if err := runMCPSetup(context.Background(), f.deps); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(f.out.String(), "openclaw config set mcp.servers.retyc") {
		t.Errorf("manual step not shown:\n%s", f.out)
	}
	if strings.Contains(f.out.String(), "Done.") {
		t.Errorf("setup claims Done while a manual step is pending:\n%s", f.out)
	}
	if !strings.Contains(f.out.String(), "Run the command above") {
		t.Errorf("no reminder to run the manual step:\n%s", f.out)
	}
}

func TestMCPSetup_RefusedInMachineMode(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_MACHINE_DIR", t.TempDir())
	err := run(context.Background(), []string{"mcp", "setup"})
	if err == nil || !strings.Contains(err.Error(), "machine") {
		t.Fatalf("err = %v, want the machine mode refusal", err)
	}
}

func TestMCPSetup_RequiresTerminal(t *testing.T) {
	isolateConfig(t)
	saved := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = saved })
	err := run(context.Background(), []string{"mcp", "setup"})
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("err = %v, want a terminal requirement", err)
	}
}
