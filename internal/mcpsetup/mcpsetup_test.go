package mcpsetup

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const (
	testToken      = "offline-token-SECRET" //nolint:gosec // G101: test fixture
	testPassphrase = "pass phrase SECRET"   //nolint:gosec // G101: test fixture
)

type runCall struct {
	name string
	args []string
}

// testEnv returns an Env rooted in a temporary home, with fake seams.
func testEnv(t *testing.T, goos string) (Env, *[]runCall) {
	t.Helper()
	home := t.TempDir()
	vars := map[string]string{}
	var calls []runCall
	e := Env{
		GOOS:      goos,
		Home:      home,
		ConfigDir: filepath.Join(home, "cfg"),
		Getenv:    func(k string) string { return vars[k] },
		LookPath:  func(string) (string, error) { return "", exec.ErrNotFound },
		Run: func(name string, args ...string) error {
			calls = append(calls, runCall{name, args})

			return nil
		},
	}

	return e, &calls
}

func testServer() Server {
	return Server{Command: "/stable/retyc", Token: testToken, Passphrase: testPassphrase}
}

func writeFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test temp file
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != want {
		t.Errorf("%s: mode %o, want %o", path, got, want)
	}
}

func clientNamed(t *testing.T, name string) Client {
	t.Helper()
	for _, c := range Clients() {
		if c.Name() == name {
			return c
		}
	}
	t.Fatalf("no client %q", name)

	return nil
}

// --- Claude Desktop ---------------------------------------------------------

func claudePath(e Env) string {
	return filepath.Join(e.ConfigDir, "Claude", "claude_desktop_config.json")
}

func TestClaudeDetected(t *testing.T) {
	e, _ := testEnv(t, "darwin")
	c := clientNamed(t, "Claude Desktop")
	if c.Detected(e) {
		t.Fatal("detected without a Claude directory")
	}
	if err := os.MkdirAll(filepath.Dir(claudePath(e)), 0o700); err != nil {
		t.Fatal(err)
	}
	if !c.Detected(e) {
		t.Fatal("not detected with a Claude directory")
	}
}

func TestClaudeConfigure_PreservesOtherServersAndKeys(t *testing.T) {
	e, _ := testEnv(t, "darwin")
	old := `{
  "globalShortcut": "Ctrl+Space",
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "gh"], "env": {"X": "1"}}
  }
}`
	writeFile(t, claudePath(e), old, 0o644)

	changed, err := clientNamed(t, "Claude Desktop").Configure(e, testServer())
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != claudePath(e) {
		t.Errorf("changed = %v", changed)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(readFile(t, claudePath(e))), &got); err != nil {
		t.Fatal(err)
	}
	if got["globalShortcut"] != "Ctrl+Space" {
		t.Errorf("globalShortcut lost: %v", got["globalShortcut"])
	}
	servers := got["mcpServers"].(map[string]any)
	if gh := servers["github"].(map[string]any); gh["command"] != "npx" {
		t.Errorf("github server changed: %v", gh)
	}
	r := servers["retyc"].(map[string]any)
	if r["command"] != "/stable/retyc" {
		t.Errorf("command = %v", r["command"])
	}
	if args, _ := json.Marshal(r["args"]); string(args) != `["mcp","serve"]` {
		t.Errorf("args = %s", args)
	}
	env := r["env"].(map[string]any)
	if env["RETYC_TOKEN"] != testToken || env["RETYC_KEY_PASSPHRASE"] != testPassphrase {
		t.Errorf("env = %v", env)
	}
	if bak := readFile(t, claudePath(e)+".bak"); bak != old {
		t.Errorf("backup = %q, want the previous file", bak)
	}
}

func TestClaudeConfigure_ReplacesExistingRetycEntry(t *testing.T) {
	e, _ := testEnv(t, "linux")
	c := clientNamed(t, "Claude Desktop")
	first := testServer()
	first.Command = "/old/retyc"
	if _, err := c.Configure(e, first); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Configure(e, testServer()); err != nil {
		t.Fatal(err)
	}
	content := readFile(t, claudePath(e))
	if strings.Count(content, `"retyc"`) != 1 || strings.Contains(content, "/old/retyc") {
		t.Errorf("entry not replaced:\n%s", content)
	}
}

func TestClaudeConfigure_CreatesFileMode0600(t *testing.T) {
	e, _ := testEnv(t, "linux")
	if _, err := clientNamed(t, "Claude Desktop").Configure(e, testServer()); err != nil {
		t.Fatal(err)
	}
	assertMode(t, claudePath(e), 0o600)
}

func TestClaudeConfigure_BackupIs0600EvenIfItExisted(t *testing.T) {
	e, _ := testEnv(t, "linux")
	writeFile(t, claudePath(e), `{"mcpServers":{"retyc":{"env":{"RETYC_TOKEN":"old"}}}}`, 0o600)
	writeFile(t, claudePath(e)+".bak", `stale`, 0o644)
	if _, err := clientNamed(t, "Claude Desktop").Configure(e, testServer()); err != nil {
		t.Fatal(err)
	}
	assertMode(t, claudePath(e)+".bak", 0o600)
	if !strings.Contains(readFile(t, claudePath(e)+".bak"), `"old"`) {
		t.Error("backup does not hold the previous file")
	}
}

func TestClaudeConfigure_TightensExistingFileTo0600(t *testing.T) {
	e, _ := testEnv(t, "linux")
	writeFile(t, claudePath(e), `{}`, 0o644)
	if _, err := clientNamed(t, "Claude Desktop").Configure(e, testServer()); err != nil {
		t.Fatal(err)
	}
	assertMode(t, claudePath(e), 0o600)
}

func TestClaudeConfigure_LeavesInvalidJSONUntouched(t *testing.T) {
	e, _ := testEnv(t, "linux")
	writeFile(t, claudePath(e), `{ broken`, 0o644)
	if _, err := clientNamed(t, "Claude Desktop").Configure(e, testServer()); err == nil {
		t.Fatal("expected an error on invalid JSON")
	}
	if got := readFile(t, claudePath(e)); got != `{ broken` {
		t.Errorf("file modified: %q", got)
	}
}

// --- Hermes -----------------------------------------------------------------

func hermesDir(e Env) string { return filepath.Join(e.Home, ".hermes") }

func TestHermesConfigure_PreservesYAMLAndComments(t *testing.T) {
	e, _ := testEnv(t, "linux")
	cfg := filepath.Join(hermesDir(e), "config.yaml")
	writeFile(t, cfg, `# my settings
model: hermes-4  # keep me
mcp_servers:
  github:
    command: "npx"
    args: ["-y", "gh"]
`, 0o644)

	if _, err := clientNamed(t, "Hermes").Configure(e, testServer()); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, cfg)
	for _, want := range []string{
		"# my settings", "# keep me", "model: hermes-4", "github:", "retyc:",
		"/stable/retyc", "${RETYC_TOKEN}", "${RETYC_KEY_PASSPHRASE}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config.yaml lacks %q:\n%s", want, got)
		}
	}
}

func TestHermesConfigure_SecretsOnlyInDotEnv(t *testing.T) {
	e, _ := testEnv(t, "linux")
	dotenv := filepath.Join(hermesDir(e), ".env")
	writeFile(t, dotenv, "OPENROUTER_API_KEY=abc\nRETYC_TOKEN=stale\n", 0o644)
	c := clientNamed(t, "Hermes")

	for range 2 { // a re-run must not duplicate anything
		if _, err := c.Configure(e, testServer()); err != nil {
			t.Fatal(err)
		}
	}

	cfg := readFile(t, filepath.Join(hermesDir(e), "config.yaml"))
	if strings.Contains(cfg, testToken) || strings.Contains(cfg, testPassphrase) {
		t.Errorf("secret in config.yaml:\n%s", cfg)
	}
	if strings.Count(cfg, "retyc:") != 1 {
		t.Errorf("retyc entry duplicated:\n%s", cfg)
	}
	env := readFile(t, dotenv)
	want := "OPENROUTER_API_KEY=abc\nRETYC_TOKEN='" + testToken + "'\nRETYC_KEY_PASSPHRASE='" + testPassphrase + "'\n"
	if env != want {
		t.Errorf(".env =\n%s\nwant\n%s", env, want)
	}
	assertMode(t, dotenv, 0o600)
}

func TestHermesConfigure_InvalidConfigWritesNoSecret(t *testing.T) {
	for name, cfg := range map[string]string{
		"invalid YAML":          "mcp_servers: [unclosed\n",
		"mcp_servers is a list": "mcp_servers:\n  - other\n",
	} {
		t.Run(name, func(t *testing.T) {
			e, _ := testEnv(t, "linux")
			writeFile(t, filepath.Join(hermesDir(e), "config.yaml"), cfg, 0o600)

			if _, err := clientNamed(t, "Hermes").Configure(e, testServer()); err == nil {
				t.Fatal("want an error")
			}
			if _, err := os.Stat(filepath.Join(hermesDir(e), ".env")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf(".env written although config.yaml was refused (stat err = %v)", err)
			}
		})
	}
}

func TestHermesConfigure_HonorsHermesHome(t *testing.T) {
	e, _ := testEnv(t, "linux")
	alt := filepath.Join(e.Home, "alt")
	e.Getenv = func(k string) string {
		if k == "HERMES_HOME" {
			return alt
		}

		return ""
	}
	if _, err := clientNamed(t, "Hermes").Configure(e, testServer()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(alt, "config.yaml")); err != nil {
		t.Errorf("config.yaml not under HERMES_HOME: %v", err)
	}
}

// --- .env quoting -----------------------------------------------------------

func TestDotEnvValue(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{"plain", "'plain'", false},
		{`a"b $c #d`, `'a"b $c #d'`, false},
		// python-dotenv unescapes \\ and \' even inside single quotes.
		{`p\\x`, "", true},
		{`p\x`, "", true},
		// python-dotenv expands ${VAR} even inside single quotes; $VAR stays.
		{"long${MISSING}pass", "", true},
		{"a$HOME b", "'a$HOME b'", false},
		{"it's", `"it's"`, false},
		{`it's "x"`, "", true},
		{`it's $x`, "", true},
		{"line\nbreak", "", true},
	}
	for _, c := range cases {
		got, err := dotenvValue(c.in)
		if c.err {
			if !errors.Is(err, ErrUnsupportedValue) {
				t.Errorf("%q: err = %v, want ErrUnsupportedValue", c.in, err)
			}

			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// --- OpenClaw ---------------------------------------------------------------

func TestOpenClawConfigure_RunsConfigSet(t *testing.T) {
	e, calls := testEnv(t, "linux")
	e.LookPath = func(string) (string, error) { return "/usr/bin/openclaw", nil }

	changed, err := clientNamed(t, "OpenClaw").Configure(e, testServer())
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("calls = %v", *calls)
	}
	call := (*calls)[0]
	if call.name != "/usr/bin/openclaw" || len(call.args) != 5 ||
		call.args[0] != "config" || call.args[1] != "set" || call.args[2] != "mcp.servers.retyc" ||
		call.args[4] != "--strict-json" {
		t.Fatalf("call = %v", call)
	}
	var entry struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	}
	if err := json.Unmarshal([]byte(call.args[3]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Command != "/stable/retyc" || strings.Join(entry.Args, " ") != "mcp serve" ||
		entry.Env["RETYC_TOKEN"] != "${RETYC_TOKEN}" || entry.Env["RETYC_KEY_PASSPHRASE"] != "${RETYC_KEY_PASSPHRASE}" {
		t.Errorf("entry = %+v", entry)
	}
	if strings.Contains(strings.Join(call.args, " "), "SECRET") {
		t.Error("secret passed on the command line")
	}
	dotenv := filepath.Join(e.Home, ".openclaw", ".env")
	if env := readFile(t, dotenv); !strings.Contains(env, "RETYC_TOKEN='"+testToken+"'") {
		t.Errorf(".env = %q", env)
	}
	assertMode(t, dotenv, 0o600)
	if len(changed) == 0 || changed[0] != dotenv {
		t.Errorf("changed = %v", changed)
	}
}

// The .env goes where OpenClaw resolves its state directory:
// OPENCLAW_STATE_DIR first, then the directory of OPENCLAW_CONFIG_PATH.
func TestOpenClawConfigure_StateDirOverrides(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want func(home string) string
	}{
		{"state dir", map[string]string{
			"OPENCLAW_STATE_DIR":   "~/oc-state",
			"OPENCLAW_CONFIG_PATH": "/elsewhere/openclaw.json",
		}, func(home string) string { return filepath.Join(home, "oc-state", ".env") }},
		{
			"config path",
			map[string]string{"OPENCLAW_CONFIG_PATH": "~/cfg/openclaw.json"},
			func(home string) string { return filepath.Join(home, "cfg", ".env") },
		},
		{
			"default",
			map[string]string{},
			func(home string) string { return filepath.Join(home, ".openclaw", ".env") },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, _ := testEnv(t, "linux")
			e.Getenv = func(k string) string { return c.vars[k] }
			oc := clientNamed(t, "OpenClaw")
			_, err := oc.Configure(e, testServer())
			var manual *ManualStepError
			if err != nil && !errors.As(err, &manual) {
				t.Fatal(err)
			}
			if want := c.want(e.Home); !strings.Contains(readFile(t, want), "RETYC_TOKEN=") {
				t.Errorf(".env not written at %s", want)
			}
			if c.name != "default" && !oc.Detected(e) {
				t.Error("not detected through the override")
			}
		})
	}
}

func TestOpenClawConfigure_ManualStepWithoutCLI(t *testing.T) {
	e, calls := testEnv(t, "linux")
	_, err := clientNamed(t, "OpenClaw").Configure(e, testServer())
	var manual *ManualStepError
	if !errors.As(err, &manual) {
		t.Fatalf("err = %v, want *ManualStepError", err)
	}
	if !strings.HasPrefix(manual.Command, "openclaw config set mcp.servers.retyc ") ||
		strings.Contains(manual.Command, "SECRET") {
		t.Errorf("command = %q", manual.Command)
	}
	if len(*calls) != 0 {
		t.Errorf("unexpected calls %v", *calls)
	}
	if _, err := os.Stat(filepath.Join(e.Home, ".openclaw", ".env")); err != nil {
		t.Errorf(".env not written: %v", err)
	}
}

// --- binary -----------------------------------------------------------------

func TestBinaryPath(t *testing.T) {
	e, _ := testEnv(t, "linux")
	if got, want := BinaryPath(e), filepath.Join(e.Home, ".local", "share", "retyc", "bin", "retyc"); got != want {
		t.Errorf("linux: %s, want %s", got, want)
	}
	e.Getenv = func(k string) string {
		switch k {
		case "XDG_DATA_HOME":
			return "/xdg"
		case "LOCALAPPDATA":
			return `C:\Users\a\AppData\Local`
		}

		return ""
	}
	if got, want := BinaryPath(e), filepath.Join("/xdg", "retyc", "bin", "retyc"); got != want {
		t.Errorf("linux XDG: %s, want %s", got, want)
	}
	e.GOOS = "darwin"
	if got, want := BinaryPath(e), filepath.Join(e.ConfigDir, "retyc", "bin", "retyc"); got != want {
		t.Errorf("darwin: %s, want %s", got, want)
	}
	e.GOOS = "windows"
	if got, want := BinaryPath(e), filepath.Join(`C:\Users\a\AppData\Local`, "retyc", "bin", "retyc.exe"); got != want {
		t.Errorf("windows: %s, want %s", got, want)
	}
}

func TestInstallBinary_ReplacesAtomically(t *testing.T) {
	e, _ := testEnv(t, "linux")
	src := filepath.Join(t.TempDir(), "retyc")
	writeFile(t, src, "v1", 0o755)
	dst, err := InstallBinary(e, src)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, src, "v2", 0o755)
	if _, err := InstallBinary(e, src); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dst); got != "v2" {
		t.Errorf("binary = %q, want v2", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(dst))
	if len(entries) != 1 {
		t.Errorf("leftover files next to the binary: %v", entries)
	}
}

func TestInstallBinary_Mode0755(t *testing.T) {
	e, _ := testEnv(t, "linux")
	src := filepath.Join(t.TempDir(), "retyc")
	writeFile(t, src, "bin", 0o700)
	dst, err := InstallBinary(e, src)
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, dst, 0o755)
}

func TestInstallBinary_SameFileIsANoop(t *testing.T) {
	e, _ := testEnv(t, "linux")
	dst := BinaryPath(e)
	writeFile(t, dst, "bin", 0o755)
	if _, err := InstallBinary(e, dst); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dst); got != "bin" {
		t.Errorf("binary = %q", got)
	}
}

// --- dependency rule ----------------------------------------------------------

// TestImports keeps mcpsetup a file-only package: the standard library and the
// YAML parser, nothing from the CLI (cobra, viper, config, api, cmd).
func TestImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") && path != "go.yaml.in/yaml/v3" {
				t.Errorf("%s imports %s", f, path)
			}
		}
	}
}
