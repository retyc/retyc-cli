package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/machinekey"
)

// statusFixture is a fake token endpoint plus a fake API for auth status.
type statusFixture struct {
	srv          *httptest.Server
	tokenErr     string // OAuth error code the token endpoint answers, if any
	activeStatus int    // HTTP status of GET /user/me/key/active, if not 200
	activePub    string // public key the API reports as active
	calls        atomic.Int32
}

// setupMachineStatus configures the machine mode from a machine directory
// holding a signing key, a post-quantum age.key and machine.json. ageMatches
// tells whether the API reports the key of age.key as the active one.
func setupMachineStatus(t *testing.T, ageMatches bool) *statusFixture {
	t.Helper()
	isolateConfig(t)
	resetMachineTokenSource()
	t.Cleanup(resetMachineTokenSource)

	f := &statusFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		switch {
		case r.URL.Path == "/token":
			if f.tokenErr != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"` + f.tokenErr + `"}`))

				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":300}`))
		case strings.HasSuffix(r.URL.Path, "/user/me/key/active"):
			if f.activeStatus != 0 {
				w.WriteHeader(f.activeStatus)
				_, _ = w.Write([]byte(`{"detail":"unauthorized"}`))

				return
			}
			_, _ = w.Write([]byte(`{"id":"k","user_id":"u","public_key":"` + f.activePub + `","private_key_enc":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)

	id, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	f.activePub = id.Recipient().String()
	if !ageMatches {
		other, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		f.activePub = other.Recipient().String()
	}

	dir := t.TempDir()
	key, err := machinekey.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := machinekey.MarshalSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := json.Marshal(config.MachineInfo{
		Version: 1, MachineID: "m-1", OrganizationID: "o-1", ClientID: "machine-abc",
		TokenEndpoint: f.srv.URL + "/token",
	})
	for name, data := range map[string][]byte{
		config.MachineSigningKeyFile: pemData,
		config.MachineAgeKeyFile:     []byte(id.String() + "\n"),
		config.MachineFile:           info,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(config.EnvMachineDirName, dir)
	t.Setenv("RETYC_API_BASE_URL", f.srv.URL)
	config.SetDefaults()

	return f
}

func runAuthStatus(t *testing.T) (map[string]any, string, error) {
	t.Helper()
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })
	var runErr error
	out := captureStream(t, &os.Stdout, func() {
		authStatusCmd.SetContext(context.Background())
		runErr = authStatusCmd.RunE(authStatusCmd, nil)
	})
	var got map[string]any
	if out != "" {
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, out)
		}
	}

	return got, out, runErr
}

func TestAuthStatusMachine(t *testing.T) {
	setupMachineStatus(t, true)
	// A stored human login must not be read.
	cfgDir := t.TempDir()
	t.Setenv(config.EnvConfigDirName, cfgDir)
	if err := os.WriteFile(filepath.Join(cfgDir, "token.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, out, err := runAuthStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	if got["authenticated"] != true || got["mode"] != "machine" ||
		got["client_id"] != "machine-abc" || got["machine_id"] != "m-1" || got["expires_at"] == nil {
		t.Errorf("unexpected status: %s", out)
	}
}

func TestAuthStatusMachineRevoked(t *testing.T) {
	f := setupMachineStatus(t, true)
	f.tokenErr = "invalid_client"

	got, out, err := runAuthStatus(t)
	if err != nil {
		t.Fatalf("revoked must exit 0, got %v", err)
	}
	if got["authenticated"] != false || got["reason"] != "machine_revoked" {
		t.Errorf("unexpected status: %s", out)
	}
}

func TestAuthStatusMachineKeyMismatch(t *testing.T) {
	setupMachineStatus(t, false)

	_, _, err := runAuthStatus(t)
	if !errors.Is(err, config.ErrMachineConfig) || exitCode(err) != exitConfig {
		t.Fatalf("err = %v (exit %d), want ErrMachineConfig / 78", err, exitCode(err))
	}
}

func TestAuthStatusMachineIncomplete(t *testing.T) {
	setupMachineStatus(t, true)
	t.Setenv(config.EnvClientKeyFileName, filepath.Join(t.TempDir(), "missing.key"))

	_, _, err := runAuthStatus(t)
	if !errors.Is(err, config.ErrMachineConfig) || exitCode(err) != exitConfig {
		t.Fatalf("err = %v (exit %d), want ErrMachineConfig / 78", err, exitCode(err))
	}
}

func TestAuthStatusHumanUnchanged(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	cfgDir := t.TempDir()
	t.Setenv(config.EnvConfigDirName, cfgDir)
	got, out, err := runAuthStatus(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"mode", "client_id", "machine_id"} {
		if _, ok := got[k]; ok {
			t.Errorf("human status carries %q: %s", k, out)
		}
	}
	if got["reason"] != "no_token" {
		t.Errorf("unexpected status: %s", out)
	}
}

// callAuthTool invokes the registered MCP auth tool name and returns its text.
func callAuthTool(t *testing.T, name string) (*mcp.CallToolResult, string) {
	t.Helper()
	srv := server.NewMCPServer("retyc", "test", server.WithToolCapabilities(false))
	registerMCPTools(srv)
	tool := srv.GetTool(name)
	if tool == nil {
		t.Fatalf("tool %s is not registered", name)
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = map[string]any{"device_code": "dc"}
	res, err := tool.Handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.Content[0])
	var w struct{ Text string }
	_ = json.Unmarshal(raw, &w)

	return res, w.Text
}

func TestMCPLoginToolsRefuseInMachineMode(t *testing.T) {
	f := setupMachineStatus(t, true)
	for _, name := range []string{"auth_login_start", "auth_login_poll", "auth_logout"} {
		before := f.calls.Load()
		_, text := callAuthTool(t, name)
		if !strings.Contains(text, "machine account: no interactive login") {
			t.Errorf("%s: text=%s", name, text)
		}
		if f.calls.Load() != before {
			t.Errorf("%s made a network call", name)
		}
	}

	res, text := callAuthTool(t, "auth_status")
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if res.IsError || got["authenticated"] != true || got["mode"] != "machine" ||
		got["client_id"] != "machine-abc" || got["machine_id"] != "m-1" || got["expires_at"] == nil {
		t.Errorf("auth_status = %s", text)
	}
}

func TestMCPAuthStatusMachineRevoked(t *testing.T) {
	f := setupMachineStatus(t, true)
	f.tokenErr = "invalid_client"
	_, text := callAuthTool(t, "auth_status")
	var got map[string]any
	_ = json.Unmarshal([]byte(text), &got)
	if got["authenticated"] != false || got["error"] == nil {
		t.Errorf("auth_status = %s", text)
	}
}

// A token is issued but the API refuses the account on the key lookup: a
// status (exit 0), not a failure.
func TestAuthStatusMachineAPIRefused(t *testing.T) {
	f := setupMachineStatus(t, true)
	f.activeStatus = http.StatusUnauthorized

	got, out, err := runAuthStatus(t)
	if err != nil {
		t.Fatalf("revoked must exit 0, got %v", err)
	}
	if got["authenticated"] != false || got["reason"] != "machine_revoked" {
		t.Errorf("unexpected status: %s", out)
	}
}
