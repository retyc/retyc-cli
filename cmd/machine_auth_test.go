package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/auth"
	"github.com/retyc/retyc-cli/core/config"
	"github.com/retyc/retyc-cli/core/crypto"
	"github.com/retyc/retyc-cli/core/machinekey"
	"github.com/retyc/retyc-cli/pkg/cliconfig"
)

// setupMachine isolates the configuration and points the machine mode at a
// fresh signing key and the token endpoint tokenURL.
func setupMachine(t *testing.T, tokenURL string) {
	t.Helper()
	isolateConfig(t)
	resetMachineTokenSource()
	t.Cleanup(resetMachineTokenSource)

	dir := t.TempDir()
	key, err := machinekey.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := machinekey.MarshalSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := filepath.Join(dir, "client.key")
	ageKey := filepath.Join(dir, "age.key")
	if err := os.WriteFile(clientKey, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ageKey, []byte(identity.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvClientIDName, "machine-abc")
	t.Setenv(config.EnvTokenEndpointName, tokenURL)
	t.Setenv(config.EnvClientKeyFileName, clientKey)
	t.Setenv(config.EnvAgeKeyFileName, ageKey)
	cliconfig.SetDefaults()
}

func TestMustGetTokenMachineNoDiskFallback(t *testing.T) {
	var oidc atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/login/config") {
			oidc.Add(1)
			http.Error(w, "unexpected", http.StatusInternalServerError)

			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()
	setupMachine(t, srv.URL+"/token")
	// A stored login must be ignored.
	cfgDir := t.TempDir()
	t.Setenv(config.EnvConfigDirName, cfgDir)
	if err := os.WriteFile(filepath.Join(cfgDir, "token.json"), []byte(`{"access_token":"disk"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.API.BaseURL = srv.URL
	src, err := mustGetToken(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.(*auth.MachineTokenSource); !ok {
		t.Fatalf("source is %T, want *auth.MachineTokenSource", src)
	}
	tok, err := src.Token()
	if err != nil || tok.AccessToken != "at" {
		t.Fatalf("Token() = %v, %v", tok, err)
	}
	if oidc.Load() != 0 {
		t.Error("the OIDC discovery was called in machine mode")
	}
}

func TestMustGetTokenMachineMemoized(t *testing.T) {
	setupMachine(t, "https://idp.invalid/token")
	cfg := &config.Config{}
	a, err := mustGetToken(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := mustGetToken(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("two calls returned different sources")
	}
	if cfg.Machine == nil || cfg.Machine.ClientID != "machine-abc" || cfg.Machine.AgeIdentity == nil {
		t.Errorf("cfg.Machine = %+v, want the identity of the environment", cfg.Machine)
	}
}

func TestAuthLoginLogoutRefusedInMachineMode(t *testing.T) {
	setupMachine(t, "https://idp.invalid/token")
	for name, c := range map[string]func() error{
		"login":  func() error { return authLoginCmd.RunE(authLoginCmd, nil) },
		"logout": func() error { return authLogoutCmd.RunE(authLogoutCmd, nil) },
	} {
		err := c()
		if !errors.Is(err, config.ErrMachineConfig) {
			t.Errorf("%s: err = %v, want ErrMachineConfig", name, err)
		}
		if got := exitCode(err); got != exitConfig {
			t.Errorf("%s: exitCode = %d, want %d", name, got, exitConfig)
		}
	}
}

func TestExitCodeMachine401(t *testing.T) {
	err := fmt.Errorf("listing: %w", &api.HTTPError{Status: http.StatusUnauthorized})
	isolateConfig(t)
	if got := exitCode(err); got != 1 {
		t.Errorf("outside machine mode: exitCode = %d, want 1", got)
	}
	t.Setenv(config.EnvClientIDName, "machine-abc")
	if got := exitCode(err); got != exitAuthRequired {
		t.Errorf("machine mode: exitCode = %d, want %d", got, exitAuthRequired)
	}
	if got := errorKind(err); got != kindAuthRequired {
		t.Errorf("machine mode: kind = %q", got)
	}
	revoked := fmt.Errorf("x: %w", auth.ErrMachineRevoked)
	if exitCode(revoked) != exitAuthRequired || errorKind(revoked) != kindAuthRequired {
		t.Error("ErrMachineRevoked is not 77 / auth_required")
	}
}

func TestMachineForbiddenMessage(t *testing.T) {
	isolateConfig(t)
	err := fmt.Errorf("creating: %w", &api.HTTPError{
		Status: http.StatusForbidden, Body: `{"detail":"machine_account_forbidden"}`,
	})
	if !api.IsMachineForbidden(err) {
		t.Fatal("IsMachineForbidden = false")
	}
	wrapped := explainMachineForbidden(err)
	if !strings.Contains(wrapped.Error(), "not available to a machine account") {
		t.Errorf("message = %q", wrapped)
	}
	var httpErr *api.HTTPError
	if !errors.As(wrapped, &httpErr) || httpErr.Status != http.StatusForbidden {
		t.Error("the HTTPError is no longer in the chain")
	}
	if got := errorKind(wrapped); got != kindForbidden {
		t.Errorf("kind = %q, want forbidden", got)
	}
	if got := exitCode(wrapped); got != 1 {
		t.Errorf("exitCode = %d, want 1", got)
	}
	other := &api.HTTPError{Status: http.StatusForbidden, Body: `{"detail":"nope"}`}
	if !errors.Is(explainMachineForbidden(other), error(other)) {
		t.Error("another 403 was rewrapped")
	}
}

func TestDebugRedactsMachineSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"access_token":"at-secret","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	client := &http.Client{Transport: &debugTransport{wrapped: http.DefaultTransport}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL,
		strings.NewReader("grant_type=client_credentials&client_assertion=jwt-secret"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, reqErr := client.Do(req)
	os.Stderr = orig
	_ = w.Close()
	trace, _ := io.ReadAll(r)
	if reqErr != nil {
		t.Fatal(reqErr)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "at-secret") {
		t.Error("the caller no longer gets the token")
	}
	if strings.Contains(string(trace), "at-secret") || strings.Contains(string(trace), "jwt-secret") {
		t.Errorf("the trace leaks a secret: %s", trace)
	}
	if !strings.Contains(string(trace), "[redacted]") {
		t.Errorf("the trace has no redaction: %s", trace)
	}
	got := string(redactDebugBody([]byte("a=1&client_assertion=jwt-secret&b=2")))
	if strings.Contains(got, "jwt-secret") || !strings.Contains(got, "b=2") {
		t.Errorf("form redaction = %q", got)
	}
}

func TestRequireIdentitySourceMachineNoPassphrase(t *testing.T) {
	setupMachine(t, "https://idp.example/token")
	t.Setenv(config.EnvKeyPassphraseName, "")

	if err := requireIdentitySource(&config.Config{}); err != nil {
		t.Fatalf("requireIdentitySource(&config.Config{}) in machine mode = %v, want nil", err)
	}
}

func TestRequireIdentitySourceMachineBadConfig(t *testing.T) {
	setupMachine(t, "https://idp.example/token")
	t.Setenv(config.EnvClientKeyFileName, filepath.Join(t.TempDir(), "missing.key"))

	err := requireIdentitySource(&config.Config{})
	if !errors.Is(err, config.ErrMachineConfig) || errors.Is(err, config.ErrNoKeyPassphrase) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
}

func TestRequireIdentitySourceUserMode(t *testing.T) {
	isolateConfig(t)
	stubIdentitySources(t, false, false)
	t.Setenv(config.EnvKeyPassphraseName, "")
	if err := requireIdentitySource(&config.Config{}); !errors.Is(err, config.ErrNoKeyPassphrase) {
		t.Fatalf("err = %v, want ErrNoKeyPassphrase", err)
	}
	t.Setenv(config.EnvKeyPassphraseName, "pw")
	if err := requireIdentitySource(&config.Config{}); err != nil {
		t.Fatalf("err = %v", err)
	}
}

// Without RETYC_KEY_PASSPHRASE, a terminal to prompt on or an identity in
// the keyring is enough; the keyring counts only when it is enabled.
func TestRequireIdentitySourcePromptOrKeyring(t *testing.T) {
	isolateConfig(t)
	t.Setenv(config.EnvKeyPassphraseName, "")
	enabled := &config.Config{Keyring: config.KeyringConfig{Enabled: true}}
	disabled := &config.Config{}

	stubIdentitySources(t, true, false)
	if err := requireIdentitySource(disabled); err != nil {
		t.Fatalf("with a terminal: err = %v, want nil", err)
	}
	stubIdentitySources(t, false, true)
	if err := requireIdentitySource(enabled); err != nil {
		t.Fatalf("with a cached identity: err = %v, want nil", err)
	}
	if err := requireIdentitySource(disabled); !errors.Is(err, config.ErrNoKeyPassphrase) {
		t.Fatalf("keyring disabled: err = %v, want ErrNoKeyPassphrase", err)
	}
}

// stubIdentitySources replaces the terminal and keyring probes for one test.
func stubIdentitySources(t *testing.T, terminal, cached bool) {
	t.Helper()
	prevTerm, prevKeyring := stdinIsTerminal, keyringHas
	t.Cleanup(func() { stdinIsTerminal, keyringHas = prevTerm, prevKeyring })
	stdinIsTerminal = func() bool { return terminal }
	keyringHas = func() bool { return cached }
}

func TestAuthLostAdvice(t *testing.T) {
	isolateConfig(t)
	if got := authLostAdvice("mount again"); !strings.Contains(got, "retyc auth login") {
		t.Errorf("human advice = %q, want retyc auth login", got)
	}
	setupMachine(t, "https://idp.example/token")
	got := authLostAdvice("mount again")
	if !strings.Contains(got, "retyc machine enable") || strings.Contains(got, "auth login") {
		t.Errorf("machine advice = %q, want retyc machine enable", got)
	}
}
