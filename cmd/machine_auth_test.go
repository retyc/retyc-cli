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
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/machinekey"
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
	if err := os.WriteFile(ageKey, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvClientIDName, "machine-abc")
	t.Setenv(config.EnvTokenEndpointName, tokenURL)
	t.Setenv(config.EnvClientKeyFileName, clientKey)
	t.Setenv(config.EnvAgeKeyFileName, ageKey)
	config.SetDefaults()
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
	if explainMachineForbidden(other) != error(other) {
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
	resp, reqErr := client.Post(srv.URL, "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=client_credentials&client_assertion=jwt-secret"))
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

type okTokenSource struct{ checks atomic.Int32 }

func (s *okTokenSource) Token() (*oauth2.Token, error) {
	s.checks.Add(1)

	return &oauth2.Token{AccessToken: "t", Expiry: time.Now().Add(time.Hour)}, nil
}

func (s *okTokenSource) Expire() {}

// TestAuthWatchMachineRepeated401 drives the clock of the watch: a burst of
// 401s reuses the token refreshed for the first one and is counted once, so
// only refusals spread over several authRefreshInterval stop the mount.
func TestAuthWatchMachineRepeated401(t *testing.T) {
	start := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	setup := func(t *testing.T) (*okTokenSource, *authWatch, *atomic.Int64, chan error) {
		t.Helper()
		src := &okTokenSource{}
		watch := newAuthWatch(src)
		watch.machine = true
		watch.interval = time.Hour // no tick: only asked checks
		watch.logf = func(string, ...any) {}
		var offset atomic.Int64
		watch.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		failed := make(chan error, 1)
		go watch.run(ctx, func(err error) { failed <- err })

		return src, watch, &offset, failed
	}
	// check asks for a check and waits until the source was asked a token.
	check := func(t *testing.T, src *okTokenSource, watch *authWatch) {
		t.Helper()
		want := src.checks.Load() + 1
		watch.checkNow()
		deadline := time.Now().Add(5 * time.Second)
		for src.checks.Load() < want {
			if time.Now().After(deadline) {
				t.Fatal("the check was not made")
			}
			time.Sleep(time.Millisecond)
		}
	}
	noFail := func(t *testing.T, failed chan error) {
		t.Helper()
		select {
		case err := <-failed:
			t.Fatalf("onFail(%v)", err)
		default:
		}
	}

	t.Run("burst within the refresh interval", func(t *testing.T) {
		src, watch, offset, failed := setup(t)
		for range 10 * machineRefusedChecks {
			check(t, src, watch)
			offset.Add(int64(time.Second))
		}
		noFail(t, failed)
	})

	t.Run("refusals spread over the refresh intervals", func(t *testing.T) {
		src, watch, offset, failed := setup(t)
		for i := range machineRefusedChecks {
			noFail(t, failed)
			check(t, src, watch)
			if i < machineRefusedChecks-1 {
				check(t, src, watch) // same token: not counted
			}
			offset.Add(int64(authRefreshInterval))
		}
		select {
		case err := <-failed:
			if !errors.Is(err, auth.ErrMachineRevoked) {
				t.Errorf("onFail(%v), want ErrMachineRevoked", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("onFail was not called")
		}
	})
}

func TestAuthWatchNotMachineIgnoresRepeated401(t *testing.T) {
	src := &okTokenSource{}
	watch := newAuthWatch(src)
	watch.machine = false
	watch.interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := make(chan error, 1)
	go watch.run(ctx, func(err error) { failed <- err })
	for range machineRefusedChecks + 1 {
		watch.checkNow()
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case err := <-failed:
		t.Fatalf("onFail outside machine mode: %v", err)
	default:
	}
}

func TestRequireIdentitySourceMachineNoPassphrase(t *testing.T) {
	setupMachine(t, "https://idp.example/token")
	t.Setenv(config.EnvKeyPassphraseName, "")

	if err := requireIdentitySource(); err != nil {
		t.Fatalf("requireIdentitySource() in machine mode = %v, want nil", err)
	}
}

func TestRequireIdentitySourceMachineBadConfig(t *testing.T) {
	setupMachine(t, "https://idp.example/token")
	t.Setenv(config.EnvClientKeyFileName, filepath.Join(t.TempDir(), "missing.key"))

	err := requireIdentitySource()
	if !errors.Is(err, config.ErrMachineConfig) || errors.Is(err, config.ErrNoKeyPassphrase) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
}

func TestRequireIdentitySourceUserMode(t *testing.T) {
	isolateConfig(t)
	t.Setenv(config.EnvKeyPassphraseName, "")
	if err := requireIdentitySource(); !errors.Is(err, config.ErrNoKeyPassphrase) {
		t.Fatalf("err = %v, want ErrNoKeyPassphrase", err)
	}
	t.Setenv(config.EnvKeyPassphraseName, "pw")
	if err := requireIdentitySource(); err != nil {
		t.Fatalf("err = %v", err)
	}
}

// The transport of `fs webdav serve` asks the watch for a check on a 401, as
// the one of `fs mount` does, and on nothing else.
func TestWebdavTransportWatchingAsksOnA401(t *testing.T) {
	var unauthorized atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if unauthorized.Load() {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"total":0}`))
	}))
	defer srv.Close()

	watch := newAuthWatch(&okTokenSource{})
	client := api.New(srv.URL, "retyc-test/1.0", watch.src, false, false,
		webdavTransportWatching(watch), api.WithRetry(time.Millisecond, 1))
	ctx := context.Background()

	if _, err := client.ListDatarooms(ctx, 1, 10); err != nil {
		t.Fatal(err)
	}
	if len(watch.asked) != 0 {
		t.Fatal("a request that succeeded asked for a check")
	}
	unauthorized.Store(true)
	if _, err := client.ListDatarooms(ctx, 1, 10); err == nil {
		t.Fatal("ListDatarooms succeeded on a 401")
	}
	if len(watch.asked) != 1 {
		t.Fatal("a 401 did not ask for a check")
	}
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

// errRoundTripper answers with a fixed error.
type errRoundTripper struct{ err error }

func (e errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// A transport error that is permanent (machine account refused) asks for a
// check at once; a transient one does not.
func TestAuthWatchTransportPermanentErrorAsksCheck(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"machine revoked", fmt.Errorf("token: %w", auth.ErrMachineRevoked), 1},
		{"no token", auth.ErrNoToken, 1},
		{"transient", errors.New("connection reset"), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watch := newAuthWatch(&okTokenSource{})
			rt := watch.roundTripper(errRoundTripper{tt.err})
			if _, err := rt.RoundTrip(req); !errors.Is(err, tt.err) { //nolint:bodyclose // no response
				t.Fatalf("err = %v", err)
			}
			if len(watch.asked) != tt.want {
				t.Errorf("asked = %d, want %d", len(watch.asked), tt.want)
			}
		})
	}
}
