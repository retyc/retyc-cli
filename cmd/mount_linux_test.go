//go:build linux

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/retycfs"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs"
)

func TestCheckMountpoint(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	full := filepath.Join(dir, "full")
	file := filepath.Join(dir, "file")
	for _, d := range []string{empty, full} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{file, filepath.Join(full, "x")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := checkMountpoint(empty); err != nil {
		t.Errorf("empty folder refused: %v", err)
	}
	for path, want := range map[string]string{
		filepath.Join(dir, "missing"): "does not exist",
		file:                          "not a directory",
		full:                          "not empty",
	} {
		if err := checkMountpoint(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("checkMountpoint(%s) = %v, want an error holding %q", filepath.Base(path), err, want)
		}
	}
}

func TestCheckFUSE_MissingDevice(t *testing.T) {
	err := checkFUSE(filepath.Join(t.TempDir(), "fuse"))
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "modprobe fuse") {
		t.Errorf("checkFUSE = %v, want the missing device and what to do about it", err)
	}
}

// fakeMountServer is a mounted filesystem that records its unmount.
type fakeMountServer struct {
	done      chan struct{}
	unmounted int
	err       error
	// wait, when set, makes Shutdown last until its context ends, and is
	// closed then.
	wait chan struct{}
	// health, when set, is read when Shutdown starts: readyAtShutdown.
	health          *serveHealth
	readyAtShutdown bool
}

func (s *fakeMountServer) Done() <-chan struct{} { return s.done }

func (s *fakeMountServer) Shutdown(ctx context.Context) error {
	s.unmounted++
	if s.health != nil {
		s.readyAtShutdown = s.health.isReady()
	}
	if s.wait != nil {
		// A drain in progress: only a cut (the context) ends it.
		<-ctx.Done()
		close(s.wait)
	}

	return s.err
}

// /readyz of the mount: ready once mounted, and no longer as soon as the
// mount starts to go away, before the drain, whatever the reason (a signal,
// a login lost, an unmount from outside).
func TestServeMount_ReadinessEndsBeforeTheDrain(t *testing.T) {
	cases := map[string]func(stop chan os.Signal, expired chan error, srv *fakeMountServer){
		"signal":       func(stop chan os.Signal, _ chan error, _ *fakeMountServer) { stop <- syscall.SIGTERM },
		"login lost":   func(_ chan os.Signal, expired chan error, _ *fakeMountServer) { expired <- auth.ErrNoRefreshToken },
		"from outside": func(_ chan os.Signal, _ chan error, srv *fakeMountServer) { close(srv.done) },
	}
	for label, trigger := range cases {
		t.Run(label, func(t *testing.T) {
			health := newServeHealth()
			health.setReady(true)
			handler, err := newObservabilityHandler(health, observabilityOptions{})
			if err != nil {
				t.Fatal(err)
			}
			probe := func() int {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

				return rec.Code
			}
			if code := probe(); code != http.StatusOK {
				t.Fatalf("/readyz of a mounted filesystem = %d, want 200", code)
			}

			srv := &fakeMountServer{done: make(chan struct{}), health: health}
			stop, expired := make(chan os.Signal, 1), make(chan error, 1)
			trigger(stop, expired, srv)
			_ = serveMount(srv, stop, expired, health)
			if srv.readyAtShutdown {
				t.Error("the mount was still ready when its shutdown started")
			}
			if code := probe(); code != http.StatusServiceUnavailable {
				t.Errorf("/readyz once the mount is over = %d, want 503", code)
			}
		})
	}
}

func TestServeMount(t *testing.T) {
	newServer := func() *fakeMountServer { return &fakeMountServer{done: make(chan struct{})} }

	t.Run("signal", func(t *testing.T) {
		srv := newServer()
		stop := make(chan os.Signal, 1)
		stop <- syscall.SIGTERM
		if err := serveMount(srv, stop, nil, newServeHealth()); err != nil || srv.unmounted != 1 {
			t.Errorf("serveMount = %v, %d unmounts; want nil and 1", err, srv.unmounted)
		}
	})

	// fusermount3 -u from another terminal: a clean exit, and Unmount is
	// still called (it releases what served the mount).
	t.Run("unmounted from outside", func(t *testing.T) {
		srv := newServer()
		close(srv.done)
		if err := serveMount(srv, nil, nil, newServeHealth()); err != nil || srv.unmounted != 1 {
			t.Errorf("serveMount = %v, %d unmounts; want nil and 1", err, srv.unmounted)
		}
	})

	// A login that cannot be renewed: unmounted, and exit code 77, which
	// tells a supervisor not to restart.
	t.Run("authentication expired", func(t *testing.T) {
		srv := newServer()
		expired := make(chan error, 1)
		expired <- fmt.Errorf("refreshing the token: %w", auth.ErrNoRefreshToken)
		err := serveMount(srv, nil, expired, newServeHealth())
		if srv.unmounted != 1 {
			t.Errorf("%d unmounts, want 1", srv.unmounted)
		}
		if !errors.Is(err, auth.ErrNoRefreshToken) || exitCode(err) != exitAuthRequired {
			t.Errorf("serveMount = %v (exit code %d), want exit code %d", err, exitCode(err), exitAuthRequired)
		}
		if !strings.Contains(err.Error(), "retyc auth login") {
			t.Errorf("the error does not say what to do: %v", err)
		}
	})

	// A second signal while the files being sent are waited for ends the
	// wait: the shutdown is told through its context.
	t.Run("second signal cuts the drain short", func(t *testing.T) {
		srv := newServer()
		srv.wait = make(chan struct{})
		stop := make(chan os.Signal, 2)
		stop <- syscall.SIGINT
		stop <- syscall.SIGINT
		if err := serveMount(srv, stop, nil, newServeHealth()); err != nil || srv.unmounted != 1 {
			t.Errorf("serveMount = %v, %d unmounts; want nil and 1", err, srv.unmounted)
		}
		select {
		case <-srv.wait:
		default:
			t.Error("the shutdown returned without its context ending")
		}
	})

	t.Run("unmount error", func(t *testing.T) {
		srv := newServer()
		srv.err = errors.New("busy")
		close(srv.done)
		if err := serveMount(srv, nil, nil, newServeHealth()); err == nil || err.Error() != "busy" {
			t.Errorf("serveMount = %v, want the unmount error", err)
		}
	})
}

// A dataroom on an API without the lookup by name is refused; one whose
// session does not resolve reports that error.
func TestMountDataroomCheck(t *testing.T) {
	sessions := map[string]*service.DataroomSession{
		"legacy": (&service.DataroomSession{}).AssumeLegacyAPI(),
	}
	tree := vfs.New(nil, vfs.Options{
		Session: func(_ context.Context, id string) (*service.DataroomSession, error) {
			if sess, ok := sessions[id]; ok {
				return sess, nil
			}

			return nil, fmt.Errorf("fetching dataroom: %w", os.ErrNotExist)
		},
	})
	defer func() { _ = tree.Close() }()
	check := mountDataroomCheck(tree, nil)

	if err := check(context.Background(), "legacy"); !errors.Is(err, retycfs.ErrLegacyAPI) {
		t.Errorf("legacy API: %v, want ErrLegacyAPI", err)
	}
	if err := check(context.Background(), "unknown"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unknown dataroom: %v, want the error of its session", err)
	}
}

// What the mount lets the user write: asked at mount time for one dataroom,
// left to the driver for all of them, and never taken for granted when the
// question fails.
func TestMountRights(t *testing.T) {
	failure := errors.New("unreachable")
	answers := map[string]vfs.Access{
		"viewer":   {Role: api.RoleViewer, Writable: true, ReadOnly: true},
		"overplan": {Role: "editor", ReadOnly: true},
		"editor":   {Role: "editor", Writable: true},
	}
	for name, tc := range map[string]struct {
		target       mountTarget
		wantReadOnly bool
		wantWhy      string
		wantHook     bool
		wantAsked    int
		wantLogged   bool
	}{
		"--read-only asks nothing": {target: mountTarget{dataroomID: "editor", readOnly: true}, wantReadOnly: true},
		"viewer": {
			target: mountTarget{dataroomID: "viewer"}, wantReadOnly: true, wantAsked: 1,
			wantWhy: "you are a viewer of this dataroom",
		},
		"plan refuses writes": {
			target: mountTarget{dataroomID: "overplan"}, wantReadOnly: true, wantAsked: 1,
			wantWhy: "the plan of its owner refuses writes",
		},
		"editor":           {target: mountTarget{dataroomID: "editor"}, wantAsked: 1},
		"cannot be told":   {target: mountTarget{dataroomID: "down"}, wantAsked: 1, wantHook: true, wantLogged: true},
		"all: driver asks": {target: mountTarget{all: true}, wantHook: true},
	} {
		t.Run(name, func(t *testing.T) {
			asked, logged := 0, 0
			ask := func(_ context.Context, id string) (vfs.Access, error) {
				asked++
				if access, ok := answers[id]; ok {
					return access, nil
				}

				return vfs.Access{}, failure
			}
			readOnly, why, hook := mountRights(context.Background(), tc.target, ask,
				func(string, ...any) { logged++ })
			if readOnly != tc.wantReadOnly || why != tc.wantWhy || (hook != nil) != tc.wantHook {
				t.Errorf("mountRights = %v, %q, hook %v; want %v, %q, hook %v",
					readOnly, why, hook != nil, tc.wantReadOnly, tc.wantWhy, tc.wantHook)
			}
			if asked != tc.wantAsked || (logged > 0) != tc.wantLogged {
				t.Errorf("asked %d times, logged %d; want %d, logged %v", asked, logged, tc.wantAsked, tc.wantLogged)
			}
		})
	}
}

// commandWithContext returns a command carrying a context, as cobra hands
// one to RunE.
func commandWithContext() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	return cmd
}

// The passphrase is asked for before anything else that could fail later:
// without it the command stops with exit code 78, having mounted nothing.
func TestRunMount_NeedsThePassphrase(t *testing.T) {
	if err := checkFUSE(fuseDevice); err != nil {
		t.Skipf("FUSE unavailable: %v", err)
	}
	isolateConfig(t)
	t.Setenv("RETYC_KEY_PASSPHRASE", "")
	err := runMount(commandWithContext(), mountTarget{dataroomID: "dr-1", mountpoint: t.TempDir()})
	if exitCode(err) != exitConfig {
		t.Errorf("runMount without a passphrase = %v (exit code %d), want exit code %d", err, exitCode(err), exitConfig)
	}
}

func TestRunMount_ChecksTheMountpointFirst(t *testing.T) {
	isolateConfig(t)
	err := runMount(commandWithContext(), mountTarget{all: true, mountpoint: filepath.Join(t.TempDir(), "missing")})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("runMount on a missing mount point = %v", err)
	}
}

// expiringTokenSource is a login whose access token is taken for valid until
// the source is told to refresh it (Expire), and that cannot be renewed once
// revoke was called: what a login revoked on the server looks like.
type expiringTokenSource struct {
	mu        sync.Mutex
	revoked   bool
	expired   bool
	asked     int
	refreshes int
}

func (s *expiringTokenSource) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshes++
	s.expired = s.revoked
}

func (s *expiringTokenSource) counts() (asked, refreshes int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.asked, s.refreshes
}

func (s *expiringTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	if s.expired {
		return nil, fmt.Errorf("refreshing token: %w", auth.ErrNoRefreshToken)
	}

	return &oauth2.Token{AccessToken: "test", TokenType: "Bearer"}, nil
}

func (s *expiringTokenSource) revoke() {
	s.mu.Lock()
	s.revoked = true
	s.mu.Unlock()
}

// A request the API answers 401 has the login checked at once, not at the
// next tick of the keepalive: a mount whose login is gone is unmounted and
// the command exits with code 77.
func TestMount_A401StopsTheMountAtOnce(t *testing.T) {
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

	src := &expiringTokenSource{}
	watch := newAuthWatch(src)
	// The tick never comes during the test: only a 401 can ask for a check.
	watch.interval = time.Hour
	client := api.New(srv.URL, "retyc-test/1.0", src, false, false,
		apiTransportWatching(watch), api.WithRetry(time.Millisecond, 1))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expired := make(chan error, 1)
	go watch.run(ctx, func(err error) { expired <- err })

	mount := &fakeMountServer{done: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- serveMount(mount, nil, expired, newServeHealth()) }()

	// A request that succeeds asks for nothing.
	if _, err := service.ListDatarooms(ctx, client); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("the mount stopped on a request that succeeded: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// The login is revoked on the server. The access token has not expired
	// for the source, which still signs the request: the API answers 401.
	src.revoke()
	unauthorized.Store(true)
	var refused *api.HTTPError
	if _, err := service.ListDatarooms(ctx, client); !errors.As(err, &refused) ||
		refused.Status != http.StatusUnauthorized {
		t.Fatalf("ListDatarooms = %v, want the 401 of the API", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, auth.ErrNoRefreshToken) || exitCode(err) != exitAuthRequired {
			t.Errorf("serveMount = %v (exit code %d), want exit code %d", err, exitCode(err), exitAuthRequired)
		}
		if mount.unmounted != 1 {
			t.Errorf("%d unmounts, want 1", mount.unmounted)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the mount did not stop after a 401")
	}
}

// A 401 has the access token refreshed and the login checked, once however
// many requests meet one; a login that is still good keeps the watch running,
// and no other answer asks for anything.
func TestAuthWatch_ChecksOnA401(t *testing.T) {
	src := &expiringTokenSource{}
	watch := newAuthWatch(src)
	watch.interval = time.Hour
	var status atomic.Int32
	status.Store(http.StatusForbidden)
	rt := watch.roundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: int(status.Load()), Body: http.NoBody}, nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := make(chan error, 1)
	go watch.run(ctx, func(err error) { failed <- err })

	// send makes one request and returns the status passed on.
	send := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://api.invalid/dataroom", nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()

		return resp.StatusCode
	}
	send()
	time.Sleep(50 * time.Millisecond)
	if asked, _ := src.counts(); asked != 0 {
		t.Errorf("the login was checked after a 403")
	}

	status.Store(http.StatusUnauthorized)
	if got := send(); got != http.StatusUnauthorized {
		t.Fatalf("the answer was not passed on: status %d", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if asked, _ := src.counts(); asked > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// More 401s: checked again, but the token is refreshed once per interval.
	for range 3 {
		send()
		time.Sleep(20 * time.Millisecond)
	}
	if asked, refreshes := src.counts(); asked == 0 || refreshes != 1 {
		t.Errorf("after 401s: %d checks, %d refreshes; want checks and one refresh", asked, refreshes)
	}
	select {
	case err := <-failed:
		t.Errorf("a check that passed stopped the watch: %v", err)
	default:
	}
}

// roundTripFunc is a transport made of one function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// flakyTokenSource fails with what it is told to, or answers a token.
type flakyTokenSource struct {
	mu    sync.Mutex
	err   error
	asked int
}

func (s *flakyTokenSource) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *flakyTokenSource) checks() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.asked
}

func (s *flakyTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	if s.err != nil {
		return nil, s.err
	}

	return &oauth2.Token{AccessToken: "test", TokenType: "Bearer"}, nil
}

// A check of the login that fails because the identity provider cannot be
// asked (network, 5xx, timeout) stops nothing: it is reported once, tried
// again at the next tick, and the watch goes on. Only a login the provider
// refuses, or that has no refresh token, stops the command. `fs webdav serve`
// runs the same watch (tokenKeepalive).
func TestAuthWatch_TransientFailureKeepsServing(t *testing.T) {
	transient := map[string]error{
		"network":  fmt.Errorf("refreshing token: %w", &net.OpError{Op: "dial", Err: errors.New("connection refused")}),
		"timeout":  fmt.Errorf("refreshing token: %w", context.DeadlineExceeded),
		"5xx":      fmt.Errorf("refreshing token: %w", &auth.RefreshError{Status: http.StatusBadGateway}),
		"429":      fmt.Errorf("refreshing token: %w", &auth.RefreshError{Status: http.StatusTooManyRequests}),
		"bad body": errors.New("refreshing token: decoding refresh response (status 200)"),
	}
	for label, failure := range transient {
		t.Run(label, func(t *testing.T) {
			src := &flakyTokenSource{}
			src.fail(failure)
			watch := newAuthWatch(src)
			watch.interval = 5 * time.Millisecond
			var mu sync.Mutex
			var lines []string
			watch.logf = func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				lines = append(lines, fmt.Sprintf(format, args...))
			}
			logged := func() []string {
				mu.Lock()
				defer mu.Unlock()

				return append([]string(nil), lines...)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failed := make(chan error, 1)
			go watch.run(ctx, func(err error) { failed <- err })

			// Several ticks fail: the watch is still running, and said so once.
			waitFor(t, func() bool { return src.checks() >= 3 })
			select {
			case err := <-failed:
				t.Fatalf("the watch stopped on a failure that may pass: %v", err)
			default:
			}
			if got := logged(); len(got) != 1 || !strings.Contains(got[0], "tried again") {
				t.Errorf("reported %q, want one warning", got)
			}

			// The provider answers again: said once too.
			src.fail(nil)
			waitFor(t, func() bool { return len(logged()) == 2 })

			// The login is refused: this one stops the command, with 77.
			src.fail(fmt.Errorf("refreshing token: %w", auth.ErrNoRefreshToken))
			select {
			case err := <-failed:
				if exitCode(err) != exitAuthRequired {
					t.Errorf("exit code %d for %v, want %d", exitCode(err), err, exitAuthRequired)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the watch did not stop on a login lost")
			}
		})
	}
}

// Another refusal by the identity provider than invalid_grant stops the
// command too: it will not pass by itself.
func TestAuthWatch_RefusalStops(t *testing.T) {
	src := &flakyTokenSource{}
	src.fail(fmt.Errorf("refreshing token: %w",
		&auth.RefreshError{Status: http.StatusUnauthorized, Code: "invalid_client"}))
	watch := newAuthWatch(src)
	watch.interval = 5 * time.Millisecond
	watch.logf = func(string, ...any) {}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := make(chan error, 1)
	go watch.run(ctx, func(err error) { failed <- err })
	select {
	case err := <-failed:
		var refused *auth.RefreshError
		if !errors.As(err, &refused) {
			t.Errorf("onFail(%v), want the refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not stop on a refusal")
	}
}

// The mount stays ready and mounted through a check of the login that fails
// without the login being lost.
func TestServeMount_TransientLoginFailureKeepsTheMount(t *testing.T) {
	src := &flakyTokenSource{}
	src.fail(fmt.Errorf("refreshing token: %w", &auth.RefreshError{Status: http.StatusServiceUnavailable}))
	watch := newAuthWatch(src)
	watch.interval = 5 * time.Millisecond
	watch.logf = func(string, ...any) {}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expired := make(chan error, 1)
	go watch.run(ctx, func(err error) { expired <- err })

	health := newServeHealth()
	health.setReady(true)
	mount := &fakeMountServer{done: make(chan struct{})}
	stop := make(chan os.Signal, 1)
	result := make(chan error, 1)
	go func() { result <- serveMount(mount, stop, expired, health) }()

	waitFor(t, func() bool { return src.checks() >= 3 })
	select {
	case err := <-result:
		t.Fatalf("the mount stopped on a failure that may pass: %v", err)
	default:
	}
	if !health.isReady() {
		t.Error("the mount is no longer ready")
	}
	stop <- syscall.SIGTERM
	if err := <-result; err != nil {
		t.Errorf("serveMount = %v", err)
	}
}

// Files lost at the shutdown are exit code 75 (exitLostWrites) and an error that counts them,
// whatever started the shutdown; with a login lost the code stays 77.
func TestServeMount_LostWrites(t *testing.T) {
	lost := &retycfs.LostWritesError{Files: 2}
	t.Run("signal", func(t *testing.T) {
		srv := &fakeMountServer{done: make(chan struct{}), err: lost}
		stop := make(chan os.Signal, 1)
		stop <- syscall.SIGTERM
		err := serveMount(srv, stop, nil, newServeHealth())
		if !errors.Is(err, lost) || exitCode(err) != exitLostWrites || !strings.Contains(err.Error(), "2 files") {
			t.Errorf("serveMount = %v (exit code %d), want the files lost and 75", err, exitCode(err))
		}
	})
	t.Run("unmounted from outside", func(t *testing.T) {
		srv := &fakeMountServer{done: make(chan struct{}), err: lost}
		close(srv.done)
		if err := serveMount(srv, nil, nil, newServeHealth()); !errors.Is(err, lost) || exitCode(err) != exitLostWrites {
			t.Errorf("serveMount = %v (exit code %d), want the files lost and 75", err, exitCode(err))
		}
	})
	t.Run("login lost", func(t *testing.T) {
		srv := &fakeMountServer{done: make(chan struct{}), err: lost}
		expired := make(chan error, 1)
		expired <- fmt.Errorf("refreshing token: %w", auth.ErrNoRefreshToken)
		err := serveMount(srv, nil, expired, newServeHealth())
		if exitCode(err) != exitAuthRequired || !strings.Contains(err.Error(), "2 files") {
			t.Errorf("serveMount = %v (exit code %d), want the files lost and %d", err, exitCode(err), exitAuthRequired)
		}
	})
}

// waitFor waits for cond to hold.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("the condition never held")
		}
		time.Sleep(time.Millisecond)
	}
}
