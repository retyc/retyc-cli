package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/pkg/api"
	"github.com/retyc/retyc-cli/pkg/diag"
	"github.com/retyc/retyc-cli/pkg/metrics"
)

func counterDelta(t *testing.T, c prometheus.Counter, before float64) float64 {
	t.Helper()

	return testutil.ToFloat64(c) - before
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
	setup := func(t *testing.T) (*okTokenSource, *Watch, *atomic.Int64, chan error) {
		t.Helper()
		src := &okTokenSource{}
		watch := NewWatch(src, false)
		watch.machine = true
		watch.Interval = time.Hour // no tick: only asked checks
		watch.Logf = func(string, ...any) {}
		var offset atomic.Int64
		watch.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		failed := make(chan error, 1)
		go watch.Run(ctx, func(err error) { failed <- err })

		return src, watch, &offset, failed
	}
	// check asks for a check and waits until the source was asked a token.
	check := func(t *testing.T, src *okTokenSource, watch *Watch) {
		t.Helper()
		want := src.checks.Load() + 1
		watch.CheckNow()
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
			if !errors.Is(err, ErrMachineRevoked) {
				t.Errorf("onFail(%v), want ErrMachineRevoked", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("onFail was not called")
		}
	})
}

func TestAuthWatchNotMachineIgnoresRepeated401(t *testing.T) {
	src := &okTokenSource{}
	watch := NewWatch(src, false)
	watch.machine = false
	watch.Interval = time.Hour
	ctx := t.Context()
	failed := make(chan error, 1)
	go watch.Run(ctx, func(err error) { failed <- err })
	for range machineRefusedChecks + 1 {
		watch.CheckNow()
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case err := <-failed:
		t.Fatalf("onFail outside machine mode: %v", err)
	default:
	}
}

// The transport of a server asks the watch for a check on a 401, and on
// nothing else.
func TestWatchTransportAsksOnA401(t *testing.T) {
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

	watch := NewWatch(&okTokenSource{}, false)
	client := api.New(srv.URL, "retyc-test/1.0", watch.src, false, false,
		api.WrapTransport(watch.RoundTripper), api.WithRetry(time.Millisecond, 1))
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

// errRoundTripper answers with a fixed error.
type errRoundTripper struct{ err error }

func (e errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// A transport error that is permanent (machine account refused) asks for a
// check at once; a transient one does not.
func TestAuthWatchTransportPermanentErrorAsksCheck(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.invalid/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"machine revoked", fmt.Errorf("token: %w", ErrMachineRevoked), 1},
		{"no token", ErrNoToken, 1},
		{"transient", errors.New("connection reset"), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watch := NewWatch(&okTokenSource{}, false)
			rt := watch.RoundTripper(errRoundTripper{tt.err})
			if _, err := rt.RoundTrip(req); !errors.Is(err, tt.err) { //nolint:bodyclose // no response
				t.Fatalf("err = %v", err)
			}
			if len(watch.asked) != tt.want {
				t.Errorf("asked = %d, want %d", len(watch.asked), tt.want)
			}
		})
	}
}

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) { return nil, errors.New("refresh expired") }

func TestCheckToken_ObservesResultAndExpiry(t *testing.T) {
	okCounter := metrics.TokenRefreshes.WithLabelValues("ok")
	errCounter := metrics.TokenRefreshes.WithLabelValues("error")
	okBefore, errBefore := testutil.ToFloat64(okCounter), testutil.ToFloat64(errCounter)

	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", Expiry: time.Now().Add(10 * time.Minute)})
	if err := checkToken(src); err != nil {
		t.Fatal(err)
	}
	if got := counterDelta(t, okCounter, okBefore); got != 1 {
		t.Errorf("ok delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.TokenExpiry); got < 500 || got > 600 {
		t.Errorf("token_expiry_seconds = %v, want about 600", got)
	}

	if err := checkToken(failingTokenSource{}); err == nil {
		t.Fatal("expected the token error to propagate")
	}
	if got := counterDelta(t, errCounter, errBefore); got != 1 {
		t.Errorf("error delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.TokenExpiry); got != 0 {
		t.Errorf("token_expiry_seconds after failure = %v, want 0", got)
	}
}

// chanWriter hands each write to the test.
type chanWriter chan string

func (c chanWriter) Write(p []byte) (int, error) {
	c <- string(p)

	return len(p), nil
}

// TestAuthWatchZeroIntervalNilLogf: a Watch whose exported fields an importer
// zeroed runs with the defaults (TokenKeepaliveInterval, diag output) rather
// than panicking.
func TestAuthWatchZeroIntervalNilLogf(t *testing.T) {
	lines := make(chanWriter, 4)
	diag.SetOutput(lines)
	t.Cleanup(func() { diag.SetOutput(nil) })

	watch := NewWatch(failingTokenSource{}, false)
	watch.Interval = 0
	watch.Logf = nil
	go watch.Run(t.Context(), func(err error) { t.Errorf("onFail(%v) on a transient failure", err) })
	watch.CheckNow()

	select {
	case line := <-lines:
		if !strings.Contains(line, "tried again every "+TokenKeepaliveInterval.String()) {
			t.Errorf("logged %q, want the default interval", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing logged to the diag output")
	}
}
