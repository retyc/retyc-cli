package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
)

// fakeClock replaces the clock of a throttleGate: sleeping moves the time
// forward at once, so no test waits a real second.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Time
	logs   []string
	// barrier, when set, makes sleepUntil block until that many sleepers are
	// waiting, then releases them all together.
	barrier int
	waiting int
	release chan struct{}
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC), release: make(chan struct{})}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *fakeClock) sleepUntil(ctx context.Context, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.sleeps = append(c.sleeps, at)
	if c.barrier > 0 {
		c.waiting++
		if c.waiting == c.barrier {
			close(c.release)
		}
		c.mu.Unlock()
		select {
		case <-c.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		c.mu.Lock()
	}
	if at.After(c.t) {
		c.t = at
	}
	c.mu.Unlock()

	return nil
}

// advance moves the clock forward by d.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) logLines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string(nil), c.logs...)
}

// otherRefusal stands for the 429 another request received.
func otherRefusal() *HTTPError {
	return &HTTPError{Status: http.StatusTooManyRequests, Body: "other request", RetryAfter: time.Second}
}

func (c *fakeClock) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, fmt.Sprintf(format, args...))
}

// install plugs the clock into client; the backoff jitter becomes the
// identity so the pauses are exact.
func (c *fakeClock) install(client *Client) {
	client.retry.gate.now = c.now
	client.retry.gate.sleepUntil = c.sleepUntil
	client.retry.gate.logf = c.logf
	client.retry.jitter = func(d time.Duration) time.Duration { return d }
}

func newRetryTestClient(srv *httptest.Server, opts ...Option) (*Client, *fakeClock) {
	client := New(srv.URL, "retyc-test/1.0", staticTokenSource(), false, false, opts...)
	clock := newFakeClock()
	clock.install(client)

	return client, clock
}

func TestRetry_429ThenOK(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "No more requests allowed", http.StatusTooManyRequests)

			return
		}
		_, _ = w.Write([]byte(`{"name":"ok"}`))
	}))
	defer srv.Close()

	var seen *countingRT
	client, clock := newRetryTestClient(srv, WrapTransport(func(base http.RoundTripper) http.RoundTripper {
		seen = &countingRT{base: base}

		return seen
	}))
	start := clock.now()
	episodes := testutil.ToFloat64(metrics.APIThrottleEpisodes)

	var dst struct {
		Name string `json:"name"`
	}
	if err := client.Get(context.Background(), "/x", &dst); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if dst.Name != "ok" {
		t.Errorf("Name = %q, want ok", dst.Name)
	}
	if hits.Load() != 2 {
		t.Errorf("server saw %d requests, want 2", hits.Load())
	}
	// Every attempt goes through the wrapped transport (metrics, tracing).
	if seen.calls != 2 {
		t.Errorf("wrapped transport saw %d round trips, want 2", seen.calls)
	}
	if got := clock.now().Sub(start); got != time.Second {
		t.Errorf("waited %s, want the Retry-After of 1s", got)
	}
	wantLog := "API rate limit: throttled from 10:00:00 to 10:00:01 (1s), 1 refusal(s), 1 request(s) held back"
	if len(clock.logs) != 1 || clock.logs[0] != wantLog {
		t.Errorf("episode log = %q, want %q", clock.logs, wantLog)
	}
	if got := testutil.ToFloat64(metrics.APIThrottleEpisodes) - episodes; got != 1 {
		t.Errorf("episodes counted = %v, want 1", got)
	}
}

func TestRetry_ReplaysJSONBody(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(data))
		n := len(bodies)
		mu.Unlock()
		if n <= 2 {
			// No Retry-After: exponential backoff.
			w.WriteHeader(http.StatusTooManyRequests)

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv)
	start := clock.now()
	const payload = `{"title":"hello"}`
	if err := client.Post(context.Background(), "/x", bytes.NewReader([]byte(payload)), nil); err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if len(bodies) != 3 {
		t.Fatalf("server saw %d requests, want 3", len(bodies))
	}
	for i, b := range bodies {
		if b != payload {
			t.Errorf("attempt %d body = %q, want %q", i+1, b, payload)
		}
	}
	// 200 ms then 400 ms (jitter is the identity here).
	want := []time.Time{start.Add(200 * time.Millisecond), start.Add(600 * time.Millisecond)}
	if len(clock.sleeps) != 2 || !clock.sleeps[0].Equal(want[0]) || !clock.sleeps[1].Equal(want[1]) {
		t.Errorf("sleeps = %v, want %v", clock.sleeps, want)
	}
	// Refused twice, held back twice: still one request.
	if len(clock.logs) != 1 || !strings.Contains(clock.logs[0], "(600ms), 2 refusal(s), 1 request(s) held back") {
		t.Errorf("episode log = %q, want 2 refusals and 1 request", clock.logs)
	}
}

func TestRetry_ReplaysMultipartBody(t *testing.T) {
	chunk := bytes.Repeat([]byte("encrypted chunk payload "), 4096)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		f, _, err := r.FormFile("upload_file")
		if err != nil {
			t.Errorf("attempt %d: FormFile() error = %v", n, err)
			http.Error(w, "bad form", http.StatusBadRequest)

			return
		}
		defer f.Close() //nolint:errcheck
		got, _ := io.ReadAll(f)
		if !bytes.Equal(got, chunk) {
			t.Errorf("attempt %d: chunk of %d bytes, want the %d bytes sent", n, len(got), len(chunk))
		}
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)

			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, _ := newRetryTestClient(srv)
	if err := client.PostMultipartChunk(context.Background(), "/file/abc/0", chunk); err != nil {
		t.Fatalf("PostMultipartChunk() error = %v", err)
	}
	if hits.Load() != 2 {
		t.Errorf("server saw %d requests, want 2", hits.Load())
	}
}

// Requests refused together wait behind one gate: a single window, not one
// pause each, and one line of log.
func TestRetry_GateSharesOneWindow(t *testing.T) {
	const n = 8
	var mu sync.Mutex
	arrived := 0
	allIn := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		arrived++
		first := arrived <= n
		if arrived == n {
			close(allIn)
		}
		mu.Unlock()
		if !first {
			_, _ = w.Write([]byte(`{}`))

			return
		}
		// Refuse the first n only once they are all in flight.
		<-allIn
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv)
	// The clock moves only once every request is waiting at the gate.
	clock.barrier = n
	start := clock.now()
	episodes := testutil.ToFloat64(metrics.APIThrottleEpisodes)

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = client.Get(context.Background(), "/x", nil)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("request %d: %v", i, err)
		}
	}
	if arrived != 2*n {
		t.Errorf("server saw %d requests, want %d", arrived, 2*n)
	}
	if got := clock.now().Sub(start); got != time.Second {
		t.Errorf("clock moved by %s, want a single window of 1s", got)
	}
	if len(clock.sleeps) != n {
		t.Errorf("%d waits, want %d", len(clock.sleeps), n)
	}
	for _, at := range clock.sleeps {
		if !at.Equal(start.Add(time.Second)) {
			t.Errorf("a request waited until %s, want %s", at, start.Add(time.Second))
		}
	}
	if got := testutil.ToFloat64(metrics.APIThrottleEpisodes) - episodes; got != 1 {
		t.Errorf("episodes counted = %v, want 1", got)
	}
	want := fmt.Sprintf("%d refusal(s), %d request(s) held back", n, n)
	if len(clock.logs) != 1 || !strings.Contains(clock.logs[0], want) {
		t.Errorf("episode log = %q, want one line with %q", clock.logs, want)
	}
}

// A request that was never refused waits at a closed gate too.
func TestRetry_NewRequestWaitsAtClosedGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv)
	start := clock.now()
	client.retry.gate.throttle(2*time.Second, otherRefusal())
	if err := client.Get(context.Background(), "/x", nil); err != nil {
		t.Fatal(err)
	}
	if got := clock.now().Sub(start); got != 2*time.Second {
		t.Errorf("waited %s, want 2s", got)
	}
}

func TestThrottleGate_ClosedGateIsNotPushedPastRetryAfter(t *testing.T) {
	clock := newFakeClock()
	g := newThrottleGate()
	g.now, g.sleepUntil, g.logf = clock.now, clock.sleepUntil, clock.logf
	start := clock.now()

	if got := g.throttle(time.Second, otherRefusal()); got != time.Second {
		t.Errorf("first refusal closes for %s, want 1s", got)
	}
	// A shorter pause received while closed changes nothing.
	if got := g.throttle(200*time.Millisecond, otherRefusal()); got != time.Second {
		t.Errorf("closed for %s after a shorter pause, want 1s", got)
	}
	// Half a second later, another Retry-After of 1 s: now+1s, no further.
	clock.advance(500 * time.Millisecond)
	if got := g.throttle(time.Second, otherRefusal()); got != time.Second {
		t.Errorf("closed for %s, want 1s from the last refusal", got)
	}
	if !g.notBefore.Equal(start.Add(1500 * time.Millisecond)) {
		t.Errorf("notBefore = %s, want start+1.5s", g.notBefore.Sub(start))
	}
}

func TestRetry_ContextCancelledWhileWaiting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, _ := newRetryTestClient(srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The wait starts, then the context is cancelled under it.
	client.retry.gate.sleepUntil = func(ctx context.Context, _ time.Time) error {
		cancel()
		<-ctx.Done()

		return ctx.Err()
	}

	err := client.Post(ctx, "/x", strings.NewReader(`{}`), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrRateLimited) {
		t.Errorf("a cancelled wait must not read as a rate limit: %v", err)
	}
}

func TestRetry_GivesUpAfterMaxAttempts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "No more requests allowed", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, _ := newRetryTestClient(srv, WithRetry(30*time.Second, 3))
	given := testutil.ToFloat64(metrics.APIRateLimited.WithLabelValues(http.MethodDelete))

	err := client.Delete(context.Background(), "/x")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if hits.Load() != 3 {
		t.Errorf("server saw %d requests, want 3", hits.Load())
	}
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("error %T is not a RateLimitError", err)
	}
	if rl.Attempts != 3 || rl.Waited != 2*time.Second {
		t.Errorf("attempts = %d, waited = %s; want 3 and 2s", rl.Attempts, rl.Waited)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusTooManyRequests ||
		!strings.Contains(httpErr.Body, "No more requests allowed") {
		t.Errorf("last refusal not wrapped: %v", httpErr)
	}
	if got := RetryAfter(err); got != time.Second {
		t.Errorf("RetryAfter() = %s, want 1s", got)
	}
	// Readable as is by a one-shot command, without the URL in front.
	if !strings.HasPrefix(err.Error(), "API rate limit, gave up after 2s (3 attempts): API error 429") {
		t.Errorf("message = %q", err.Error())
	}
	if got := testutil.ToFloat64(metrics.APIRateLimited.WithLabelValues(http.MethodDelete)) - given; got != 1 {
		t.Errorf("rate_limited_total moved by %v, want 1", got)
	}
}

func TestRetry_GivesUpAfterMaxWait(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retryAfter string
		wantHits   int32
		wantWaited time.Duration
	}{
		// 4 s + 4 s spent; a third pause would pass the 10 s budget.
		{"budget spent", "4", 3, 8 * time.Second},
		// The server asks for more than the whole budget: not even waited.
		{"pause above budget", "60", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Retry-After", tc.retryAfter)
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer srv.Close()

			client, clock := newRetryTestClient(srv, WithRetry(10*time.Second, 100))
			start := clock.now()
			_, err := client.GetBytes(context.Background(), "/x")
			if !errors.Is(err, ErrRateLimited) {
				t.Fatalf("error = %v, want ErrRateLimited", err)
			}
			if hits.Load() != tc.wantHits {
				t.Errorf("server saw %d requests, want %d", hits.Load(), tc.wantHits)
			}
			if got := clock.now().Sub(start); got != tc.wantWaited {
				t.Errorf("waited %s, want %s", got, tc.wantWaited)
			}
		})
	}
}

// The gate never stays closed for longer than a request may wait, whatever
// the server asks for.
func TestRetry_GateClosureIsCappedByMaxWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv, WithRetry(10*time.Second, 5))
	if err := client.Get(context.Background(), "/x", nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if got := client.retry.gate.notBefore.Sub(clock.now()); got != 10*time.Second {
		t.Errorf("gate closed for %s, want the 10s budget", got)
	}
}

// One attempt: the request is not replayed and says so, but its refusal still
// closes the gate for the requests that follow.
func TestRetry_SingleAttempt(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv, WithRetry(30*time.Second, 1))
	err := client.Get(context.Background(), "/x", nil)
	if !errors.Is(err, ErrRateLimited) || hits.Load() != 1 || len(clock.sleeps) != 0 {
		t.Fatalf("error = %v, hits = %d, sleeps = %d; want ErrRateLimited, 1, 0", err, hits.Load(), len(clock.sleeps))
	}
	if !strings.HasPrefix(err.Error(), "API rate limit, gave up after 0s (1 attempt): ") {
		t.Errorf("message = %q", err.Error())
	}
	// No Retry-After: the first backoff step, 200 ms.
	if got := client.retry.gate.notBefore.Sub(clock.now()); got != 200*time.Millisecond {
		t.Errorf("gate closed for %s after the refusal, want 200ms", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, value string
		want        time.Duration
	}{
		{"absent", "", 0},
		{"seconds", "1", time.Second},
		{"seconds with spaces", " 30 ", 30 * time.Second},
		{"zero", "0", 0},
		{"negative", "-5", 0},
		{"above the cap", "99999999999", retryAfterMax},
		{"beyond 64 bits", "99999999999999999999999999", retryAfterMax},
		{"http date", now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{"past date", now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{"fraction", "1.5", 0},
		{"garbage", "soon", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfter(tc.value, now); got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %s, want %s", tc.value, got, tc.want)
			}
		})
	}
}

func TestHTTPError_RateLimited(t *testing.T) {
	err := statusError(http.StatusTooManyRequests, []byte("slow down"))
	if !errors.Is(err, ErrRateLimited) {
		t.Error("a 429 must match ErrRateLimited")
	}
	if errors.Is(statusError(http.StatusServiceUnavailable, nil), ErrRateLimited) {
		t.Error("a 503 must not match ErrRateLimited")
	}
	if RetryAfter(errors.New("x")) != 0 || RetryAfter(statusError(http.StatusNotFound, nil)) != 0 {
		t.Error("RetryAfter must be 0 outside a 429")
	}
}

func TestBackoff_DoublesUpToTheCap(t *testing.T) {
	rt := newRetryTransport(nil, time.Minute, 20, false)
	rt.jitter = func(d time.Duration) time.Duration { return d }
	want := []time.Duration{200, 400, 800, 1600, 3200, 5000, 5000}
	for i, w := range want {
		if got := rt.backoff(i + 1); got != w*time.Millisecond {
			t.Errorf("backoff(%d) = %s, want %s", i+1, got, w*time.Millisecond)
		}
	}
	if got := rt.backoff(80); got != retryBackoffMax {
		t.Errorf("backoff(80) = %s, want the cap", got)
	}
	for range 100 {
		if d := fullJitter(time.Second); d <= 0 || d > time.Second {
			t.Fatalf("fullJitter(1s) = %s, out of (0, 1s]", d)
		}
	}
}

// In a trace, each attempt is a CLIENT span of its own and the wait between
// them an api.throttle event on the caller's span, carrying the attempt and
// the pause only: nothing of the refusal's body.
func TestRetry_TraceHasOneSpanPerAttemptAndAThrottleEvent(t *testing.T) {
	const sentinel = "SENTINEL-do-not-export"
	exp := telemetrytest.Install(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, sentinel, http.StatusTooManyRequests)

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client, _ := newRetryTestClient(srv, WrapTransport(telemetry.RoundTripper))
	ctx, parent := telemetry.Tracer().Start(context.Background(), "caller")
	if err := client.Get(ctx, "/dataroom", nil); err != nil {
		t.Fatal(err)
	}
	parent.End()

	var statuses []int64
	events := 0
	for _, s := range exp.GetSpans() {
		for _, kv := range s.Attributes {
			if kv.Key == "http.response.status_code" {
				statuses = append(statuses, kv.Value.AsInt64())
			}
			if strings.Contains(kv.Value.String(), sentinel) {
				t.Errorf("attribute %s leaks the body of the refusal", kv.Key)
			}
		}
		for _, ev := range s.Events {
			if ev.Name != telemetry.EventThrottle {
				continue
			}
			events++
			if s.Name != "caller" {
				t.Errorf("throttle event on span %q, want the caller's", s.Name)
			}
			got := map[string]int64{}
			for _, kv := range ev.Attributes {
				got[string(kv.Key)] = kv.Value.AsInt64()
			}
			if len(got) != 2 || got[string(telemetry.AttrRetryAttempt)] != 1 ||
				got[string(telemetry.AttrRetryWaitMS)] != 1000 {
				t.Errorf("throttle event attributes = %v, want attempt 1 and wait_ms 1000 only", got)
			}
		}
	}
	if len(statuses) != 2 || statuses[0] != http.StatusTooManyRequests || statuses[1] != http.StatusOK {
		t.Errorf("CLIENT span statuses = %v, want [429 200]", statuses)
	}
	if events != 1 {
		t.Errorf("%d api.throttle events, want 1", events)
	}
}

// The episode line reports the window the gate was closed, not the time of
// the answer that ends the episode: on an idle client that answer may come
// long after.
func TestRetry_EpisodeLogIsTheClosedWindow(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv, WithRetry(30*time.Second, 1))
	if err := client.Get(context.Background(), "/x", nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	// Given up: nothing ended the episode yet.
	if logs := clock.logLines(); len(logs) != 0 {
		t.Fatalf("logged before the gate reopened: %q", logs)
	}

	clock.advance(10 * time.Minute)
	if err := client.Get(context.Background(), "/x", nil); err != nil {
		t.Fatal(err)
	}
	want := "API rate limit: throttled from 10:00:00 to 10:00:01 (1s), 1 refusal(s), 0 request(s) held back"
	if logs := clock.logLines(); len(logs) != 1 || logs[0] != want {
		t.Errorf("episode log = %q, want %q", logs, want)
	}
}

// blockingServer answers its first request only once released, with first;
// the following ones get a 200 at once.
type blockingServer struct {
	*httptest.Server
	hits     atomic.Int32
	inFlight chan struct{}
	release  chan struct{}
}

func newBlockingServer(first func(http.ResponseWriter)) *blockingServer {
	b := &blockingServer{inFlight: make(chan struct{}), release: make(chan struct{})}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if b.hits.Add(1) == 1 {
			close(b.inFlight)
			<-b.release
			first(w)

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))

	return b
}

// An answer to a request sent before the refusal comes back while the gate
// is closed: it says nothing about the limit and must not end the episode.
func TestRetry_AnswerInFlightDoesNotEndTheEpisode(t *testing.T) {
	srv := newBlockingServer(func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) })
	defer srv.Close()
	client, clock := newRetryTestClient(srv.Server)

	done := make(chan error, 1)
	go func() { done <- client.Get(context.Background(), "/x", nil) }()
	<-srv.inFlight
	// Another request is refused while this one is in flight.
	client.retry.gate.throttle(time.Second, otherRefusal())
	close(srv.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if logs := clock.logLines(); len(logs) != 0 {
		t.Fatalf("a 200 received while the gate is closed ended the episode: %q", logs)
	}

	// The next request waits for the gate, and its answer ends the episode.
	if err := client.Get(context.Background(), "/x", nil); err != nil {
		t.Fatal(err)
	}
	logs := clock.logLines()
	if len(logs) != 1 || !strings.Contains(logs[0], "(1s), 1 refusal(s), 1 request(s) held back") {
		t.Errorf("episode log = %q, want one line for the 1s window", logs)
	}
}

// A 429 received while another request already closed the gate pushes it to
// now + Retry-After, no further, and belongs to the same episode.
func TestRetry_RefusalWhileGateClosedByAnotherRequest(t *testing.T) {
	srv := newBlockingServer(func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer srv.Close()
	client, clock := newRetryTestClient(srv.Server)
	start := clock.now()
	episodes := testutil.ToFloat64(metrics.APIThrottleEpisodes)

	done := make(chan error, 1)
	go func() { done <- client.Get(context.Background(), "/x", nil) }()
	<-srv.inFlight
	// The gate closes for 1 s on the refusal of another request; this one is
	// refused half a second later.
	client.retry.gate.throttle(time.Second, otherRefusal())
	clock.advance(500 * time.Millisecond)
	close(srv.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if srv.hits.Load() != 2 {
		t.Errorf("server saw %d requests, want 2", srv.hits.Load())
	}
	want := start.Add(1500 * time.Millisecond)
	if len(clock.sleeps) != 1 || !clock.sleeps[0].Equal(want) {
		t.Errorf("waited until %v, want start+1.5s only", clock.sleeps)
	}
	if got := testutil.ToFloat64(metrics.APIThrottleEpisodes) - episodes; got != 1 {
		t.Errorf("episodes counted = %v, want 1", got)
	}
	logs := clock.logLines()
	if len(logs) != 1 || !strings.Contains(logs[0], "(1.5s), 2 refusal(s), 1 request(s) held back") {
		t.Errorf("episode log = %q, want one 1.5s episode with 2 refusals", logs)
	}
}

// max_wait bounds the whole time a request is held back: when the refusal of
// another request pushes the gate past what this one may still wait, it
// gives up at once instead of waiting a second budget.
func TestRetry_GatePushedPastTheBudgetWhileWaiting(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "20")
		http.Error(w, "own refusal", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv, WithRetry(30*time.Second, 10))
	start := clock.now()
	gate := client.retry.gate
	pushed := false
	gate.sleepUntil = func(ctx context.Context, at time.Time) error {
		err := clock.sleepUntil(ctx, at)
		if !pushed {
			// 20 s in, another request is told to wait an hour: the gate
			// closes for the 30 s cap.
			pushed = true
			gate.throttle(30*time.Second, otherRefusal())
		}

		return err
	}

	err := client.Get(context.Background(), "/x", nil)
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("error = %v, want a RateLimitError", err)
	}
	if rl.Waited != 20*time.Second || rl.Attempts != 1 {
		t.Errorf("waited %s over %d attempt(s), want 20s and 1", rl.Waited, rl.Attempts)
	}
	if got := clock.now().Sub(start); got != 20*time.Second {
		t.Errorf("held back %s in all, want 20s (never past the 30s budget)", got)
	}
	if hits.Load() != 1 {
		t.Errorf("server saw %d requests, want 1", hits.Load())
	}
	if rl.Last == nil || rl.Last.Body != "other request" {
		t.Errorf("wrapped refusal = %+v, want the one that closed the gate", rl.Last)
	}
}

// A request that finds the gate closed for longer than its budget is not
// sent at all, and its message says so.
func TestRetry_GateClosedPastTheBudgetOfANewRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()

	client, clock := newRetryTestClient(srv, WithRetry(5*time.Second, 10))
	client.retry.gate.throttle(10*time.Second, otherRefusal())
	err := client.Post(context.Background(), "/x", strings.NewReader(`{}`), nil)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v, want ErrRateLimited", err)
	}
	if hits.Load() != 0 || len(clock.sleeps) != 0 {
		t.Errorf("hits = %d, sleeps = %d; want neither", hits.Load(), len(clock.sleeps))
	}
	if !strings.HasPrefix(err.Error(), "API rate limit, gave up after 0s without sending the request: ") {
		t.Errorf("message = %q", err.Error())
	}
}

// Retry-After given as an HTTP date is read against the clock of the gate.
func TestRetry_RetryAfterAsHTTPDate(t *testing.T) {
	var hits atomic.Int32
	var date atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", date.Load().(string))
			w.WriteHeader(http.StatusTooManyRequests)

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv)
	start := clock.now()
	date.Store(start.Add(2 * time.Second).Format(http.TimeFormat))
	if err := client.Get(context.Background(), "/x", nil); err != nil {
		t.Fatal(err)
	}
	if got := clock.now().Sub(start); got != 2*time.Second || hits.Load() != 2 {
		t.Errorf("waited %s over %d requests, want 2s and 2", got, hits.Load())
	}
}

// A body that cannot be rebuilt is sent once: the 429 goes back to the
// caller as it is, Retry-After included.
func TestRetry_BodyThatCannotBeReplayed(t *testing.T) {
	var hits atomic.Int32
	var date atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", date.Load().(string))
		http.Error(w, "No more requests allowed", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, clock := newRetryTestClient(srv)
	date.Store(clock.now().Add(3 * time.Second).Format(http.TimeFormat))
	// Not a type http.NewRequest knows: no GetBody.
	stream := struct{ io.Reader }{strings.NewReader(`{"a":1}`)}
	err := client.Post(context.Background(), "/x", stream, nil)

	if hits.Load() != 1 || len(clock.sleeps) != 0 {
		t.Errorf("hits = %d, sleeps = %d; want 1 and 0", hits.Load(), len(clock.sleeps))
	}
	var rl *RateLimitError
	if errors.As(err, &rl) {
		t.Errorf("a request that is not replayed must not report retries: %v", err)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v, want the 429 as an HTTPError", err)
	}
	if httpErr.RetryAfter != 3*time.Second || !strings.Contains(httpErr.Body, "No more requests allowed") {
		t.Errorf("HTTPError = %+v, want Retry-After 3s and the body", httpErr)
	}
}
