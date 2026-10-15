package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
)

// Pauses between two attempts at a request answered 429 without a
// Retry-After header: retryBackoffBase doubled at each attempt, capped at
// retryBackoffMax, with full jitter.
const (
	retryBackoffBase = 200 * time.Millisecond
	retryBackoffMax  = 5 * time.Second
)

// rateLimitBodyMax bounds what is kept of a 429 body; the rest is drained.
const rateLimitBodyMax = 4 << 10

// retryAfterMax caps a Retry-After given in seconds: a larger value is read
// as this one rather than overflowing a time.Duration.
const retryAfterMax = 24 * time.Hour

// RateLimitError is the error of a request the API kept answering 429 until
// its retry budget (api.retry.max_wait, api.retry.max_attempts) ran out. It
// wraps the last refusal, so errors.Is(err, ErrRateLimited) matches and
// RetryAfter reads the pause the server last asked for.
type RateLimitError struct {
	// Waited is the time the request spent held back, all attempts included.
	Waited time.Duration
	// Attempts is the number of times the request was sent; 0 for a request
	// that spent its whole budget behind the refusals of other requests.
	Attempts int
	// Last is the refusal of the final attempt or, for a request given up
	// while waiting at the gate, the refusal that last closed it.
	Last *HTTPError
}

func (e *RateLimitError) Error() string {
	waited := e.Waited.Round(100 * time.Millisecond)
	switch e.Attempts {
	case 0:
		return fmt.Sprintf("API rate limit, gave up after %s without sending the request: %s", waited, e.Last)
	case 1:
		return fmt.Sprintf("API rate limit, gave up after %s (1 attempt): %s", waited, e.Last)
	default:
		return fmt.Sprintf("API rate limit, gave up after %s (%d attempts): %s", waited, e.Attempts, e.Last)
	}
}

// Unwrap returns the last refusal.
func (e *RateLimitError) Unwrap() error { return e.Last }

// RetryAfter returns the pause the server asked for in the 429 found in err's
// chain, or 0 when err is not a rate-limit refusal or carried no Retry-After.
func RetryAfter(err error) time.Duration {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusTooManyRequests {
		return httpErr.RetryAfter
	}

	return 0
}

// parseRetryAfter reads a Retry-After header: whole seconds or an HTTP date
// (RFC 9110 §10.2.3). An absent, malformed or past value is 0; a number of
// seconds above retryAfterMax, however large, is retryAfterMax.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if isDigits(value) {
		secs, err := strconv.ParseInt(value, 10, 64)
		if err != nil || secs > int64(retryAfterMax/time.Second) {
			// Only digits: an error here is a value out of range.
			return retryAfterMax
		}

		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := at.Sub(now); d > 0 {
			return d
		}
	}

	return 0
}

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return s != ""
}

// unwrapRateLimit strips the *url.Error http.Client puts around a
// RateLimitError, so the message reads "API rate limit, ..." without the
// method and URL in front. Any other error is returned as is.
func unwrapRateLimit(err error) error {
	var rl *RateLimitError
	if errors.As(err, &rl) {
		return rl
	}

	return err
}

// retryTransport replays a request the API answered 429 (the rate limit of
// the ingress, 100 requests/s per source IP). A refused request never reached
// the API, so replaying it is safe whatever its method.
//
// It is the outermost RoundTripper of the client, outside the wrappers of
// WrapTransport: every attempt is a request counted by the metrics and a
// CLIENT span of its own.
type retryTransport struct {
	base        http.RoundTripper
	gate        *throttleGate
	maxWait     time.Duration
	maxAttempts int
	debug       bool
	// jitter picks the pause of a backoff step in (0, d]. Replaced in tests.
	jitter func(d time.Duration) time.Duration
}

func newRetryTransport(base http.RoundTripper, maxWait time.Duration, maxAttempts int, debug bool) *retryTransport {
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	return &retryTransport{
		base:        base,
		gate:        newThrottleGate(),
		maxWait:     maxWait,
		maxAttempts: maxAttempts,
		debug:       debug,
		jitter:      fullJitter,
	}
}

// fullJitter returns a random duration in (0, d].
func fullJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}

	return time.Duration(rand.Int64N(int64(d))) + 1 //nolint:gosec // G404: retry jitter, not a secret
}

// backoff is the pause before the attempt that follows the attempt-th one
// (1-based) when the server gave no Retry-After.
func (t *retryTransport) backoff(attempt int) time.Duration {
	d := retryBackoffMax
	if shift := attempt - 1; shift < 10 && retryBackoffBase<<shift < retryBackoffMax {
		d = retryBackoffBase << shift
	}

	return t.jitter(d)
}

// replayable reports whether req can be sent again: no body, or a body
// http.NewRequest knows how to rebuild (every request of the Client).
func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// RoundTrip sends req once the gate is open, and again after each 429 until
// the retry budget is spent. The time spent held back, at the gate or for the
// request's own Retry-After, never exceeds maxWait.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	var waited time.Duration
	// counted is set once the request is counted as held back in an episode.
	counted := false
	for attempt := 1; ; attempt++ {
		held, refusal, err := t.gate.wait(ctx, attempt-1, t.maxWait-waited, &counted)
		waited += held
		if err != nil || refusal != nil {
			// A RoundTripper closes the body even when it fails; the body of
			// an earlier attempt was closed by the transport that sent it.
			if attempt == 1 && req.Body != nil {
				_ = req.Body.Close()
			}
			if err != nil {
				return nil, err
			}

			// The gate stays closed for longer than this request may wait.
			return nil, t.giveUp(req, waited, attempt-1, refusal)
		}

		out := req
		if attempt > 1 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("rebuilding the request body: %w", err)
			}
			out = req.Clone(ctx)
			out.Body = body
		}

		resp, err := t.base.RoundTrip(out)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests {
			t.gate.settle()

			return resp, err
		}
		if !replayable(req) {
			// Left to the caller, which turns it into an HTTPError.
			return resp, nil
		}

		last := &HTTPError{
			Status:     http.StatusTooManyRequests,
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), t.gate.now()),
		}
		// Drain and close before waiting, so the connection is free again.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, rateLimitBodyMax))
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		last.Body = string(body)

		pause := last.RetryAfter
		if pause <= 0 {
			pause = t.backoff(attempt)
		}
		// The gate is closed for the other requests too, even when this one
		// is not replayed, but never for longer than a request may wait.
		closed := t.gate.throttle(min(pause, t.maxWait), last)
		if attempt >= t.maxAttempts || waited+max(pause, closed) > t.maxWait {
			return nil, t.giveUp(req, waited, attempt, last)
		}
		if t.debug {
			fmt.Fprintf(os.Stderr, "< 429 Too Many Requests, attempt %d, retrying in %s\n",
				attempt, closed.Round(time.Millisecond))
		}
	}
}

// giveUp builds the error of a request whose retry budget is spent.
func (t *retryTransport) giveUp(req *http.Request, waited time.Duration, attempts int, last *HTTPError) error {
	metrics.APIRateLimited.WithLabelValues(req.Method).Inc()
	if t.debug {
		fmt.Fprintf(os.Stderr, "< 429 Too Many Requests, giving up after %s and %d attempt(s)\n",
			waited.Round(time.Millisecond), attempts)
	}

	return &RateLimitError{Waited: waited, Attempts: attempts, Last: last}
}

// throttleGate holds back every request of a client while the API is rate
// limiting it. The first 429 closes it until notBefore; requests, new or
// replayed, wait for it to open. Without it, the requests in flight are
// refused one after the other, each waits its own Retry-After and all leave
// together a second later; with it the client goes quiet, the bucket of the
// ingress refills, and the requests leave as they come.
//
// An episode runs from the 429 that closes the gate to the moment it opens
// again for good; it is logged as one line, by the first answer that is not
// a 429 once the gate is open. A process that exits before such an answer
// (a one-shot command whose last request is given up) logs nothing: its
// error message says it.
type throttleGate struct {
	// now, sleepUntil and logf are replaced in tests.
	now        func() time.Time
	sleepUntil func(ctx context.Context, at time.Time) error
	logf       func(format string, args ...any)

	mu        sync.Mutex
	notBefore time.Time
	// last is the refusal that last closed or pushed the gate.
	last *HTTPError
	// Episode state: held counts requests, each one once whatever the
	// number of times it waited.
	active   bool
	start    time.Time
	refusals int
	held     int
}

func newThrottleGate() *throttleGate {
	g := &throttleGate{
		now: time.Now,
		logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	}
	g.sleepUntil = func(ctx context.Context, at time.Time) error {
		timer := time.NewTimer(at.Sub(g.now()))
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return g
}

// wait blocks until the gate is open and returns the time spent. attempt is
// the number of times the request was already sent, for the trace event;
// counted tells whether the request is already counted in the episode.
//
// budget is what the request may still wait. The gate can be pushed by the
// refusal of another request while this one waits, so the budget is checked
// against each deadline: as soon as the gate stays closed for longer than
// what is left, wait returns the refusal that closed it, without sleeping.
// A done context ends the wait with its error.
func (g *throttleGate) wait(
	ctx context.Context, attempt int, budget time.Duration, counted *bool,
) (time.Duration, *HTTPError, error) {
	var total time.Duration
	waited := false
	observe := func() {
		if waited {
			metrics.APIThrottleWait.Observe(total.Seconds())
		}
	}
	for {
		g.mu.Lock()
		now := g.now()
		until := g.notBefore
		if !now.Before(until) {
			g.mu.Unlock()
			observe()

			return total, nil, nil
		}
		if until.Sub(now) > budget-total {
			refusal := g.last
			g.mu.Unlock()
			observe()
			if refusal == nil {
				refusal = &HTTPError{Status: http.StatusTooManyRequests}
			}

			return total, refusal, nil
		}
		if !*counted {
			*counted = true
			g.held++
		}
		g.mu.Unlock()

		waited = true
		telemetry.ThrottleEvent(ctx, attempt, until.Sub(now))
		err := g.sleepUntil(ctx, until)
		total += g.now().Sub(now)
		if err != nil {
			observe()

			return total, nil, err
		}
	}
}

// throttle records a 429 (last) asking for pause and returns how long the
// gate stays closed from now. An open gate closes for pause, which starts an
// episode unless one is still running; a gate already closed is pushed to
// now+pause at most, never further than the Retry-After just received.
func (g *throttleGate) throttle(pause time.Duration, last *HTTPError) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if !g.active {
		g.active = true
		g.start = now
		g.refusals, g.held = 0, 0
		metrics.APIThrottleEpisodes.Inc()
	}
	g.refusals++
	if at := now.Add(pause); at.After(g.notBefore) {
		g.notBefore = at
		g.last = last
	}

	return g.notBefore.Sub(now)
}

// settle is called with every answer that is not a 429. An answer received
// while the gate is closed belongs to a request sent before the refusal and
// says nothing; once the gate has opened again, it ends the episode. The
// line logs the window the gate was closed, start to notBefore, not the time
// of this answer, which may come long after on an idle client.
func (g *throttleGate) settle() {
	g.mu.Lock()
	if !g.active || g.now().Before(g.notBefore) {
		g.mu.Unlock()

		return
	}
	start, end, refusals, held := g.start, g.notBefore, g.refusals, g.held
	g.active = false
	g.mu.Unlock()

	g.logf("API rate limit: throttled from %s to %s (%s), %d refusal(s), %d request(s) held back",
		start.Format(time.TimeOnly), end.Format(time.TimeOnly),
		end.Sub(start).Round(10*time.Millisecond), refusals, held)
}

// WithRetry sets the budget of a request the API answers 429: the total time
// it may be held back and the number of times it is sent. With 1 the request
// is not replayed, but its refusal still closes the gate: the next requests
// of the client wait for the pause the server asked for. The defaults are those of api.retry.max_wait and
// api.retry.max_attempts.
func WithRetry(maxWait time.Duration, maxAttempts int) Option {
	return func(o *clientOptions) { o.retryMaxWait, o.retryMaxAttempts = maxWait, maxAttempts }
}

// Defaults of a Client built without WithRetry.
const (
	defaultRetryMaxWait     = config.DefaultRetryMaxWait
	defaultRetryMaxAttempts = config.DefaultRetryMaxAttempts
)
