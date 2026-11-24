package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/core/diag"
	"github.com/retyc/retyc-cli/core/metrics"
)

// The watch over the login of a long-running server (`fs webdav serve`,
// `fs mount`, or a program serving datarooms): it keeps the access token warm
// and tells the server when the login is lost for good.

// TokenKeepaliveInterval is how often the login is checked when nothing asks
// for a check.
const TokenKeepaliveInterval = 60 * time.Second

// authRefreshInterval is the least time between two refreshes of the access
// token forced by a 401: an API that answers 401 for another reason than the
// login costs one refresh per interval, not one per request.
const authRefreshInterval = 30 * time.Second

// Watch is the keepalive of a login, which can also be asked to check it
// at once: a request the API answers 401 is the sign that the login may be
// gone, and waiting for the next tick would leave the command serving errors
// for up to a minute.
//
// A check asked for does not trust the access token the source holds: the
// API has just refused it, whatever its expiry says (a login revoked on the
// server). The source is told to refresh it (RefreshingTokenSource.Expire),
// which fails when the login is gone, and otherwise costs one refresh.
type Watch struct {
	src oauth2.TokenSource
	// Interval is how often the login is checked when nothing asks for a
	// check (TokenKeepaliveInterval, also when not positive). Set it before
	// Run.
	Interval time.Duration
	// asked holds at most one check asked for and not made yet.
	asked chan struct{}
	// refreshed is when a refresh was last forced. Only run reads it.
	refreshed time.Time
	now       func() time.Time
	// failing tells that the last check failed without the login being lost.
	// Only run reads it.
	failing bool
	// Logf reports those failures, and their end; diag output by default,
	// also when nil. Set it before Run.
	Logf func(format string, args ...any)
	// machine is set for a machine account, whose revocation shows as a
	// token that keeps being obtained yet keeps being refused.
	machine bool
}

// machineRefusedChecks is how many checks asked for after a 401 may obtain a
// fresh token (a refresh forced by distrust, so at least authRefreshInterval
// apart) before the machine account is taken as revoked: the API refused the
// requests signed with the tokens before, which takes over a minute.
const machineRefusedChecks = 3

// NewWatch returns the watch of the login src gives tokens for. machine is
// set for a machine account (config.MachineMode in the CLI).
func NewWatch(src oauth2.TokenSource, machine bool) *Watch {
	return &Watch{
		src: src, Interval: TokenKeepaliveInterval, asked: make(chan struct{}, 1), now: time.Now,
		machine: machine,
		Logf:    diagLogf,
	}
}

// diagLogf is the default Logf of a Watch: a line on the diag output.
func diagLogf(format string, args ...any) { diag.Printf(format+"\n", args...) }

// distrust makes the next check refresh the access token, when the source
// can be told to and none was forced for authRefreshInterval. It tells
// whether the token was expired: only then does the next check obtain a
// fresh one.
func (w *Watch) distrust() bool {
	src, ok := w.src.(interface{ Expire() })
	if !ok {
		return false
	}
	if now := w.now(); w.refreshed.IsZero() || now.Sub(w.refreshed) >= authRefreshInterval {
		w.refreshed = now
		src.Expire()

		return true
	}

	return false
}

// Run checks the login every Interval, and whenever CheckNow asks, until ctx
// ends or a check finds the login lost for good (IsPermanent: no refresh
// token, or one the identity provider refuses): onFail is then called with
// the failure, once.
//
// Any other failure (the identity provider unreachable, answering a 5xx or
// too slowly) says nothing of the login: the command keeps serving and the
// check is made again at the next tick, or the next time one is asked for.
// It is reported once, as is its end, not at every tick it lasts.
func (w *Watch) Run(ctx context.Context, onFail func(error)) {
	// Interval and Logf are exported: an unset or zero value falls back to
	// the defaults of NewWatch rather than panicking.
	interval := w.Interval
	if interval <= 0 {
		interval = TokenKeepaliveInterval
	}
	logf := w.Logf
	if logf == nil {
		logf = diagLogf
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// refused counts the checks asked for after a 401 that obtained a fresh
	// token, the old one having been expired by distrust (machine mode only):
	// a check that reuses the token refreshed less than authRefreshInterval
	// ago says nothing new. A tick with no 401 since the previous one starts
	// the count again.
	refused := 0
	askedSinceTick := false
	for {
		forced := false
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !askedSinceTick {
				refused = 0
			}
			askedSinceTick = false
		case <-w.asked:
			askedSinceTick = true
			forced = w.distrust()
		}
		err := checkToken(w.src)
		if w.machine {
			if forced && err == nil {
				refused++
			}
			if refused >= machineRefusedChecks {
				onFail(fmt.Errorf("the API keeps refusing the token of the machine account: %w", ErrMachineRevoked))

				return
			}
		}
		switch {
		case err == nil:
			if w.failing {
				w.failing = false
				logf("The login is checked again: the access token is valid.")
			}
		case IsPermanent(err):
			onFail(err)

			return
		case !w.failing:
			w.failing = true
			logf("Warning: the login could not be checked, which is tried again every %s: %v", interval, err)
		}
	}
}

// CheckNow asks Run for a check of the login, without waiting for it. Several
// calls before the check is made are one check.
func (w *Watch) CheckNow() {
	select {
	case w.asked <- struct{}{}:
	default:
	}
}

// RoundTripper wraps the transport of the API client: a request the API
// answers 401, or that the token source could not sign because the login is
// gone, asks for a check of the login at once. The answer is passed on as it
// is.
func (w *Watch) RoundTripper(base http.RoundTripper) http.RoundTripper {
	return watchTransport{base: base, watch: w}
}

type watchTransport struct {
	base  http.RoundTripper
	watch *Watch
}

func (t watchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	switch {
	case err != nil:
		// A login lost for good (refused refresh, machine account refused
		// by the token endpoint) is checked at once, not at the next tick.
		if IsPermanent(err) {
			t.watch.CheckNow()
		}
	case resp.StatusCode == http.StatusUnauthorized:
		t.watch.CheckNow()
	}

	return resp, err
}

// checkToken asks src for a valid token (refreshing it when needed) and feeds
// the retycfs_token_* metrics: the result counter and the seconds left on
// the access token, 0 when unknown.
func checkToken(src oauth2.TokenSource) error {
	tok, err := src.Token()
	if err != nil {
		metrics.TokenRefreshes.WithLabelValues("error").Inc()
		metrics.TokenExpiry.Set(0)

		return err
	}
	metrics.TokenRefreshes.WithLabelValues("ok").Inc()
	if tok.Expiry.IsZero() {
		metrics.TokenExpiry.Set(0)
	} else {
		metrics.TokenExpiry.Set(max(time.Until(tok.Expiry).Seconds(), 0))
	}

	return nil
}
