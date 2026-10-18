package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"filippo.io/age"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
)

// What the long-running commands that serve datarooms share (`fs webdav
// serve`, `fs mount`): the checks made before they serve anything, and the
// watch over the login that stops them when it cannot be renewed.

// servePassphraseReader returns the key passphrase from the environment.
// No interactive prompt — identical to mcpPassphraseReader.
func servePassphraseReader() (string, error) {
	return config.RequireKeyPassphrase()
}

// serveStartupCheck runs the validation calls performed before the command
// serves anything (the WebDAV port bound, the filesystem mounted): a dataroom
// listing (auth + API reachability) and the key unlock, which bypasses the
// keyring so a wrong RETYC_KEY_PASSPHRASE fails at startup rather than at the
// first dataroom access. The unlocked identity is returned so the command
// never runs scrypt again.
func serveStartupCheck(
	ctx context.Context, client *api.Client, reader service.PassphraseReader,
) (*age.HybridIdentity, error) {
	if _, err := service.ListDatarooms(ctx, client); err != nil {
		return nil, fmt.Errorf("API connectivity check failed: %w", err)
	}
	identity, err := service.UnlockUserIdentity(ctx, client, reader)
	if err != nil {
		return nil, fmt.Errorf("key passphrase check failed: %w", err)
	}

	return identity, nil
}

// tokenKeepaliveInterval is how often the login is checked when nothing asks
// for a check.
const tokenKeepaliveInterval = 60 * time.Second

// authRefreshInterval is the least time between two refreshes of the access
// token forced by a 401: an API that answers 401 for another reason than the
// login costs one refresh per interval, not one per request.
const authRefreshInterval = 30 * time.Second

// authWatch is the keepalive of a login, which can also be asked to check it
// at once: a request the API answers 401 is the sign that the login may be
// gone, and waiting for the next tick would leave the command serving errors
// for up to a minute.
//
// A check asked for does not trust the access token the source holds: the
// API has just refused it, whatever its expiry says (a login revoked on the
// server). The source is told to refresh it (auth.RefreshingTokenSource.Expire),
// which fails when the login is gone, and otherwise costs one refresh.
type authWatch struct {
	src      oauth2.TokenSource
	interval time.Duration
	// asked holds at most one check asked for and not made yet.
	asked chan struct{}
	// refreshed is when a refresh was last forced. Only run reads it.
	refreshed time.Time
	now       func() time.Time
	// failing tells that the last check failed without the login being lost.
	// Only run reads it.
	failing bool
	// logf reports those failures, and their end.
	logf func(format string, args ...any)
	// machine is set for a machine account, whose revocation shows as a
	// token that keeps being obtained yet keeps being refused.
	machine bool
}

// machineRefusedChecks is how many checks asked for after a 401 may obtain a
// fresh token (a refresh forced by distrust, so at least authRefreshInterval
// apart) before the machine account is taken as revoked: the API refused the
// requests signed with the tokens before, which takes over a minute.
const machineRefusedChecks = 3

func newAuthWatch(src oauth2.TokenSource) *authWatch {
	return &authWatch{
		src: src, interval: tokenKeepaliveInterval, asked: make(chan struct{}, 1), now: time.Now,
		machine: config.MachineMode(),
		logf:    func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) },
	}
}

// distrust makes the next check refresh the access token, when the source
// can be told to and none was forced for authRefreshInterval. It tells
// whether the token was expired: only then does the next check obtain a
// fresh one.
func (w *authWatch) distrust() bool {
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

// run checks the login every interval, and whenever checkNow asks, until ctx
// ends or a check finds the login lost for good (auth.IsPermanent: no refresh
// token, or one the identity provider refuses): onFail is then called with
// the failure, once.
//
// Any other failure (the identity provider unreachable, answering a 5xx or
// too slowly) says nothing of the login: the command keeps serving and the
// check is made again at the next tick, or the next time one is asked for.
// It is reported once, as is its end, not at every tick it lasts.
func (w *authWatch) run(ctx context.Context, onFail func(error)) {
	ticker := time.NewTicker(w.interval)
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
				onFail(fmt.Errorf("the API keeps refusing the token of the machine account: %w", auth.ErrMachineRevoked))

				return
			}
		}
		switch {
		case err == nil:
			if w.failing {
				w.failing = false
				w.logf("The login is checked again: the access token is valid.")
			}
		case auth.IsPermanent(err):
			onFail(err)

			return
		case !w.failing:
			w.failing = true
			w.logf("Warning: the login could not be checked, which is tried again every %s: %v", w.interval, err)
		}
	}
}

// checkNow asks run for a check of the login, without waiting for it. Several
// calls before the check is made are one check.
func (w *authWatch) checkNow() {
	select {
	case w.asked <- struct{}{}:
	default:
	}
}

// roundTripper wraps the transport of the API client: a request the API
// answers 401, or that the token source could not sign because the login is
// gone, asks for a check of the login at once. The answer is passed on as it
// is.
func (w *authWatch) roundTripper(base http.RoundTripper) http.RoundTripper {
	return authWatchTransport{base: base, watch: w}
}

type authWatchTransport struct {
	base  http.RoundTripper
	watch *authWatch
}

func (t authWatchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	switch {
	case err != nil:
		// A login lost for good (refused refresh, machine account refused
		// by the token endpoint) is checked at once, not at the next tick.
		if auth.IsPermanent(err) {
			t.watch.checkNow()
		}
	case resp.StatusCode == http.StatusUnauthorized:
		t.watch.checkNow()
	}

	return resp, err
}

// apiTransportWatching is the transport of `fs mount`: tracing outermost
// (one CLIENT span per round trip, traceparent injected), Prometheus metrics
// inside it, around the wrapper that reports a 401 to watch. `fs webdav
// serve` uses the wrapper alone (webdavTransportWatching); the other
// commands use the bare transport.
func apiTransportWatching(watch *authWatch) api.Option {
	return api.WrapTransport(func(base http.RoundTripper) http.RoundTripper {
		return telemetry.RoundTripper(metrics.RoundTripper(watch.roundTripper(base)))
	})
}

// webdavTransportWatching is the transport of `fs webdav serve`: the wrapper
// that reports a 401 to watch, without the tracing and metrics of the mount.
func webdavTransportWatching(watch *authWatch) api.Option {
	return api.WrapTransport(watch.roundTripper)
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

// authLostAdvice is what to do once the login of a serving command is lost
// for good, then restart (e.g. "mount again"): log in again, or, for a
// machine account, which has no login to renew, have it enabled again.
func authLostAdvice(restart string) string {
	if config.MachineMode() {
		return "The machine account was refused (disabled or deleted?): ask an organization admin to enable it again " +
			"(`retyc machine enable`), or re-enroll it if it was deleted, and " + restart
	}

	return "Run `retyc auth login` and " + restart
}

// requireIdentitySource fails fast, before any network call, when the key that
// unlocks the account is not available: the machine configuration in machine
// mode (no passphrase exists there), the key passphrase otherwise.
func requireIdentitySource() error {
	if config.MachineMode() {
		_, err := config.LoadMachine()

		return err
	}
	if config.KeyPassphrase() == "" {
		return config.ErrNoKeyPassphrase
	}

	return nil
}
