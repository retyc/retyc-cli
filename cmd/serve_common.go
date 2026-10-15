package cmd

import (
	"context"
	"errors"
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

// tokenKeepalive pings tokenSource every 60s to keep the access token warm.
// When the login is lost for good (see authWatch.run) it invokes onFail(err)
// and returns, letting the caller shut the server down gracefully (so
// in-flight uploads, orphaned-node cleanup, and temp-dir removal all run). A
// check that fails for another reason is tried again. Stops when ctx is
// cancelled.
func tokenKeepalive(ctx context.Context, src oauth2.TokenSource, onFail func(error)) {
	newAuthWatch(src).run(ctx, onFail)
}

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
}

func newAuthWatch(src oauth2.TokenSource) *authWatch {
	return &authWatch{
		src: src, interval: tokenKeepaliveInterval, asked: make(chan struct{}, 1), now: time.Now,
		logf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) },
	}
}

// distrust makes the next check refresh the access token, when the source
// can be told to and none was forced for authRefreshInterval.
func (w *authWatch) distrust() {
	src, ok := w.src.(interface{ Expire() })
	if !ok {
		return
	}
	if now := w.now(); w.refreshed.IsZero() || now.Sub(w.refreshed) >= authRefreshInterval {
		w.refreshed = now
		src.Expire()
	}
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-w.asked:
			w.distrust()
		}
		err := checkToken(w.src)
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
		if errors.Is(err, auth.ErrNoToken) || errors.Is(err, auth.ErrNoRefreshToken) {
			t.watch.checkNow()
		}
	case resp.StatusCode == http.StatusUnauthorized:
		t.watch.checkNow()
	}

	return resp, err
}

// apiTransportWatching is apiTransport for a command that watches its login:
// the same wrappers, around the one that reports a 401 to watch.
func apiTransportWatching(watch *authWatch) api.Option {
	return api.WrapTransport(func(base http.RoundTripper) http.RoundTripper {
		return telemetry.RoundTripper(metrics.RoundTripper(watch.roundTripper(base)))
	})
}

// checkToken asks src for a valid token (refreshing it when needed) and feeds
// the retyc_cli_token_* metrics: the result counter and the seconds left on
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
