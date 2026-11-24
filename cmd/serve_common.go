package cmd

import (
	"context"
	"fmt"
	"net/http"

	"filippo.io/age"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/auth"
	"github.com/retyc/retyc-cli/core/config"
	"github.com/retyc/retyc-cli/core/keyring"
	"github.com/retyc/retyc-cli/core/metrics"
	"github.com/retyc/retyc-cli/core/service"
	"github.com/retyc/retyc-cli/core/telemetry"
)

// What the long-running commands that serve datarooms share (`fs webdav
// serve`, `fs mount`): the checks made before they serve anything, and the
// watch over the login that stops them when it cannot be renewed.

// serveStartupCheck runs the validation calls performed before the command
// serves anything (the WebDAV port bound, the filesystem mounted): a dataroom
// listing (auth + API reachability) and the key unlock. The unlocked identity
// is returned so the command never runs scrypt again.
//
// A passphrase set in the environment (the unattended case: container,
// supervisor) is checked without the keyring, so a wrong RETYC_KEY_PASSPHRASE
// fails at startup rather than being masked by a cached identity. Without
// it, the key is unlocked as by the one-shot commands: from the keyring, else
// with the passphrase read by reader (a prompt on the terminal), then cached.
func serveStartupCheck(
	ctx context.Context, cfg *config.Config, client *api.Client, reader service.PassphraseReader,
) (*age.HybridIdentity, error) {
	if _, err := service.ListDatarooms(ctx, client); err != nil {
		return nil, fmt.Errorf("API connectivity check failed: %w", err)
	}
	var identity *age.HybridIdentity
	var err error
	if config.MachineMode() || config.KeyPassphrase() != "" {
		identity, err = service.UnlockUserIdentity(ctx, client, reader)
	} else {
		identity, err = service.ResolveActiveUserIdentity(ctx, cfg, client, reader)
	}
	if err != nil {
		return nil, fmt.Errorf("key passphrase check failed: %w", err)
	}

	return identity, nil
}

// newAuthWatch returns the watch of the login of a serving command.
func newAuthWatch(src oauth2.TokenSource) *auth.Watch {
	return auth.NewWatch(src, config.MachineMode())
}

// apiTransportWatching is the transport of `fs mount`: tracing outermost
// (one CLIENT span per round trip, traceparent injected), Prometheus metrics
// inside it, around the wrapper that reports a 401 to watch. `fs webdav
// serve` uses the wrapper alone (webdavTransportWatching); the other
// commands use the bare transport.
func apiTransportWatching(watch *auth.Watch) api.Option {
	return api.WrapTransport(func(base http.RoundTripper) http.RoundTripper {
		return telemetry.RoundTripper(metrics.RoundTripper(watch.RoundTripper(base)))
	})
}

// webdavTransportWatching is the transport of `fs webdav serve`: the wrapper
// that reports a 401 to watch, without the tracing and metrics of the mount.
func webdavTransportWatching(watch *auth.Watch) api.Option {
	return api.WrapTransport(watch.RoundTripper)
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
// unlocks the account cannot be had: the machine configuration in machine
// mode (no passphrase exists there); otherwise RETYC_KEY_PASSPHRASE, an
// identity cached in the keyring, or a terminal to prompt on. Without any of
// them the command stops with ErrNoKeyPassphrase (exit code 78), as before
// the prompt existed: an unattended run is not changed. The check is
// best-effort: a cached identity can expire before it is read (keyring.ttl)
// or belong to another key than the active one; the command then stops with
// the same error, still before serving.
func requireIdentitySource(cfg *config.Config) error {
	if config.MachineMode() {
		_, err := config.LoadMachine()

		return err
	}
	if config.KeyPassphrase() != "" || stdinIsTerminal() {
		return nil
	}
	if cfg.Keyring.Enabled && keyringHas() {
		return nil
	}

	return fmt.Errorf("no TTY detected and no identity cached in the keyring: %w", config.ErrNoKeyPassphrase)
}

// keyringHas reports whether the keyring caches an identity, of any key (the
// active one is not known yet). A variable so
// that tests do not depend on the keyring of the session running them.
var keyringHas = keyring.HasAny
