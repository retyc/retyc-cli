package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/retyc/retyc-cli/pkg/api"
	"github.com/retyc/retyc-cli/pkg/config"
	"github.com/retyc/retyc-cli/pkg/dav"
	"github.com/retyc/retyc-cli/pkg/service"
	"github.com/retyc/retyc-cli/pkg/ui"
	"github.com/retyc/retyc-cli/pkg/vfs"
)

// `retyc fs webdav serve`: the cobra command over the WebDAV adapter of
// package dav.

// bindUnsafeWrite binds --unsafe-write to api.unsafe_write, which config.Load
// then reads: call it before. Like the other flags, bound in RunE, never in
// init().
func bindUnsafeWrite(flags *pflag.FlagSet) {
	_ = viper.BindPFlag("api.unsafe_write", flags.Lookup("unsafe-write"))
}

// resolveWebdavAddr returns the host:port to bind, with the usual precedence
// (flag > env > config file > default). Binding the flag to the viper key
// here rather than in init() keeps the binding alive across the viper.Reset()
// that the config tests perform. A value without a port ("0.0.0.0", the form --addr took
// before it included the port) is an error.
func resolveWebdavAddr(flags *pflag.FlagSet) (string, error) {
	_ = viper.BindPFlag("webdav.addr", flags.Lookup("addr"))
	addr := viper.GetString("webdav.addr")
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return "", fmt.Errorf("--addr %q: expected host:port, e.g. 127.0.0.1:8888", addr)
	}

	return addr, nil
}

var webdavCmd = &cobra.Command{
	Use:   "webdav",
	Short: "WebDAV server integration",
}

var webdavServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a local WebDAV server exposing your storage spaces",
	Long: `Start a local WebDAV server on localhost that exposes all your RETYC storage spaces.

Storage spaces are exposed under the /spaces folder; other element types may be
added at the root in the future.

Key passphrase: prompted on the terminal unless the key is in the keyring cache;
without a terminal, set RETYC_KEY_PASSPHRASE (env var).

Authentication: pass --auth to require HTTP Basic credentials (user "retyc").
The password is read from RETYC_WEBDAV_PASSWORD, or generated randomly and
printed at startup when the variable is unset.

Example:
  RETYC_KEY_PASSPHRASE=your-passphrase retyc fs webdav serve --addr 127.0.0.1:8888 --auth
  # Then mount http://localhost:8888 in your WebDAV client
  # Storage spaces appear under /spaces`,
	RunE: func(cmd *cobra.Command, args []string) error {
		initCtx := cmd.Context()

		// Fail-fast: a malformed address would otherwise only surface once the
		// token, the API and the key passphrase have all been checked.
		addr, err := resolveWebdavAddr(cmd.Flags())
		if err != nil {
			return err
		}

		bindUnsafeWrite(cmd.Flags())
		resolveCacheFlags(cmd.Flags())
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		// Fail-fast: the key (passphrase, keyring or a terminal to prompt on,
		// or the machine configuration) must be at hand before any network call.
		if err := requireIdentitySource(cfg); err != nil {
			return err
		}
		tokSrc, err := mustGetToken(initCtx, cfg)
		if err != nil {
			return err
		}
		// A request the API answers 401 has the login checked at once, as in
		// `fs mount`: a lost login (or a refused machine account) stops the
		// server without waiting for the next tick of the keepalive.
		watch := newAuthWatch(tokSrc)
		client := api.New(cfg.API.BaseURL, cliUserAgent(), tokSrc, insecure, debug,
			webdavTransportWatching(watch), apiRetry(cfg), api.WithUnsafeWrite(cfg.API.UnsafeWrite))

		// Fail-fast before binding the port: auth + API reachability, then the
		// key itself (a wrong passphrase would otherwise only surface on the
		// first dataroom access). The unlocked identity is kept for the whole run.
		identity, err := serveStartupCheck(initCtx, cfg, client, readKeyPassphrase)
		if err != nil {
			return err
		}

		store, err := newMetaStore(initCtx, cfg, cfg.Cache.MaxStale)
		if err != nil {
			return err
		}
		server := dav.New(client, dav.Options{
			VFS: vfs.Options{
				TTL:               cfg.Cache.TTL,
				MaxStale:          cfg.Cache.MaxStale,
				NegativeTTL:       cfg.Cache.NegativeTTL,
				Store:             store,
				KeepSealed:        store != nil && cfg.Cache.Redis.HighConfidentiality,
				Identity:          identity,
				ListConcurrency:   service.Concurrency().List,
				UploadConcurrency: service.Concurrency().Upload,
			},
			LogRequest: func(r *http.Request, err error) {
				// URL.Path is percent-decoded: "%1b" arrives as a raw ESC.
				if err != nil {
					fmt.Fprintf(os.Stderr, "webdav: %s %s: %s\n",
						r.Method, ui.Escape(r.URL.Path), ui.EscapeLines(err.Error()))

					return
				}
				fmt.Fprintf(os.Stderr, "webdav: %s %s\n", r.Method, ui.Escape(r.URL.Path))
			},
		})
		// Runs once the server has stopped accepting requests, on every way
		// out of this function.
		defer func() { _ = server.Close() }()

		authEnabled, _ := cmd.Flags().GetBool("auth")
		var rootHandler http.Handler = server
		if authEnabled {
			password := config.WebdavPassword()
			if password == "" {
				password, err = dav.GeneratePassword()
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "WebDAV credentials: user %q, password %q (generated for this session)\n",
					dav.AuthUser, password)
			} else {
				fmt.Fprintf(os.Stderr, "WebDAV auth enabled: user %q, password from RETYC_WEBDAV_PASSWORD\n",
					dav.AuthUser)
			}
			rootHandler = dav.BasicAuth(rootHandler, dav.AuthUser, password)
		} else if !dav.IsLoopbackAddr(addr) {
			fmt.Fprintf(os.Stderr,
				"WARNING: binding to %s without authentication exposes the contents of all storage spaces "+
					"in cleartext to the network; consider --auth\n", addr)
		}
		srv := &http.Server{
			Addr:              addr,
			Handler:           rootHandler,
			ReadHeaderTimeout: 30 * time.Second,
		}
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// Single shutdown path shared by SIGINT/SIGTERM and auth expiry, so the
		// server always drains gracefully instead of being killed mid-request.
		shutdown := dav.NewShutdown(srv, cancel, dav.DrainTimeout)

		// Renew the mirrored server locks while the WebDAV locks stand, and
		// release them on shutdown. locksDone closes once they are released:
		// the command does not return before (see dav.ServeUntilDrained).
		locksDone := make(chan struct{})
		go func() {
			defer close(locksDone)
			server.RunLocks(ctx)
		}()

		authErrCh := make(chan error, 1)
		// Keep the access token warm; when the login is lost for good, shut
		// the server down gracefully (in-flight uploads, orphaned-node cleanup
		// and temp-dir removal all run).
		go watch.Run(ctx, func(err error) {
			select {
			case authErrCh <- err:
			default:
			}
			shutdown()
		})

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigCh)
		go func() {
			select {
			case <-sigCh:
				shutdown()
			case <-ctx.Done():
			}
		}()

		// Bind explicitly rather than ListenAndServe so a port in use fails
		// before anything is served.
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			shutdown()
			<-locksDone

			return fmt.Errorf("WebDAV server: %w", err)
		}
		fmt.Fprintf(os.Stderr, "WebDAV server listening on http://%s\n", ln.Addr())

		if err := dav.ServeUntilDrained(srv, ln, shutdown, locksDone); err != nil {
			return fmt.Errorf("WebDAV server: %w", err)
		}

		// Surface an auth-expiry shutdown as a non-zero exit with a clear message.
		select {
		case err := <-authErrCh:
			return fmt.Errorf("authentication expired: %w\n%s", err, authLostAdvice("restart the WebDAV server"))
		default:
		}

		return nil
	},
}

func init() {
	webdavServeCmd.Flags().String("addr", "127.0.0.1:8888", "host:port to bind")
	webdavServeCmd.Flags().Bool("unsafe-write", false,
		"let the API acknowledge uploads before they are stored (faster; a failed background store is not reported)")
	addCacheFlags(webdavServeCmd, true)
	webdavServeCmd.Flags().Bool("auth", false,
		"require HTTP Basic auth (password from RETYC_WEBDAV_PASSWORD or generated)")
	webdavCmd.AddCommand(webdavServeCmd)
	fsCmd.AddCommand(webdavCmd)
}
