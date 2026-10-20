//go:build linux

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/retycfs"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// fuseDevice is what a FUSE mount is made through.
const fuseDevice = "/dev/fuse"

// checkMountpoint refuses a mount point the mount would fail on, or hide the
// content of: it must exist, be a folder, and be empty.
func checkMountpoint(path string) error {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("mount point %s does not exist: create it first (mkdir -p)", path)
	case err != nil:
		return fmt.Errorf("mount point: %w", err)
	case !info.IsDir():
		return fmt.Errorf("mount point %s is not a directory", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("mount point: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("mount point %s is not empty (is something mounted there already?)", path)
	}

	return nil
}

// checkFUSE reports why a FUSE filesystem cannot be mounted here, before
// anything is asked of the API: no device, or no helper to mount with for a
// user who is not root.
func checkFUSE(device string) error {
	f, err := os.OpenFile(device, os.O_RDWR, 0) //nolint:gosec // G304: the FUSE device
	if err != nil {
		return fmt.Errorf("cannot open %s: %w\n"+
			"FUSE must be available: load the kernel module (modprobe fuse), "+
			"or give the container the device (--device %s) and CAP_SYS_ADMIN", device, err, device)
	}
	_ = f.Close()
	if os.Geteuid() == 0 {
		// Root mounts with mount(2); the helper is only the fallback.
		return nil
	}
	for _, helper := range []string{"fusermount3", "fusermount"} {
		if _, err := exec.LookPath(helper); err == nil {
			return nil
		}
	}

	return errors.New("fusermount3 not found: install the fuse3 package, or run as root")
}

// mountLogf prints on stderr what the tree and the driver have to tell the
// operator. The arguments come raw and are escaped here, like webdavLogf.
func mountLogf(format string, args ...any) {
	escaped := make([]any, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case error:
			escaped[i] = ui.EscapeLines(v.Error())
		case string:
			escaped[i] = ui.Escape(v)
		default:
			escaped[i] = arg
		}
	}
	fmt.Fprintf(os.Stderr, "mount: "+format+"\n", escaped...)
}

// mountDataroomCheck returns the check the driver makes of a dataroom before
// serving it: its session resolves, and its API has the lookup by name. The
// driver needs that API (a lookup would otherwise list a whole folder, and a
// rename could not replace); `webdav serve` keeps its fallback for the older
// one.
func mountDataroomCheck(tree *vfs.FS, client *api.Client) func(context.Context, string) error {
	return func(ctx context.Context, dataroomID string) error {
		sess, err := tree.Session(ctx, dataroomID)
		if err != nil {
			return err
		}
		supported, err := sess.SupportsNameLookup(ctx, client, dataroomID)
		if err != nil {
			return err
		}
		if !supported {
			return retycfs.ErrLegacyAPI
		}

		return nil
	}
}

// accessFunc is vfs.FS.Access: what the user may do in a dataroom.
type accessFunc func(ctx context.Context, dataroomID string) (vfs.Access, error)

// mountRights decides what the mount lets the user write, from the role the
// user has and the state of the owner's plan (ask is vfs.FS.Access, one
// request per call).
//
//   - --read-only: nothing is asked.
//   - One dataroom: asked here. A dataroom no write of this user can succeed
//     in is mounted read-only ("ro": the kernel refuses the writes itself),
//     and why says so for the mount message. When the question fails, the
//     mount is made anyway: the reads do not depend on it. The driver is then
//     given the question (hook), refuses the writes until it is answered, and
//     asks again when the dataroom is next entered.
//   - All datarooms: the driver asks for each dataroom when it is first
//     entered, and refuses the writes to those that are read-only.
func mountRights(
	ctx context.Context, target mountTarget, ask accessFunc, logf func(format string, args ...any),
) (readOnly bool, why string, hook accessFunc) {
	switch {
	case target.readOnly:
		return true, "", nil
	case target.all:
		return false, "", ask
	}
	access, err := ask(ctx, target.dataroomID)
	switch {
	case err != nil:
		logf("cannot tell whether dataroom %s is writable, writes are refused until it can be told: %s",
			target.dataroomID, err)

		return false, "", ask
	case access.ReadOnly:
		return true, access.Reason(), nil
	}

	return false, "", nil
}

// kernelNegativeTimeout turns cache.negative_ttl into the timeout retycfs
// expects: there zero means "the default", and a negative value "no negative
// cache", which is what a zero cache.negative_ttl asks for.
func kernelNegativeTimeout(negativeTTL time.Duration) time.Duration {
	if negativeTTL == 0 {
		return -1
	}

	return negativeTTL
}

// runMount mounts the target and serves it until it is unmounted.
func runMount(cmd *cobra.Command, target mountTarget) (retErr error) {
	// The mount is the only command that traces. Tracing is decided by the
	// environment only; a bad OTEL_* value is reported under --debug and the
	// mount runs untraced. Shutdown flushes the spans once it is unmounted.
	tel, err := telemetry.Init(cmd.Context(), telemetry.Options{Version: Version, Debug: debug})
	if err != nil && debug {
		fmt.Fprintln(os.Stderr, "Tracing disabled:", err)
	}
	defer tel.Shutdown(context.Background())

	// The init span covers everything before the mount is in place, and is
	// the only span parented to TRACEPARENT: a supervisor's trace closes once
	// the filesystem is up. FUSE operations get their own roots.
	initCtx, initSpan := telemetry.Tracer().Start(telemetry.ParentFromEnv(cmd.Context()), "retyc fs mount init")
	initDone := false
	defer func() {
		if !initDone {
			telemetry.RecordError(initSpan, retErr)
			initSpan.End()
		}
	}()

	// Fail fast, before the token, the API and the key are asked for.
	if err := checkMountpoint(target.mountpoint); err != nil {
		return err
	}
	if err := checkFUSE(fuseDevice); err != nil {
		return err
	}
	if err := requireIdentitySource(); err != nil {
		return err
	}

	resolveMountFlags(cmd.Flags())
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	settings, err := newMountSettings(cfg)
	if err != nil {
		return err
	}
	target.readOnly = settings.readOnly
	tokSrc, err := mustGetToken(initCtx, cfg)
	if err != nil {
		return err
	}
	// A request the API answers 401 has the login checked at once: an
	// operation of the mount that meets one does not wait for the next tick
	// of the keepalive to stop a mount whose login is gone.
	watch := newAuthWatch(tokSrc)
	client := api.New(cfg.API.BaseURL, cliUserAgent(), tokSrc, insecure, debug,
		apiTransportWatching(watch), apiRetry(cfg), api.WithUnsafeWrite(cfg.API.UnsafeWrite))

	// Auth, API reachability, then the key passphrase: the identity is
	// unlocked once and kept for the whole run.
	identity, err := serveStartupCheck(initCtx, client, servePassphraseReader)
	if err != nil {
		return err
	}

	// The tree is built with MaxStale zero (below): Redis keeps the listings
	// accordingly.
	store, err := newMetaStore(initCtx, cfg, 0)
	if err != nil {
		return err
	}
	tree := vfs.New(client, vfs.Options{
		TTL:         cfg.Cache.TTL,
		NegativeTTL: cfg.Cache.NegativeTTL,
		Store:       store,
		KeepSealed:  store != nil && cfg.Cache.Redis.HighConfidentiality,
		// MaxStale stays zero whatever cache.max_stale says: an expired
		// listing is never served. An open then never gets a version older
		// than the TTL (close-to-open, see retycfs.fileNode.Open), which
		// stale-while-revalidate would not let it tell.
		Identity:          identity,
		ListConcurrency:   service.Concurrency().List,
		UploadConcurrency: service.Concurrency().Upload,
		SpoolDir:          settings.spoolDir,
		FileMode:          settings.fileMode,
		Logf:              mountLogf,
	})
	defer func() { _ = tree.Close() }()

	// The observability listener is bound before anything is mounted, so a bad
	// address fails fast. /readyz answers 503 until the filesystem is mounted.
	health := newServeHealth()
	metricsSrv, err := startObservability(settings.metrics, health, tree)
	if err != nil {
		return err
	}
	defer stopObservability(metricsSrv)

	check := mountDataroomCheck(tree, client)
	source := "all datarooms"
	if !target.all {
		source = "retyc://" + target.dataroomID
		// A dataroom that does not exist, or that this driver cannot serve,
		// is refused here rather than at the first ls.
		switch err := check(initCtx, target.dataroomID); {
		case errors.Is(err, api.ErrNotFound):
			return fmt.Errorf("dataroom %s not found, or not shared with you: %w", target.dataroomID, err)
		case errors.Is(err, retycfs.ErrLegacyAPI):
			return fmt.Errorf("the API at %s predates what `retyc fs mount` needs (lookup by name); "+
				"`retyc fs webdav serve` still works with it: %w", cfg.API.BaseURL, err)
		case err != nil:
			return fmt.Errorf("dataroom %s: %w", target.dataroomID, err)
		}
	}

	readOnly, why, access := mountRights(initCtx, target, tree.Access, mountLogf)
	srv, err := retycfs.Mount(initCtx, tree, target.mountpoint, retycfs.Options{
		All:           target.all,
		DataroomID:    target.dataroomID,
		ReadOnly:      readOnly,
		Access:        access,
		CheckDataroom: check,
		Logf:          mountLogf,
		// The kernel keeps a name and its attributes for as long as the
		// listing behind them is trusted unless told otherwise
		// (mount.entry_ttl, mount.attr_ttl), and a missing name for as long
		// as the tree answers it missing.
		EntryTimeout:    settings.entryTTL,
		AttrTimeout:     settings.attrTTL,
		NegativeTimeout: kernelNegativeTimeout(cfg.Cache.NegativeTTL),
		NoKernelCache:   !settings.kernelCache,
		ReadDirPlus:     settings.readDirPlus,
		AllowOther:      settings.allowOther,
		UID:             settings.uid,
		GID:             settings.gid,
		FileMode:        settings.fileMode,
		DirMode:         settings.dirMode,
		DrainTimeout:    mountDrain(settings.drainTimeout),
		MirrorLocks:     settings.mirrorLocks && !readOnly,
		// Deletes are writes: they share the bound of the uploads.
		BackgroundDelete:  settings.backgroundDelete && !readOnly,
		DeleteConcurrency: service.Concurrency().Upload,
		LocalFiles:        settings.localFiles,
	})
	if err != nil {
		return err
	}
	mode := "read-write"
	switch {
	case readOnly && why != "":
		mode = "read-only: " + why
	case readOnly:
		mode = "read-only"
	}
	fmt.Fprintf(os.Stderr, "Mounted %s on %s (%s). Unmount with Ctrl-C or `fusermount3 -u %s`.\n",
		source, target.mountpoint, mode, target.mountpoint)
	health.setReady(true)
	initSpan.End()
	initDone = true

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// The warmup starts once the mount is ready and never delays it; it
	// stops as soon as the mount is going away, and is waited for before the
	// tree is closed.
	warmCtx, stopWarmup := context.WithCancel(ctx)
	warmDone := startWarmup(warmCtx, tree, target, settings)
	defer func() {
		stopWarmup()
		<-warmDone
	}()

	authErrCh := make(chan error, 1)
	go watch.run(ctx, func(err error) {
		authErrCh <- err
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	return serveMount(srv, sigCh, authErrCh, health, stopWarmup)
}

// warmer is what the warmup walks (*vfs.FS).
type warmer interface {
	Warmup(ctx context.Context, dataroomID string, maxDepth int) vfs.WarmupStats
}

// startWarmup walks the mounted tree in the background (see vfs.FS.Warmup)
// unless the settings turn it off, and tells the operator what it walked in
// one line. The channel is closed once the walk is over, at once when there
// is none.
func startWarmup(ctx context.Context, tree warmer, target mountTarget, settings mountSettings) <-chan struct{} {
	done := make(chan struct{})
	if !settings.warmup {
		close(done)

		return done
	}
	go func() {
		defer close(done)
		stats := tree.Warmup(ctx, target.dataroomID, settings.warmupDepth)
		how := "warmed"
		if stats.Interrupted {
			how = "warmup interrupted"
		}
		mountLogf("listing cache %s: %d folders, %d files, %d errors in %s",
			how, stats.Folders, stats.Files, stats.Errors, stats.Duration.Round(time.Millisecond))
	}()

	return done
}

// stopObservability closes the observability listener, if any, once the mount
// is over: the probes answer for as long as the drain lasts.
func stopObservability(srv *http.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// mountDrain turns mount.drain_timeout into the drain retycfs expects: there
// zero means "the default", and a negative value "no drain", which is what a
// zero mount.drain_timeout asks for.
func mountDrain(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return -1
	}

	return timeout
}

// mountServer is the mounted filesystem as its lifecycle sees it
// (*retycfs.Server).
type mountServer interface {
	Done() <-chan struct{}
	Shutdown(ctx context.Context) error
}

// serveMount waits for the end of the mount and unmounts. There are three
// ways out: a signal, a login that cannot be renewed, or the filesystem
// unmounted from outside (fusermount3 -u, umount), which is a clean exit.
//
// Shutdown wakes the readers of the access log, waits for a busy mount point,
// gives the files being sent the drain timeout to reach the API, and does
// nothing when the filesystem is gone already. A signal received while it
// runs (a second Ctrl-C) ends the drain at once: what is not sent is lost,
// and reported by the driver. Files lost at the shutdown, however it started,
// are an error (*retycfs.LostWritesError, marked lostWritesError: exit code
// 75): only a mount that lost nothing exits with 0.
//
// health stops answering ready as soon as one of the three happens, before the
// drain: an orchestrator stops counting on a mount that is going away, or
// whose login is lost. stopping, when not nil, is called then too: what runs
// in the background for the mount (the warmup) stops before the drain.
func serveMount(
	srv mountServer, stop <-chan os.Signal, authExpired <-chan error, health *serveHealth, stopping func(),
) error {
	var authErr error
	select {
	case <-stop:
		// The driver tells whether anything is still to send, and for how long
		// it is waited for.
		fmt.Fprintln(os.Stderr, "Unmounting.")
	case authErr = <-authExpired:
	case <-srv.Done():
	}
	health.setReady(false)
	if stopping != nil {
		stopping()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	err := srv.Shutdown(ctx)
	if authErr != nil {
		// Wrapped: the exit code tells a supervisor not to restart (77).
		authErr = fmt.Errorf("authentication expired: %w\n%s", authErr, authLostAdvice("mount again"))
		// The files lost on the way are still told: the count, never a name.
		var lost *retycfs.LostWritesError
		if errors.As(err, &lost) {
			return errors.Join(authErr, lostWritesError{lost})
		}

		return authErr
	}

	// A *retycfs.LostWritesError included: exit code 75, with the count.
	if err != nil {
		var lost *retycfs.LostWritesError
		if errors.As(err, &lost) {
			return lostWritesError{err}
		}
	}

	return err
}
