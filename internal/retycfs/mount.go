//go:build linux

package retycfs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// FSType is the type the mount shows in /proc/self/mountinfo and df -T, after
// the "fuse." the kernel puts before it.
const FSType = "retycfs"

// maxWrite is the size of the largest request the kernel sends: 1 MiB, the
// most it accepts, in place of the 128 KiB default. Reads then come in
// requests of up to 256 KiB.
const maxWrite = 1 << 20

// defaultUnmountGrace is how long Unmount waits for a busy mount point.
const defaultUnmountGrace = 5 * time.Second

// DefaultDrainTimeout is what the uploads in progress are given to end when
// the mount is stopped (Options.DrainTimeout).
const DefaultDrainTimeout = 5 * time.Minute

// abortGrace is how long a shutdown whose drain is over still waits for the
// requests it cancelled to return.
const abortGrace = 5 * time.Second

// cleanupGrace is how long the end of a mount whose drain was cut waits for
// what the cancelled uploads still do: removing from the API what they had
// sent (service.DiscardFailedUpload, which has a timeout of its own, longer).
// It is shorter than abortGrace: Shutdown sees the end of it.
const cleanupGrace = 3 * time.Second

// lossSettle is how long an upload cancelled by the end of the drain is given
// to return before its file is reported lost without waiting for it: one that
// returns later is busy with that cleanup, which must not delay the report.
const lossSettle = 250 * time.Millisecond

// LostWritesError is what Shutdown returns when files being written were not
// sent before the filesystem went away: their changes are lost. Each was
// reported through Options.Logf, by IDs; the error only counts them.
//
// With Options.BackgroundDelete it also counts the files removed through the
// mount whose delete did not reach the API in time: they may still be in the
// dataroom.
type LostWritesError struct {
	// Files is the number of files whose changes are lost.
	Files int
	// Deletes is the number of files removed whose background delete did not
	// end before the filesystem went away.
	Deletes int
}

func (e *LostWritesError) Error() string {
	var parts []string
	switch {
	case e.Files == 1:
		parts = append(parts,
			"1 file being written was not sent before the filesystem was unmounted: its changes are lost")
	case e.Files > 1 || e.Deletes == 0:
		parts = append(parts, fmt.Sprintf("%d files being written were not sent before the filesystem was unmounted: "+
			"their changes are lost", e.Files))
	}
	switch {
	case e.Deletes == 1:
		parts = append(parts,
			"1 file removed was not deleted before the filesystem was unmounted: it may still be in the dataroom")
	case e.Deletes > 1:
		parts = append(parts, fmt.Sprintf("%d files removed were not deleted before the filesystem was unmounted: "+
			"they may still be in the dataroom", e.Deletes))
	}

	return strings.Join(parts, "; ")
}

// The reasons a drain ends before everything is sent.
var (
	errDrainTimeout = errors.New("the drain timeout is over")
	errDrainCut     = errors.New("the shutdown was forced")
)

// Options are the settings of a mount.
type Options struct {
	// All presents every dataroom the user can reach, one folder each, at the
	// root. Otherwise DataroomID names the dataroom that is the root.
	All        bool
	DataroomID string

	// ReadOnly mounts the filesystem read only ("ro"): the kernel refuses
	// every write itself, and the handlers answer EROFS.
	ReadOnly bool
	// Access, when set, tells what the user may do in a dataroom
	// (vfs.FS.Access) on a mount that is not read only as a whole. It is
	// asked when a dataroom is first entered, after CheckDataroom, and its
	// answer is kept for the life of the mount: the writes to a dataroom it
	// reports ReadOnly (a viewer, a plan that refuses writes) answer EROFS.
	//
	// Until it has answered, the writes to the dataroom answer EROFS too: a
	// failure never makes a dataroom writable. It never blocks a read either:
	// the failure is reported once through Logf, and the question is asked
	// again on the next access to the dataroom. Nil makes every dataroom
	// writable, the API deciding each write.
	Access func(ctx context.Context, dataroomID string) (vfs.Access, error)

	// EntryTimeout and AttrTimeout are how long the kernel keeps a name and
	// the attributes of an inode without asking again; zero means
	// vfs.DefaultCacheTTL, the TTL of the listings behind them.
	// NegativeTimeout is how long it keeps a name that does not exist; zero
	// means vfs.DefaultNegativeTTL. A negative value disables the cache.
	EntryTimeout    time.Duration
	AttrTimeout     time.Duration
	NegativeTimeout time.Duration

	// CheckDataroom is asked once per dataroom, when it is first entered,
	// whether the driver may serve it; nil accepts every dataroom. It returns
	// ErrLegacyAPI for a dataroom whose API has no lookup by name. A dataroom
	// refused answers ENOTSUP, and is asked about again on the next access.
	CheckDataroom func(ctx context.Context, dataroomID string) error

	// Logf receives what the driver has to tell its operator: a handler that
	// panicked, a dataroom it does not serve, a mount point detached while
	// busy. Nil discards the messages. Nothing it receives holds a file name.
	Logf func(format string, args ...any)

	// AccessLogSize is the number of operations .retycfs/accesslog keeps;
	// zero means 4096.
	AccessLogSize int

	// UnmountGrace is how long Unmount waits for a mount point that is busy
	// before detaching it; zero means five seconds. The drain bounds it.
	UnmountGrace time.Duration

	// DrainTimeout is what a shutdown gives the uploads to end, from the
	// moment it starts: the flushes in progress, and the files still open,
	// which are sent as they are. Past it they are cancelled, what they held
	// is lost and reported through Logf. Zero means DefaultDrainTimeout, a
	// negative value no drain at all.
	DrainTimeout time.Duration

	// UID and GID are the owner every inode is presented with; nil means
	// those of the process.
	UID, GID *uint32
	// FileMode and DirMode are the permissions presented for a node the API
	// stores no mode for; zero means 0644 and 0755.
	FileMode, DirMode os.FileMode

	// NoKernelCache makes every open drop the pages the kernel holds for the
	// file (no FOPEN_KEEP_CACHE): a file read twice is downloaded twice.
	NoKernelCache bool

	// MirrorLocks makes the open for writing of a file that exists at the API
	// take an exclusive API lock on it (vfs.LockManager), one per inode, kept
	// until the last handle opened for writing on it is released: another
	// cooperating client then sees the file locked, and a file another client
	// locked answers EBUSY to open(2). The locks are advisory: the API
	// refuses no write for them. A file created through the mount takes none
	// before it is opened again once stored. The mount renews the locks while
	// they stand and releases those left when it is unmounted.
	MirrorLocks bool

	// BackgroundDelete makes unlink(2) of a file or a symbolic link the
	// dataroom holds answer once the removal is recorded here, before the API
	// is asked: the node is absent from the mount at once, and deleted at the
	// API by a queue that sends DeleteConcurrency deletes at once (zero means
	// DefaultDeleteConcurrency). What is refused without asking the API (a
	// read-only mount or dataroom) is still an error of unlink; what the API
	// refuses is not: the delete that fails is reported through Logf, by
	// identifiers, and the file is listed again. Whatever needs the name free
	// at the API (the first flush of a file created under it, mkdir, symlink,
	// a rename onto it, a server-side copy) waits for the delete first, and
	// rmdir for those of the children of the folder. A shutdown waits for the
	// queue as long as its drain lasts (see Server.Shutdown).
	BackgroundDelete  bool
	DeleteConcurrency int

	// LocalFiles are glob patterns (path.Match) on the name of a file. A
	// regular file created through the mount under a name that matches one,
	// where the dataroom holds no node of that name, is a local file: it
	// lives in the spool directory for as long as the mount does, is listed,
	// read, written and removed like any other, and never reaches the API (no
	// request when it is created, closed, fsync'ed or unlinked). It is gone,
	// without a report, when the mount ends. Editors create such files next
	// to the one they edit: swap files, backups.
	//
	// A node the dataroom already holds under such a name is a file like any
	// other. A name that matches is looked up in the listing of its folder,
	// never by a request of its own. Renaming a local file to a name that
	// matches no pattern, or over a node, makes it an ordinary file, sent
	// like one created under that name. Empty: no local file. Mount refuses
	// a malformed pattern.
	LocalFiles []string

	// AllowOther lets the other users of the machine into the mount
	// ("allow_other"); access is then decided by the mode, owner and group
	// presented. Through the fusermount3 helper it needs user_allow_other in
	// /etc/fuse.conf.
	AllowOther bool

	// procStatus replaces the reader of /proc/<pid>/status (tests).
	procStatus procStatusReader
	// detach replaces the detach of a busy mount point (tests).
	detach func(mountpoint string) error
	// unmount replaces fuse.Server.Unmount (tests).
	unmount func() error
}

// drainTimeout returns the drain a shutdown gets.
func (o Options) drainTimeout() time.Duration {
	switch {
	case o.DrainTimeout == 0:
		return DefaultDrainTimeout
	case o.DrainTimeout < 0:
		return 0
	}

	return o.DrainTimeout
}

// timeout returns d, def when it is zero, and the shortest timeout the kernel
// takes when it is negative: go-fuse reads a zero as "use the default", so
// "no cache" has to be spelled one nanosecond.
func timeout(d, def time.Duration) *time.Duration {
	switch {
	case d == 0:
		d = def
	case d < 0:
		d = time.Nanosecond
	}

	return &d
}

// Server is a mounted filesystem.
type Server struct {
	srv        *fuse.Server
	drv        *driver
	mountpoint string

	// done is closed once the filesystem is unmounted, by Unmount or by
	// anyone else.
	done     chan struct{}
	doneOnce sync.Once
	// unmount serializes Unmount.
	unmount sync.Mutex

	// drain starts the drain once; drainTimer ends it.
	drain      sync.Once
	drainTimer *time.Timer
	// drainStart is when a drain with something to send started (see
	// startDrain), zero when there was nothing: finish then says nothing.
	drainStart time.Time

	// stopLocks ends the renewal of the API locks, which then releases those
	// still held; locksDone is closed once it has. Both nil without
	// Options.MirrorLocks.
	stopLocks context.CancelFunc
	locksDone chan struct{}
}

// Mount mounts the datarooms tree serves on mountpoint, read-write unless
// Options.ReadOnly, and returns once the kernel has the mount. ctx bounds nothing past that: the
// filesystem is served until Unmount, or until it is unmounted from outside
// (fusermount3 -u, umount), which Done and Wait report.
//
// The caller keeps tree and closes it after Unmount.
//
// Mount options: "default_permissions" (the kernel checks access against the
// mode, owner and group of each inode; the driver implements no Access), and
// "ro" with Options.ReadOnly. No writeback cache: with it the kernel stops
// asking the driver for the size and the modification time of a file, and a
// file another client extends is read truncated; every write(2) is one WRITE
// request, stored in the spool of the file before it returns. The mount is made by mount(2) when the process
// is root and by the fusermount3 helper otherwise; both take these options.
func Mount(ctx context.Context, tree *vfs.FS, mountpoint string, opts Options) (*Server, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !opts.All && opts.DataroomID == "" {
		return nil, errors.New("retycfs: no dataroom to mount")
	}
	for _, pattern := range opts.LocalFiles {
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("retycfs: local file pattern %q: %w", pattern, err)
		}
	}

	// The path the kernel will show in /proc/self/mountinfo, which is where
	// Unmount looks for it.
	if abs, err := filepath.Abs(mountpoint); err == nil {
		mountpoint = abs
	}
	if resolved, err := filepath.EvalSymlinks(mountpoint); err == nil {
		mountpoint = resolved
	}

	d := newDriver(tree, opts)
	mountOpts := []string{"default_permissions"}
	if opts.ReadOnly {
		mountOpts = append(mountOpts, "ro")
	}

	id := ident{drv: d, ino: rootIno, typ: vfs.TypeDir}
	var root fs.InodeEmbedder
	source := "retyc://"
	if opts.All {
		root = &allRoot{base: base{ident: id}}
	} else {
		id.dataroomID = opts.DataroomID
		root = &dirNode{base: base{ident: id}, dataroomRoot: true, mountRoot: true}
		source += opts.DataroomID
	}

	srv, err := fs.Mount(mountpoint, root, &fs.Options{
		EntryTimeout:    timeout(opts.EntryTimeout, vfs.DefaultCacheTTL),
		AttrTimeout:     timeout(opts.AttrTimeout, vfs.DefaultCacheTTL),
		NegativeTimeout: timeout(opts.NegativeTimeout, vfs.DefaultNegativeTTL),
		RootStableAttr:  &fs.StableAttr{Ino: rootIno},
		// Every inode is given its permissions (attrSource.fill): a mode of
		// 0 stored with a node is presented as 0, not as go-fuse's 0644.
		NullPermissions: true,
		MountOptions: fuse.MountOptions{
			FsName:  source,
			Name:    FSType,
			Options: mountOpts,
			// mount(2) needs CAP_SYS_ADMIN and works without the fusermount3
			// helper, which a scratch image does not have. go-fuse falls back
			// on the helper when it fails.
			DirectMount: os.Geteuid() == 0,
			AllowOther:  opts.AllowOther,
			MaxWrite:    maxWrite,
			// Without it, serving extended attributes costs one
			// GETXATTR security.capability per write(2).
			//
			// ATOMIC_O_TRUNC: open(O_TRUNC) arrives as one OPEN carrying the
			// flag, not as a SETATTR to size 0 then an OPEN. The spool then
			// starts empty and nothing of the version is downloaded.
			//
			// DIRECT_IO_ALLOW_MMAP (Linux 6.6): a file being written is
			// opened FOPEN_DIRECT_IO, which otherwise refuses a shared mmap.
			ExtraCapabilities: fuse.CAP_HANDLE_KILLPRIV_V2 | fuse.CAP_ATOMIC_O_TRUNC | fuse.CAP_DIRECT_IO_ALLOW_MMAP,
			// One read per handle at a time, in the order of the offsets.
			// By default the kernel sends the reads of its read-ahead in
			// parallel and they arrive in any order: around a chunk boundary
			// a late read asks again for a chunk the two-chunk window of
			// vfs.File has just let go, which is downloaded twice, and the
			// reads no longer look sequential, which is what starts the
			// download of the next chunk. Nothing is lost: the pace of a
			// read is the download of its chunks, not the number of
			// requests in flight.
			SyncRead:     true,
			PanicHandler: d.panicked,
			// What go-fuse has to say (a connection that ends) goes where
			// the driver's own messages go.
			Logger: log.New(logfWriter{d}, "", 0),
			// Debug stays off, whatever the CLI is asked: its output holds
			// the name of every file looked up.
		},
	})
	if err != nil {
		d.abort(nil)
		d.notify.stop()
		d.log.close()

		return nil, fmt.Errorf("mounting on %s: %w", mountpoint, err)
	}

	s := &Server{srv: srv, drv: d, mountpoint: mountpoint, done: make(chan struct{})}
	if opts.MirrorLocks {
		// The leases of the API are short (five minutes at most) and a file
		// stays open for hours: the manager renews the locks until the
		// filesystem is unmounted, then releases those no handle did.
		lockCtx, stop := context.WithCancel(context.Background()) //nolint:gosec // G118: called by finish (Server.stopLocks)
		s.stopLocks, s.locksDone = stop, make(chan struct{})
		go func() {
			defer close(s.locksDone)
			tree.Locks().Run(lockCtx)
		}()
	}
	go func() {
		srv.Wait()
		s.finish()
	}()

	return s, nil
}

// logfWriter hands the lines go-fuse logs to Options.Logf. With Debug off
// those are its own failures only, which name no file.
type logfWriter struct{ d *driver }

func (w logfWriter) Write(p []byte) (int, error) {
	w.d.logf("%s", strings.TrimRight(string(p), "\n"))

	return len(p), nil
}

// panicked answers a panic the handlers did not recover themselves, in the
// code of go-fuse between the kernel and them: EIO for that request, the
// stack to the operator, and the mount stays up.
func (d *driver) panicked(v any) fuse.Status {
	d.logf("panic while serving a FUSE request: %v\n%s", v, debug.Stack())

	return fuse.EIO
}

// startDrain starts the drain, once: from now the uploads have
// Options.DrainTimeout to end, after which they are cancelled.
func (s *Server) startDrain() {
	s.drain.Do(func() {
		s.drv.draining.Store(true)
		timeout := s.drv.opts.drainTimeout()
		s.drainTimer = time.AfterFunc(timeout, func() { s.drv.abort(errDrainTimeout) })
		// The operator learns why the command does not end at once, and how
		// to make it.
		files, deletes := s.drv.pending()
		if files == 0 && deletes == 0 {
			return
		}
		s.drainStart = time.Now()
		if timeout <= 0 {
			s.drv.logf("stopping: %s still to send to the API, abandoned (no drain timeout)",
				pendingWork(files, deletes))

			return
		}
		s.drv.logf("stopping: %s still to send to the API, waiting for them up to %s (drain timeout); "+
			"a second signal abandons them", pendingWork(files, deletes), timeout)
	})
}

// finish records that the filesystem is unmounted and releases what served
// it. The readers of the access log meet the end of the file.
func (s *Server) finish() {
	s.startDrain()
	s.doneOnce.Do(func() {
		d := s.drv
		// No new request arrives any more. What the last handles left to send
		// is sent before the caller closes the tree, as long as the drain
		// lasts. closeSpools returns once every file that is lost is reported:
		// the uploads the drain cancelled are not waited for before that, they
		// may be held by their cleanup at an API that does not answer.
		d.uploads.wait(d.stopped)
		closed := d.closeSpools()
		// After the spools: a file created under a name being deleted waits
		// for that delete to be sent.
		d.deletes.drain()
		grace, cancel := context.WithTimeout(context.Background(), cleanupGrace)
		select {
		case <-closed:
			d.uploads.wait(grace)
		case <-grace.Done():
			d.logf("uploads cancelled by the shutdown are still cleaning up at the API: they are left behind")
		}
		cancel()
		if s.stopLocks != nil {
			// After the last flushes: a file is unlocked once it is sent. The
			// release has its own short timeout (vfs.LockManager.ReleaseAll).
			s.stopLocks()
			<-s.locksDone
		}
		s.drainTimer.Stop()
		if !s.drainStart.IsZero() {
			took := time.Since(s.drainStart).Round(100 * time.Millisecond)
			if lost, deletes := int(d.lost.Load()), int(d.lostDeletes.Load()); lost+deletes > 0 {
				d.logf("drain over after %s: %s not sent", took, pendingWork(lost, deletes))
			} else {
				d.logf("drain over after %s: everything was sent", took)
			}
		}
		d.abort(nil)
		d.log.close()
		d.notify.stop()
		d.inodes.close()
		close(s.done)
	})
}

// Done is closed once the filesystem is unmounted, by Unmount or from
// outside.
func (s *Server) Done() <-chan struct{} { return s.done }

// Wait returns once the filesystem is unmounted.
func (s *Server) Wait() { <-s.done }

// Unmount is Shutdown with nothing to cut the drain short.
func (s *Server) Unmount() error { return s.Shutdown(context.Background()) }

// Shutdown unmounts the filesystem. It is no error that it already is, by
// Shutdown or from outside.
//
// The readers of the access log are woken with the end of the file first:
// blocked, they would hold the mount busy. A mount point that is still busy
// after that (a file open, a shell in a folder) is tried again for
// Options.UnmountGrace, then detached: it leaves the tree at once and the
// processes still in it get ENOTCONN, which is what they get anyway when the
// process serving them exits.
//
// What is being written has Options.DrainTimeout, counted from the call, to
// reach the API: the flushes in progress (a close(2) being answered, the
// flush that follows the last close of a file), then the files still open,
// sent as they are. Past it, or as soon as ctx ends (a second signal), what
// is not sent is cancelled and lost, each file reported through Options.Logf,
// and the filesystem is unmounted all the same. New writes are not refused
// during the drain: they are part of what it sends, or loses. Once the spools
// are closed, opening a file for writing answers ENOTCONN.
//
// The error is, or wraps (errors.As), a *LostWritesError when files were lost
// that way, whoever unmounted the filesystem. The call that follows the loss
// returns it, those made later do not.
func (s *Server) Shutdown(ctx context.Context) error {
	s.startDrain()
	stop := context.AfterFunc(ctx, func() { s.drv.abort(errDrainCut) })
	defer stop()

	result := make(chan error, 1)
	go func() { result <- s.unmountAndFinish() }()
	select {
	case err := <-result:
		return s.withLosses(err)
	case <-s.drv.stopped.Done():
	}
	// The drain is over: what was cancelled returns shortly. A handler that
	// does not (a download the kernel no longer waits for) is left behind.
	timer := time.NewTimer(abortGrace)
	defer timer.Stop()
	select {
	case err := <-result:
		return s.withLosses(err)
	case <-timer.C:
		return s.withLosses(
			fmt.Errorf("unmounting %s: requests are still in progress after the drain", s.mountpoint))
	}
}

// withLosses adds to err, the outcome of a shutdown, the files lost since the
// last call: a loss is returned once.
func (s *Server) withLosses(err error) error {
	lost, deletes := int(s.drv.lost.Swap(0)), int(s.drv.lostDeletes.Swap(0))
	switch {
	case lost == 0 && deletes == 0:
		return err
	case err == nil:
		return &LostWritesError{Files: lost, Deletes: deletes}
	}

	return errors.Join(err, &LostWritesError{Files: lost, Deletes: deletes})
}

// unmountAndFinish unmounts, detaches a mount point that stays busy, and
// waits for what the drain lets end. A mount point that cannot be detached is
// the error returned, after the rest: what is being written is sent or
// reported lost, and the locks released, whether the kernel let go or not.
func (s *Server) unmountAndFinish() error {
	s.unmount.Lock()
	defer s.unmount.Unlock()

	s.drv.log.close()
	if s.gone() {
		s.finish()

		return nil
	}

	grace := s.drv.opts.UnmountGrace
	if grace <= 0 {
		grace = defaultUnmountGrace
	}
	deadline := time.Now().Add(grace)
	stopped := s.drv.stopped.Done()
	var failed error
	err := s.unmountOnce(stopped)
retry:
	for err != nil && !s.gone() && time.Now().Before(deadline) {
		select {
		case <-stopped:
			break retry
		case <-time.After(100 * time.Millisecond):
		}
		err = s.unmountOnce(stopped)
	}
	if err != nil && !s.gone() {
		s.drv.logf("%s is busy, detaching it: %s", s.mountpoint, strings.TrimSpace(err.Error()))
		detachFn := detach
		if s.drv.opts.detach != nil {
			detachFn = s.drv.opts.detach
		}
		if derr := detachFn(s.mountpoint); derr != nil {
			failed = fmt.Errorf("unmounting %s: %w", s.mountpoint, errors.Join(err, derr))
		}
	}
	s.finish()

	return failed
}

// errUnmountPending is what unmountOnce answers when the drain ends while
// go-fuse is still unmounting.
var errUnmountPending = errors.New("the unmount is still in progress")

// unmountOnce asks go-fuse to unmount. Once the kernel has let the mount
// point go, fuse.Server.Unmount waits for the FUSE connection to close, which
// another mount of the same filesystem keeps open for as long as a file is
// open through it: the bind mount a CSI node plugin gives each pod, in
// another mount namespace. The mount point gone from this namespace is then
// the unmount done: what is being written is sent, or reported lost, now and
// not when the last pod lets go, and the connection serves what is left
// meanwhile (a write to a file whose spool is closed fails). A request still
// in progress holds the connection the same way, mount or not.
func (s *Server) unmountOnce(stopped <-chan struct{}) error {
	unmount := s.srv.Unmount
	if s.drv.opts.unmount != nil {
		unmount = s.drv.opts.unmount
	}
	result := make(chan error, 1)
	go func() { result <- unmount() }()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	// The end of the drain gives go-fuse a moment more: with no drain at all
	// it is over before the unmount could answer.
	var cut <-chan time.Time
	for {
		select {
		case err := <-result:
			return err
		case <-stopped:
			stopped, cut = nil, time.After(500*time.Millisecond)
		case <-cut:
			return errUnmountPending
		case <-tick.C:
		}
		if mounted, err := isMounted(s.mountpoint); err != nil || mounted {
			continue
		}
		// Unmounted here: a connection that closes returns at once.
		select {
		case err := <-result:
			return err
		case <-time.After(500 * time.Millisecond):
		}
		s.drv.logf("%s is unmounted, but its FUSE connection is still open (requests in progress, or another "+
			"mount of it with files open): they are served until they end", s.mountpoint)

		return nil
	}
}

// gone reports whether the filesystem is unmounted already.
func (s *Server) gone() bool {
	select {
	case <-s.done:
		return true
	default:
	}
	mounted, err := isMounted(s.mountpoint)

	return err == nil && !mounted
}

// detach removes a busy mount point from the tree (MNT_DETACH), by umount2
// when the process may, through the fusermount3 helper otherwise.
func detach(mountpoint string) error {
	if err := unix.Unmount(mountpoint, unix.MNT_DETACH); err == nil {
		return nil
	}
	var lastErr error
	for _, helper := range []string{"fusermount3", "fusermount"} {
		bin, err := exec.LookPath(helper)
		if err != nil {
			lastErr = err

			continue
		}
		out, err := exec.Command(bin, "-u", "-z", mountpoint).CombinedOutput() //nolint:gosec // fixed helper, our mount point
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s -u -z: %w: %s", helper, err, strings.TrimSpace(string(out)))
	}

	return lastErr
}

// isMounted reports whether a retycfs filesystem is mounted on mountpoint,
// from /proc/self/mountinfo.
func isMounted(mountpoint string) (bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw": the
		// mount point is the fifth field, the type the first after the dash.
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || unescapeMount(fields[4]) != mountpoint {
			continue
		}
		for i, field := range fields {
			if field == "-" && i+1 < len(fields) && fields[i+1] == "fuse."+FSType {
				return true, nil
			}
		}
	}

	return false, sc.Err()
}

// unescapeMount decodes a path of /proc/self/mountinfo, where a space, a tab,
// a newline and a backslash are written as a backslash and three octal
// digits.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var c byte
			ok := true
			for _, d := range []byte(s[i+1 : i+4]) {
				if d < '0' || d > '7' {
					ok = false

					break
				}
				c = c<<3 | (d - '0')
			}
			if ok {
				b.WriteByte(c)
				i += 3

				continue
			}
		}
		b.WriteByte(s[i])
	}

	return b.String()
}

// pendingWork says how many files and deletes are meant, for the drain's
// messages.
func pendingWork(files, deletes int) string {
	plural := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}

		return fmt.Sprintf("%d %s", n, many)
	}
	switch {
	case deletes == 0:
		return plural(files, "file", "files")
	case files == 0:
		return plural(deletes, "delete", "deletes")
	}

	return plural(files, "file", "files") + " and " + plural(deletes, "delete", "deletes")
}
