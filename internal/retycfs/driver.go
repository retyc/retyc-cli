//go:build linux

package retycfs

import (
	"context"
	"errors"
	"os"
	"path"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// driver is what every inode of one mount shares.
type driver struct {
	tree   *vfs.FS
	opts   Options
	attrs  attrSource
	inodes *inodeTable
	log    *accessLog
	notify *notifier
	// spools are the files being written; uploads the last flushes of those
	// whose handles are all closed.
	spools  *spoolRegistry
	uploads *inflight
	// clock dates what vfs answers (see stamp).
	clock atomic.Uint64
	// lockKeys numbers the API locks taken (see fileNode.lockForWrite).
	lockKeys atomic.Uint64

	// usable holds the datarooms Options.CheckDataroom accepted. A refusal is
	// not kept: it is asked again, and reported once (reported).
	usable   sync.Map // dataroom ID → struct{}
	reported sync.Map // dataroom ID → struct{}

	// rights holds what Options.Access answered for each dataroom.
	rights sync.Map // dataroom ID → *dataroomRights

	// stopped ends when the drain of a shutdown is over (see
	// Server.Shutdown): the uploads nobody waits for any more are cancelled
	// with it. Its cause tells why, context.Canceled for a shutdown that
	// sent everything.
	stopped context.Context
	abort   context.CancelCauseFunc
	// draining is set once the drain of a shutdown has started, lost counts
	// the files whose changes were lost from then on (see openSpool.retire).
	draining atomic.Bool
	lost     atomic.Int64

	// deletes sends the deletes unlink answered before the API did; nil
	// without Options.BackgroundDelete. lostDeletes counts those the end of
	// the drain of a shutdown cut.
	deletes     *deleteQueue
	lostDeletes atomic.Int64

	// procStatus reads what tells whether the caller of an interrupted
	// request is being killed (see callerDying).
	procStatus procStatusReader

	// wrapSpool, when set, stands between the driver and each spool vfs
	// opens from then on (tests: an instant of a race made to happen).
	wrapSpool atomic.Pointer[func(vfs.Spool) vfs.Spool]
}

// newDriver returns the driver of a mount of tree.
func newDriver(tree *vfs.FS, opts Options) *driver {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: IDs are 32 bits on Linux
	if opts.UID != nil {
		uid = *opts.UID
	}
	if opts.GID != nil {
		gid = *opts.GID
	}
	fileMode, dirMode := uint32(opts.FileMode.Perm()), uint32(opts.DirMode.Perm())
	if fileMode == 0 {
		fileMode = defaultFileMode
	}
	if dirMode == 0 {
		dirMode = defaultDirMode
	}
	d := &driver{
		tree:    tree,
		opts:    opts,
		attrs:   attrSource{uid: uid, gid: gid, fileMode: fileMode, dirMode: dirMode, epoch: time.Now()},
		inodes:  newInodeTable(),
		log:     newAccessLog(opts.AccessLogSize),
		notify:  newNotifier(),
		spools:  newSpoolRegistry(),
		uploads: newInflight(),

		procStatus: readProcStatus,
	}
	if opts.procStatus != nil {
		d.procStatus = opts.procStatus
	}
	d.inodes.pins = d.spools.folders
	if opts.BackgroundDelete && !opts.ReadOnly {
		d.deletes = newDeleteQueue(d, opts.DeleteConcurrency)
	}
	stopped, cancel := context.WithCancelCause(context.Background())
	var told sync.Once
	d.stopped = stopped
	d.abort = func(cause error) {
		// Nothing is sent past this point: no file is opened for writing
		// any more.
		d.spools.seal()
		cancel(cause)
		if d.drainCut() {
			told.Do(func() {
				d.logf("%s: the uploads still in progress are cancelled, what they held is lost",
					context.Cause(stopped))
			})
		}
	}

	return d
}

// drainCut reports whether the drain of the shutdown ended before everything
// was sent.
func (d *driver) drainCut() bool {
	cause := context.Cause(d.stopped)

	return errors.Is(cause, errDrainTimeout) || errors.Is(cause, errDrainCut)
}

// detached returns a context for an upload nobody waits for (the flush that
// follows the last close of a file): it keeps the values of ctx, not its
// cancellation, and ends with the drain of a shutdown.
func (d *driver) detached(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(d.stopped, cancel)

	return ctx, func() {
		stop()
		cancel()
	}
}

// dataroomRights is what the driver knows of the user's right to write in one
// dataroom.
type dataroomRights struct {
	// asking serializes the question: the accesses that arrive while it is
	// asked wait for its answer rather than ask it again.
	asking sync.Mutex
	// state is rightsUnknown until Options.Access has answered.
	state atomic.Int32
	// failed: the last failure was reported. Guarded by asking.
	failed bool
}

const (
	rightsUnknown int32 = iota
	rightsWritable
	rightsReadOnly
)

// stamp returns a new date for an answer of vfs, to take before asking: of two
// answers about one node, the one asked for last is the one the inode table
// keeps (see inodeState.observe).
func (d *driver) stamp() uint64 { return d.clock.Add(1) }

// localName reports whether name is one a file created through the mount is
// kept local under (Options.LocalFiles).
func (d *driver) localName(name string) bool {
	for _, pattern := range d.opts.LocalFiles {
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}

	return false
}

// readOnly reports whether writes to the dataroom are refused: the whole
// mount (Options.ReadOnly), or that dataroom, which Options.Access reported
// read-only or has not answered for yet. It answers from memory.
func (d *driver) readOnly(dataroomID string) bool {
	if d.opts.ReadOnly {
		return true
	}
	if d.opts.Access == nil || dataroomID == "" {
		return false
	}
	rights := d.rightsOf(dataroomID, false)

	return rights == nil || rights.state.Load() != rightsWritable
}

// rightsOf returns what the driver knows of the rights in the dataroom, nil
// when it holds nothing and create is false.
func (d *driver) rightsOf(dataroomID string, create bool) *dataroomRights {
	held, ok := d.rights.Load(dataroomID)
	if !ok {
		if !create {
			return nil
		}
		held, _ = d.rights.LoadOrStore(dataroomID, &dataroomRights{})
	}
	rights, _ := held.(*dataroomRights)

	return rights
}

// learnAccess asks Options.Access what the user may do in the dataroom, until
// it has answered once. A failure leaves the dataroom as it was, read-only
// for the writes and open to the reads, and is reported once; the next
// access asks again.
func (d *driver) learnAccess(ctx context.Context, dataroomID string) {
	if d.opts.Access == nil || d.opts.ReadOnly || dataroomID == "" {
		return
	}
	rights := d.rightsOf(dataroomID, true)
	if rights.state.Load() != rightsUnknown {
		return
	}
	rights.asking.Lock()
	defer rights.asking.Unlock()
	if rights.state.Load() != rightsUnknown {
		return
	}
	access, err := d.opts.Access(ctx, dataroomID)
	switch {
	case err != nil:
		if !rights.failed && ctx.Err() == nil {
			rights.failed = true
			d.logf("dataroom %s: cannot tell whether it is writable, writes are refused until it can be told: %s",
				dataroomID, errnoName(toErrno(err)))
		}
	case access.ReadOnly:
		rights.state.Store(rightsReadOnly)
		d.logf("dataroom %s is read-only: %s", dataroomID, access.Reason())
	default:
		rights.state.Store(rightsWritable)
		if rights.failed {
			d.logf("dataroom %s is writable", dataroomID)
		}
	}
}

// logf reports a message to the operator through Options.Logf, if any.
func (d *driver) logf(format string, args ...any) {
	if d.opts.Logf != nil {
		d.opts.Logf(format, args...)
	}
}

// checkDataroom reports whether the driver serves the dataroom (see
// Options.CheckDataroom), and learns what the user may do in one it serves
// (see Options.Access).
func (d *driver) checkDataroom(ctx context.Context, dataroomID string) error {
	if err := d.served(ctx, dataroomID); err != nil {
		return err
	}
	d.learnAccess(ctx, dataroomID)

	return nil
}

// served reports whether the driver serves the dataroom.
func (d *driver) served(ctx context.Context, dataroomID string) error {
	if d.opts.CheckDataroom == nil {
		return nil
	}
	if _, ok := d.usable.Load(dataroomID); ok {
		return nil
	}
	err := d.opts.CheckDataroom(ctx, dataroomID)
	if err == nil {
		d.usable.Store(dataroomID, struct{}{})

		return nil
	}
	if _, told := d.reported.LoadOrStore(dataroomID, struct{}{}); !told && ctx.Err() == nil {
		d.logf("dataroom %s is not served: %s", dataroomID, err)
	}

	return err
}

// call is one FUSE operation in progress: what the access log and the
// retycfs_ops_* metrics say of it, and the recovery of a handler that
// panics.
type call struct {
	drv   *driver
	rec   accessRecord
	start time.Time
	// release ends the watch of the request's context (see call.guard).
	release func()
}

// begin opens the record of operation op on inode ino. Its end must be
// deferred, directly:
//
//	c := d.begin("lookup", ino)
//	defer c.end(&errno)
func (d *driver) begin(op string, ino uint64) *call {
	now := time.Now()

	return &call{drv: d, start: now, rec: accessRecord{at: now, op: op, ino: ino}}
}

// ranged adds the offset and the length of a read to the record.
func (c *call) ranged(off int64, size int) {
	c.rec.off, c.rec.size, c.rec.ranged = off, size, true
}

// end closes the record with the errno the handler returns, and turns a
// panic of the handler into EIO: the stack goes to the operator, the mount
// stays up. It must be the deferred function itself, or recover sees nothing.
func (c *call) end(errno *syscall.Errno) {
	if c.release != nil {
		c.release()
	}
	if r := recover(); r != nil {
		*errno = syscall.EIO
		c.drv.logf("panic in the %s handler: %v\n%s", c.rec.op, r, debug.Stack())
	}
	c.rec.duration = time.Since(c.start)
	c.rec.errno = *errno
	c.drv.log.record(c.rec)
	metrics.Ops.WithLabelValues(c.rec.op, resultLabel(*errno)).Inc()
	metrics.OpDuration.WithLabelValues(c.rec.op).Observe(c.rec.duration.Seconds())
}

// startSpan opens the span of an operation that may reach the API: a root
// "FUSE <op>", kept only if it did (see telemetry.UsedSpan). It carries the
// operation and identifiers, never a name or a path.
func startSpan(ctx context.Context, op, dataroomID, nodeID string) (context.Context, telemetry.UsedSpan) {
	attrs := []attribute.KeyValue{telemetry.AttrFuseOp.String(op)}
	if dataroomID != "" {
		attrs = append(attrs, telemetry.AttrDataroomID.String(dataroomID))
	}
	if nodeID != "" {
		attrs = append(attrs, telemetry.AttrNodeID.String(nodeID))
	}

	return telemetry.StartUsedRoot(ctx, "FUSE "+op,
		trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attrs...))
}

// unlessErrno returns err for the span of an operation, or nil when the
// operation answers it with the errno expected: that answer is the result
// asked for, not a failure. A lookup is how a program asks whether a name
// exists, and most are answered ENOENT (the probes of a shell, of an editor,
// of a build): recorded as errors, they would bury the real ones.
func unlessErrno(err error, expected syscall.Errno) error {
	if err != nil && pathErrno(err) == expected {
		return nil
	}

	return err
}

// notifier tells the kernel what changed elsewhere, from a goroutine of its
// own.
//
// A notification must never be sent from the handler of a request on the
// inode it names, nor on its parent: the kernel takes for it the lock the
// request already holds, and both wait for each other. Handlers queue, this
// goroutine sends. The one exception is contentNow.
//
// A notification that waits is not queued twice: while one the kernel is slow
// to take holds the queue back, the same change seen again and again would
// otherwise fill it.
type notifier struct {
	queue chan func()
	done  chan struct{}

	mu      sync.RWMutex
	stopped bool

	// waiting holds the notifications queued and not sent yet.
	pending sync.Mutex
	waiting map[notification]struct{}
}

// notification identifies what a notification says: the pages of inode, or,
// with a name, the entry name of the folder inode.
type notification struct {
	inode *fs.Inode
	name  string
	entry bool
}

// notifyBacklog bounds the notifications waiting to be sent. One that does
// not fit is dropped: the kernel then learns of the change when its own
// cache expires, which is the rule without notifications.
const notifyBacklog = 4096

// contentNowWait bounds the wait of contentNow.
const contentNowWait = 2 * time.Second

func newNotifier() *notifier {
	n := &notifier{
		queue:   make(chan func(), notifyBacklog),
		done:    make(chan struct{}),
		waiting: make(map[notification]struct{}),
	}
	go func() {
		defer close(n.done)
		for send := range n.queue {
			send()
		}
	}()

	return n
}

// content asks the kernel to drop the pages and the attributes it caches for
// inode.
func (n *notifier) content(inode *fs.Inode) {
	if inode != nil {
		n.once(notification{inode: inode}, func() { _ = inode.NotifyContent(0, -1) })
	}
}

// contentNow does what content does and returns once the kernel has done it,
// or after contentNowWait. It is for the handler of an OPEN alone, which must
// not answer before the kernel has dropped the size it knew: the kernel
// bounds the reads of the new handle by it.
//
// An OPEN for reading holds no lock the notification takes: the kernel takes
// neither the lock of the inode nor one of its pages to send it, and what the
// invalidation waits for is the pages locked by reads in flight, which other
// goroutines answer. Those can be as slow as a download, hence the bound: past
// it the handler answers and the notification lands when it can.
func (n *notifier) contentNow(inode *fs.Inode) {
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		_ = inode.NotifyContent(0, -1)
	}()
	timer := time.NewTimer(contentNowWait)
	defer timer.Stop()
	select {
	case <-sent:
	case <-timer.C:
	}
}

// entry asks the kernel to drop what it caches for name in the folder dir.
func (n *notifier) entry(dir *fs.Inode, name string) {
	n.once(notification{inode: dir, name: name, entry: true}, func() { _ = dir.NotifyEntry(name) })
}

// once queues fn, which sends the notification what, unless one is already
// waiting to be sent. It stops waiting just before it is sent: a change seen
// while the kernel takes it is queued again.
func (n *notifier) once(what notification, fn func()) {
	n.pending.Lock()
	_, queued := n.waiting[what]
	if !queued {
		n.waiting[what] = struct{}{}
	}
	n.pending.Unlock()
	if queued {
		return
	}
	forget := func() {
		n.pending.Lock()
		delete(n.waiting, what)
		n.pending.Unlock()
	}
	if !n.send(func() { forget(); fn() }) {
		forget()
	}
}

// send queues fn, and reports whether it did.
func (n *notifier) send(fn func()) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.stopped {
		return false
	}
	select {
	case n.queue <- fn:
		return true
	default:
		return false
	}
}

// flush waits until the notifications queued so far are sent.
func (n *notifier) flush() {
	sent := make(chan struct{})
	if !n.send(func() { close(sent) }) {
		return
	}
	select {
	case <-sent:
	case <-n.done:
	}
}

// stop sends what is queued and ends the goroutine.
func (n *notifier) stop() {
	n.mu.Lock()
	if !n.stopped {
		n.stopped = true
		close(n.queue)
	}
	n.mu.Unlock()
	<-n.done
}

// pending counts what a shutdown would still send: the files whose spool
// holds changes not sent (local files excepted, they are never sent) and
// the background deletes not ended.
func (d *driver) pending() (files, deletes int) {
	for _, sp := range d.spools.open() {
		if !sp.local.Load() && sp.spool.Dirty() {
			files++
		}
	}
	if q := d.deletes; q != nil {
		q.mu.Lock()
		deletes = len(q.jobs)
		q.mu.Unlock()
	}

	return files, deletes
}
