//go:build linux

package retycfs

import (
	"context"
	"errors"
	"io"
	"math"
	"strconv"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// fileNode is a regular file.
type fileNode struct {
	base
}

var (
	_ fs.NodeOpener         = (*fileNode)(nil)
	_ fs.NodeReader         = (*fileNode)(nil)
	_ fs.NodeWriter         = (*fileNode)(nil)
	_ fs.NodeFlusher        = (*fileNode)(nil)
	_ fs.NodeFsyncer        = (*fileNode)(nil)
	_ fs.NodeReleaser       = (*fileNode)(nil)
	_ fs.NodeCopyFileRanger = (*fileNode)(nil)
)

// spoolHandle is a handle on a file being written: one reference on the spool
// of its inode (see openSpool). Every handle opened while the spool lives is
// one, those opened for reading included: they read what is being written.
type spoolHandle struct {
	sp *openSpool
	// writable: the handle was opened for writing. appends: with O_APPEND.
	writable bool
	appends  bool
	// sends: the handle changes the file (opened for writing, or with
	// O_TRUNC), so its flush, its fsync and its release send the spool. A
	// handle that only reads a file being written sends nothing: closing it
	// must not store a version of what another process is still writing.
	sends bool
	// locked: the handle is one of those the API lock of the inode stands
	// for (see fileNode.lockForWrite).
	locked bool
}

// handleKind is the kind a file handle counts as in
// retyc_cli_fuse_open_handles: write for one that changes its file.
func handleKind(fh fs.FileHandle) string {
	if h, ok := fh.(*spoolHandle); ok && h.sends {
		return "write"
	}

	return "read"
}

// countHandle counts a handle the kernel was just given.
func countHandle(fh fs.FileHandle) {
	metrics.FuseOpenHandles.WithLabelValues(handleKind(fh)).Inc()
}

// fileHandle is a file open for reading: the version it was opened on, which
// it reads to its end whatever becomes of the file (see vfs.File).
type fileHandle struct {
	file    vfs.File
	version string
}

// Open opens the current version of the file for reading.
//
// Close-to-open consistency: the version opened is not the one the inode
// table remembers but the one vfs.FS.Lookup answers at that moment, so a file
// replaced elsewhere is read in its new version by an open that follows.
// Lookup costs nothing when the listing of the folder, or the entry of the
// name, is younger than the cache TTL, and one request otherwise. How old the
// answer may be is therefore the TTL, provided the FS never serves an expired
// listing (vfs.Options.MaxStale zero, which is what `retyc fs mount` sets):
// Lookup answers a name an expired listing holds from that listing, and
// nothing tells the caller.
//
// The kernel keeps the pages it holds for the inode (FOPEN_KEEP_CACHE) only
// when they are of the version opened: a version never changes, so its pages
// never go stale. A handle opened while another one still reads an older
// version does not use the page cache at all (FOPEN_DIRECT_IO, see
// inodeState.opened).
func (n *fileNode) Open(
	ctx context.Context, flags uint32,
) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	c := n.drv.begin("open", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)
	defer func() {
		if errno == 0 && fh != nil {
			countHandle(fh)
		}
	}()

	st := n.state()
	truncate := flags&syscall.O_TRUNC != 0
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY || truncate {
		if n.drv.readOnly(n.dataroomID) {
			return nil, 0, syscall.EROFS
		}

		return n.openForWrite(ctx, st, flags)
	}
	// A file being written is read from its spool, by every handle opened
	// from then on.
	if sp := st.join(); sp != nil {
		return &spoolHandle{sp: sp}, fuse.FOPEN_DIRECT_IO, 0
	}

	ctx, span := startSpan(ctx, "open", n.dataroomID, n.seed.ID)
	node, file, err := n.open(ctx, st)
	if err == nil {
		span.Span().SetAttributes(telemetry.AttrVersionID.String(node.VersionID))
	}
	span.End(err)
	if err != nil {
		return nil, 0, pathErrno(err)
	}

	switch keepCache, direct := st.opened(n.EmbeddedInode(), node.VersionID); {
	case direct:
		fuseFlags = fuse.FOPEN_DIRECT_IO
	case keepCache && !n.drv.opts.NoKernelCache:
		fuseFlags = fuse.FOPEN_KEEP_CACHE
	}

	return &fileHandle{file: file, version: node.VersionID}, fuseFlags, 0
}

// openForWrite opens the file for writing: on the spool of its inode, which
// the first such open creates (vfs.FS.OpenSpool, no request) and the others
// share. O_TRUNC arrives here as a flag (CAP_ATOMIC_O_TRUNC) and is passed
// on: the spool starts empty and nothing of the version is downloaded.
// Without it nothing is downloaded either until the first read or write.
//
// The handle is FOPEN_DIRECT_IO: the page cache belongs to the inode, and
// may hold pages of the version the file had, which a handle opened before
// goes on reading. Reads and writes go to the spool, at the offsets asked.
//
// With Options.MirrorLocks the API lock of the file is taken first, before
// anything is truncated: a file another client locked is refused (EBUSY) as
// it was found.
func (n *fileNode) openForWrite(
	ctx context.Context, st *inodeState, flags uint32,
) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	truncate := flags&syscall.O_TRUNC != 0
	h := &spoolHandle{
		writable: flags&syscall.O_ACCMODE != syscall.O_RDONLY,
		appends:  flags&syscall.O_APPEND != 0,
		sends:    true,
	}
	locked, err := n.lockForWrite(ctx, st)
	if err != nil {
		return nil, 0, toErrno(err)
	}
	h.locked = locked
	sp := st.join()
	if sp == nil {
		ctx, span := startSpan(ctx, "open", n.dataroomID, n.seed.ID)
		var err error
		sp, err = n.openSpool(ctx, st, truncate)
		span.End(err)
		if err != nil {
			n.unlockWrite(ctx, st, locked)

			return nil, 0, pathErrno(err)
		}
	} else if truncate {
		if err := sp.spool.Truncate(0); err != nil {
			sp.release(ctx, false)
			n.unlockWrite(ctx, st, locked)

			return nil, 0, toErrno(err)
		}
	}
	sp.write()
	h.sp = sp

	return h, fuse.FOPEN_DIRECT_IO, 0
}

// lockReleaseTimeout bounds the release of an API lock, which nothing waits
// for but the RELEASE that asks for it.
const lockReleaseTimeout = 10 * time.Second

// lockForWrite counts one more handle opened for writing on the API lock of
// the file, and takes that lock when none is held (Options.MirrorLocks). It
// reports whether the handle is counted: unlockWrite must then be called once
// for it.
//
// There is one lock per inode, not per handle: the API holds one lock per
// token and would refuse the second handle of a single process. The lock is
// taken at the longest lease and renewed by vfs.LockManager.Run for as long
// as it is held (no expiry: it stands until it is released, or until the
// mount stops).
//
// A file that has no node at the API takes none: one created through the
// mount and not flushed yet, or one unlinked here. Such a file gets no lock
// when its first flush stores it either; the next open for writing takes one.
//
// The error is api.ErrLocked when another client holds the file (EBUSY), or
// the one of a request interrupted (EINTR). Any other failure of the API is
// reported and the file opened without a lock, as WebDAV grants a LOCK the
// API could not mirror: the lock is a courtesy to other clients, no write
// depends on it. The next open for writing asks again, and so does the one
// that follows the loss of the lock: when the API neither renewed it nor gave
// it again (vfs.LockManager drops it then), the handles already open go on
// without it, and the next one opened takes it anew, or is refused when
// another client took the file meanwhile.
func (n *fileNode) lockForWrite(ctx context.Context, st *inodeState) (bool, error) {
	if !n.drv.opts.MirrorLocks {
		return false, nil
	}
	node, unlinked := st.view()
	if node.ID == "" || unlinked {
		return false, nil
	}

	l := &st.lock
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.key != "" && !n.drv.tree.Locks().Holds(l.key) {
		// Lost at a renewal: nothing stands behind the key any more.
		l.key = ""
	}
	if l.key == "" {
		key := "fuse:" + strconv.FormatUint(n.ino, 10) + ":" + strconv.FormatUint(n.drv.lockKeys.Add(1), 10)
		// The label is what the manager names the file by in what it reports:
		// an ID, never a name.
		err := n.drv.tree.Locks().Take(ctx, key, node.ID, "node "+node.ID, time.Time{})
		switch {
		case err == nil:
			l.key = key
		case errors.Is(err, api.ErrLocked), ctx.Err() != nil:
			return false, err
		default:
			n.drv.logf("the API lock of a file could not be taken, it is opened without it: dataroom %s, node %q, inode %d: %s",
				n.dataroomID, node.ID, n.ino, errnoName(toErrno(err)))
		}
	}
	l.refs++

	return true, nil
}

// unlockWrite ends what lockForWrite counted for one handle (counted is what
// it reported), and releases the API lock with the last of them. The request
// does not follow the cancellation of ctx: a lock left behind would stand
// until its lease ends.
func (n *fileNode) unlockWrite(ctx context.Context, st *inodeState, counted bool) {
	if !counted {
		return
	}
	l := &st.lock
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refs--
	if l.refs > 0 || l.key == "" {
		return
	}
	key := l.key
	l.key = ""
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lockReleaseTimeout)
	defer cancel()
	n.drv.tree.Locks().Release(ctx, key)
}

// openSpool returns the spool of the inode with one more reference, creating
// it on the node the name resolves to now (close-to-open, like a read). A
// spool another open created meanwhile is the one returned, truncated when
// asked.
func (n *fileNode) openSpool(ctx context.Context, st *inodeState, truncate bool) (*openSpool, error) {
	node, err := n.revalidate(ctx, st, false)
	if err != nil {
		return nil, err
	}
	path, ok := n.drv.pathAt(st.where())
	if !ok {
		return nil, errStale
	}
	if n.drv.spools.isSealed() {
		return nil, errGoingAway
	}
	spool, err := n.drv.tree.OpenSpool(ctx, n.dataroomID, path, &node, truncate)
	if err != nil {
		return nil, err
	}
	sp, mine := st.attach(n.drv.newOpenSpool(st, n.ino, n.dataroomID, spool), n.EmbeddedInode())
	if mine {
		if err := n.drv.register(sp, st.where()); err != nil {
			return nil, err
		}

		return sp, nil
	}
	_ = spool.Close()
	if truncate {
		if err := sp.spool.Truncate(0); err != nil {
			sp.release(ctx, false)

			return nil, err
		}
	}

	return sp, nil
}

// open revalidates the node and opens its version. The error is the one of
// vfs, or errStale (see revalidate).
func (n *fileNode) open(ctx context.Context, st *inodeState) (vfs.Node, vfs.File, error) {
	node, err := n.revalidate(ctx, st, true)
	if err != nil {
		return vfs.Node{}, nil, err
	}
	file, err := n.drv.tree.Open(ctx, n.dataroomID, node)

	return node, file, err
}

// revalidate returns the node the name of the file resolves to now, and
// records it. A name that is gone, or that names another node, has its entry
// dropped from the kernel: ENOENT for the first, ESTALE for the second, on
// which the kernel resolves the path again and reaches the new node.
//
// The name asked about is the one vfs last found the file under (see
// inodeState.at), then the one it found it under before: a lookup answered
// from a listing older than a move puts the old place first. A file the table
// holds no place for is ESTALE.
//
// When the version is not the one the kernel was told of, the kernel drops
// what it caches for the inode before the open is answered (see
// notifier.contentNow): its size above all, which is what it bounds the reads
// of the new handle by. That is for an open for reading (wait): one for
// writing reads around the page cache, may hold the lock of the inode
// (O_TRUNC), and is told later like any other change.
func (n *fileNode) revalidate(ctx context.Context, st *inodeState, wait bool) (vfs.Node, error) {
	known := st.current()
	missing := errStale
	for range 2 {
		at := st.where()
		if !at.known() {
			break
		}
		dir, ok := at.parent.Operations().(*dirNode)
		if !ok {
			break
		}
		seen := n.drv.stamp()
		var node vfs.Node
		err := dir.withPath(ctx, func(path string) (err error) {
			node, err = n.drv.tree.Lookup(ctx, n.dataroomID, path, at.name)

			return err
		})
		switch {
		case err == nil && node.ID == known.ID && node.Type == vfs.TypeFile:
			st.observe(node, at, seen)
			switch {
			case node.VersionID == known.VersionID:
			case wait:
				n.drv.notify.contentNow(n.EmbeddedInode())
			default:
				n.drv.notify.content(n.EmbeddedInode())
			}

			return node, nil
		case err != nil && toErrno(err) != syscall.ENOENT:
			return vfs.Node{}, err
		}
		n.drv.notify.entry(at.parent, at.name)
		if missing = err; err == nil {
			missing = errStale
		}
		if !st.relocate(at) {
			break
		}
	}

	return vfs.Node{}, missing
}

// Read reads from the version the handle was opened on, with the guarded
// context of the request (see driver.guard): a signal the reader handles
// interrupts nothing, the kill of the reader ends this read only, the
// download it waited for goes on for the others.
//
// A read that fails returns no byte, even when some were read: the page cache
// takes a short read for the end of the file.
func (n *fileNode) Read(
	ctx context.Context, fh fs.FileHandle, dest []byte, off int64,
) (res fuse.ReadResult, errno syscall.Errno) {
	c := n.drv.begin("read", n.ino)
	c.ranged(off, len(dest))
	defer c.end(&errno)
	ctx = c.guard(ctx)

	if h, ok := fh.(*spoolHandle); ok {
		// The spool brings the version in at its first read, whole, and
		// cannot be interrupted while it does.
		read, err := h.sp.spool.ReadAt(dest, off)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, toErrno(err)
		}

		metrics.FuseBytes.WithLabelValues("read").Add(float64(read))

		return fuse.ReadResultData(dest[:read]), 0
	}
	h, ok := fh.(*fileHandle)
	if !ok {
		return nil, syscall.EBADF
	}
	ctx, span := startSpan(ctx, "read", n.dataroomID, n.seed.ID)
	span.Span().SetAttributes(telemetry.AttrVersionID.String(h.version))
	read, err := h.file.ReadAtContext(ctx, dest, off)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	span.End(err)
	if err != nil {
		return nil, toErrno(err)
	}
	metrics.FuseBytes.WithLabelValues("read").Add(float64(read))

	return fuse.ReadResultData(dest[:read]), 0
}

// Write stores data in the spool of the file. Nothing goes to the API before
// a flush: the API takes a version whole, with its size first.
//
// A handle opened with O_APPEND writes at the end of the spool, whatever
// offset the kernel computed from the size it knew.
func (n *fileNode) Write(
	_ context.Context, fh fs.FileHandle, data []byte, off int64,
) (written uint32, errno syscall.Errno) {
	c := n.drv.begin("write", n.ino)
	c.ranged(off, len(data))
	defer c.end(&errno)

	h, ok := fh.(*spoolHandle)
	if !ok || !h.writable {
		return 0, syscall.EBADF
	}
	if h.appends {
		h.sp.appending.Lock()
		defer h.sp.appending.Unlock()
		off = h.sp.spool.Size()
	}
	// Before the bytes are there: a flush never finds them unannounced.
	h.sp.changed()
	count, err := h.sp.spool.WriteAt(data, off)
	if count == 0 && err != nil {
		return 0, toErrno(err)
	}

	metrics.FuseBytes.WithLabelValues("write").Add(float64(count))

	// A short write: the caller gets the error at its next one.
	return uint32(count), 0 //nolint:gosec // G115: bounded by the size of a request
}

// Flush is the close(2) of one descriptor opened for writing: the spool is
// sent as a new version when it changed, and the error is what close returns
// (ENOSPC for a dataroom or a spool with no room left, EACCES for a refusal).
// It costs nothing when the spool is clean, and sends nothing for a
// descriptor that only reads the file (see spoolHandle.sends).
//
// Nor does it send a file that was created or truncated by its open and not
// changed since (see openSpool.unwritten): the release of the last handle
// does, and a failure is then reported as a loss, close having answered.
// fsync sends it in any case. A local file (Options.LocalFiles) is never
// sent, by a close or by an fsync.
//
// The guarded context of the request bounds it (see driver.guard): a signal
// the program handles does not interrupt its close, which never answers
// EINTR; the kill of the program cancels the upload and leaves the spool as
// it was, for the release, which sends it.
func (n *fileNode) Flush(ctx context.Context, fh fs.FileHandle) (errno syscall.Errno) {
	c := n.drv.begin("flush", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	return n.sync(ctx, "flush", fh)
}

// Fsync sends the spool like a flush: once it returns, the content is a
// version at the API.
func (n *fileNode) Fsync(ctx context.Context, fh fs.FileHandle, _ uint32) (errno syscall.Errno) {
	c := n.drv.begin("fsync", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	return n.sync(ctx, "fsync", fh)
}

// sync flushes the spool of the handle. A handle that reads a version (opened
// before the file was written here) holds no spool and has nothing to send;
// one that reads the spool leaves it to the handles that write it.
func (n *fileNode) sync(ctx context.Context, op string, fh fs.FileHandle) syscall.Errno {
	h, ok := fh.(*spoolHandle)
	if !ok || !h.sends {
		return 0
	}
	sp := h.sp
	if op == "flush" && sp.unwritten() {
		return 0
	}
	ctx, span := startSpan(ctx, op, n.dataroomID, n.seed.ID)
	err := sp.flush(ctx)
	span.End(err)

	return toErrno(err)
}

// CopyFileRange makes the destination a server-side copy of the file when
// the call is the copy of a whole file into a new one, which is what cp(1)
// asks: the storage duplicates the chunks, nothing is downloaded and nothing
// is sent (vfs.Spool.CopyFrom, one request). That takes all of:
//
//   - both files in one dataroom, which the user may write to;
//   - the range starts at offset 0 of both and covers the whole source;
//   - the source is read at its current version, and is not being written
//     here (a spool that has changes to send);
//   - the destination was created through this mount and holds nothing yet:
//     no node at the API, no byte written. A file that exists is not replaced
//     this way: the API copies into a new node only, so its versions would go
//     with the node deleted to make room.
//
// Anything else is EXDEV, on which the kernel copies the bytes itself through
// reads and writes; so is a copy the API refused for a reason the bytes
// might not meet. ENOSYS would turn the operation off for the life of the
// mount.
//
// The copy keeps the modification time of its source, as cp -p would, and its
// mode at the API until the file is released: see openSpool.copied.
func (n *fileNode) CopyFileRange(
	ctx context.Context, fhIn fs.FileHandle, offIn uint64,
	out *fs.Inode, fhOut fs.FileHandle, offOut uint64, length uint64, _ uint64,
) (copied uint32, errno syscall.Errno) {
	c := n.drv.begin("copy_file_range", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	dst, ok := fhOut.(*spoolHandle)
	if !ok || !dst.writable || offIn != 0 || offOut != 0 || n.drv.readOnly(n.dataroomID) {
		return 0, syscall.EXDEV
	}
	if to, ok := out.Operations().(*fileNode); !ok || to.dataroomID != n.dataroomID {
		return 0, syscall.EXDEV
	}
	sp := dst.sp
	// A local file is never a node: the bytes are copied into it instead.
	if !sp.pending() || sp.spool.Size() != 0 || sp.local.Load() {
		return 0, syscall.EXDEV
	}

	ctx, span := startSpan(ctx, "copy_file_range", n.dataroomID, n.seed.ID)
	node, err := n.copyInto(ctx, fhIn, length, sp)
	span.End(err)
	switch {
	case err == nil && node.ID != "":
		return uint32(min(uint64(node.Size), length)), 0 //nolint:gosec // G115: the kernel bounds length to 32 bits
	case errors.Is(err, api.ErrRateLimited):
		return 0, syscall.EIO
	}
	switch errno := pathErrno(err); errno {
	case syscall.ENOSPC, syscall.EACCES, syscall.EINTR:
		// The bytes would meet the same refusal, after a download.
		return 0, errno
	}

	return 0, syscall.EXDEV
}

// errNotWholeFile is the error of a copy_file_range that is not the copy of
// a whole file at its current version.
var errNotWholeFile = errors.New("retycfs: not the copy of a whole file")

// copyInto makes the pending spool sp the server-side copy of the file, when
// length covers the version the handle fhIn reads and that version is the
// current one. A zero node and no error: the destination was unlinked
// meanwhile.
func (n *fileNode) copyInto(ctx context.Context, fhIn fs.FileHandle, length uint64, sp *openSpool) (vfs.Node, error) {
	st := n.state()
	version := ""
	switch h := fhIn.(type) {
	case *fileHandle:
		version = h.version
	case *spoolHandle:
		// A file written here a moment ago, whose spool has nothing left to
		// send: its version is the one of its last flush.
		held, exists := h.sp.spool.Node()
		if !exists || h.sp.spool.Dirty() {
			return vfs.Node{}, errNotWholeFile
		}
		version = held.VersionID
	}
	if held := st.held(); held != nil && held.spool.Dirty() {
		return vfs.Node{}, errNotWholeFile
	}
	src, err := n.revalidate(ctx, st, false)
	if err != nil {
		return vfs.Node{}, err
	}
	// The answer to the kernel counts the bytes copied on 32 bits.
	if version == "" || src.VersionID != version || src.Size <= 0 || src.Size > math.MaxUint32 ||
		uint64(src.Size) > length {
		return vfs.Node{}, errNotWholeFile
	}
	srcPath, ok := n.drv.pathAt(st.where())
	if !ok {
		return vfs.Node{}, errStale
	}

	// Like a flush: the copy gives the file its node (see openSpool.sending).
	if err := sp.send(ctx); err != nil {
		return vfs.Node{}, err
	}
	defer sp.sent()
	// The copy creates the node: see openSpool.flush.
	if err := sp.drv.deletes.waitAt(ctx, sp.st.where()); err != nil {
		return vfs.Node{}, err
	}
	node, err := sp.spool.CopyFrom(ctx, srcPath)
	if err != nil {
		return vfs.Node{}, err
	}
	sp.changed()
	sp.copied(node)

	return node, nil
}

// Release closes the handle. One that read a version the file no longer has
// may have filled the page cache with it: those pages are dropped. The last
// handle of a file being written flushes its spool once more and closes it
// (see openSpool.release); the last one opened for writing then releases the
// API lock of the file, if it holds one, once that flush is over.
func (n *fileNode) Release(ctx context.Context, fh fs.FileHandle) (errno syscall.Errno) {
	c := n.drv.begin("release", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)
	if fh != nil {
		metrics.FuseOpenHandles.WithLabelValues(handleKind(fh)).Dec()
	}

	if h, ok := fh.(*spoolHandle); ok {
		ctx, span := startSpan(ctx, "release", n.dataroomID, n.seed.ID)
		h.sp.release(ctx, h.sends)
		n.unlockWrite(ctx, h.sp.st, h.locked)
		span.End(nil)

		return 0
	}
	h, ok := fh.(*fileHandle)
	if !ok {
		return 0
	}
	_ = h.file.Close()
	n.drv.notify.content(n.state().released(h.version))

	return 0
}
