//go:build linux

package retycfs

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// openSpool is the one vfs.Spool of an inode: the local copy every handle
// opened for writing on the inode writes to, and every handle opened since
// reads from. It is counted by reference; the release of the last handle
// flushes it and closes it.
//
// While it lives it answers for the inode: size and modification time
// (inodeState.view), content, truncation. A handle opened for reading before
// it keeps the version it opened (fileHandle).
type openSpool struct {
	drv        *driver
	st         *inodeState
	ino        uint64
	dataroomID string
	spool      vfs.Spool

	// appending serializes the writes of the handles opened with O_APPEND:
	// each lands at the size the one before left.
	appending sync.Mutex

	// changes counts what was done to the content since the spool was opened
	// (see changed), flushed is what it counted when the last flush that
	// succeeded began: a spool where both are equal holds nothing but what
	// its opens left there, a file created or truncated by open(2).
	changes atomic.Uint64
	flushed atomic.Uint64

	// local marks a local file (Options.LocalFiles): a file created here that
	// the API never hears of. Nothing sends it (flush), it outlives its
	// handles (release) until it is unlinked or the mount ends, and it is no
	// loss then (retire). It is set before the spool is registered, and
	// cleared for good by the rename that makes the file an ordinary one
	// (dirNode.Rename).
	local atomic.Bool

	// sending is held around what may give the file its node at the API (a
	// flush, a server-side copy), from the request to the record of its
	// outcome in the inode table: whoever holds it reads there whether the
	// API holds the file (see settled). It holds one token.
	sending chan struct{}

	// refs counts the handles, writers those of them that send the spool
	// (see spoolHandle.sends), closing the releases of a last handle that
	// are still flushing. All are guarded by st.mu.
	refs    int
	writers int
	closing int
	// flushErr is the error of the last flush that failed, nil once one
	// succeeded since: what close reports when the spool goes with changes
	// nothing sent. Guarded by st.mu.
	flushErr error

	// modeOwed: the file has, here, a mode its node does not carry yet (see
	// stored). It is sent when the file is released (settleMode), unless a
	// chmod settles it first. Guarded by st.mu.
	modeOwed bool
	// moding serializes the requests that store the mode of the file while
	// the spool lives: a chmod, and the release that sends a mode owed.
	moding sync.Mutex

	// at is where the registry of the driver holds the spool. Guarded by
	// spoolRegistry.mu.
	at location
}

// spoolRegistry holds the spools open on a mount: all of them, and by place
// those whose file has a name. The place is what a lookup, a listing, an
// unlink and a rename find a file being written by, before asking vfs: a file
// created here and not flushed yet exists nowhere else.
type spoolRegistry struct {
	mu   sync.Mutex
	all  map[*openSpool]struct{}
	byAt map[location]*openSpool
	// created numbers the files created through the mount.
	created uint64
	// sealed is set once the shutdown closes the spools: none is added any
	// more (see seal).
	sealed bool
}

func newSpoolRegistry() *spoolRegistry {
	return &spoolRegistry{all: make(map[*openSpool]struct{}), byAt: make(map[location]*openSpool)}
}

// newOpenSpool returns the openSpool of the inode ino over spool, held by
// nothing yet (see inodeState.attach).
func (d *driver) newOpenSpool(st *inodeState, ino uint64, dataroomID string, spool vfs.Spool) *openSpool {
	if wrap := d.wrapSpool.Load(); wrap != nil {
		spool = (*wrap)(spool)
	}

	return &openSpool{
		drv: d, st: st, ino: ino, dataroomID: dataroomID, spool: spool,
		sending: make(chan struct{}, 1),
	}
}

// seal closes the registry, for good: from now on add refuses, and so do the
// opens for writing and the creations that would need a new spool
// (errGoingAway). It returns the spools open at that instant, which are all
// there will ever be.
//
// A shutdown seals it when it stops sending: a spool opened after the last
// ones were flushed and closed (on a mount detached while still in use)
// would be neither sent nor reported.
func (r *spoolRegistry) seal() []*openSpool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sealed = true
	out := make([]*openSpool, 0, len(r.all))
	for sp := range r.all {
		out = append(out, sp)
	}

	return out
}

// isSealed reports whether seal was called.
func (r *spoolRegistry) isSealed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.sealed
}

// pendingKey returns the inode table key of a file created through the mount,
// which has no node ID before its first flush. It cannot collide with one.
func (r *spoolRegistry) pendingKey() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.created++

	return "pending:" + strconv.FormatUint(r.created, 10)
}

// add registers sp at the place at, or nowhere when at names none. It
// registers nothing and reports false once the registry is sealed.
func (r *spoolRegistry) add(sp *openSpool, at location) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed {
		return false
	}
	r.all[sp] = struct{}{}
	if at.known() {
		sp.at = at
		r.byAt[at] = sp
	}

	return true
}

// register adds sp, which was just attached to its inode, to the registry at
// the place at. Once the shutdown has sealed the registry it takes the spool
// back from its inode and closes it instead, and returns errGoingAway: the
// file is not opened.
func (d *driver) register(sp *openSpool, at location) error {
	if d.spools.add(sp, at) {
		return nil
	}
	sp.st.mu.Lock()
	if sp.st.spool == sp {
		sp.st.spool = nil
	}
	sp.st.mu.Unlock()
	_ = sp.spool.Close()

	return errGoingAway
}

// unname takes sp away from its place: its file has no name any more.
func (r *spoolRegistry) unname(sp *openSpool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unnameLocked(sp)
}

func (r *spoolRegistry) unnameLocked(sp *openSpool) {
	if sp.at.known() && r.byAt[sp.at] == sp {
		delete(r.byAt, sp.at)
	}
	sp.at = location{}
}

// drop forgets sp, and returns the place it was at.
func (r *spoolRegistry) drop(sp *openSpool) location {
	r.mu.Lock()
	defer r.mu.Unlock()
	at := sp.at
	r.unnameLocked(sp)
	delete(r.all, sp)

	return at
}

// move records that the file of sp is now at the place to. A spool the
// registry dropped meanwhile stays out: it is closed, and would answer for
// the name for good.
func (r *spoolRegistry) move(sp *openSpool, to location) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, open := r.all[sp]; !open {
		return
	}
	r.unnameLocked(sp)
	sp.at = to
	r.byAt[to] = sp
}

// find returns the spool of the file at the place at, nil when none is open.
//
// A local file may be asked for long after its last handle was closed, by
// when the kernel may have forgotten the inode of its folder and been given
// another for it: the place it is held at then names the folder by an inode
// that is no longer the live one. Such a file is found by the inode number
// of the folder, and moved to the place asked about.
func (r *spoolRegistry) find(at location) *openSpool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sp := r.byAt[at]; sp != nil || !at.known() {
		return sp
	}
	for held, sp := range r.byAt {
		if held.name == at.name && sp.local.Load() && sameDir(held.parent, at.parent) {
			delete(r.byAt, held)
			sp.at = at
			r.byAt[at] = sp

			return sp
		}
	}

	return nil
}

// sameDir reports whether a and b are inodes of one folder: the same inode,
// or two the kernel was given for one inode number, the first forgotten since.
func sameDir(a, b *fs.Inode) bool {
	return a == b || (a != nil && b != nil && a.StableAttr().Ino == b.StableAttr().Ino)
}

// folders returns the inode numbers of the folders the named spools are in:
// sameDir finds a local file by that number once the kernel has forgotten
// the inode of its folder, so the inode table keeps it (inodeTable.pins).
func (r *spoolRegistry) folders() map[uint64]struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[uint64]struct{}, len(r.byAt))
	for at := range r.byAt {
		out[at.parent.StableAttr().Ino] = struct{}{}
	}

	return out
}

// named returns the spools whose file has a name.
func (r *spoolRegistry) named() map[location]*openSpool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[location]*openSpool, len(r.byAt))
	for at, sp := range r.byAt {
		out[at] = sp
	}

	return out
}

// open returns every spool open.
func (r *spoolRegistry) open() []*openSpool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*openSpool, 0, len(r.all))
	for sp := range r.all {
		out = append(out, sp)
	}

	return out
}

// hold takes a reference on the spool for an operation that finds it by its
// place and keeps it across a request (rename, unlink): the release of the
// last handle, which the kernel sends after close(2) has returned, then
// leaves the spool open, and the operation closes it when it lets go
// (letGo). Without it the operation would go on with a closed spool, and put
// it back in the registry.
//
// It returns nil, as for no spool, when sp is nil or no longer the spool of
// its inode.
func (sp *openSpool) hold() *openSpool {
	if sp == nil {
		return nil
	}
	sp.st.mu.Lock()
	defer sp.st.mu.Unlock()
	if sp.st.spool != sp {
		return nil
	}
	sp.refs++

	return sp
}

// letGo ends a hold. It does nothing on nil.
func (sp *openSpool) letGo(ctx context.Context) {
	if sp != nil {
		sp.release(ctx, false)
	}
}

// pending reports whether the file has nothing at the API yet: created here
// and never flushed.
func (sp *openSpool) pending() bool {
	_, exists := sp.spool.Node()
	_, unlinked := sp.st.view()

	return !exists && !unlinked
}

// entry returns the directory entry of the file as its spool knows it.
func (sp *openSpool) entry(seen uint64) dirEntry {
	node, _ := sp.st.view()

	return dirEntry{node: node, ino: sp.ino, dataroomID: sp.dataroomID, seen: seen, local: true}
}

// path returns the path of the file in its dataroom, from the place the
// inode table holds it at.
func (sp *openSpool) path() (string, bool) {
	return sp.drv.pathAt(sp.st.where())
}

// pathAt returns the path of the name at.name in the folder at.parent.
func (d *driver) pathAt(at location) (string, bool) {
	if !at.known() {
		return "", false
	}
	dir, ok := at.parent.Operations().(*dirNode)
	if !ok {
		return "", false
	}
	parent, ok := dir.path()
	if !ok {
		return "", false
	}

	return joinPath(parent, at.name), true
}

// joinPath returns the path of name in the folder at parent.
func joinPath(parent, name string) string {
	if parent == "/" {
		return "/" + name
	}

	return parent + "/" + name
}

// filePerm returns the permission bits the file node is presented with.
func (a attrSource) filePerm(node vfs.Node) os.FileMode {
	if !node.HasMode() {
		return os.FileMode(a.fileMode)
	}

	return node.Mode.Perm()
}

// changed records a change of the content asked for as such: a write, a
// truncation other than the one of an open, a server-side copy.
func (sp *openSpool) changed() { sp.changes.Add(1) }

// unwritten reports whether nothing changed the content since the spool was
// opened or last flushed, but the opens themselves: a file created, or
// truncated by O_TRUNC, and not written yet.
//
// The close of a descriptor does not send such a spool (fileNode.Flush). The
// kernel flushes at every close(2), of a duplicate too, and tells nothing of
// the descriptors left: a shell that runs `echo text > file` opens the file,
// duplicates the descriptor and closes the first one before it writes, which
// would store an empty version, then the one meant. The release of the last
// handle sends it (release): an empty file is created all the same.
func (sp *openSpool) unwritten() bool { return sp.changes.Load() == sp.flushed.Load() }

// flush sends the content of the spool as a new version when it changed, and
// records the outcome in the inode table. It is called by the flush(2) and
// the fsync(2) of the handles that write, and by the release of the last of
// them: a clean spool sends nothing.
//
// A file created through the mount gets its node here, with its mode: the
// spool declares it in the request that creates the node (vfs.Spool.SetMode).
//
// A local file is never sent: its flush does nothing.
func (sp *openSpool) flush(ctx context.Context) error {
	if sp.local.Load() {
		return nil
	}
	if err := sp.send(ctx); err != nil {
		sp.st.mu.Lock()
		sp.flushErr = err
		sp.st.mu.Unlock()

		return err
	}
	defer sp.sent()

	_, existed := sp.spool.Node()
	want, unlinked := sp.st.view()
	if !existed && !unlinked {
		// The first flush creates the node: the API must not hold its name
		// for a file whose delete is not sent yet (Options.BackgroundDelete).
		if err := sp.drv.deletes.waitAt(ctx, sp.st.where()); err != nil {
			sp.st.mu.Lock()
			sp.flushErr = err
			sp.st.mu.Unlock()

			return err
		}
	}
	// Read before the content is: a change that lands while it is sent is
	// not one this flush answers for.
	changes := sp.changes.Load()
	node, err := sp.spool.Flush(ctx)
	sp.st.mu.Lock()
	sp.flushErr = err
	sp.st.mu.Unlock()
	if err != nil {
		return err
	}
	sp.flushed.Store(changes)
	sp.stored(ctx, node, !existed && !unlinked, want)

	return nil
}

// send takes sending, or gives up when ctx ends first: the flushes of a spool
// wait for one another here as they would in vfs.
func (sp *openSpool) send(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case sp.sending <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sent gives sending back.
func (sp *openSpool) sent() { <-sp.sending }

// settled returns the node of the file as the inode table holds it once no
// flush nor copy is between its request and its record: its ID is empty when
// the API holds nothing of the file.
//
// It is for the unlink of a file found pending, called after
// vfs.Spool.Unlinked: what was in flight is then cancelled or undone, and
// nothing is sent any more, so the wait is short and the answer final. What
// it catches is the flush that ended between the moment the file was found
// pending and its unlink: the node that flush created is at the API, and
// nothing else knows.
func (sp *openSpool) settled() vfs.Node {
	sp.sending <- struct{}{}
	defer sp.sent()

	return sp.st.current()
}

// stored records node, the file as a flush or a server-side copy left it at
// the API. The API now knows the file under an ID: that ID is given the inode
// number the file already has.
//
// created tells a node the call made, which must carry the mode of want, the
// file as it is here (an explicit 0 included). It does when the creation took the mode; when the node
// answered has another (an API that ignores the field), it is set by a
// request of its own, once.
func (sp *openSpool) stored(ctx context.Context, node vfs.Node, created bool, want vfs.Node) {
	if node.ID == "" {
		// Unlinked: nothing was sent.
		return
	}
	sp.drv.inodes.alias(node.ID, sp.ino)
	sp.st.adopt(node, sp.drv.stamp())

	if !created || !want.HasMode() || want.Mode.Perm() == sp.drv.attrs.filePerm(node) {
		return
	}
	mode := want.Mode.Perm()
	path, ok := sp.path()
	if !ok {
		return
	}
	if err := sp.drv.tree.Chmod(ctx, sp.dataroomID, path, mode); err == nil {
		sp.st.edit(sp.drv.stamp(), func(n *vfs.Node) { n.Mode, n.ModeSet = mode, true })
	}
}

// copied records node, the file as a server-side copy made it (see stored).
//
// The copy has the mode of its source, the file the one it was created with,
// or was given since. That one stays the mode of the file here, and is owed
// to the API rather than sent at once: cp -p and cp -a create their
// destination with a restrictive mode, copy, then give it the mode of the
// source, which the copy already has. Two requests would cancel each other.
// What is still owed when the file is released is sent then (settleMode).
func (sp *openSpool) copied(node vfs.Node) {
	if node.ID == "" {
		// Unlinked: nothing was copied.
		return
	}
	sp.drv.inodes.alias(node.ID, sp.ino)
	seen := sp.drv.stamp()

	st := sp.st
	st.mu.Lock()
	defer st.mu.Unlock()
	// Read with the record, not before the copy: a chmod may have landed
	// while it ran.
	want, wantSet := st.node.Mode.Perm(), st.node.HasMode()
	if !wantSet {
		want, wantSet = node.Mode.Perm(), node.HasMode()
	}
	sp.modeOwed = wantSet && want != sp.drv.attrs.filePerm(node)
	node.Mode, node.ModeSet = want, wantSet
	st.node = bare(node)
	st.seen = max(st.seen, seen)
	st.pagesOf = ""
}

// settleMode sends the mode the file has here when its node does not carry it
// (see copied). It is called when the spool is released by its last writer,
// by its last handle, and by a shutdown; final tells a call nothing follows,
// which reports a mode that could not be stored: the node keeps the one it
// has, and nothing else would tell.
func (sp *openSpool) settleMode(ctx context.Context, final bool) {
	sp.moding.Lock()
	defer sp.moding.Unlock()

	st := sp.st
	st.mu.Lock()
	owed, mode, unlinked, id := sp.modeOwed, st.node.Mode.Perm(), st.unlinked, st.node.ID
	st.mu.Unlock()
	if !owed || unlinked {
		return
	}
	path, ok := sp.path()
	if !ok {
		return
	}
	// One that the node carries after all costs no request (vfs.FS.Chmod).
	err := sp.drv.tree.Chmod(ctx, sp.dataroomID, path, mode)
	if err == nil {
		st.mu.Lock()
		sp.modeOwed = false
		st.mu.Unlock()

		return
	}
	if final {
		// Neither the error nor the path: both may hold a name.
		sp.drv.logf("the mode of a file could not be stored, its node keeps the one it had: "+
			"dataroom %s, node %s, inode %d, mode %04o: %s",
			sp.dataroomID, id, sp.ino, mode, errnoName(toErrno(err)))
	}
}

// write counts one more handle that sends the spool.
func (sp *openSpool) write() {
	sp.st.mu.Lock()
	sp.writers++
	sp.st.mu.Unlock()
}

// written reports whether a handle that sends the spool is open.
func (sp *openSpool) written() bool {
	sp.st.mu.Lock()
	defer sp.st.mu.Unlock()

	return sp.writers > 0
}

// release ends one handle; sends tells one that was counted by write. The
// last handle that sends the spool flushes it, with a context of its own
// (driver.detached): the flush of a close(2) may have been interrupted, which
// cancels its upload, and nobody reads what a release answers. Only the end
// of the drain of a shutdown cancels it. The handles that only read it
// send nothing when they end, as long as one that writes is open.
//
// The last handle of all flushes it too, whatever it is (a flush that failed
// is tried once more), and closes it. Both send the mode the file was given
// here when a server-side copy left its node with another (settleMode). A
// spool closed with changes no flush
// sent is told to the operator: the changes are lost.
//
// A handle opened while that last flush runs keeps the spool alive: the one
// that ends last closes it. So does another last release that overlaps this
// one: whichever ends last closes the spool, and reports for both (close
// reads the state of the spool, not the error of one flush).
//
// A local file is neither sent nor closed with its last handle: it stays the
// spool of its inode, found by name and opened again, until it is unlinked
// (the last handle to go after that closes it) or the mount ends
// (closeSpools).
func (sp *openSpool) release(ctx context.Context, sends bool) {
	st := sp.st
	st.mu.Lock()
	sp.refs--
	if sends {
		sp.writers--
	}
	last := sp.refs == 0
	lastWriter := sends && sp.writers == 0
	// Read with the counters, under the mutex a rename reads them under once
	// it has made the file an ordinary one: either this release sends the
	// file, or that rename sees no writer left and does.
	if sp.local.Load() {
		gone := last && st.unlinked && sp.closing == 0 && st.spool == sp
		if gone {
			st.spool = nil
		}
		st.mu.Unlock()
		if gone {
			sp.close()
		}

		return
	}
	if last {
		sp.closing++
	}
	st.mu.Unlock()
	if !last && !lastWriter {
		return
	}

	done := sp.drv.uploads.begin()
	defer done()
	flushCtx, cancel := sp.drv.detached(ctx)
	_ = sp.flush(flushCtx)
	sp.settleMode(flushCtx, last)
	cancel()
	if !last {
		// Handles that read it are still open: the last one tries again.
		return
	}

	st.mu.Lock()
	sp.closing--
	if sp.refs > 0 || sp.closing > 0 || st.spool != sp {
		st.mu.Unlock()

		return
	}
	st.spool = nil
	inode := st.inode
	st.mu.Unlock()

	sp.close()
	// The pages the kernel may hold are those of a version the file had
	// before it was written here.
	sp.drv.notify.content(inode)
}

// close closes the spool once nothing refers to it: see retire for what is
// reported of it first. Closing waits for a flush still in flight, which
// includes what a failed upload removes from the API.
func (sp *openSpool) close() {
	sp.retire()
	_ = sp.spool.Close()
}

// retire takes the spool out of the driver, short of closing it. One that
// still holds changes (dirty: no flush sent them, and the file was not
// unlinked) loses them, which is reported once, here, with the error of the
// last flush that failed: a flush that failed and was followed by one that
// succeeded lost nothing. It waits for no flush: the report of a loss never
// comes after the cleanup of the upload that failed.
func (sp *openSpool) retire() {
	node, exists := sp.spool.Node()
	_, unlinked := sp.st.view()
	// A local file was never meant to be sent: it is no loss.
	lost, size := sp.spool.Dirty() && !sp.local.Load(), sp.spool.Size()
	at := sp.drv.spools.drop(sp)

	if lost {
		if sp.drv.draining.Load() {
			sp.drv.lost.Add(1)
		}
		sp.st.mu.Lock()
		flushErr := sp.flushErr
		sp.st.mu.Unlock()
		reason := "not flushed"
		switch {
		case sp.drv.drainCut():
			reason = "not sent before the end of the shutdown drain"
		case flushErr != nil:
			reason = errnoName(toErrno(flushErr))
		}
		// Neither the error nor the path: both may hold a name. The file is
		// told by its node, or by the folder it was created in when it was
		// never stored, and by the size of what is lost.
		sp.drv.logf("the last flush of a file failed, its changes are lost: dataroom %s, %s, inode %d, %d bytes: %s",
			sp.dataroomID, lostFile(node, exists, at), sp.ino, size, reason)
	}
	if !exists && !unlinked && at.known() {
		// Created here and never stored: the name is gone with the spool.
		sp.st.remove(sp.drv.stamp())
		sp.drv.notify.entry(at.parent, at.name)
	}
}

// lostFile tells which file a loss is reported for, by identifiers only:
// "node <id>" for a file the API holds, otherwise "no node (never stored),
// parent <id>" with the node of the folder it was created in, "root" for the
// root of the dataroom and "unknown" when that folder is not known any more.
func lostFile(node vfs.Node, exists bool, at location) string {
	if exists && node.ID != "" {
		return "node " + node.ID
	}
	parent := "unknown"
	if dir, ok := parentDir(at); ok {
		parent = "root"
		if !dir.dataroomRoot {
			if folder, _ := dir.state().view(); folder.ID != "" {
				parent = folder.ID
			} else {
				parent = "unknown"
			}
		}
	}

	return "no node (never stored), parent " + parent
}

// parentDir returns the folder of the place at, if it has one.
func parentDir(at location) (*dirNode, bool) {
	if !at.known() {
		return nil, false
	}
	dir, ok := at.parent.Operations().(*dirNode)

	return dir, ok
}

// closeSpools flushes and closes the spools still open when the filesystem
// goes away under them, all at once and for as long as the drain of the
// shutdown lasts (a mount detached while busy, a process that holds a
// file open through Ctrl-C): what they hold would otherwise be lost.
//
// What is sent is the file as its writer left it at that instant, which may
// be half of what it meant to write: the version is complete for the API and
// nothing tells a reader otherwise. The operator is told of each file sent
// while handles were open on it, and (by retire) of each whose flush failed.
//
// The local files go with the mount: they are closed, never sent, and neither
// reported nor counted as lost.
//
// It returns once every spool is flushed or reported lost. closed ends later,
// when the spools are closed: that waits for the uploads the end of the drain
// cancelled, which remove what they had sent from the API first.
func (d *driver) closeSpools() (closed <-chan struct{}) {
	var retired, all sync.WaitGroup
	// Sealed first: a spool opened from here on would be in no snapshot, so
	// neither sent nor reported.
	for _, sp := range d.spools.seal() {
		retired.Add(1)
		all.Go(func() {
			sp.st.mu.Lock()
			open := sp.refs > 0
			sp.st.mu.Unlock()
			dirty := sp.spool.Dirty()

			flushed := make(chan error, 1)
			go func() {
				err := sp.flush(d.stopped)
				// A mode still owed goes with the file, or is reported.
				sp.settleMode(d.stopped, true)
				flushed <- err
			}()
			err, returned := error(nil), false
			select {
			case err = <-flushed:
				returned = true
			case <-d.stopped.Done():
				// Cancelled: it returns at once, unless its cleanup holds it.
				settle := time.NewTimer(lossSettle)
				select {
				case err = <-flushed:
					returned = true
				case <-settle.C:
				}
				settle.Stop()
			}
			if node, _ := sp.spool.Node(); returned && err == nil && dirty && open && !sp.local.Load() {
				// No path: it may hold a name.
				d.logf("a file was sent as it was at shutdown, the file was still open: dataroom %s, node %q, inode %d",
					sp.dataroomID, node.ID, sp.ino)
			}
			sp.st.mu.Lock()
			if sp.st.spool == sp {
				sp.st.spool = nil
			}
			sp.st.mu.Unlock()
			sp.retire()
			retired.Done()

			if !returned {
				<-flushed
			}
			_ = sp.spool.Close()
		})
	}
	retired.Wait()
	done := make(chan struct{})
	go func() {
		all.Wait()
		close(done)
	}()

	return done
}

// inflight counts the last flushes in progress, which a shutdown waits for.
type inflight struct {
	mu sync.Mutex
	n  int
	// idle is closed when none is in progress; nil before the first.
	idle chan struct{}
}

func newInflight() *inflight { return &inflight{} }

// begin counts one more, until the function it returns is called.
func (f *inflight) begin() (done func()) {
	f.mu.Lock()
	if f.n == 0 {
		f.idle = make(chan struct{})
	}
	f.n++
	f.mu.Unlock()

	return func() {
		f.mu.Lock()
		f.n--
		if f.n == 0 {
			close(f.idle)
		}
		f.mu.Unlock()
	}
}

// wait returns once none is in progress, or when ctx ends: it reports
// whether none is.
func (f *inflight) wait(ctx context.Context) bool {
	for {
		f.mu.Lock()
		n, idle := f.n, f.idle
		f.mu.Unlock()
		if n == 0 {
			return true
		}
		select {
		case <-idle:
		case <-ctx.Done():
			return false
		}
	}
}
