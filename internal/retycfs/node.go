//go:build linux

package retycfs

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// maxNameLen is the longest name the driver presents, and the one Statfs
// reports.
const maxNameLen = 255

// unboundedBytes is the capacity and the free space reported where there is
// no quota to report: the root of the "all datarooms" mode, a dataroom whose
// API has no storage counters.
const unboundedBytes = 1 << 50

// base is what every inode of the tree embeds: its identity, and the
// operations that are the same for a folder, a file and a symbolic link.
//
// It holds no state of the node. go-fuse keeps the object of the first lookup
// of an inode and drops those of the later ones, so what the driver knows of
// an inode is in the inode table, reached through state. seed is the node the
// lookup that made this object saw: only what the table starts from when it
// holds nothing for the inode.
type base struct {
	fs.Inode
	ident
}

// ident is the identity of an inode.
type ident struct {
	drv *driver
	ino uint64
	// dataroomID is empty for the root of the "all datarooms" mode.
	dataroomID string
	seed       vfs.Node
}

// state returns the state of the inode in the table.
func (b *base) state() *inodeState {
	return b.drv.inodes.state(b.ino, b.seed)
}

var (
	_ fs.NodeGetattrer     = (*base)(nil)
	_ fs.NodeSetattrer     = (*base)(nil)
	_ fs.NodeStatfser      = (*base)(nil)
	_ fs.NodeGetxattrer    = (*base)(nil)
	_ fs.NodeListxattrer   = (*base)(nil)
	_ fs.NodeSetxattrer    = (*base)(nil)
	_ fs.NodeRemovexattrer = (*base)(nil)
	_ fs.NodeFsyncer       = (*base)(nil)
	_ fs.NodeOnForgetter   = (*base)(nil)
)

// OnForget drops the state of the inode once the kernel holds it no more.
func (b *base) OnForget() {
	b.drv.inodes.forget(b.ino, b.EmbeddedInode())
}

// Getattr answers from the node as last seen in a lookup or a listing, and
// from its spool for a file being written: it never asks the API, and never
// waits for an upload. The kernel asks again once the attribute timeout has
// passed, and by then looks the name up again too, which is what refreshes
// the node.
func (b *base) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) (errno syscall.Errno) {
	c := b.drv.begin("getattr", b.ino)
	defer c.end(&errno)
	b.drv.fillAttr(b.state(), b.ino, &out.Attr)

	return 0
}

// fillAttr writes the attributes of the inode of st to out (see
// inodeState.view). A file removed while open has no link left.
func (d *driver) fillAttr(st *inodeState, ino uint64, out *fuse.Attr) {
	node, unlinked := st.view()
	d.attrs.fill(node, ino, out)
	if unlinked {
		out.Nlink = 0
	}
}

// Setattr is chmod, chown, truncate and utimens.
//
//   - size: the spool of the file is truncated when it has one (ftruncate,
//     or a truncate of a file open elsewhere), and sent at the next flush.
//     Otherwise one is opened for the call and flushed before it returns:
//     truncate(2) to 0 is one request, to another size the download of what
//     is kept and its upload.
//   - mtime: kept by a spool that has changes to send, and declared with
//     them; otherwise declared for the current version (one PATCH, no new
//     version; none for the time the version already carries).
//   - mode: stored by the API for a file (one PUT, none for the mode its
//     node already carries). A file not flushed yet gets it with its first
//     flush.
//   - owner, group and access time are not stored: accepted and ignored, or
//     cp -p, tar and rsync would fail on every file.
//
// The API keeps neither a mode nor a modification time for a folder: both
// are accepted and ignored there too.
func (b *base) Setattr(
	ctx context.Context, _ fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut,
) (errno syscall.Errno) {
	if b.drv.readOnly(b.dataroomID) {
		return syscall.EROFS
	}
	c := b.drv.begin("setattr", b.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	st := b.state()
	node, unlinked := st.view()
	_, sized := in.GetSize()
	switch {
	case node.Type == vfs.TypeFile:
		ctx, span := startSpan(ctx, "setattr", b.dataroomID, b.seed.ID)
		err := b.setFileAttr(ctx, st, in, unlinked)
		span.End(err)
		if err != nil {
			return pathErrno(err)
		}
	case sized && node.Type == vfs.TypeDir:
		return syscall.EISDIR
	case sized:
		return syscall.EINVAL
	}
	b.drv.fillAttr(st, b.ino, &out.Attr)

	return 0
}

// setFileAttr applies the changes of a Setattr to a file.
func (b *base) setFileAttr(ctx context.Context, st *inodeState, in *fuse.SetAttrIn, unlinked bool) error {
	if size, ok := in.GetSize(); ok {
		if err := b.truncate(ctx, st, int64(size)); err != nil { //nolint:gosec // G115: the kernel bounds a file size
			return err
		}
	}
	// Joined, not merely looked at: the release of the last handle follows
	// close(2) and may come while the request runs, and would close the
	// spool under it (vfs.ErrClosed, EIO for a utimensat that follows a
	// close).
	sp := st.join()
	if sp != nil {
		defer sp.release(ctx, false)
	}
	if mtime, ok := in.GetMTime(); ok {
		switch {
		case sp != nil:
			if err := sp.spool.SetModTime(ctx, mtime); err != nil {
				return err
			}
		case !unlinked:
			path, ok := b.drv.pathAt(st.where())
			if !ok {
				return errStale
			}
			if err := b.drv.tree.SetModTime(ctx, b.dataroomID, path, mtime); err != nil {
				return err
			}
		}
		st.edit(b.drv.stamp(), func(n *vfs.Node) { n.ModTime = mtime })
	}
	if mode, ok := in.GetMode(); ok {
		perm := os.FileMode(mode).Perm()
		// A file with nothing at the API yet, or nothing any more, keeps its
		// mode here: the first flush of the former creates it with that mode.
		if sp != nil {
			sp.spool.SetMode(perm)
			// Not while a release sends a mode owed: the last request
			// would not be the one of the last chmod.
			sp.moding.Lock()
			defer sp.moding.Unlock()
		}
		if !unlinked && (sp == nil || !sp.pending()) {
			path, ok := b.drv.pathAt(st.where())
			if !ok {
				return errStale
			}
			if err := b.drv.tree.Chmod(ctx, b.dataroomID, path, perm); err != nil {
				return err
			}
		}
		// The node now carries the mode asked for, whatever it was owed.
		st.edit(b.drv.stamp(), func(n *vfs.Node) {
			n.Mode, n.ModeSet = perm, true
			if sp != nil {
				sp.modeOwed = false
			}
		})
	}

	return nil
}

// truncate sets the size of a file (see Setattr). The spool of a file that
// no handle writes any more (those left only read it) is sent before the call
// returns: no close would send it.
func (b *base) truncate(ctx context.Context, st *inodeState, size int64) error {
	sp := st.join()
	if sp != nil {
		defer sp.release(ctx, false)
		sp.changed()
		if err := sp.spool.Truncate(size); err != nil || sp.written() {
			return err
		}

		return sp.flush(ctx)
	}
	file, ok := b.EmbeddedInode().Operations().(*fileNode)
	if !ok {
		return errStale
	}
	if size == st.current().Size {
		return nil
	}
	sp, err := file.openSpool(ctx, st, size == 0)
	if err != nil {
		return err
	}
	defer sp.release(ctx, false)
	sp.changed()
	if err := sp.spool.Truncate(size); err != nil {
		return err
	}

	return sp.flush(ctx)
}

// Fsync has nothing to write for a folder or a link.
func (b *base) Fsync(context.Context, fs.FileHandle, uint32) syscall.Errno { return 0 }

// Statfs reports the quota of the dataroom: its reserved capacity, or what
// is left of its owner's plan, as used + free. The counters are cached by
// vfs for the listing TTL, so df costs one request per TTL at most.
//
// Without counters, and at the root of the "all datarooms" mode, a large
// constant is reported: summing the quotas would cost one request per
// dataroom, for a number that means little when several datarooms draw on
// one plan.
func (b *base) Statfs(ctx context.Context, out *fuse.StatfsOut) (errno syscall.Errno) {
	c := b.drv.begin("statfs", b.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	out.Bsize, out.Frsize = blockSize, blockSize
	out.NameLen = maxNameLen
	total, free := int64(unboundedBytes), int64(unboundedBytes)
	if b.dataroomID != "" {
		ctx, span := startSpan(ctx, "statfs", b.dataroomID, "")
		used, left, ok := b.drv.tree.Quota(ctx, b.dataroomID)
		span.End(nil)
		if ok {
			total, free = max(used, 0)+max(left, 0), max(left, 0)
		}
	}
	out.Blocks = uint64(total) / blockSize
	out.Bfree = uint64(free) / blockSize
	out.Bavail = out.Bfree

	return 0
}

// maxDepth bounds the walk up the locations of the table: observations made
// at different times could, in theory, describe a loop.
const maxDepth = 1024

// errStale is the error of an inode the driver has no path for: ESTALE, on
// which the kernel resolves the path again, and the lookups it makes tell the
// table where things are.
var errStale = errors.New("retycfs: no known path")

// pathErrno is toErrno for an error that may be errStale.
func pathErrno(err error) syscall.Errno {
	if errors.Is(err, errStale) {
		return syscall.ESTALE
	}

	return toErrno(err)
}

// path returns the path of the folder in its dataroom, "/" for its root, by
// walking up the places the inode table holds: for each folder, the one vfs
// last found it at (see inodeState.at). It is false for a folder the table
// holds no place for.
//
// The path is what internal/vfs is addressed by. It never leaves the
// process: neither the access log nor a span carries it.
func (n *dirNode) path() (string, bool) {
	var names []string
	for dir := n; !dir.dataroomRoot; {
		at := dir.state().where()
		if !at.known() || len(names) == maxDepth {
			return "", false
		}
		parent, ok := at.parent.Operations().(*dirNode)
		if !ok {
			return "", false
		}
		names = append(names, at.name)
		dir = parent
	}
	var b strings.Builder
	for i := len(names) - 1; i >= 0; i-- {
		b.WriteByte('/')
		b.WriteString(names[i])
	}
	if b.Len() == 0 {
		return "/", true
	}

	return b.String(), true
}

// withPath runs fn, a question to vfs, with the path of the folder.
//
// When vfs answers that nothing is there, either the name asked about is
// missing or the path is not the folder's any more: a folder moved elsewhere,
// which the table still holds at a place read from a listing older than the
// move. revive tells them apart, and fn runs once more when the folder turned
// out to be somewhere else. errStale is the error of a folder without a path.
func (n *dirNode) withPath(ctx context.Context, fn func(path string) error) error {
	path, ok := n.path()
	if !ok {
		return errStale
	}
	err := fn(path)
	if err == nil || toErrno(err) != syscall.ENOENT {
		return err
	}
	if stale := n.revive(ctx); stale != nil {
		return stale
	}
	if moved, ok := n.path(); ok && moved != path {
		return fn(moved)
	}

	return err
}

// revive checks that the folder is where the table holds it, and otherwise
// falls back on the place it held it at before. It returns nil when the path
// of the folder, changed or not, is one vfs confirms, errStale when none is,
// and the error of vfs when it could not tell.
//
// It costs nothing while vfs has the folder in cache, one lookup by name
// otherwise, and walks up only as far as a folder that is found.
func (n *dirNode) revive(ctx context.Context) error {
	if n.dataroomRoot {
		return nil
	}
	st := n.state()
	for range 2 {
		at := st.where()
		if !at.known() {
			break
		}
		parent, ok := at.parent.Operations().(*dirNode)
		if !ok {
			break
		}
		var node vfs.Node
		err := parent.withPath(ctx, func(path string) (err error) {
			node, err = n.drv.tree.Lookup(ctx, n.dataroomID, path, at.name)

			return err
		})
		switch {
		case err == nil && node.ID == n.seed.ID:
			return nil
		case err != nil && toErrno(err) != syscall.ENOENT:
			return err
		}
		// The name is gone, or names another node: the kernel drops it.
		n.drv.notify.entry(at.parent, at.name)
		if !st.relocate(at) {
			break
		}
	}

	return errStale
}

// presentable reports whether name can be the name of a directory entry. A
// name the API holds is free text: one the kernel cannot take is left out of
// the listing instead of failing it.
func presentable(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= maxNameLen &&
		!strings.ContainsAny(name, "/\x00")
}

// dirEntry is one entry of a folder as the driver presents it: a node of a
// dataroom, or the folder that stands for a dataroom.
type dirEntry struct {
	node       vfs.Node
	ino        uint64
	dataroomID string
	// seen is the stamp of the answer of vfs the entry comes from.
	seen uint64
	// dataroomRoot marks the folder of a dataroom, which is no node.
	dataroomRoot bool
	// local marks a file answered for by its spool (openSpool.entry): the
	// table already holds what the entry says, and more recent.
	local bool
}

// nodeEntry returns the entry of a node of a dataroom, from an answer of vfs
// stamped seen.
func (d *driver) nodeEntry(dataroomID string, node vfs.Node, seen uint64) dirEntry {
	return dirEntry{node: node, ino: d.inodes.ino(node.ID), dataroomID: dataroomID, seen: seen}
}

// child returns the inode of entry e of the folder parent and writes its
// attributes to out. It is where the driver sees a node go by, for a lookup
// as for a listing: the table learns the node, and the kernel is told to drop
// its pages when the version is not the one it knew. It learns where the node
// is too: parent and the name are the place vfs has just found it at, which is
// what its path is built from (the folder of a dataroom has none: paths start
// there).
//
// An entry older than what the table holds (the listing of a folder opened a
// while ago) teaches it nothing, and is answered with the attributes of the
// node as the table knows it.
//
// The number is the one the table holds for the node now (inodeTable.lend),
// not the one of the entry, which may come from a listing read before the
// table swept it. The object is the one go-fuse holds for the number when
// there is one.
func (d *driver) child(ctx context.Context, parent *fs.Inode, e dirEntry, out *fuse.EntryOut) *fs.Inode {
	key := e.node.ID
	switch {
	case e.dataroomRoot:
		key = dataroomKey(e.dataroomID)
	case e.local:
		// A file known by its spool: its number is the spool's.
		key = ""
	}
	ino, live := d.inodes.lend(key, e.ino)
	e.ino = ino
	st := d.inodes.state(e.ino, e.node)
	var at location
	if !e.dataroomRoot {
		at = location{parent: parent, name: e.node.Name}
	}
	if !e.local {
		d.notify.content(st.observe(e.node, at, e.seen))
	}
	d.fillAttr(st, e.ino, &out.Attr)
	if live != nil {
		return live
	}

	id := ident{drv: d, ino: e.ino, dataroomID: e.dataroomID, seed: e.node}
	var ops fs.InodeEmbedder
	switch e.node.Type {
	case vfs.TypeDir:
		ops = &dirNode{base: base{ident: id}, dataroomRoot: e.dataroomRoot}
	case vfs.TypeSymlink:
		ops = &linkNode{base: base{ident: id}}
	default:
		ops = &fileNode{base: base{ident: id}}
	}

	inode := parent.NewInode(ctx, ops, fs.StableAttr{Mode: typeBits(e.node.Type), Ino: e.ino})
	d.inodes.lent(e.ino, inode)

	return inode
}

// dirNode is a folder of a dataroom, or the root of one.
type dirNode struct {
	base
	// dataroomRoot marks the root of a dataroom: where paths start.
	dataroomRoot bool
	// mountRoot marks the root of the mount, which holds the control folder.
	mountRoot bool
}

var (
	_ fs.NodeLookuper       = (*dirNode)(nil)
	_ fs.NodeOpendirHandler = (*dirNode)(nil)
	_ fs.NodeOnAdder        = (*dirNode)(nil)
	_ fs.NodeMkdirer        = (*dirNode)(nil)
	_ fs.NodeRmdirer        = (*dirNode)(nil)
	_ fs.NodeUnlinker       = (*dirNode)(nil)
	_ fs.NodeRenamer        = (*dirNode)(nil)
	_ fs.NodeCreater        = (*dirNode)(nil)
	_ fs.NodeSymlinker      = (*dirNode)(nil)
	_ fs.NodeLinker         = (*dirNode)(nil)
	_ fs.NodeMknoder        = (*dirNode)(nil)
)

// OnAdd hangs the control folder from the root of the mount.
func (n *dirNode) OnAdd(ctx context.Context) {
	if n.mountRoot {
		n.drv.addControl(ctx, n.EmbeddedInode())
	}
}

// Lookup is the lookup of one name on its own: a stat, an open, a path
// component the kernel resolves. It goes through vfs.FS.Lookup, which answers
// from the cached listing of the folder when there is one and otherwise asks
// the API for that name alone. The entries of a listing never come here: see
// dirHandle.Lookup.
//
// A name a local file may hold (Options.LocalFiles) is answered by the local
// file when there is one, and otherwise from the listing of the folder
// (dirNode.listed): editors probe such names many times over, and none of
// them is worth a request.
func (n *dirNode) Lookup(
	ctx context.Context, name string, out *fuse.EntryOut,
) (child *fs.Inode, errno syscall.Errno) {
	c := n.drv.begin("lookup", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	if n.mountRoot && name == controlDirName {
		return n.drv.lookupControl(n.EmbeddedInode(), out)
	}

	// A file being written is the mount's to answer for: one created here
	// exists nowhere else until its first flush.
	if sp := n.drv.spools.find(location{parent: n.EmbeddedInode(), name: name}); sp != nil {
		return n.drv.child(ctx, n.EmbeddedInode(), sp.entry(n.drv.stamp()), out), 0
	}

	ctx, span := startSpan(ctx, "lookup", n.dataroomID, n.seed.ID)
	seen := n.drv.stamp()
	node, err := n.lookup(ctx, name)
	span.End(unlessErrno(err, syscall.ENOENT))
	if err != nil {
		return nil, pathErrno(err)
	}
	if !presentable(node.Name) {
		return nil, syscall.ENOENT
	}

	return n.drv.child(ctx, n.EmbeddedInode(), n.drv.nodeEntry(n.dataroomID, node, seen), out), 0
}

// lookup asks vfs for the child name of the folder: by that name, or in the
// listing of the folder for a name a local file may hold.
func (n *dirNode) lookup(ctx context.Context, name string) (node vfs.Node, err error) {
	if n.drv.localName(name) {
		return n.listed(ctx, name)
	}
	if err := n.drv.checkDataroom(ctx, n.dataroomID); err != nil {
		return vfs.Node{}, err
	}
	err = n.withPath(ctx, func(path string) (err error) {
		node, err = n.drv.tree.Lookup(ctx, n.dataroomID, path, name)

		return err
	})

	return node, err
}

// listed returns the child name of the folder as its listing holds it,
// vfs.ErrNotExist when it holds none: the listing vfs has in cache, read
// through the API when that one is missing or expired, as for a readdir. It
// never asks for the name alone.
func (n *dirNode) listed(ctx context.Context, name string) (vfs.Node, error) {
	if err := n.drv.checkDataroom(ctx, n.dataroomID); err != nil {
		return vfs.Node{}, err
	}
	var nodes []vfs.Node
	err := n.withPath(ctx, func(path string) (err error) {
		nodes, err = n.drv.tree.ReadDir(ctx, n.dataroomID, path)

		return err
	})
	if err != nil {
		return vfs.Node{}, err
	}
	if node, ok := vfs.FindNode(nodes, name); ok {
		return node, nil
	}

	return vfs.Node{}, vfs.ErrNotExist
}

// lookupRemote is lookup asked of the API whatever vfs holds in cache.
func (n *dirNode) lookupRemote(ctx context.Context, name string) (node vfs.Node, err error) {
	if err := n.drv.checkDataroom(ctx, n.dataroomID); err != nil {
		return vfs.Node{}, err
	}
	err = n.withPath(ctx, func(path string) (err error) {
		node, _, err = n.drv.tree.LookupRemote(ctx, n.dataroomID, path, name)

		return err
	})

	return node, err
}

// OpendirHandle lists the folder, once: the handle keeps the listing and
// answers from it for every entry the kernel then asks about.
func (n *dirNode) OpendirHandle(
	ctx context.Context, _ uint32,
) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	c := n.drv.begin("opendir", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	h := &dirHandle{drv: n.drv, dir: n.EmbeddedInode(), list: n.list}
	if errno := h.load(ctx); errno != 0 {
		return nil, 0, errno
	}

	return h, 0, 0
}

// list returns the entries of the folder, from vfs.FS.ReadDir: one listing
// through the API when the cache holds none that is fresh, nothing otherwise.
//
// It is also where the driver compares what the kernel knows of the folder
// with what the API holds: a file whose version moved has its pages dropped,
// a name that is gone, or that now names another node, has its entry dropped.
//
// The files being written in the folder are listed as their spools know them:
// with their current size and modification time, and, for those created here
// and not flushed yet, although the API holds nothing of them.
func (n *dirNode) list(ctx context.Context) ([]dirEntry, syscall.Errno) {
	ctx, span := startSpan(ctx, "readdir", n.dataroomID, n.seed.ID)
	seen := n.drv.stamp()
	err := n.drv.checkDataroom(ctx, n.dataroomID)
	var nodes []vfs.Node
	if err == nil {
		err = n.withPath(ctx, func(path string) (err error) {
			nodes, err = n.drv.tree.ReadDir(ctx, n.dataroomID, path)

			return err
		})
	}
	span.End(err)
	if err != nil {
		return nil, pathErrno(err)
	}

	written := make(map[string]*openSpool)
	for at, sp := range n.drv.spools.named() {
		if sameDir(at.parent, n.EmbeddedInode()) {
			written[at.name] = sp
		}
	}
	entries := make([]dirEntry, 0, len(nodes)+len(written))
	for name, sp := range written {
		if sp.pending() || vfsHolds(nodes, name) {
			entries = append(entries, sp.entry(seen))
		}
	}
	for _, node := range nodes {
		if !presentable(node.Name) || (n.mountRoot && node.Name == controlDirName) || written[node.Name] != nil {
			continue
		}
		if st, ok := n.drv.inodes.peek(node.ID); ok {
			at := location{parent: n.EmbeddedInode(), name: node.Name}
			n.drv.notify.content(st.observe(node, at, seen))
		}
		entries = append(entries, n.drv.nodeEntry(n.dataroomID, node, seen))
	}
	n.drv.reconcile(n.EmbeddedInode(), entries)

	return entries, 0
}

// reconcile drops from the kernel the entries of dir that the listing no
// longer holds, or holds for another node: a file deleted, renamed or
// replaced elsewhere. Without it the kernel would answer for the old name
// until its entry timeout.
func (d *driver) reconcile(dir *fs.Inode, entries []dirEntry) {
	known := dir.Children()
	if len(known) == 0 {
		return
	}
	listed := make(map[string]uint64, len(entries))
	for _, e := range entries {
		listed[e.node.Name] = e.ino
	}
	for name, child := range known {
		if name == controlDirName && dir.IsRoot() {
			continue
		}
		if ino, ok := listed[name]; !ok || ino != child.StableAttr().Ino {
			d.notify.entry(dir, name)
		}
	}
}

// vfsHolds reports whether the listing nodes holds name.
func vfsHolds(nodes []vfs.Node, name string) bool {
	_, ok := vfs.FindNode(nodes, name)

	return ok
}

// The mutations of a folder. Each asks vfs, which calls the API and edits its
// cached listings, then records the outcome in the inode table: the kernel
// updates its own entries from the answer, and go-fuse its tree (RmChild,
// MvChild) once the handler returns. No notification is needed for a change
// the kernel itself asked for.

// stateOf returns the state of the inode a child of a folder stands for, nil
// when it is not one of a dataroom (the control folder).
func stateOf(inode *fs.Inode) *inodeState {
	if inode == nil {
		return nil
	}
	if ops, ok := inode.Operations().(interface{ state() *inodeState }); ok {
		return ops.state()
	}

	return nil
}

// writable checks that name can be created, removed or renamed in the folder,
// and returns the errno that refuses it.
func (n *dirNode) writable(name string) syscall.Errno {
	switch {
	case n.drv.readOnly(n.dataroomID):
		return syscall.EROFS
	case n.mountRoot && name == controlDirName:
		return syscall.EPERM
	case len(name) > maxNameLen:
		return syscall.ENAMETOOLONG
	case !presentable(name):
		return syscall.EINVAL
	}

	return 0
}

// Mkdir creates a folder: one request. The mode is not stored: the API keeps
// none for a folder.
func (n *dirNode) Mkdir(
	ctx context.Context, name string, _ uint32, out *fuse.EntryOut,
) (child *fs.Inode, errno syscall.Errno) {
	if errno := n.writable(name); errno != 0 {
		return nil, errno
	}
	c := n.drv.begin("mkdir", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	ctx, span := startSpan(ctx, "mkdir", n.dataroomID, n.seed.ID)
	seen := n.drv.stamp()
	var node vfs.Node
	err := n.drv.checkDataroom(ctx, n.dataroomID)
	if err == nil {
		// The API holds the name of a file until its delete is sent.
		err = n.drv.deletes.waitName(ctx, n, name)
	}
	if err == nil {
		err = n.withPath(ctx, func(path string) (err error) {
			node, err = n.drv.tree.Mkdir(ctx, n.dataroomID, joinPath(path, name))

			return err
		})
	}
	span.End(err)
	if err != nil {
		return nil, pathErrno(err)
	}
	if node.ModTime.IsZero() {
		// The creation answers no time; the next listing brings the API's.
		node.ModTime = time.Now()
	}

	return n.drv.child(ctx, n.EmbeddedInode(), n.drv.nodeEntry(n.dataroomID, node, seen), out), 0
}

// Rmdir removes an empty folder: vfs lists it through the API first (never
// from the cache) and answers ENOTEMPTY when it holds something, so two
// requests. A folder that holds a file created here and not flushed yet is
// not empty either, and neither is one that holds a local file
// (Options.LocalFiles), although the API holds nothing in it: ENOTEMPTY until
// those files are removed.
func (n *dirNode) Rmdir(ctx context.Context, name string) (errno syscall.Errno) {
	if errno := n.writable(name); errno != 0 {
		return errno
	}
	c := n.drv.begin("rmdir", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	child := n.GetChild(name)
	for at := range n.drv.spools.named() {
		if child != nil && sameDir(at.parent, child) {
			return syscall.ENOTEMPTY
		}
	}
	ctx, span := startSpan(ctx, "rmdir", n.dataroomID, n.seed.ID)
	var err error
	if child != nil {
		// The files removed from the folder are still in it at the API until
		// their deletes are sent (Options.BackgroundDelete).
		folder, _ := child.Operations().(*dirNode)
		err = n.drv.deletes.waitFolder(ctx, folder)
	}
	if err == nil {
		err = n.withPath(ctx, func(path string) error {
			return n.drv.tree.Remove(ctx, n.dataroomID, joinPath(path, name), false)
		})
	}
	span.End(err)
	if err != nil {
		return pathErrno(err)
	}
	if st := stateOf(child); st != nil {
		st.remove(n.drv.stamp())
	}

	return 0
}

// Unlink removes a file or a link: one request, none for a file created here
// and not flushed yet, nor for a local file (Options.LocalFiles), which is one
// that is never flushed. A file that is open stays readable and writable
// through its handles: its spool becomes a local file that nothing sends any
// more (vfs.Spool.Unlinked), and a handle that reads a version keeps reading
// it for as long as the API serves its chunks.
//
// A file found pending is unlinked first, which cancels its first flush when
// one is in flight (vfs undoes one that completed all the same), and whether
// the API holds it is read after (openSpool.settled): a first flush that
// ended between the two has created the node, which is then removed like any
// other. Deciding on the first look alone would answer 0 and leave the file
// at the API. When that removal fails the error is returned with the spool
// already unlinked: the file stays at the API as that flush sent it.
func (n *dirNode) Unlink(ctx context.Context, name string) (errno syscall.Errno) {
	if errno := n.writable(name); errno != 0 {
		return errno
	}
	c := n.drv.begin("unlink", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	// Held: the release of its last handle may come while the request runs.
	sp := n.drv.spools.find(location{parent: n.EmbeddedInode(), name: name}).hold()
	defer func() { sp.letGo(ctx) }()
	born := false
	if sp != nil && sp.pending() {
		n.unlinked(sp, sp.st)
		if born = sp.settled().ID != ""; !born {
			return 0
		}
	}
	if n.drv.deletes != nil && !born {
		if handled, errno := n.unlinkLater(ctx, name, sp); handled {
			return errno
		}
	}
	ctx, span := startSpan(ctx, "unlink", n.dataroomID, n.seed.ID)
	err := n.withPath(ctx, func(path string) error {
		return n.drv.tree.Remove(ctx, n.dataroomID, joinPath(path, name), false)
	})
	if born && err != nil && pathErrno(err) == syscall.ENOENT {
		// Gone already: removed elsewhere since that flush.
		err = nil
	}
	span.End(err)
	if err != nil {
		return pathErrno(err)
	}
	st := stateOf(n.GetChild(name))
	if sp != nil {
		st = sp.st
	}
	n.unlinked(sp, st)

	return 0
}

// unlinked records that the file of st, written through sp when it is not
// nil, has been removed.
func (n *dirNode) unlinked(sp *openSpool, st *inodeState) {
	if st != nil {
		st.remove(n.drv.stamp())
	}
	if sp != nil {
		n.drv.spools.unname(sp)
		sp.spool.Unlinked()
	}
}

// Rename renames or moves a node within its dataroom, in one request. It
// replaces a file that holds the destination name, as rename(2) does, in the
// transaction of the rename (vfs.FS.Rename with replace), unless
// RENAME_NOREPLACE asks for EEXIST. RENAME_EXCHANGE is EINVAL, another
// dataroom EXDEV: mv then copies and deletes.
//
// A file being written follows: the rename goes through its spool
// (vfs.Spool.Rename), which waits for the flush in flight and takes the new
// path. One created here and not flushed yet is renamed without a request,
// since the API holds nothing of it; its first flush sends it under the new
// name. Whether it is flushed is read once that flush is over: a rename that
// crossed the first flush would otherwise ask nothing while the file is born
// under its old name.
//
// The spools of both names are held for the call (openSpool.hold): the
// release of their last handle follows close(2) and may come while the
// request runs.
//
// A local file (Options.LocalFiles) stays one when its new name matches a
// pattern and the dataroom holds no node under it: nothing is asked. Under
// any other name, or over a node, it becomes an ordinary file created here
// and not flushed yet: sent by the close of a handle that writes it, or, when
// none is open, by the rename itself, whose error is then the one of that
// upload (the file stays local, under its old name). Over a node it is sent
// as a new version of that node, like any file not flushed yet. A local file
// under the destination name is replaced like any other, at no request.
func (n *dirNode) Rename(
	ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32,
) (errno syscall.Errno) {
	if errno := n.writable(name); errno != 0 {
		return errno
	}
	c := n.drv.begin("rename", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	if flags&^uint32(unix.RENAME_NOREPLACE) != 0 {
		// RENAME_EXCHANGE, RENAME_WHITEOUT.
		return syscall.EINVAL
	}
	dst, ok := newParent.(*dirNode)
	if !ok || dst.dataroomID != n.dataroomID {
		return syscall.EXDEV
	}
	if errno := dst.writable(newName); errno != 0 {
		return errno
	}
	replace := flags&unix.RENAME_NOREPLACE == 0
	from := location{parent: n.EmbeddedInode(), name: name}
	to := location{parent: dst.EmbeddedInode(), name: newName}
	if from == to {
		return 0
	}
	// The API holds the destination name until the delete of the file that
	// had it is sent (Options.BackgroundDelete).
	if err := n.drv.deletes.waitName(ctx, dst, newName); err != nil {
		return pathErrno(err)
	}
	src, over := n.drv.spools.find(from).hold(), n.drv.spools.find(to).hold()
	defer func() {
		src.letGo(ctx)
		over.letGo(ctx)
	}()
	if over != nil && !replace {
		return syscall.EEXIST
	}
	newDir, ok := dst.path()
	if !ok {
		return syscall.ESTALE
	}
	newPath := joinPath(newDir, newName)

	ctx, span := startSpan(ctx, "rename", n.dataroomID, n.seed.ID)
	sent := func() error {
		return n.withPath(ctx, func(path string) error {
			return n.drv.tree.Rename(ctx, n.dataroomID, joinPath(path, name), newPath, replace)
		})
	}
	var err error
	pending := false
	// local: the file renamed is a local one. kept: it stays one.
	local := src != nil && src.local.Load()
	kept := local
	if src != nil {
		err = src.spool.Rename(ctx, newPath, func(exists bool) error {
			if pending = !exists; pending {
				taken, err := dst.renamePending(ctx, newName, replace)
				kept = local && !taken && n.drv.localName(newName)

				return err
			}

			return sent()
		})
	} else {
		err = sent()
	}
	if err == nil && local && !kept {
		err = n.publish(ctx, src, from, to)
	}
	span.End(err)

	moved := n.GetChild(name)
	if err != nil {
		errno := pathErrno(err)
		if errno == syscall.EISDIR && moved != nil && moved.IsDir() {
			// A folder over a folder: the API replaces none, empty or not.
			errno = syscall.ENOTEMPTY
		}

		return errno
	}

	seen := n.drv.stamp()
	// What held the destination name is gone. Under a file the API holds
	// nothing of yet, a file it does hold stays, until the flush that gives
	// it the content of the other.
	var replaced *inodeState
	if !pending {
		replaced = stateOf(dst.GetChild(newName))
	}
	if over != nil && over != src {
		replaced = over.st
		n.drv.spools.unname(over)
		over.spool.Unlinked()
	}
	st := stateOf(moved)
	if src != nil {
		st = src.st
	}
	if replaced != nil && replaced != st {
		replaced.remove(seen)
	}
	if st != nil {
		st.place(to, seen)
	}
	if src != nil {
		n.drv.spools.move(src, to)
	}
	if moved != nil && moved.IsDir() {
		// The files being written below a folder that moved are sent there.
		for _, sp := range n.drv.spools.named() {
			if path, ok := sp.path(); ok {
				sp.spool.SetPath(path)
			}
		}
	}

	return 0
}

// renamePending checks that a file the API holds nothing of can take the name
// newName in the folder: a folder there is EISDIR, and anything is EEXIST
// when it must not be replaced. A file there keeps its node: the first flush
// of the renamed file gives it a new version. taken tells that the dataroom
// holds a node under the name.
func (n *dirNode) renamePending(ctx context.Context, newName string, replace bool) (taken bool, err error) {
	node, err := n.lookup(ctx, newName)
	switch {
	case err != nil && pathErrno(err) == syscall.ENOENT:
		return false, nil
	case err != nil:
		return false, err
	case !replace:
		return true, vfs.ErrExist
	case node.Type == vfs.TypeDir:
		return true, vfs.ErrIsDir
	}

	return true, nil
}

// publish makes the local file of sp, just renamed from the place from to the
// place to, an ordinary file created here and not flushed yet. A handle that
// writes it sends it when it is closed. Without one nothing would, so it is
// sent here, to its new path: when that fails the file is put back as it was,
// local and under its old name, and the error is the one of the rename.
func (n *dirNode) publish(ctx context.Context, sp *openSpool, from, to location) error {
	// Cleared before the writers are counted: see openSpool.release.
	sp.local.Store(false)
	if sp.written() {
		return nil
	}
	// The flush records the node at the place the file is held at.
	sp.st.place(to, n.drv.stamp())
	err := sp.flush(ctx)
	if err == nil {
		return nil
	}
	sp.local.Store(true)
	sp.st.place(from, n.drv.stamp())
	if old, ok := n.drv.pathAt(from); ok {
		sp.spool.SetPath(old)
	}

	return err
}

// Create creates a file and opens it for writing, at no request: the file is
// a spool (vfs.FS.OpenSpool on a path that names nothing) until its first
// flush, which sends node, version and content. Until then it has an inode of
// its own, is listed in its folder and found by name (see spoolRegistry), and
// leaves nothing behind when it is never flushed.
//
// A name that matches Options.LocalFiles makes a local file instead, when the
// listing of the folder holds no node under it: the same spool, which nothing
// ever sends (openSpool.local). No request is made for it, O_EXCL or not; a
// node the dataroom holds under the name is opened like any other.
//
// The kernel asks for a creation when it believes the name is free. When the
// name is taken after all (a file created elsewhere since the kernel last
// asked), the answer is ESTALE: the kernel looks the name up again and opens
// what it finds, or EEXIST with O_EXCL.
func (n *dirNode) Create(
	ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut,
) (child *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	if errno := n.writable(name); errno != 0 {
		return nil, nil, 0, errno
	}
	c := n.drv.begin("create", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	taken := syscall.ESTALE
	if flags&syscall.O_EXCL != 0 {
		taken = syscall.EEXIST
	}
	at := location{parent: n.EmbeddedInode(), name: name}
	if n.drv.spools.find(at) != nil {
		return nil, nil, 0, taken
	}

	ctx, span := startSpan(ctx, "create", n.dataroomID, n.seed.ID)
	sp, err := n.create(ctx, at, mode, flags&syscall.O_EXCL != 0, n.drv.localName(name))
	span.End(err)
	switch {
	case errors.Is(err, vfs.ErrExist):
		n.drv.notify.entry(at.parent, at.name)

		return nil, nil, 0, taken
	case err != nil:
		return nil, nil, 0, pathErrno(err)
	}

	node, _ := sp.st.view()
	id := ident{drv: n.drv, ino: sp.ino, dataroomID: n.dataroomID, seed: node}
	// A number of its own: no object of it can be live yet.
	n.drv.inodes.lend("", sp.ino)
	child = n.NewInode(ctx, &fileNode{base: base{ident: id}}, fs.StableAttr{Mode: syscall.S_IFREG, Ino: sp.ino})
	n.drv.inodes.lent(sp.ino, child)
	sp.st.mu.Lock()
	sp.st.inode = child
	sp.st.mu.Unlock()
	n.drv.fillAttr(sp.st, sp.ino, &out.Attr)

	sp.write()
	h := &spoolHandle{sp: sp, writable: true, sends: true, appends: flags&syscall.O_APPEND != 0}
	countHandle(h)

	return child, h, fuse.FOPEN_DIRECT_IO, 0
}

// create opens the spool of a new file at the place at, and gives it an inode.
// vfs.ErrExist when the name is taken.
//
// The name is free when the kernel has just looked it up: vfs then holds the
// answer, and a plain creation asks nothing. That answer may be a cached
// listing or a negative entry older than a file created elsewhere, which the
// first flush would then give a new version. O_EXCL promises that never
// happens: an exclusive creation asks the API for the name, one request by
// name hash (vfs.FS.LookupRemote; none on an API without that lookup, where
// the cache decides as for a plain creation). A file created elsewhere
// between that answer and the flush is still overwritten: the API has no
// exclusive creation.
//
// local makes the file a local one. Its name is looked for in the listing of
// the folder only (see lookup), whatever O_EXCL promises: the file is never
// sent, so it overwrites nothing.
func (n *dirNode) create(
	ctx context.Context, at location, mode uint32, exclusive, local bool,
) (*openSpool, error) {
	lookup := n.lookup
	if exclusive && !local {
		lookup = n.lookupRemote
	}
	switch _, err := lookup(ctx, at.name); {
	case err == nil:
		return nil, vfs.ErrExist
	case pathErrno(err) != syscall.ENOENT:
		return nil, err
	}
	dir, ok := n.path()
	if !ok {
		return nil, errStale
	}
	if n.drv.spools.isSealed() {
		return nil, errGoingAway
	}
	spool, err := n.drv.tree.OpenSpool(ctx, n.dataroomID, joinPath(dir, at.name), nil, false)
	if err != nil {
		return nil, err
	}
	// The first flush creates the node with its mode, in one request.
	spool.SetMode(os.FileMode(mode).Perm())

	ino := n.drv.inodes.ino(n.drv.spools.pendingKey())
	node := vfs.Node{Name: at.name, Type: vfs.TypeFile, Mode: os.FileMode(mode).Perm(), ModeSet: true}
	st := n.drv.inodes.state(ino, node)
	st.place(at, n.drv.stamp())
	fresh := n.drv.newOpenSpool(st, ino, n.dataroomID, spool)
	fresh.local.Store(local)
	sp, _ := st.attach(fresh, nil)
	if err := n.drv.register(sp, at); err != nil {
		return nil, err
	}

	return sp, nil
}

// Symlink creates a symbolic link: one request. The target is stored as it is
// given, relative or absolute, whether or not it names anything: the kernel
// follows it, the driver never does. An API without symbolic links answers
// EPERM, as symlink(2) documents for a filesystem that cannot create one.
func (n *dirNode) Symlink(
	ctx context.Context, target, name string, out *fuse.EntryOut,
) (child *fs.Inode, errno syscall.Errno) {
	if errno := n.writable(name); errno != 0 {
		return nil, errno
	}
	c := n.drv.begin("symlink", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	// A file created here and not flushed yet holds its name.
	if n.drv.spools.find(location{parent: n.EmbeddedInode(), name: name}) != nil {
		return nil, syscall.EEXIST
	}
	ctx, span := startSpan(ctx, "symlink", n.dataroomID, n.seed.ID)
	seen := n.drv.stamp()
	var node vfs.Node
	err := n.drv.checkDataroom(ctx, n.dataroomID)
	if err == nil {
		err = n.drv.deletes.waitName(ctx, n, name)
	}
	if err == nil {
		err = n.withPath(ctx, func(path string) (err error) {
			node, err = n.drv.tree.Symlink(ctx, n.dataroomID, joinPath(path, name), target)

			return err
		})
	}
	span.End(err)
	if err != nil {
		return nil, pathErrno(err)
	}
	if node.ModTime.IsZero() {
		node.ModTime = time.Now()
	}

	return n.drv.child(ctx, n.EmbeddedInode(), n.drv.nodeEntry(n.dataroomID, node, seen), out), 0
}

// Hard links and device nodes are nothing a dataroom holds.

func (n *dirNode) Link(context.Context, fs.InodeEmbedder, string, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, n.unsupported()
}

func (n *dirNode) Mknod(context.Context, string, uint32, uint32, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, n.unsupported()
}

// unsupported is the errno of an operation the driver never performs: EPERM,
// which is what link(2) and mknod(2) document for a filesystem without them,
// and EROFS where nothing is written anyway.
func (n *dirNode) unsupported() syscall.Errno {
	if n.drv.readOnly(n.dataroomID) {
		return syscall.EROFS
	}

	return syscall.EPERM
}

// linkNode is a symbolic link. Its target came with the node, decrypted like
// its name: reading it asks nothing. The kernel follows it; the driver never
// does.
type linkNode struct {
	base
}

var _ fs.NodeReadlinker = (*linkNode)(nil)

func (n *linkNode) Readlink(context.Context) (target []byte, errno syscall.Errno) {
	c := n.drv.begin("readlink", n.ino)
	defer c.end(&errno)

	return []byte(n.state().current().Target), 0
}
