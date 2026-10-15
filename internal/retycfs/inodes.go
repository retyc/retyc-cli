//go:build linux

package retycfs

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// The inode numbers the driver assigns itself. Everything else comes from the
// table, starting after them.
const (
	rootIno      uint64 = 1
	controlIno   uint64 = 2 // .retycfs
	accessLogIno uint64 = 3 // .retycfs/accesslog
)

// dataroomKey is the table key of the folder that stands for a dataroom in
// the "all datarooms" mode. A dataroom is not a node: its inode is synthetic.
// The prefix cannot collide with a node ID, which is a UUID.
func dataroomKey(dataroomID string) string { return dataroomPrefix + dataroomID }

const dataroomPrefix = "dataroom:"

// inodeTable gives every node a stable inode number for as long as the kernel
// or the driver holds it, and holds what the driver knows of each inode the
// kernel holds.
//
// Three maps:
//
//   - ids, key (a node ID, a dataroomKey, a pendingKey) → inode number. A node
//     keeps its number through renames, moves and new versions, and gets the
//     same one back after the kernel forgot it, for as long as its record
//     lives.
//   - recs, inode number → record: the keys that name the number and the
//     objects handed to go-fuse with it (see lend). sweep drops a record and
//     its keys once nothing can hold the number any more; the node then gets
//     a new number at its next lookup. Numbers are never reused: next only
//     counts up.
//   - states, inode number → state, holds an entry while the kernel holds the
//     inode (it is dropped on FORGET).
//
// The state of an inode lives here, never in the object a Lookup returns:
// go-fuse keeps the object of the first lookup of an inode and discards the
// one of every later lookup, and hands Getattr the first handle opened on the
// inode, whatever handle the caller means.
type inodeTable struct {
	mu     sync.Mutex
	next   uint64
	ids    map[string]uint64
	recs   map[uint64]*inodeRecord
	states map[uint64]*inodeState

	// now is the clock of the grace (handoutGrace), replaced by tests.
	now func() time.Time
	// held is the function held, replaced by tests: an object go-fuse holds
	// cannot be made outside a mount.
	held func(*fs.Inode) bool
	// sweepAt is the number of records at which the next assignment sweeps.
	sweepAt int
	// pins returns the numbers something outside the table compares (see
	// sameDir), which sweep keeps. Nil: none. Called without mu held.
	pins func() map[uint64]struct{}

	// The sweep that follows FORGETs (see forget): nothing grows after the
	// kernel lets go of many inodes at once, so the growth alone would never
	// sweep them. schedule runs f after d (time.AfterFunc, replaced by
	// tests) and returns what stops it; stopSweep is that of the sweep
	// scheduled, nil when none is. forgotten counts the FORGETs since it was
	// scheduled. closed: the mount is over, nothing is scheduled any more.
	schedule  func(d time.Duration, f func()) (stop func() bool)
	stopSweep func() bool
	forgotten int
	closed    bool
}

// inodeRecord is what holds an inode number assigned.
type inodeRecord struct {
	// keys are the keys of ids that name the number: a node ID, and the
	// pendingKey of a file created here before its first flush (alias).
	keys []string
	// last is when the number was last assigned or handed out.
	last time.Time
	// lending counts the handouts between lend and lent: an object is being
	// made with the number, and is not in lent yet.
	lending int
	// lent holds the objects made with the number that may still be live
	// (see sweep), and pruneAt the length at which lent prunes them. A lookup
	// of a node go-fuse holds returns the object it holds (lend), so a new
	// one is only made when none is live: the list stays short.
	lent    []lentInode
	pruneAt int
}

// lentInode is an object handed to go-fuse, and when.
type lentInode struct {
	inode *fs.Inode
	at    time.Time
}

const (
	// handoutGrace is how long a number handed out is kept whatever go-fuse
	// says of the object. An object returned by a handler is registered by
	// go-fuse right after the handler returns, in the same goroutine and with
	// nothing slower than inode mutexes to wait for: until then it does not
	// read as held (see sweep).
	handoutGrace = time.Minute
	// sweepMin is the fewest records a sweep is started for.
	sweepMin = 1024
	// lentMin is the shortest list of lent objects pruned.
	lentMin = 4
	// forgetSweepDelay is how long after a FORGET the sweep it calls for
	// runs: past the grace of a handout made at the time of the FORGET.
	forgetSweepDelay = handoutGrace + time.Second
)

func newInodeTable() *inodeTable {
	return &inodeTable{
		next:    accessLogIno,
		ids:     make(map[string]uint64),
		recs:    make(map[uint64]*inodeRecord),
		states:  make(map[uint64]*inodeState),
		now:     time.Now,
		held:    held,
		sweepAt: sweepMin,
		schedule: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
	}
}

// ino returns the inode number of key (a node ID, or a dataroomKey),
// assigning the next free one the first time, or the first time since its
// record was swept. An assignment that makes the table twice as large as
// after the last sweep sweeps it.
func (t *inodeTable) ino(key string) uint64 {
	t.mu.Lock()
	ino, grown := t.assignLocked(key)
	t.mu.Unlock()
	if grown {
		t.sweep()
	}

	return ino
}

// assignLocked returns the number of key, assigning one when it has none, and
// reports whether the table has grown enough to be swept. The caller holds
// mu.
func (t *inodeTable) assignLocked(key string) (ino uint64, grown bool) {
	if ino, ok := t.ids[key]; ok {
		return ino, false
	}
	t.next++
	t.ids[key] = t.next
	t.recs[t.next] = &inodeRecord{keys: []string{key}, last: t.now()}

	return t.next, len(t.recs) >= t.sweepAt
}

// lend returns the number an object handed to go-fuse is made with: the one
// of key, or ino itself when key is empty (a file known by its spool). The
// number is taken here, when the object is made, and not from a listing read
// earlier: the record may have been swept since.
//
// live is the object go-fuse holds for the number, when there is one: the
// caller returns it instead of making another, which go-fuse would discard
// for it anyway. Otherwise the caller makes one and gives it to lent; until
// then the record cannot be swept.
func (t *inodeTable) lend(key string, ino uint64) (_ uint64, live *fs.Inode) {
	t.mu.Lock()
	grown := false
	if key != "" {
		ino, grown = t.assignLocked(key)
	}
	rec := t.recs[ino]
	if rec == nil {
		// A number whose record was swept while a spool still knows it: it
		// is kept again, for as long as the object made with it.
		rec = &inodeRecord{}
		t.recs[ino] = rec
	}
	rec.last = t.now()
	for i := len(rec.lent) - 1; i >= 0 && live == nil; i-- {
		if t.held(rec.lent[i].inode) {
			live = rec.lent[i].inode
			// Handing it out again is a handout: a FORGET may land before
			// the handler returns it and go-fuse registers it again, so
			// lent's pruning must not let it go within the grace either.
			rec.lent[i].at = rec.last
		}
	}
	if live == nil {
		rec.lending++
	}
	t.mu.Unlock()
	if grown {
		t.sweep()
	}

	return ino, live
}

// lent records inode, the object made with the number ino that lend handed
// out. go-fuse registers it once the handler returns, or discards it for an
// object it registered for the number meanwhile (a concurrent lookup).
func (t *inodeTable) lent(ino uint64, inode *fs.Inode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.recs[ino]
	if rec == nil {
		return
	}
	now := t.now()
	rec.lending--
	rec.last = now
	rec.lent = append(rec.lent, lentInode{inode: inode, at: now})
	if len(rec.lent) >= max(rec.pruneAt, lentMin) {
		t.pruneLocked(rec, now)
	}
}

// pruneLocked lets go of the objects of rec that are dead and old enough to
// have been registered if they ever were (see sweep): nothing can make them
// live again, and a forgotten object still holds what go-fuse hung on it. The
// caller holds mu.
func (t *inodeTable) pruneLocked(rec *inodeRecord, now time.Time) {
	cutoff := now.Add(-handoutGrace)
	rec.lent = slices.DeleteFunc(rec.lent, func(l lentInode) bool {
		return l.at.Before(cutoff) && !t.held(l.inode)
	})
	if len(rec.lent) == 0 {
		rec.lent = nil
	}
	rec.pruneAt = 2 * len(rec.lent)
}

// sweep drops the records nothing holds any more, with their keys and their
// state, and the states of numbers without a record that nothing uses.
//
// A record is held while one of these is true:
//
//   - it names a dataroom (dataroomKey): bounded by the datarooms, kept;
//   - a number is being handed out (lending), or was within handoutGrace;
//   - an object handed out with it is held (see held): for the kernel, or
//     as a folder that still has children;
//   - its state is in use (busy): a handle, a spool, a live inode;
//   - something compares it (pins: the folder of a local file, sameDir).
//
// Why a number dropped is never one the kernel still holds. go-fuse keeps at
// most one object per number (registerNew deduplicates on StableAttr), and
// every object the driver gives it is made with a number from lend and
// recorded by lent, or is one lend returned (held then). An object the kernel
// holds, or that go-fuse keeps in its tree, is held. An object on its way to
// go-fuse is not, until registered: a new one, or a held one that a FORGET
// unregisters before the lookup that returned it registers it again. Both are
// the race of a LOOKUP with the FORGET of the same node (OnForget of the old
// object may run before or after the new registration), and the grace covers
// them, measured from the last handout: go-fuse registers the object in the
// goroutine of the handler, right after it returns, waiting for nothing
// slower than inode mutexes, never a minute later. So at the instant a
// record is dropped no object of the number is held, none is on its way, and
// none can come back: go-fuse revives an object only when a handler returns
// it, and lend returns no object of a number swept (it makes a new number).
// The next lookup of the node takes a new number from lend, with a new
// object; the old number is gone for good. Two live objects for one node, or
// a live object whose number ids no longer holds, cannot follow.
//
// What the dropped number leaves behind: a state that a dead object recreates
// (path walks through the state of a parent) is swept as a state without a
// record, once not in use.
//
// A record kept loses the dead objects past the grace all the same
// (pruneLocked): the record of a dataroom, or of a number pinned, outlives
// many objects.
//
// It runs when an assignment doubles the table (ino, lend), and once the
// grace has passed after FORGETs (forget): what the kernel lets go of is
// released without the table having to grow.
func (t *inodeTable) sweep() {
	var pinned map[uint64]struct{}
	if t.pins != nil {
		pinned = t.pins()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cutoff := now.Add(-handoutGrace)
	for ino, rec := range t.recs {
		t.pruneLocked(rec, now)
		if rec.lending > 0 || rec.last.After(cutoff) || rec.names(dataroomPrefix) {
			continue
		}
		if _, ok := pinned[ino]; ok {
			continue
		}
		if st, ok := t.states[ino]; ok && st.busy() {
			continue
		}
		if len(rec.lent) > 0 {
			// pruneLocked kept only objects held or within the grace, and
			// the grace of the record covers the latter.
			continue
		}
		for _, key := range rec.keys {
			if t.ids[key] == ino {
				delete(t.ids, key)
			}
		}
		delete(t.recs, ino)
		delete(t.states, ino)
	}
	for ino, st := range t.states {
		if _, ok := t.recs[ino]; !ok && !st.busy() {
			delete(t.states, ino)
		}
	}
	t.sweepAt = max(sweepMin, 2*len(t.recs))
}

// held reports whether go-fuse holds inode: the kernel has a reference to it,
// or it is in the tree of go-fuse (a folder forgotten while it has children).
// An object made and not registered yet reads as not held: the grace covers
// it (see sweep).
//
// Forgotten is deprecated in favour of NodeOnForgetter, which tells when an
// object is forgotten but not what sweep asks: whether an object is held now.
// An object go-fuse discarded for the one it already held is never forgotten,
// it was never registered.
func held(inode *fs.Inode) bool {
	return !inode.Forgotten() //nolint:staticcheck // SA1019: see above, OnForget cannot answer this
}

// names reports whether one of the keys of the record starts with prefix.
func (r *inodeRecord) names(prefix string) bool {
	return slices.ContainsFunc(r.keys, func(k string) bool { return strings.HasPrefix(k, prefix) })
}

// state returns the state of ino, created from seed when the table holds
// none: the first lookup of the inode, or one the kernel forgot while an
// object still refers to it.
func (t *inodeTable) state(ino uint64, seed vfs.Node) *inodeState {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.states[ino]
	if !ok {
		st = &inodeState{node: seed}
		t.states[ino] = st
	}

	return st
}

// peek returns the state of the inode of key, if the table holds one. It
// assigns nothing.
func (t *inodeTable) peek(key string) (*inodeState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ino, ok := t.ids[key]
	if !ok {
		return nil, false
	}
	st, ok := t.states[ino]

	return st, ok
}

// alias gives key the inode number ino, unless it already has one: a file
// created through the mount had an inode before the API gave it a node ID, and
// keeps it. Both keys then share the record of the number, and are swept
// together.
func (t *inodeTable) alias(key string, ino uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.ids[key]; ok {
		return
	}
	rec := t.recs[ino]
	if rec == nil {
		// Swept already: nothing holds the number, the key gets its own at
		// its next lookup.
		return
	}
	t.ids[key] = ino
	rec.keys = append(rec.keys, key)
}

// forget drops the state of ino once the kernel has forgotten inode, unless
// handles are still open on it or another live inode took its place, and the
// objects of the number that are dead past the grace (pruneLocked). The inode
// number stays assigned until sweep finds nothing that holds it: forget
// schedules one, past the grace of a handout made now, so that a mass of
// FORGETs (memory pressure, drop_caches) releases the records and the objects
// they hold without the table having to grow. At most one sweep is scheduled
// at a time, and one more once it ran when FORGETs came meanwhile: one sweep
// per grace at most, however many FORGETs.
func (t *inodeTable) forget(ino uint64, inode *fs.Inode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if rec := t.recs[ino]; rec != nil {
		t.pruneLocked(rec, t.now())
	}
	if !t.closed {
		t.forgotten++
		t.scheduleSweepLocked()
	}
	st, ok := t.states[ino]
	if !ok {
		return
	}
	st.mu.Lock()
	if st.inode == inode {
		st.inode = nil
	}
	busy := st.open > 0 || st.stale > 0 || st.inode != nil || st.spool != nil
	st.mu.Unlock()
	if !busy {
		delete(t.states, ino)
	}
}

// scheduleSweepLocked schedules the sweep that follows FORGETs, unless one is
// already scheduled or the mount is over. The caller holds mu.
func (t *inodeTable) scheduleSweepLocked() {
	if t.stopSweep != nil || t.closed || t.forgotten == 0 {
		return
	}
	t.forgotten = 0
	t.stopSweep = t.schedule(forgetSweepDelay, t.sweepForgotten)
}

// sweepForgotten is the sweep forget scheduled. FORGETs that came after it
// was scheduled may be of objects still within their grace: they get the
// next one.
func (t *inodeTable) sweepForgotten() {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return
	}
	t.sweep()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopSweep = nil
	t.scheduleSweepLocked()
}

// close stops the sweep scheduled, if any, and schedules none any more: the
// mount is over.
func (t *inodeTable) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.stopSweep != nil {
		t.stopSweep()
		t.stopSweep = nil
	}
}

// size returns the number of keys and of states held.
func (t *inodeTable) size() (ids, states int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return len(t.ids), len(t.states)
}

// location is where a node hangs in the tree: the folder vfs found it in, and
// its name there. The folder is held as its inode, which stands for its own
// state in the table: a folder that moves takes what it holds with it.
type location struct {
	parent *fs.Inode
	name   string
}

// known reports whether the location names a place.
func (l location) known() bool { return l.parent != nil }

// inodeState is what the driver knows of one inode.
type inodeState struct {
	mu sync.Mutex
	// node is the node as last seen in a lookup or a listing.
	node vfs.Node
	// seen dates node: the stamp (driver.stamp) of the answer of vfs it comes
	// from. An answer older than that is not recorded: an open folder keeps
	// the listing read when it was opened, and replays it long after.
	seen uint64
	// at is where vfs last found the node, was where it found it before that.
	// They are what the path given to vfs is built from, never the tree
	// go-fuse keeps: its newest parent is the one of the last lookup too, and
	// a lookup answered from a listing that predates a move puts the old
	// place first. was is what is tried when vfs finds nothing at at.
	at, was location
	// pagesOf is the version the kernel's page cache may hold pages of, empty
	// when it holds none the driver vouches for. An open keeps the cache
	// (FOPEN_KEEP_CACHE) only when it opens that version.
	pagesOf string
	// open counts the handles open on node.VersionID, stale those open on a
	// version the file had before: they keep reading what they opened.
	open  int
	stale int
	// inode is the live inode, set by the first open: what a notification to
	// the kernel is addressed to. Nil before, when the kernel caches no page.
	inode *fs.Inode
	// spool is the local copy the file is written through, while a handle
	// opened for writing, or since one was, lives (see openSpool). While it is
	// set it answers for the size, the modification time and the content of
	// the inode, and what vfs says of the node is not recorded.
	spool *openSpool
	// unlinked: the file was removed through this mount. Handles still open
	// on it go on reading and writing its spool.
	unlinked bool

	// lock is the API lock of the file while handles opened for writing hold
	// it (Options.MirrorLocks). It has its own mutex, held across the request
	// that takes or releases the lock, which mu never is.
	lock mirrorLock
}

// mirrorLock is the API lock of one inode: one lock for all the handles
// opened for writing on it, released with the last of them.
type mirrorLock struct {
	mu sync.Mutex
	// refs counts the handles the lock stands for.
	refs int
	// key is what vfs.LockManager knows the lock by, empty when none is held:
	// before the first handle, and when the API could not be asked for it.
	key string
}

// view returns the node as the driver presents it: the one last seen, with
// the size and the modification time of its spool while it has one. It never
// waits for more than a short mutex: Getattr answers from it. unlinked tells
// a file removed through this mount.
func (st *inodeState) view() (node vfs.Node, unlinked bool) {
	st.mu.Lock()
	node, sp, unlinked := st.node, st.spool, st.unlinked
	st.mu.Unlock()
	if sp != nil {
		node.Size, node.ModTime = sp.spool.Size(), sp.spool.ModTime()
	}

	return node, unlinked
}

// held returns the spool of the inode, nil when it has none.
func (st *inodeState) held() *openSpool {
	st.mu.Lock()
	defer st.mu.Unlock()

	return st.spool
}

// busy reports whether the state is in use: a handle open, a spool, or an
// inode the kernel or go-fuse still holds.
func (st *inodeState) busy() bool {
	st.mu.Lock()
	inode := st.inode
	busy := st.open > 0 || st.stale > 0 || st.spool != nil
	st.mu.Unlock()

	return busy || (inode != nil && held(inode))
}

// join takes a reference on the spool of the inode for one more handle, and
// returns nil when the inode has none.
func (st *inodeState) join() *openSpool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.spool != nil {
		st.spool.refs++
	}

	return st.spool
}

// attach makes sp the spool of the inode, with one reference, unless another
// open got there first: the spool returned is then that one, with one more
// reference, and fresh is false. The handles open on the version become
// stale: they keep reading it (see vfs.File) while the file changes.
func (st *inodeState) attach(sp *openSpool, inode *fs.Inode) (held *openSpool, fresh bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.spool != nil {
		st.spool.refs++

		return st.spool, false
	}
	sp.refs = 1
	st.spool = sp
	st.inode = inode
	st.stale += st.open
	st.open = 0
	st.pagesOf = ""

	return sp, true
}

// adopt records node, the file as a flush of its spool left it at the API,
// dated seen. A node the state already holds in that version teaches nothing:
// what the driver changed since (a mode) is kept.
func (st *inodeState) adopt(node vfs.Node, seen uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if node.ID == st.node.ID && node.VersionID == st.node.VersionID {
		return
	}
	// A mode the file was given here and its node does not carry yet stays
	// the mode of the file (see openSpool.copied).
	if !node.HasMode() || (st.spool != nil && st.spool.modeOwed) {
		node.Mode, node.ModeSet = st.node.Mode, st.node.ModeSet
	}
	st.node = node
	st.seen = max(st.seen, seen)
	st.pagesOf = ""
}

// place records a change made through this mount, dated seen: the node is
// now at the place at, under the name of that place.
func (st *inodeState) place(at location, seen uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.at, st.was = at, location{}
	st.node.Name = at.name
	st.seen = max(st.seen, seen)
}

// remove records that the file was removed through this mount.
func (st *inodeState) remove(seen uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.unlinked = true
	st.seen = max(st.seen, seen)
}

// edit changes the node the state holds, for a change made through this
// mount.
func (st *inodeState) edit(seen uint64, change func(node *vfs.Node)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	change(&st.node)
	st.seen = max(st.seen, seen)
}

// current returns the node as last seen.
func (st *inodeState) current() vfs.Node {
	st.mu.Lock()
	defer st.mu.Unlock()

	return st.node
}

// where returns the place vfs last found the node at.
func (st *inodeState) where() location {
	st.mu.Lock()
	defer st.mu.Unlock()

	return st.at
}

// relocate is called when vfs no longer finds the node at dead. It falls back
// on the place the node was found at before, and reports whether there is
// another place than dead to try. Without one the state keeps dead: the next
// lookup of the node corrects it.
func (st *inodeState) relocate(dead location) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.at != dead {
		return st.at.known()
	}
	if !st.was.known() {
		return false
	}
	st.at, st.was = st.was, location{}

	return true
}

// observe records node, found at the place at (none for the folder of a
// dataroom) by an answer of vfs stamped seen, as the inode's current one. An
// answer older than the last one recorded is ignored. It reports the live
// inode to purge the pages of when the version changed under a kernel that
// may cache some, nil otherwise.
//
// The handles open at that moment become stale: they go on reading the
// version they opened (see vfs.File), and the pages they bring in are those
// of an old version, so no open uses the cache while one of them lives.
func (st *inodeState) observe(node vfs.Node, at location, seen uint64) (purge *fs.Inode) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if seen < st.seen || st.spool != nil || st.unlinked {
		// While the file is written here, the mount is what knows it.
		return nil
	}
	st.seen = seen
	if at.known() && at != st.at {
		if st.at.known() {
			st.was = st.at
		}
		st.at = at
	}
	changed := node.Type == vfs.TypeFile && node.VersionID != st.node.VersionID
	st.node = node
	if !changed {
		return nil
	}
	st.stale += st.open
	st.open = 0
	st.pagesOf = ""

	return st.inode
}

// opened records a handle open on version. It reports whether the kernel may
// keep the pages it holds for the inode, and whether the handle must read
// around the page cache (FOPEN_DIRECT_IO).
//
// The page cache belongs to the inode, not to the handle. While a handle is
// open on another version than the one opened here, it fills the cache with
// its own version: this handle would be served those pages. It is therefore
// opened direct, and reads through its vfs.File only. So is a handle whose
// version is not the current one any more.
//
// What is left: the handle open before the change keeps reading through the
// cache, under the attributes of the inode, which are those of the new
// version. Its reads stop at the size of the new version when that one is
// shorter.
func (st *inodeState) opened(inode *fs.Inode, version string) (keepCache, direct bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.inode = inode
	if version != st.node.VersionID {
		// The file changed between the revalidation and this call.
		st.stale++

		return false, true
	}
	st.open++
	if st.stale > 0 {
		return false, true
	}
	keepCache = st.pagesOf == version
	st.pagesOf = version

	return keepCache, false
}

// released records the end of a handle open on version. It reports the inode
// to purge the pages of when the handle read an old version: what it brought
// into the page cache is not the file any more.
func (st *inodeState) released(version string) (purge *fs.Inode) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if version == st.node.VersionID && st.open > 0 {
		st.open--

		return nil
	}
	if st.stale > 0 {
		st.stale--
	}
	st.pagesOf = ""

	return st.inode
}
