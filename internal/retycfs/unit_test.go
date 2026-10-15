//go:build linux

package retycfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	gofuse "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// — Inode table —————————————————————————————————————————————————————————————

func TestInodeTable_NumbersAreStable(t *testing.T) {
	table := newTestInodeTable(t)
	a, b := table.ino("node-a"), table.ino("node-b")
	if a <= accessLogIno || b <= accessLogIno || a == b {
		t.Fatalf("inode numbers %d and %d: want two distinct ones past the reserved %d", a, b, accessLogIno)
	}
	if again := table.ino("node-a"); again != a {
		t.Errorf("node-a: %d then %d", a, again)
	}
	// A dataroom and a node never share a number, whatever their IDs.
	if dr := table.ino(dataroomKey("node-a")); dr == a {
		t.Error("a dataroom took the number of the node of the same ID")
	}

	// Forgotten by the kernel, the node keeps its number and loses its state.
	inode := &gofuse.Inode{}
	st := table.state(a, vfs.Node{ID: "node-a", VersionID: "v1"})
	st.inode = inode
	table.forget(a, inode)
	if _, held := table.peek("node-a"); held {
		t.Error("state kept after the forget")
	}
	if again := table.ino("node-a"); again != a {
		t.Errorf("node-a after the forget: %d, want %d", again, a)
	}
	if ids, states := table.size(); ids != 3 || states != 0 {
		t.Errorf("table holds %d numbers and %d states, want 3 and 0", ids, states)
	}
}

// advance moves the clock of the table by d.
func (t *inodeTable) advance(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.now = func() time.Time { return now.Add(d) }
}

// handOut is a lookup of key: the number lent, an object made with it.
func (t *inodeTable) handOut(key string) uint64 {
	ino, live := t.lend(key, 0)
	if live == nil {
		// A zero object reads as Forgotten(): go-fuse never registered it, or
		// forgot it since.
		t.lent(ino, &gofuse.Inode{})
	}

	return ino
}

func TestInodeTable_SweepDropsWhatNothingHolds(t *testing.T) {
	table := newTestInodeTable(t)
	a := table.handOut("node-a")
	dr := table.handOut(dataroomKey("dr"))
	table.state(a, vfs.Node{ID: "node-a"})

	// Within the grace of the last handout, a number is kept: the object may
	// not be registered yet.
	table.sweep()
	if ids, _ := table.size(); ids != 2 {
		t.Fatalf("%d numbers after a sweep within the grace, want 2", ids)
	}

	table.advance(handoutGrace + time.Second)
	table.sweep()
	if _, held := table.peek("node-a"); held {
		t.Error("state kept with its number dropped")
	}
	if ids, states := table.size(); ids != 1 || states != 0 {
		t.Errorf("table holds %d numbers and %d states, want the dataroom's only", ids, states)
	}
	if again := table.ino(dataroomKey("dr")); again != dr {
		t.Errorf("dataroom: %d then %d, want its number kept", dr, again)
	}
	// Looked up again, the node gets a new number: none is ever reused.
	if again := table.ino("node-a"); again == a || again <= dr {
		t.Errorf("node-a after the sweep: %d, want a new number past %d", again, dr)
	}
}

// A live object handed out again may be forgotten by the kernel before the
// handler returns it, and go-fuse then registers it again: the re-handout
// starts a new grace, so the pruning of lent does not let it go meanwhile.
func TestInodeTable_HandingOutAgainRestartsTheGrace(t *testing.T) {
	table := newTestInodeTable(t)
	a := &gofuse.Inode{}
	live := map[*gofuse.Inode]bool{a: true}
	table.held = func(inode *gofuse.Inode) bool { return live[inode] }

	ino, got := table.lend("node", 0)
	if got != nil {
		t.Fatalf("first lend returned a live object")
	}
	table.lent(ino, a)

	table.advance(handoutGrace + time.Second)
	if again, got := table.lend("node", 0); again != ino || got != a {
		t.Fatalf("lend = %d, %p, want %d and the live object", again, got, ino)
	}
	// The kernel forgets it before the handler returns; other handouts of
	// the number make objects of their own and prune lent.
	live[a] = false
	for range lentMin {
		table.handOut("node")
	}
	table.mu.Lock()
	kept := slices.ContainsFunc(table.recs[ino].lent, func(l lentInode) bool { return l.inode == a })
	table.mu.Unlock()
	if !kept {
		t.Error("the object handed out again was pruned within its grace")
	}
}

func TestInodeTable_SweepKeepsWhatIsHeld(t *testing.T) {
	table := newTestInodeTable(t)
	open, lending := table.handOut("open"), table.ino("lending")
	pinned, listed := table.handOut("pinned"), table.ino("listed")
	table.state(open, vfs.Node{ID: "open", VersionID: "v1"}).opened(&gofuse.Inode{}, "v1")
	if got, live := table.lend("lending", 0); got != lending || live != nil {
		t.Fatalf("lend = %d, %v, want %d and no live object", got, live, lending)
	}
	table.pins = func() map[uint64]struct{} { return map[uint64]struct{}{pinned: {}} }

	table.advance(handoutGrace + time.Second)
	table.sweep()
	for key, want := range map[string]uint64{"open": open, "lending": lending, "pinned": pinned} {
		if got, ok := table.ids[key]; !ok || got != want {
			t.Errorf("%s: number %d (%v), want %d kept", key, got, ok, want)
		}
	}
	// A number assigned for a listing and never handed out goes.
	if _, ok := table.ids["listed"]; ok {
		t.Errorf("listed: number %d kept, nothing holds it", listed)
	}

	// Once the handout ends, and the grace with it, the number goes.
	table.lent(lending, &gofuse.Inode{})
	table.advance(2 * (handoutGrace + time.Second))
	table.sweep()
	if _, ok := table.ids["lending"]; ok {
		t.Error("lending: number kept once the object was made and forgotten")
	}
}

func TestInodeTable_AliasIsSweptWithItsPendingKey(t *testing.T) {
	table := newTestInodeTable(t)
	ino := table.handOut("pending:1")
	table.alias("node-x", ino)
	if got := table.ino("node-x"); got != ino {
		t.Fatalf("node-x: %d, want the number of the pending file %d", got, ino)
	}
	table.advance(handoutGrace + time.Second)
	table.sweep()
	if ids, _ := table.size(); ids != 0 {
		t.Errorf("%d keys left, want both keys of the number gone", ids)
	}
	if got := table.ino("node-x"); got == ino {
		t.Errorf("node-x got its old number %d back", got)
	}
	// An alias onto a number swept is not recorded: the key gets its own.
	table.alias("node-y", ino)
	if _, ok := table.ids["node-y"]; ok {
		t.Error("alias onto a swept number")
	}
}

func TestInodeTable_SweepsAsItGrows(t *testing.T) {
	table := newTestInodeTable(t)
	for i := range 10 * sweepMin {
		table.handOut(fmt.Sprintf("node-%d", i))
		table.advance(time.Second)
	}
	// Only what was handed out within the grace is left, and what was
	// assigned since the last sweep.
	if ids, _ := table.size(); ids > 2*sweepMin {
		t.Errorf("%d numbers held, want at most %d", ids, 2*sweepMin)
	}
}

// newTestInodeTable is newInodeTable, closed at the end of the test: no
// sweep scheduled by a FORGET outlives it.
func newTestInodeTable(t *testing.T) *inodeTable {
	t.Helper()
	table := newInodeTable()
	t.Cleanup(table.close)

	return table
}

// manualSweeps replaces the scheduler of the sweep that follows FORGETs: the
// sweeps scheduled are returned by the function, run when the test says.
func (t *inodeTable) manualSweeps() (scheduled func() []func()) {
	// A FORGET may have armed the real scheduler already (the kernel evicts
	// as it likes): stopped, the forgets it counted re-arm the manual one.
	if t.stopSweep != nil {
		t.stopSweep()
		t.stopSweep = nil
	}
	var pending []func()
	t.schedule = func(_ time.Duration, f func()) func() bool {
		pending = append(pending, f)

		return func() bool { return true }
	}

	return func() []func() {
		out := pending
		pending = nil

		return out
	}
}

// records counts the records of the table and the objects they hold.
func (t *inodeTable) records() (recs, objects int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, rec := range t.recs {
		objects += len(rec.lent)
	}

	return len(t.recs), objects
}

// The kernel forgets many inodes at once and nothing grows afterwards: the
// FORGETs alone release the records, and the objects they hold, once the
// grace has passed.
func TestInodeTable_ForgetsReleaseWithoutGrowth(t *testing.T) {
	table := newTestInodeTable(t)
	scheduled := table.manualSweeps()
	live := map[*gofuse.Inode]bool{}
	table.held = func(inode *gofuse.Inode) bool { return live[inode] }

	const n = 3 * sweepMin / 4 // below the growth that sweeps
	objects := make(map[uint64]*gofuse.Inode, n)
	for i := range n {
		ino, _ := table.lend(fmt.Sprintf("node-%d", i), 0)
		inode := &gofuse.Inode{}
		live[inode] = true
		table.lent(ino, inode)
		table.state(ino, vfs.Node{ID: fmt.Sprintf("node-%d", i)}).inode = inode
		objects[ino] = inode
	}
	if recs, held := table.records(); recs != n || held != n {
		t.Fatalf("%d records holding %d objects, want %d", recs, held, n)
	}

	// Half are forgotten long after their handout: their objects go at
	// once, their records with the sweep.
	table.advance(handoutGrace + time.Second)
	i := 0
	for ino, inode := range objects {
		if i++; i > n/2 {
			break
		}
		live[inode] = false
		table.forget(ino, inode)
	}
	if _, held := table.records(); held != n-n/2 {
		t.Errorf("%d objects held after %d forgets past the grace, want %d", held, n/2, n-n/2)
	}
	sweeps := scheduled()
	if len(sweeps) != 1 {
		t.Fatalf("%d sweeps scheduled by the forgets, want 1", len(sweeps))
	}

	// The others are handed out again, then forgotten within the grace of
	// that handout: the sweep scheduled meanwhile keeps them, the next one
	// takes them.
	for ino, inode := range objects {
		if live[inode] {
			if got, l := table.lend("", ino); got != ino || l != inode {
				t.Fatalf("lend(%d) = %d, %p", ino, got, l)
			}
		}
	}
	for ino, inode := range objects {
		if live[inode] {
			live[inode] = false
			table.forget(ino, inode)
		}
	}
	table.advance(time.Second)
	sweeps[0]()
	if recs, _ := table.records(); recs != n-n/2 {
		t.Errorf("%d records after the first sweep, want the %d forgotten within their grace", recs, n-n/2)
	}
	sweeps = scheduled()
	if len(sweeps) != 1 {
		t.Fatalf("%d sweeps scheduled after the first, want 1 for the forgets since", len(sweeps))
	}
	table.advance(forgetSweepDelay)
	sweeps[0]()
	recs, held := table.records()
	ids, states := table.size()
	if recs+held+ids+states != 0 {
		t.Errorf("table holds %d records, %d objects, %d keys, %d states, want nothing", recs, held, ids, states)
	}
	if more := scheduled(); len(more) != 0 {
		t.Errorf("%d sweeps scheduled with no forget since the last", len(more))
	}

	// Closed with the mount: no sweep is scheduled any more.
	ino := table.handOut("late")
	table.close()
	table.forget(ino, nil)
	if more := scheduled(); len(more) != 0 {
		t.Error("a sweep scheduled after close")
	}
}

func TestInodeTable_SweepDropsStatesWithoutNumber(t *testing.T) {
	table := newTestInodeTable(t)
	// A state recreated for a number swept: a dead object walking a path.
	table.state(4242, vfs.Node{ID: "gone"})
	busy := table.state(4243, vfs.Node{ID: "busy", VersionID: "v1"})
	busy.opened(&gofuse.Inode{}, "v1")
	table.sweep()
	if _, states := table.size(); states != 1 {
		t.Errorf("%d states, want the one in use only", states)
	}
}

func TestInodeTable_StateIsPerInodeNotPerObject(t *testing.T) {
	table := newTestInodeTable(t)
	ino := table.ino("f")
	// Two lookups of one node: two objects, each with the node it saw.
	first := table.state(ino, vfs.Node{ID: "f", Type: vfs.TypeFile, VersionID: "v1", Size: 1})
	second := table.state(ino, vfs.Node{ID: "f", Type: vfs.TypeFile, VersionID: "v2", Size: 2})
	if first != second {
		t.Fatal("two lookups of one inode got two states")
	}
	// The seed of the second is not what the table knows: observe is.
	if got := second.current().VersionID; got != "v1" {
		t.Errorf("current version = %s, want v1 until the node is observed", got)
	}
	second.observe(vfs.Node{ID: "f", Type: vfs.TypeFile, VersionID: "v2", Size: 2}, location{}, 0)
	if got := first.current(); got.VersionID != "v2" || got.Size != 2 {
		t.Errorf("the first object sees %+v, want the node observed through the second", got)
	}
}

func TestInodeTable_ForgetKeepsWhatIsInUse(t *testing.T) {
	table := newTestInodeTable(t)
	ino := table.ino("f")
	live, other := &gofuse.Inode{}, &gofuse.Inode{}
	st := table.state(ino, vfs.Node{ID: "f", Type: vfs.TypeFile, VersionID: "v1"})
	st.opened(live, "v1")

	// The forget of another object of the same inode changes nothing.
	table.forget(ino, other)
	if _, held := table.peek("f"); !held {
		t.Fatal("state dropped by the forget of an object that is not the live one")
	}
	// A handle still open keeps the state.
	table.forget(ino, live)
	if _, held := table.peek("f"); !held {
		t.Fatal("state dropped while a handle is open")
	}
	st.released("v1")
	table.forget(ino, live)
	if _, held := table.peek("f"); held {
		t.Error("state kept once nothing uses it")
	}
}

func TestInodeState_VersionChange(t *testing.T) {
	file := func(version string) vfs.Node {
		return vfs.Node{ID: "f", Type: vfs.TypeFile, VersionID: version}
	}
	inode := &gofuse.Inode{}
	st := &inodeState{node: file("v1")}
	observe := func(version string) *gofuse.Inode { return st.observe(file(version), location{}, 0) }
	// opened says how a handle on version is opened: "keep" (the page cache
	// as it is), "cache" (the page cache, emptied) or "direct" (around it).
	opened := func(version string) string {
		switch keep, direct := st.opened(inode, version); {
		case keep && direct:
			return "keep+direct"
		case direct:
			return "direct"
		case keep:
			return "keep"
		}

		return "cache"
	}

	// Never opened: the kernel caches no page, nothing to purge.
	if purge := observe("v2"); purge != nil {
		t.Error("purge asked for an inode that was never opened")
	}

	// First open: no pages vouched for yet, then they are.
	if got := opened("v2"); got != "cache" {
		t.Errorf("first open: %s", got)
	}
	if got := opened("v2"); got != "keep" {
		t.Errorf("second open of the same version: %s, want the cache kept", got)
	}
	// The same version seen again changes nothing.
	if purge := observe("v2"); purge != nil {
		t.Error("purge asked without a version change")
	}

	// A new version: the pages go, the two handles become stale.
	if purge := observe("v3"); purge != inode {
		t.Error("no purge on a version change")
	}
	if st.open != 0 || st.stale != 2 {
		t.Errorf("open %d stale %d, want 0 and 2", st.open, st.stale)
	}
	// While a stale handle lives it fills the page cache with the old
	// version: a handle on the new one reads around the cache.
	for range 2 {
		if got := opened("v3"); got != "direct" {
			t.Errorf("an open next to a stale handle: %s, want direct", got)
		}
	}
	// So does a handle on a version that is not the current one any more.
	if got := opened("v2"); got != "direct" {
		t.Errorf("an open of an old version: %s, want direct", got)
	}
	if purge := st.released("v2"); purge != inode {
		t.Error("no purge when a stale handle is released")
	}
	// Each stale handle that goes takes its pages with it.
	if purge := st.released("v2"); purge != inode {
		t.Error("no purge when a stale handle is released")
	}
	if got := opened("v3"); got != "direct" {
		t.Errorf("an open next to the last stale handle: %s, want direct", got)
	}
	if purge := st.released("v2"); purge != inode {
		t.Error("no purge when the last stale handle is released")
	}
	if st.stale != 0 || st.open != 3 {
		t.Errorf("open %d stale %d, want 3 and 0", st.open, st.stale)
	}
	// From there the cache is used again, and vouched for after one open.
	if got := opened("v3"); got != "cache" {
		t.Errorf("the open after the purge: %s", got)
	}
	if got := opened("v3"); got != "keep" {
		t.Errorf("the cache is not kept once the stale handles are gone: %s", got)
	}
	// A current handle released purges nothing.
	if purge := st.released("v3"); purge != nil {
		t.Error("purge on the release of a current handle")
	}

	// A folder or a link has no version to change.
	dir := &inodeState{node: vfs.Node{ID: "d", Type: vfs.TypeDir}, inode: inode}
	if purge := dir.observe(vfs.Node{ID: "d", Type: vfs.TypeDir, VersionID: "x"}, location{}, 0); purge != nil {
		t.Error("purge asked for a folder")
	}
}

// An open folder keeps the listing read when it was opened, and replays it
// entry by entry long after: what it says of a node must not undo what a
// later lookup said.
func TestInodeState_OlderObservationIsIgnored(t *testing.T) {
	file := func(version string, size int64) vfs.Node {
		return vfs.Node{ID: "f", Type: vfs.TypeFile, VersionID: version, Size: size}
	}
	inode := &gofuse.Inode{}
	a, b := location{parent: &gofuse.Inode{}, name: "f"}, location{parent: &gofuse.Inode{}, name: "g"}
	st := &inodeState{node: file("v1", 1)}
	st.observe(file("v1", 1), a, 1) // the listing, read at 1
	st.opened(inode, "v1")

	if purge := st.observe(file("v2", 2), b, 2); purge != inode { // a lookup, at 2
		t.Fatal("no purge on the version change")
	}
	// The listing replayed: older than what the table holds.
	if purge := st.observe(file("v1", 1), a, 1); purge != nil {
		t.Error("an older observation purged the pages")
	}
	if got := st.current(); got.VersionID != "v2" || got.Size != 2 {
		t.Errorf("an older observation replaced the node: %+v", got)
	}
	if st.where() != b || st.was != a {
		t.Error("an older observation moved the node")
	}
	if st.open != 0 || st.stale != 1 {
		t.Errorf("open %d stale %d, want 0 and 1", st.open, st.stale)
	}
	// The same answer again, and a newer one, are recorded.
	if purge := st.observe(file("v2", 2), b, 2); purge != nil {
		t.Error("purge without a change")
	}
	if purge := st.observe(file("v3", 3), b, 3); purge != inode || st.current().VersionID != "v3" {
		t.Error("a newer observation was not recorded")
	}
}

// The place of a node: the last one vfs found it at, and the one before as
// what is left to try when nothing is there any more.
func TestInodeState_Location(t *testing.T) {
	node := vfs.Node{ID: "d", Type: vfs.TypeDir}
	a, b := location{parent: &gofuse.Inode{}, name: "d"}, location{parent: &gofuse.Inode{}, name: "d"}
	st := &inodeState{node: node}
	if st.where().known() {
		t.Fatal("a place before any observation")
	}
	// The folder of a dataroom is observed without a place.
	st.observe(node, location{}, 1)
	if st.where().known() || st.relocate(location{}) {
		t.Fatal("a place out of nowhere")
	}

	st.observe(node, a, 2)
	if st.where() != a {
		t.Fatal("the place observed is not held")
	}
	if st.relocate(a) || st.where() != a {
		t.Error("nothing to fall back on: the place must stay")
	}
	st.observe(node, b, 3)
	st.observe(node, b, 4)
	if st.where() != b || st.was != a {
		t.Fatal("the place before is not kept")
	}
	// A place that is not the current one any more: the current one is to try.
	if !st.relocate(a) || st.where() != b {
		t.Error("relocate of a place already left")
	}
	if !st.relocate(b) || st.where() != a {
		t.Error("no fallback on the place before")
	}
	if st.relocate(a) {
		t.Error("a second fallback")
	}
}

// — Errors ——————————————————————————————————————————————————————————————————

func TestToErrno(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("listing the folder: %w", err) }
	for _, tc := range []struct {
		name string
		err  error
		want syscall.Errno
	}{
		{"nil", nil, 0},
		{"not exist", vfs.ErrNotExist, syscall.ENOENT},
		{"not exist, wrapped", wrap(os.ErrNotExist), syscall.ENOENT},
		{"404", wrap(&api.HTTPError{Status: 404}), syscall.ENOENT},
		{"410", wrap(api.ErrGone), syscall.ENOENT},
		{"exist", vfs.ErrExist, syscall.EEXIST},
		{"409", wrap(api.ErrConflict), syscall.EEXIST},
		{"not empty", wrap(vfs.ErrNotEmpty), syscall.ENOTEMPTY},
		{"is a folder", vfs.ErrIsDir, syscall.EISDIR},
		{"not a folder", vfs.ErrNotDir, syscall.ENOTDIR},
		{"path through a file", wrap(os.ErrInvalid), syscall.ENOTDIR},
		{"not a file", vfs.ErrNotFile, syscall.EINVAL},
		{"storage", wrap(vfs.ErrStorageExceeded), syscall.ENOSPC},
		{"forbidden", vfs.ErrForbidden, syscall.EACCES},
		{"403 from a listing", wrap(&api.HTTPError{Status: 403}), syscall.EACCES},
		{"unauthenticated", vfs.ErrUnauthenticated, syscall.EACCES},
		{"401 from a listing", wrap(&api.HTTPError{Status: 401}), syscall.EACCES},
		{"no token", wrap(auth.ErrNoToken), syscall.EACCES},
		{"no refresh token", wrap(auth.ErrNoRefreshToken), syscall.EACCES},
		{"legacy API", wrap(ErrLegacyAPI), syscall.ENOTSUP},
		{"replace unsupported", vfs.ErrReplaceUnsupported, syscall.ENOTSUP},
		{"cancelled", wrap(context.Canceled), syscall.EINTR},
		{"going away", wrap(errGoingAway), syscall.ENOTCONN},
		// After the client's own wait: an error, never "try again".
		{"rate limited", wrap(api.ErrRateLimited), syscall.EIO},
		{"rate limited 429", wrap(&api.HTTPError{Status: 429}), syscall.EIO},
		// A missing chunk is a 404 too, and is not "no such file".
		{"chunk missing", wrap(api.ErrChunkMissing), syscall.EIO},
		{"chunk missing with its 404", errors.Join(api.ErrChunkMissing, api.ErrNotFound), syscall.EIO},
		{"unreadable cut", wrap(vfs.ErrChunkLayout), syscall.EIO},
		{"closed", vfs.ErrClosed, syscall.EIO},
		{"deadline", context.DeadlineExceeded, syscall.EIO},
		{"500", wrap(&api.HTTPError{Status: 500}), syscall.EIO},
		// The errno of the HTTP client is not the one of the file.
		{"connection refused", wrap(syscall.ECONNREFUSED), syscall.EIO},
		{"anything else", errors.New("decrypting: bad key"), syscall.EIO},
	} {
		if got := toErrno(tc.err); got != tc.want {
			t.Errorf("%s: toErrno(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
	if toErrno(api.ErrRateLimited) == syscall.EAGAIN {
		t.Error("a rate limit must never be EAGAIN")
	}
}

// — Attributes ——————————————————————————————————————————————————————————————

func TestAttrSource_Fill(t *testing.T) {
	epoch := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mtime := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	src := attrSource{uid: 1000, gid: 100, fileMode: defaultFileMode, dirMode: defaultDirMode, epoch: epoch}

	for _, tc := range []struct {
		name         string
		node         vfs.Node
		mode         uint32
		size, blocks uint64
		nlink        uint32
		wantMtime    time.Time
	}{
		{
			name: "file with a mode", node: vfs.Node{Type: vfs.TypeFile, Size: 1025, Mode: 0o640, ModTime: mtime},
			mode: syscall.S_IFREG | 0o640, size: 1025, blocks: 3, nlink: 1, wantMtime: mtime,
		},
		{
			name: "file without a mode", node: vfs.Node{Type: vfs.TypeFile, Size: 512, ModTime: mtime},
			mode: syscall.S_IFREG | 0o644, size: 512, blocks: 1, nlink: 1, wantMtime: mtime,
		},
		{
			name: "empty file without a time", node: vfs.Node{Type: vfs.TypeFile},
			mode: syscall.S_IFREG | 0o644, nlink: 1, wantMtime: epoch,
		},
		{
			name: "special bits are dropped",
			node: vfs.Node{Type: vfs.TypeFile, Mode: 0o755 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky, ModTime: mtime},
			mode: syscall.S_IFREG | 0o755, nlink: 1, wantMtime: mtime,
		},
		{
			name: "file with an explicit 0", node: vfs.Node{Type: vfs.TypeFile, ModeSet: true, ModTime: mtime},
			mode: syscall.S_IFREG, nlink: 1, wantMtime: mtime,
		},
		{
			name: "file with setuid alone", node: vfs.Node{Type: vfs.TypeFile, Mode: fs.ModeSetuid, ModeSet: true},
			mode: syscall.S_IFREG, nlink: 1, wantMtime: epoch,
		},
		{
			name: "folder with an explicit 0", node: vfs.Node{Type: vfs.TypeDir, ModeSet: true},
			mode: syscall.S_IFDIR, nlink: 2, wantMtime: epoch,
		},
		{
			name: "folder without a mode", node: vfs.Node{Type: vfs.TypeDir, ModTime: mtime},
			mode: syscall.S_IFDIR | 0o755, nlink: 2, wantMtime: mtime,
		},
		{
			name: "folder with a mode", node: vfs.Node{Type: vfs.TypeDir, Mode: 0o700, Size: 99},
			mode: syscall.S_IFDIR | 0o700, nlink: 2, wantMtime: epoch,
		},
		{
			name: "symlink", node: vfs.Node{Type: vfs.TypeSymlink, Target: "../a/b", Mode: 0o600, ModTime: mtime},
			mode: syscall.S_IFLNK | 0o777, size: 6, blocks: 1, nlink: 1, wantMtime: mtime,
		},
	} {
		var out fuse.Attr
		src.fill(tc.node, 42, &out)
		if out.Mode != tc.mode || out.Size != tc.size || out.Blocks != tc.blocks || out.Nlink != tc.nlink {
			t.Errorf("%s: mode %o size %d blocks %d nlink %d; want %o %d %d %d",
				tc.name, out.Mode, out.Size, out.Blocks, out.Nlink, tc.mode, tc.size, tc.blocks, tc.nlink)
		}
		if out.Ino != 42 || out.Uid != 1000 || out.Gid != 100 || out.Blksize != blockSize {
			t.Errorf("%s: ino %d owner %d:%d blksize %d", tc.name, out.Ino, out.Uid, out.Gid, out.Blksize)
		}
		want := uint64(tc.wantMtime.Unix()) //nolint:gosec // G115: a date of this century
		if out.Mtime != want || out.Ctime != want || out.Atime != want {
			t.Errorf("%s: times %d %d %d, want %d", tc.name, out.Mtime, out.Ctime, out.Atime, want)
		}
	}
}

func TestXattrs(t *testing.T) {
	names := func(list []xattr) string {
		var out []string
		for _, x := range list {
			out = append(out, x.name+"="+x.value)
		}

		return strings.Join(out, " ")
	}
	file := vfs.Node{ID: "n1", Type: vfs.TypeFile, VersionID: "v1", MIMEType: "text/plain"}
	if got, want := names(xattrs("dr1", file)),
		"user.retyc.dataroom_id=dr1 user.retyc.node_id=n1 user.retyc.version_id=v1 user.retyc.mime=text/plain"; got != want {
		t.Errorf("file: %s", got)
	}
	if got := names(xattrs("dr1", vfs.Node{ID: "d1", Type: vfs.TypeDir, VersionID: "x", MIMEType: "y"})); got !=
		"user.retyc.dataroom_id=dr1 user.retyc.node_id=d1" {
		t.Errorf("folder: %s", got)
	}
	if got := names(xattrs("dr1", vfs.Node{Type: vfs.TypeDir})); got != "user.retyc.dataroom_id=dr1" {
		t.Errorf("dataroom root: %s", got)
	}
	if got := xattrs("", vfs.Node{Type: vfs.TypeDir}); len(got) != 0 {
		t.Errorf("root of all datarooms: %v", got)
	}

	// The size is asked for with an empty buffer.
	if n, errno := fit(nil, "value"); n != 5 || errno != syscall.ERANGE {
		t.Errorf("fit(nil) = %d, %v", n, errno)
	}
	buf := make([]byte, 8)
	if n, errno := fit(buf, "value"); n != 5 || errno != 0 || string(buf[:n]) != "value" {
		t.Errorf("fit = %d, %v, %q", n, errno, buf[:n])
	}
}

func TestNames(t *testing.T) {
	for name, want := range map[string]bool{
		"a.txt": true, ".hidden": true, "é": true, strings.Repeat("x", 255): true,
		"": false, ".": false, "..": false, "a/b": false, "a\x00b": false, strings.Repeat("x", 256): false,
	} {
		if got := presentable(name); got != want {
			t.Errorf("presentable(%q) = %v, want %v", name, got, want)
		}
	}
	if got := folderName("Q3/Q4 \x00review"); got != "Q3_Q4 _review" {
		t.Errorf("folderName = %q", got)
	}
}

func TestTimeout(t *testing.T) {
	if got := *timeout(0, time.Minute); got != time.Minute {
		t.Errorf("zero = %v, want the default", got)
	}
	if got := *timeout(3*time.Second, time.Minute); got != 3*time.Second {
		t.Errorf("set = %v", got)
	}
	if got := *timeout(-1, time.Minute); got != time.Nanosecond {
		t.Errorf("negative = %v, want the shortest", got)
	}
}

func TestUnescapeMount(t *testing.T) {
	for in, want := range map[string]string{
		"/mnt/dr":            "/mnt/dr",
		`/mnt/my\040dr`:      "/mnt/my dr",
		`/mnt/a\011b\134c`:   "/mnt/a\tb\\c",
		`/mnt/trailing\04`:   `/mnt/trailing\04`,
		`/mnt/not\09xoctal`:  `/mnt/not\09xoctal`,
		`/mnt/two\040\040sp`: "/mnt/two  sp",
	} {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}

// — Access log ——————————————————————————————————————————————————————————————

func TestAccessRecord_Format(t *testing.T) {
	at := time.Date(2026, 10, 12, 8, 30, 15, 123456000, time.UTC)
	lookup := accessRecord{at: at, op: "lookup", ino: 7, duration: 1234 * time.Microsecond, errno: syscall.ENOENT}
	want := "2026-10-12T08:30:15.123456Z lookup ino=7 1.234ms ENOENT\n"
	if got := string(lookup.appendTo(nil)); got != want {
		t.Errorf("lookup = %q, want %q", got, want)
	}
	read := accessRecord{
		at: at, op: "read", ino: 9, off: 4096, size: 131072, ranged: true, duration: 87 * time.Microsecond,
	}
	want = "2026-10-12T08:30:15.123456Z read ino=9 off=4096 len=131072 87µs ok\n"
	if got := string(read.appendTo(nil)); got != want {
		t.Errorf("read = %q, want %q", got, want)
	}
	if got := errnoName(syscall.Errno(200)); got != "errno=200" {
		t.Errorf("unnamed errno = %q", got)
	}
}

// readAll reads what the reader has until it would block.
func readLines(t *testing.T, r *accessReader, want int) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var text strings.Builder
	buf := make([]byte, 256)
	for strings.Count(text.String(), "\n") < want {
		n, err := r.read(ctx, buf)
		if err != nil || n == 0 {
			t.Fatalf("read = %d, %v after %q", n, err, text.String())
		}
		text.Write(buf[:n])
	}

	return strings.Split(strings.TrimSuffix(text.String(), "\n"), "\n")
}

func TestAccessLog_RingIsBounded(t *testing.T) {
	log := newAccessLog(4)
	early := log.reader()
	for i := range 3 {
		log.record(accessRecord{op: "getattr", ino: uint64(i + 1)})
	}
	// A reader starts at the oldest record held, and reads whole lines even
	// through a buffer smaller than one.
	small := make([]byte, 10)
	n, err := early.read(context.Background(), small)
	if err != nil || n != 10 {
		t.Fatalf("read into a small buffer = %d, %v", n, err)
	}
	rest := readLines(t, early, 3)
	if line := string(small) + rest[0]; !strings.Contains(line, " getattr ino=1 ") {
		t.Errorf("first line = %q", line)
	}
	if !strings.Contains(rest[2], " ino=3 ") {
		t.Errorf("third line = %q", rest[2])
	}

	// Ten more records in a ring of four: six are lost to that reader, which
	// is told, and reads the four that are left.
	for i := range 10 {
		log.record(accessRecord{op: "read", ino: uint64(100 + i)})
	}
	lines := readLines(t, early, 5)
	if lines[0] != "# 6 operations dropped" {
		t.Errorf("first line after the overflow = %q", lines[0])
	}
	if !strings.Contains(lines[1], " ino=106 ") || !strings.Contains(lines[4], " ino=109 ") {
		t.Errorf("lines after the overflow = %q", lines[1:])
	}

	// A reader that opens now starts at the oldest of the four.
	late := log.reader()
	if lines := readLines(t, late, 4); !strings.Contains(lines[0], " ino=106 ") {
		t.Errorf("a new reader starts at %q", lines[0])
	}
}

func TestAccessLog_ReadBlocksUntilARecord(t *testing.T) {
	log := newAccessLog(8)
	r := log.reader()
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := r.read(context.Background(), buf)
		got <- string(buf[:n])
	}()
	select {
	case line := <-got:
		t.Fatalf("read returned %q from an empty log", line)
	case <-time.After(50 * time.Millisecond):
	}
	log.record(accessRecord{op: "open", ino: 5})
	select {
	case line := <-got:
		if !strings.Contains(line, " open ino=5 ") {
			t.Errorf("line = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read not woken by a record")
	}
}

func TestAccessLog_CloseWakesReadersWithEOF(t *testing.T) {
	log := newAccessLog(8)
	log.record(accessRecord{op: "open", ino: 5})
	r := log.reader()
	buf := make([]byte, 256)
	if n, err := r.read(context.Background(), buf); n == 0 || err != nil {
		t.Fatalf("read = %d, %v", n, err)
	}

	done := make(chan int, 1)
	go func() {
		n, _ := r.read(context.Background(), buf)
		done <- n
	}()
	time.Sleep(20 * time.Millisecond)
	log.close()
	log.close() // twice is fine
	select {
	case n := <-done:
		if n != 0 {
			t.Errorf("read returned %d bytes at the end of the log", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked read was not woken by close")
	}
	// What was recorded before the close is still read by a new reader, then
	// the end.
	late := log.reader()
	if n, err := late.read(context.Background(), buf); n == 0 || err != nil {
		t.Errorf("backlog after close = %d, %v", n, err)
	}
	if n, err := late.read(context.Background(), buf); n != 0 || err != nil {
		t.Errorf("after the backlog = %d, %v; want the end of the file", n, err)
	}
}

func TestAccessLog_ReadIsInterruptible(t *testing.T) {
	log := newAccessLog(8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := log.reader().read(ctx, make([]byte, 64))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("read = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked read ignored its context")
	}
}

// — Notifier ————————————————————————————————————————————————————————————————

func TestNotifier_SendsInOrderAndStops(t *testing.T) {
	n := newNotifier()
	var order []int
	for i := range 5 {
		if !n.send(func() { order = append(order, i) }) {
			t.Fatal("send refused")
		}
	}
	n.flush()
	if fmt.Sprint(order) != "[0 1 2 3 4]" {
		t.Errorf("order = %v", order)
	}
	n.stop()
	n.stop()
	if n.send(func() { t.Error("sent after stop") }) {
		t.Error("send accepted after stop")
	}
	n.flush() // returns at once
}

// A notification waiting to be sent is not queued again: one the kernel is
// slow to take must not let the same change fill the queue.
func TestNotifier_CoalescesWhatWaits(t *testing.T) {
	n := newNotifier()
	defer n.stop()
	blocked, release := make(chan struct{}), make(chan struct{})
	n.send(func() { close(blocked); <-release })
	<-blocked

	a, b := &gofuse.Inode{}, &gofuse.Inode{}
	sent := make(map[notification]int)
	queue := func(what notification) { n.once(what, func() { sent[what]++ }) }
	pages, other := notification{inode: a}, notification{inode: b}
	entry, sibling := notification{inode: a, name: "x", entry: true}, notification{inode: a, name: "y", entry: true}
	for range 100 {
		queue(pages)
		queue(entry)
	}
	queue(other)
	queue(sibling)
	if got := len(n.queue); got != 4 {
		t.Errorf("%d notifications queued, want 4", got)
	}
	close(release)
	n.flush()
	for _, what := range []notification{pages, other, entry, sibling} {
		if sent[what] != 1 {
			t.Errorf("%+v sent %d times, want once", what, sent[what])
		}
	}

	// Once sent it can be queued again.
	queue(pages)
	n.flush()
	if sent[pages] != 2 {
		t.Errorf("a notification already sent was not queued again: %d", sent[pages])
	}
}
