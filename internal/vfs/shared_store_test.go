package vfs

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// newTreeInstances returns two FS on the API a that share store, as two
// processes sharing a store outside them would: one session, nothing cached.
func newTreeInstances(t *testing.T, a *treeAPI, store metastore.MetaStore, opts Options) (one, other *FS) {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	a.pub = identity.Recipient().String()
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	opts.Store = store
	build := func() *FS {
		fs := New(testClient(srv), opts)
		fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: a.pub, NameSalt: a.salt})

		return fs
	}

	return build(), build()
}

// — Entries and the generation of the store —————————————————————————————————————

// A lookup by name answered "found" before another instance removed the node
// leaves no positive entry behind: the instances that have no listing of the
// folder would find the deleted file for a TTL.
func TestLookup_FoundBeforeARemovalElsewhereIsNotKept(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs, other := newTreeInstances(t, a, memstore.New(), Options{NegativeTTL: time.Minute, NoListingAhead: true})
	mustLookup(t, fs, "/", "a", "d-a")

	arrived, release := a.holdNextLookup()
	done := make(chan error, 1)
	go func() {
		_, err := fs.Lookup(context.Background(), "dr1", "/a", "x.txt")
		done <- err
	}()
	<-arrived
	other.forget("dr1", "/a", "x.txt") // what a Remove records
	release()
	if err := <-done; err != nil {
		t.Fatalf("Lookup = %v, want the node the API answered", err)
	}
	if e, ok := cachedEntry(fs, "/a", "x.txt"); ok {
		t.Errorf("entry kept = %+v, want none: the folder changed in the store while the API answered", e)
	}
}

// A lookup by name answered "missing" before another instance created the
// name leaves no negative entry over the positive one of the creation: every
// instance, the creator included, would answer ENOENT.
func TestLookup_MissingBeforeACreationElsewhereIsNotKept(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs, other := newTreeInstances(t, a, memstore.New(), Options{NegativeTTL: time.Minute, NoListingAhead: true})
	mustLookup(t, fs, "/", "a", "d-a")

	arrived, release := a.holdNextLookup()
	done := make(chan error, 1)
	go func() {
		_, err := fs.Lookup(context.Background(), "dr1", "/a", "new")
		done <- err
	}()
	<-arrived
	other.upsert("dr1", "/a", Node{ID: "n-new", Name: "new", Type: TypeFile}) // what an upload records
	release()
	if err := <-done; !errors.Is(err, ErrNotExist) {
		t.Fatalf("Lookup = %v, want what the API answered", err)
	}
	if e, ok := cachedEntry(other, "/a", "new"); !ok || e.Node == nil || e.Node.ID != "n-new" {
		t.Errorf("entry = (%+v, %v), want the node the other instance created", e, ok)
	}
	lookups, _, _ := a.counts()
	mustLookup(t, other, "/a", "new", "n-new")
	mustLookup(t, fs, "/a", "new", "n-new")
	if after, _, _ := a.counts(); after != lookups {
		t.Errorf("%d lookups reached the API, want the entry to answer", after-lookups)
	}
}

// afterUpsertStore runs a hook right after an UpsertNode: the write of
// another process that lands between two operations of this one.
type afterUpsertStore struct {
	*memstore.Store
	after func()
}

func (s *afterUpsertStore) UpsertNode(ctx context.Context, key metastore.ListingKey, n metastore.Node) (uint64, error) {
	gen, err := s.Store.UpsertNode(ctx, key, n)
	if hook := s.after; hook != nil {
		s.after = nil
		hook()
	}

	return gen, err
}

// The entry an upsert keeps for a node of a folder that is not listed is
// stored under the generation its edit left: a removal by another process in
// between is not answered by it.
func TestUpsert_EntryNotKeptOverAWriteElsewhere(t *testing.T) {
	store := &afterUpsertStore{Store: memstore.New()}
	fs := New(nil, Options{Store: store, List: newHeldList().list})
	store.after = func() {
		if _, err := store.RemoveNode(context.Background(), key("dr1", "/d"), "x"); err != nil {
			t.Error(err)
		}
	}
	fs.upsert("dr1", "/d", Node{ID: "n1", Name: "x", Type: TypeFile})
	if e, ok := cachedEntry(fs, "/d", "x"); ok {
		t.Errorf("entry kept = %+v, want none: the node was removed elsewhere since the edit", e)
	}

	// Nothing in between: the entry is kept, as before.
	fs.upsert("dr1", "/d", Node{ID: "n2", Name: "y", Type: TypeFile})
	if e, ok := cachedEntry(fs, "/d", "y"); !ok || e.Node == nil || e.Node.ID != "n2" {
		t.Errorf("entry = (%+v, %v), want the node upserted", e, ok)
	}
}

// — A store that fails ——————————————————————————————————————————————————————————

// downStore is a memstore that fails everything while down, without applying
// it, and counts what it was asked.
type downStore struct {
	metastore.MetaStore
	down   atomic.Bool
	asked  atomic.Int32
	closed atomic.Int32
}

func (s *downStore) fail() error {
	s.asked.Add(1)
	if s.down.Load() {
		return errStoreDown
	}

	return nil
}

func (s *downStore) GetListing(ctx context.Context, key metastore.ListingKey) (*metastore.Listing, bool, error) {
	if err := s.fail(); err != nil {
		return nil, false, err
	}

	return s.MetaStore.GetListing(ctx, key)
}

func (s *downStore) ListingMeta(ctx context.Context, key metastore.ListingKey) (metastore.ListingMeta, bool, error) {
	if err := s.fail(); err != nil {
		return metastore.ListingMeta{}, false, err
	}

	return s.MetaStore.ListingMeta(ctx, key)
}

func (s *downStore) GetNode(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, error) {
	if err := s.fail(); err != nil {
		return nil, metastore.ListingMeta{}, false, err
	}

	return s.MetaStore.GetNode(ctx, key, name)
}

func (s *downStore) GetNamed(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, *metastore.Entry, bool, error) {
	if err := s.fail(); err != nil {
		return nil, metastore.ListingMeta{}, false, nil, false, err
	}

	return s.MetaStore.GetNamed(ctx, key, name)
}

func (s *downStore) RenewListingIf(
	ctx context.Context, key metastore.ListingKey, etag string, fetchedAt time.Time, gen uint64,
) (bool, error) {
	if err := s.fail(); err != nil {
		return false, err
	}

	return s.MetaStore.RenewListingIf(ctx, key, etag, fetchedAt, gen)
}

func (s *downStore) Generation(ctx context.Context, key metastore.ListingKey) (uint64, error) {
	if err := s.fail(); err != nil {
		return 0, err
	}

	return s.MetaStore.Generation(ctx, key)
}

func (s *downStore) PutListingIf(
	ctx context.Context, key metastore.ListingKey, l *metastore.Listing, gen uint64,
) (bool, error) {
	if err := s.fail(); err != nil {
		return false, err
	}

	return s.MetaStore.PutListingIf(ctx, key, l, gen)
}

func (s *downStore) DeleteListing(ctx context.Context, key metastore.ListingKey) error {
	if err := s.fail(); err != nil {
		return err
	}

	return s.MetaStore.DeleteListing(ctx, key)
}

func (s *downStore) DeleteEntries(ctx context.Context, dataroomID, parentPath string) error {
	if err := s.fail(); err != nil {
		return err
	}

	return s.MetaStore.DeleteEntries(ctx, dataroomID, parentPath)
}

func (s *downStore) GetEntry(ctx context.Context, key metastore.EntryKey) (*metastore.Entry, bool, error) {
	if err := s.fail(); err != nil {
		return nil, false, err
	}

	return s.MetaStore.GetEntry(ctx, key)
}

func (s *downStore) GetDatarooms(ctx context.Context) (*metastore.DataroomList, bool, error) {
	if err := s.fail(); err != nil {
		return nil, false, err
	}

	return s.MetaStore.GetDatarooms(ctx)
}

func (s *downStore) PutDatarooms(ctx context.Context, list *metastore.DataroomList) error {
	if err := s.fail(); err != nil {
		return err
	}

	return s.MetaStore.PutDatarooms(ctx, list)
}

func (s *downStore) Close() error {
	s.closed.Add(1)

	return s.MetaStore.Close()
}

// testClock is a clock a test moves.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// A store that fails, a read included, is set aside for TTL + MaxStale and
// not for good: meanwhile it is asked nothing, then it is used again, and set
// aside again should it still fail. One line tells each change.
func TestFS_FailedStoreIsSuspendedThenUsedAgain(t *testing.T) {
	store := &downStore{MetaStore: memstore.New()}
	var logs logRecorder
	var calls atomic.Int32
	fs := New(nil, Options{
		Store: store, Logf: logs.logf, TTL: time.Minute, MaxStale: 2 * time.Minute,
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			calls.Add(1)

			return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
		},
	})
	clock := &testClock{now: time.Now()}
	fs.now = clock.Now
	ctx := context.Background()
	readDir := func(when string, wantCalls int32) {
		t.Helper()
		if nodes, err := fs.ReadDir(ctx, "dr1", "/"); err != nil || len(nodes) != 1 {
			t.Fatalf("%s: ReadDir = (%+v, %v)", when, nodes, err)
		}
		if got := calls.Load(); got != wantCalls {
			t.Fatalf("%s: listed %d times, want %d", when, got, wantCalls)
		}
	}
	wantLogs := func(when string, n int, last string) {
		t.Helper()
		got := logs.list()
		if len(got) != n || (n > 0 && !strings.Contains(got[n-1], last)) {
			t.Fatalf("%s: logs = %q, want %d, the last one saying %q", when, got, n, last)
		}
	}

	readDir("at first", 1)
	readDir("cached in the store", 1)
	wantLogs("a store that works", 0, "")

	// A read fails: the listing is asked of the API, and kept in memory.
	store.down.Store(true)
	readDir("the store down", 2)
	wantLogs("the store down", 1, errStoreDown.Error())
	asked := store.asked.Load()
	readDir("suspended", 2)
	fs.InvalidateListing("dr1", "/")
	readDir("suspended, after an invalidation", 3)
	if got := store.asked.Load(); got != asked {
		t.Errorf("the suspended store was asked %d more times, want none", got-asked)
	}
	wantLogs("suspended", 1, errStoreDown.Error())

	// Not before TTL + MaxStale.
	clock.advance(3*time.Minute - time.Second)
	readDir("just before the end", 3)
	if got := store.asked.Load(); got != asked {
		t.Errorf("the store was asked again %d times before the end of its suspension", got-asked)
	}

	// Past it the store is back, the private one gone with what it held: the
	// listing comes from the configured store, where the first one still is.
	store.down.Store(false)
	clock.advance(2 * time.Second)
	readDir("at the end", 3)
	wantLogs("back", 2, "back on the configured store")
	readDir("back", 3)
	if got := store.asked.Load(); got == asked {
		t.Error("the store was not asked again once its suspension was over")
	}
	fs.mu.Lock()
	current := fs.store
	fs.mu.Unlock()
	if current != metastore.MetaStore(store) {
		t.Error("the FS did not go back to the configured store")
	}

	// It fails again: suspended again, and told again.
	store.down.Store(true)
	fs.InvalidateListing("dr1", "/")
	wantLogs("down again", 3, errStoreDown.Error())
	readDir("suspended again", 4)
	readDir("suspended again, cached", 4)

	if err := fs.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if got := store.closed.Load(); got != 1 {
		t.Errorf("the configured store was closed %d times, want once, by Close", got)
	}
}

// A read the caller gave up on is the caller's failure, not the store's.
func TestFS_CancelledReadDoesNotSuspendTheStore(t *testing.T) {
	store := &downStore{MetaStore: memstore.New()}
	var logs logRecorder
	fs := New(nil, Options{Store: store, Logf: logs.logf, List: newHeldList().list})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store.down.Store(true)
	fs.mu.Lock()
	_, ok := fs.heldLocked(ctx, key("dr1", "/"))
	fs.unlock()
	store.down.Store(false)
	if ok || len(logs.list()) != 0 {
		t.Errorf("a read with a context that is over: held %v, logs %q, want a miss and no suspension", ok, logs.list())
	}
}

// A listing asked of the API under one store is not stored in the one that
// took its place meanwhile: its generation was read from the other.
func TestFetch_NotStoredInAStoreThatChangedMeanwhile(t *testing.T) {
	store := &downStore{MetaStore: memstore.New()}
	held := newHeldList("f")
	fs := New(nil, Options{Store: store, List: held.list})
	got := make(chan []Node, 1)
	go func() {
		nodes, _ := fs.ReadDir(context.Background(), "dr1", "/")
		got <- nodes
	}()
	<-held.entered
	store.down.Store(true)
	fs.InvalidateListing("dr1", "/elsewhere") // fails: the store is suspended
	close(held.release)
	if nodes := <-got; len(nodes) != 1 {
		t.Fatalf("ReadDir = %+v, want the answer of the API", nodes)
	}
	if l := cachedListing(fs, "dr1", "/"); l != nil {
		t.Errorf("the answer was stored in the store that took over: %+v", l)
	}
}

// The list of a DataroomCache built on its own follows the same rule.
func TestDataroomCache_FailedStoreIsSuspendedThenUsedAgain(t *testing.T) {
	store := &downStore{MetaStore: memstore.New()}
	var logs logRecorder
	var calls atomic.Int32
	c := NewDataroomCache(func(context.Context) ([]Dataroom, error) {
		calls.Add(1)

		return []Dataroom{{ID: "id-1", Title: "Docs"}}, nil
	}, Options{Store: store, Logf: logs.logf, TTL: time.Minute, MaxStale: time.Minute})
	clock := &testClock{now: time.Now()}
	c.store.(*ownDataroomStore).now = clock.Now
	ctx := context.Background()
	resolve := func(when string, wantCalls int32) {
		t.Helper()
		if id, err := c.IDForName(ctx, "Docs"); err != nil || id != "id-1" {
			t.Fatalf("%s: IDForName = (%q, %v)", when, id, err)
		}
		if got := calls.Load(); got != wantCalls {
			t.Fatalf("%s: listed %d times, want %d", when, got, wantCalls)
		}
	}

	store.down.Store(true)
	resolve("the store down", 1)
	asked := store.asked.Load()
	resolve("suspended", 1)
	if got := store.asked.Load(); got != asked {
		t.Errorf("the suspended store was asked %d more times", got-asked)
	}
	if got := logs.list(); len(got) != 1 || !strings.Contains(got[0], errStoreDown.Error()) {
		t.Fatalf("logs = %q, want the suspension once", got)
	}

	store.down.Store(false)
	clock.advance(2*time.Minute + time.Second)
	resolve("back", 2) // the private store went with the list
	resolve("back, cached", 2)
	if stored, ok, _ := store.MetaStore.GetDatarooms(ctx); !ok || len(stored.Items) != 1 {
		t.Errorf("the configured store holds (%+v, %v), want the list fetched once it was back", stored, ok)
	}
	if got := logs.list(); len(got) != 2 || !strings.Contains(got[1], "back on the configured store") {
		t.Errorf("logs = %q, want the return told once", got)
	}
}

// — Hidden nodes and a shared store —————————————————————————————————————————————

// A node hidden here stays absent when another instance, which knows nothing
// of it, puts it back in the shared store: in a listing, in the child read
// for a lookup, in an entry. The stored values are not written through.
func TestHideNode_NotBroughtBackByAnotherInstance(t *testing.T) {
	store := memstore.New()
	list := func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}, {ID: "n2", Name: "b", Type: "file"}}, nil
	}
	opts := Options{Store: store, List: list, TTL: time.Minute, FetchTimeout: time.Minute}
	fs, other := New(nil, opts), New(nil, opts)
	ctx := context.Background()

	fs.HideNode("dr1", "/", Node{ID: "n1", Name: "a"})
	fs.HideNode("dr1", "/sub", Node{ID: "n3", Name: "c"})
	if nodes, err := other.ReadDir(ctx, "dr1", "/"); err != nil || len(nodes) != 2 {
		t.Fatalf("ReadDir of the other instance = (%+v, %v), want both nodes", nodes, err)
	}
	err := store.PutEntry(ctx, entryKey("dr1", "/sub", "c"),
		&Entry{Node: &Node{ID: "n3", Name: "c", Type: TypeFile}, FetchedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}

	nodes, err := fs.ReadDir(ctx, "dr1", "/")
	if err != nil || len(nodes) != 1 || nodes[0].ID != "n2" {
		t.Errorf("ReadDir = (%+v, %v), want the hidden node left out", nodes, err)
	}
	if n, err := fs.Lookup(ctx, "dr1", "/", "a"); !errors.Is(err, ErrNotExist) {
		t.Errorf("Lookup of the hidden node, listed in the store = (%+v, %v), want ErrNotExist", n, err)
	}
	if n, err := fs.Lookup(ctx, "dr1", "/", "b"); err != nil || n.ID != "n2" {
		t.Errorf("Lookup of its sibling = (%+v, %v)", n, err)
	}
	if n, err := fs.Lookup(ctx, "dr1", "/sub", "c"); !errors.Is(err, ErrNotExist) {
		t.Errorf("Lookup of the hidden node, held as an entry = (%+v, %v), want ErrNotExist", n, err)
	}
	if _, ok := fs.cachedFileID("dr1", "/", "a"); ok {
		t.Error("the overwrite shortcut found the hidden node")
	}

	// The other instance still reads what it stored.
	if l, ok, _ := store.GetListing(ctx, key("dr1", "/")); !ok || len(l.Nodes) != 2 {
		t.Errorf("the stored listing = (%+v, %v), want its two nodes untouched", l, ok)
	}
	if e, ok, _ := store.GetEntry(ctx, entryKey("dr1", "/sub", "c")); !ok || e.Node == nil {
		t.Errorf("the stored entry = (%+v, %v), want it untouched", e, ok)
	}

	// Shown again, it is read from the store like any other.
	fs.mu.Lock()
	delete(fs.hidden, "n1")
	fs.mu.Unlock()
	if nodes, _ := fs.ReadDir(ctx, "dr1", "/"); len(nodes) != 2 {
		t.Errorf("ReadDir once shown again = %+v, want both nodes", nodes)
	}
}

// — The first listing of a dataroom —————————————————————————————————————————————

// keyedStore is a memstore that, like a store naming its keys by the
// dataroom's name hash, knows nothing of a dataroom whose session is not
// resolved: generation 0, nothing held.
type keyedStore struct {
	*memstore.Store
	codec metastore.Codec
}

func (s *keyedStore) Bind(c metastore.Codec) { s.codec = c }

func (s *keyedStore) Generation(ctx context.Context, key metastore.ListingKey) (uint64, error) {
	if _, ok := s.codec.Hash(key.DataroomID, key.Path); !ok {
		return 0, nil
	}

	return s.Store.Generation(ctx, key)
}

// The first listing of a dataroom, whose session is resolved by the fetch
// itself, is stored even though another instance wrote to the folder before:
// the generation is read again once the store can name the dataroom.
func TestFetch_FirstListingOfADataroomIsStored(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a.pub = identity.Recipient().String()
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	store := &keyedStore{Store: memstore.New()}
	ctx := context.Background()
	for range 3 { // what another instance did to the folder
		if err := store.DeleteListing(ctx, key("dr1", "/")); err != nil {
			t.Fatal(err)
		}
	}
	var resolved atomic.Int32
	fs := New(testClient(srv), Options{
		Store: store, TTL: time.Minute,
		Session: func(context.Context, string) (*service.DataroomSession, error) {
			resolved.Add(1)

			return &service.DataroomSession{Identity: identity, PublicKey: a.pub, NameSalt: a.salt}, nil
		},
	})

	nodes, err := fs.ReadDir(ctx, "dr1", "/")
	if err != nil || len(nodes) != 1 || nodes[0].Type != TypeDir {
		t.Fatalf("ReadDir = (%+v, %v), want the folder a", nodes, err)
	}
	if l := cachedListing(fs, "dr1", "/"); l == nil {
		t.Fatal("the first listing of the dataroom was not stored")
	}
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	if _, listings, _ := a.counts(); listings != 1 {
		t.Errorf("%d listings reached the API, want 1", listings)
	}
	if got := resolved.Load(); got != 1 {
		t.Errorf("the session was resolved %d times, want once", got)
	}

	// A session that does not resolve is the error of the listing, asked once.
	failing := errors.New("no session")
	var asked atomic.Int32
	broken := New(testClient(srv), Options{
		Store: memstore.New(),
		Session: func(context.Context, string) (*service.DataroomSession, error) {
			asked.Add(1)

			return nil, failing
		},
	})
	if _, err := broken.ReadDir(ctx, "dr1", "/"); !errors.Is(err, failing) || asked.Load() != 1 {
		t.Errorf("ReadDir without a session = %v after %d resolutions, want its error, asked once", err, asked.Load())
	}
}
