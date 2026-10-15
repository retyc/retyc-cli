package vfs

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// flakyStore is a memstore whose writes can be made to fail without being
// applied, as a store outside the process could.
type flakyStore struct {
	*memstore.Store
	failWrites atomic.Bool
	closed     atomic.Bool
}

var errStoreDown = errors.New("store down")

func (s *flakyStore) PutListing(ctx context.Context, key metastore.ListingKey, l *metastore.Listing) error {
	if s.failWrites.Load() {
		return errStoreDown
	}

	return s.Store.PutListing(ctx, key, l)
}

func (s *flakyStore) PutListingIf(
	ctx context.Context, key metastore.ListingKey, l *metastore.Listing, gen uint64,
) (bool, error) {
	if s.failWrites.Load() {
		return false, errStoreDown
	}

	return s.Store.PutListingIf(ctx, key, l, gen)
}

func (s *flakyStore) UpsertNode(ctx context.Context, key metastore.ListingKey, node metastore.Node) (uint64, error) {
	if s.failWrites.Load() {
		return 0, errStoreDown
	}

	return s.Store.UpsertNode(ctx, key, node)
}

func (s *flakyStore) RemoveNode(ctx context.Context, key metastore.ListingKey, name string) (uint64, error) {
	if s.failWrites.Load() {
		return 0, errStoreDown
	}

	return s.Store.RemoveNode(ctx, key, name)
}

func (s *flakyStore) DeleteListing(ctx context.Context, key metastore.ListingKey) error {
	if s.failWrites.Load() {
		return errStoreDown
	}

	return s.Store.DeleteListing(ctx, key)
}

func (s *flakyStore) DeleteSubtree(ctx context.Context, dataroomID, path string) error {
	if s.failWrites.Load() {
		return errStoreDown
	}

	return s.Store.DeleteSubtree(ctx, dataroomID, path)
}

func (s *flakyStore) Close() error {
	s.closed.Store(true)

	return s.Store.Close()
}

// The listings go to the store given in Options, not to one of the FS's own.
func TestFS_UsesTheConfiguredStore(t *testing.T) {
	store := memstore.New()
	fs := New(nil, Options{Store: store, List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
	}})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/sub"); err != nil {
		t.Fatal(err)
	}
	l, ok, _ := store.GetListing(ctx, key("dr1", "/sub"))
	if !ok || len(l.Nodes) != 1 || l.Nodes[0].ID != "n1" || l.FetchedAt.IsZero() {
		t.Errorf("store listing = (%+v, %v), want the fetched one", l, ok)
	}
}

// A store that fails an invalidation still holds the listing the mutation
// made wrong: it must not be served. The FS sets the store aside and fetches
// again from the API.
func TestFS_FailedStoreWriteIsNotServed(t *testing.T) {
	store := &flakyStore{Store: memstore.New()}
	var calls atomic.Int32
	fs := New(nil, Options{Store: store, List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		id := "old"
		if calls.Add(1) > 1 {
			id = "new"
		}

		return []service.DataroomNodeInfo{{ID: id, Name: "a", Type: "file"}}, nil
	}})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	store.failWrites.Store(true)
	fs.InvalidateListing("dr1", "/") // the store keeps the listing
	if _, ok, _ := store.GetListing(ctx, key("dr1", "/")); !ok {
		t.Fatal("the fake store applied the failed delete")
	}

	nodes, err := fs.ReadDir(ctx, "dr1", "/")
	if err != nil || len(nodes) != 1 || nodes[0].ID != "new" {
		t.Errorf("ReadDir after a failed invalidation = (%+v, %v), want a fresh listing", nodes, err)
	}
	// The replacement store works: the listing is cached again.
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("listing fetched %d times, want 2", got)
	}
	if err := fs.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if !store.closed.Load() {
		t.Error("the configured store was not closed")
	}
}

// Without a way to resolve a session, a listing through the API fails cleanly.
func TestFS_SessionWithoutIdentity(t *testing.T) {
	fs := New(nil, Options{})
	if _, err := fs.Session(context.Background(), "dr1"); err == nil {
		t.Error("Session succeeded without identity nor Options.Session")
	}
}

func TestFS_TTL(t *testing.T) {
	if got := New(nil, Options{}).opts.ttl(); got != DefaultCacheTTL {
		t.Errorf("TTL of zero Options = %v, want %v", got, DefaultCacheTTL)
	}
	if got := New(nil, Options{TTL: time.Second}).opts.ttl(); got != time.Second {
		t.Errorf("TTL = %v, want 1s", got)
	}
}

// Options.ListConcurrency sizes the refresh slots.
func TestFS_ListConcurrency(t *testing.T) {
	if got := cap(New(nil, Options{}).slots); got != DefaultListConcurrency {
		t.Errorf("refresh slots of zero Options = %d, want %d", got, DefaultListConcurrency)
	}
	if got := cap(New(nil, Options{ListConcurrency: 7}).slots); got != 7 {
		t.Errorf("refresh slots = %d, want 7", got)
	}
}

// AddFolder seeds the folder's own empty listing and names it in its parent's,
// dropping what was cached below the path.
func TestFS_AddFolder(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{
		"/":         {nodes: []service.DataroomNodeInfo{{ID: "f-1", Name: "doc.txt", Type: "file"}}, fetchedAt: time.Now()},
		"/new":      {nodes: []service.DataroomNodeInfo{{ID: "ghost", Name: "ghost", Type: "file"}}, fetchedAt: time.Now()},
		"/new/sub":  {fetchedAt: time.Now()},
		"/newer":    {fetchedAt: time.Now()},
		"/other/ab": {fetchedAt: time.Now()},
	})

	fs.addFolder("dr1", "/new", Node{ID: "d-1", Name: "new", Type: TypeDir})

	if l := cachedListing(fs, "dr1", "/new"); l == nil || l.Nodes == nil || len(l.Nodes) != 0 {
		t.Errorf("listing of the new folder = %+v, want an empty one", l)
	}
	if nodeCacheHas(fs, "dr1", "/new/sub") {
		t.Error("a listing below the new folder survived")
	}
	if !nodeCacheHas(fs, "dr1", "/newer") || !nodeCacheHas(fs, "dr1", "/other/ab") {
		t.Error("a listing outside the new folder was dropped")
	}
	root := cachedNodes(fs, "dr1", "/")
	if len(root) != 2 || root[1].ID != "d-1" || root[1].Type != TypeDir {
		t.Errorf("parent listing = %+v, want doc.txt then the new folder", root)
	}
}

// Move carries the node, renamed, from one cached listing to the other.
func TestFS_Move(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{
		"/a": {nodes: []service.DataroomNodeInfo{{ID: "f-1", Name: "doc.txt", Type: "file", Size: 9, VersionID: "v1"}},
			fetchedAt: time.Now()},
		"/b": {nodes: []service.DataroomNodeInfo{}, fetchedAt: time.Now()},
	})

	fs.move("dr1", "/a", "doc.txt", "/b", "new.txt", "d-b")

	if src := cachedNodes(fs, "dr1", "/a"); len(src) != 0 {
		t.Errorf("source listing = %+v, want it empty", src)
	}
	dst := cachedNodes(fs, "dr1", "/b")
	if len(dst) != 1 || dst[0].ID != "f-1" || dst[0].Name != "new.txt" || dst[0].Size != 9 || dst[0].VersionID != "v1" {
		t.Errorf("destination listing = %+v, want f-1 renamed new.txt, other fields kept", dst)
	}
}

// With HideSymlinks a symbolic link is not found by Lookup, nor taken for a
// folder by resolveFolderID; ReadDir still returns it. Without it, Lookup finds it.
func TestFS_HideSymlinks(t *testing.T) {
	list := func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return []service.DataroomNodeInfo{{ID: "l-1", Name: "link", Type: "symlink", Size: 6}}, nil
	}
	ctx := context.Background()

	hiding := New(nil, Options{List: list, HideSymlinks: true})
	if _, err := hiding.Lookup(ctx, "dr1", "/", "link"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Lookup(link) with HideSymlinks = %v, want not found", err)
	}
	if _, err := hiding.resolveFolderID(ctx, "dr1", "/link"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("resolveFolderID(/link) with HideSymlinks = %v, want not found", err)
	}
	if nodes, err := hiding.ReadDir(ctx, "dr1", "/"); err != nil || len(nodes) != 1 || nodes[0].Type != TypeSymlink {
		t.Errorf("ReadDir with HideSymlinks = (%+v, %v), want the symlink", nodes, err)
	}

	showing := New(nil, Options{List: list})
	if n, err := showing.Lookup(ctx, "dr1", "/", "link"); err != nil || n.ID != "l-1" || n.Type != TypeSymlink {
		t.Errorf("Lookup(link) = (%+v, %v), want the symlink", n, err)
	}
}

// The mode is kept when an upsert carries none for the same node (keepMode),
// and replaced when it carries one or names another node.
func TestFS_UpsertKeepsTheMode(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{
		"/": {nodes: []service.DataroomNodeInfo{
			service.DataroomNodeInfo{ID: "f-1", Name: "run.sh", Type: "file"}.WithMode(0o755),
		}, fetchedAt: time.Now()},
	})

	fs.upsert("dr1", "/", Node{ID: "f-1", Name: "run.sh", Type: TypeFile, Size: 3})
	if n := cachedNodes(fs, "dr1", "/")[0]; n.Mode != 0o755 || n.Size != 3 {
		t.Errorf("after an upsert without mode = %+v, want mode 0755 kept and size 3", n)
	}
	fs.upsert("dr1", "/", Node{ID: "f-1", Name: "run.sh", Type: TypeFile, Mode: 0o644})
	if n := cachedNodes(fs, "dr1", "/")[0]; n.Mode != 0o644 {
		t.Errorf("after an upsert with a mode = %v, want 0644", n.Mode)
	}
	fs.upsert("dr1", "/", Node{ID: "f-2", Name: "run.sh", Type: TypeFile})
	if n := cachedNodes(fs, "dr1", "/")[0]; n.Mode != 0 || n.ID != "f-2" {
		t.Errorf("after another node took the name = %+v, want f-2 without mode", n)
	}
}

// NodeFromInfo carries every field of the service's node.
func TestNodeFromInfo(t *testing.T) {
	mtime := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	info := service.DataroomNodeInfo{
		ID: "n1", Name: "f.txt", Type: "file", MIMEType: "text/plain", Size: 12, VersionID: "v1", ChunkCount: 1,
	}.WithMode(0o640).WithModTime(mtime).WithOrigin("d-1", mtime.Add(-time.Hour))

	got := NodeFromInfo(info)
	want := Node{
		ID: "n1", Name: "f.txt", Type: TypeFile, MIMEType: "text/plain", Size: 12, VersionID: "v1", ChunkCount: 1,
		Mode: 0o640, ModeSet: true, ModTime: mtime, ParentID: "d-1", CreatedAt: mtime.Add(-time.Hour),
	}
	if got != want {
		t.Errorf("NodeFromInfo = %+v, want %+v", got, want)
	}
	// An explicit 0 is a mode; no mode is none.
	if n := NodeFromInfo(service.DataroomNodeInfo{ID: "n2"}.WithMode(0)); !n.HasMode() || n.Mode != 0 {
		t.Errorf("explicit 0: NodeFromInfo = %+v, want a stored 0", n)
	}
	if n := NodeFromInfo(service.DataroomNodeInfo{ID: "n3"}); n.HasMode() {
		t.Errorf("no mode: NodeFromInfo = %+v, want none", n)
	}
	if nodesFromInfos(nil) != nil {
		t.Error("nodesFromInfos(nil) is not nil")
	}
	if empty := nodesFromInfos([]service.DataroomNodeInfo{}); empty == nil || len(empty) != 0 {
		t.Errorf("nodesFromInfos(empty) = %v, want an empty, non-nil slice", empty)
	}
}

func TestSplitPath(t *testing.T) {
	cases := map[string][2]string{
		"/file.txt":         {"/", "file.txt"},
		"/folder/sub/f.txt": {"/folder/sub", "f.txt"},
		"/":                 {"/", ""},
		"relative":          {"/", "relative"},
	}
	for p, want := range cases {
		if parent, name := SplitPath(p); parent != want[0] || name != want[1] {
			t.Errorf("SplitPath(%q) = (%q, %q), want (%q, %q)", p, parent, name, want[0], want[1])
		}
	}
}

// recordingStore is a memstore that remembers the keys listings were put
// under.
type recordingStore struct {
	*memstore.Store
	mu  sync.Mutex
	put map[metastore.ListingKey]bool
}

func (s *recordingStore) PutListing(ctx context.Context, key metastore.ListingKey, l *metastore.Listing) error {
	s.mu.Lock()
	s.put[key] = true
	s.mu.Unlock()

	return s.Store.PutListing(ctx, key, l)
}

func (s *recordingStore) PutListingIf(
	ctx context.Context, key metastore.ListingKey, l *metastore.Listing, gen uint64,
) (bool, error) {
	stored, err := s.Store.PutListingIf(ctx, key, l, gen)
	if stored {
		s.mu.Lock()
		s.put[key] = true
		s.mu.Unlock()
	}

	return stored, err
}

func (s *recordingStore) keys() []metastore.ListingKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]metastore.ListingKey, 0, len(s.put))
	for key := range s.put {
		keys = append(keys, key)
	}

	return keys
}

// Every spelling of a folder is one listing: fetched once, read, edited and
// dropped under the clean form of its path.
func TestFS_PathsAreNormalised(t *testing.T) {
	var calls atomic.Int32
	var listed []string
	store := &recordingStore{Store: memstore.New(), put: make(map[metastore.ListingKey]bool)}
	list := func(_ context.Context, _, path string) ([]service.DataroomNodeInfo, error) {
		calls.Add(1)
		listed = append(listed, path) // one call at most: see the assertion below

		return []service.DataroomNodeInfo{{ID: "n1", Name: "f", Type: "file"}}, nil
	}
	fs := New(nil, Options{Store: store, List: list})
	ctx := context.Background()
	spellings := []string{"/a", "/a/", "/a//", "//a", "a", "/a/.", "/b/../a"}

	for _, p := range spellings {
		nodes, err := fs.ReadDir(ctx, "dr1", p)
		if err != nil || len(nodes) != 1 {
			t.Fatalf("ReadDir(%q) = (%+v, %v)", p, nodes, err)
		}
	}
	if got := calls.Load(); got != 1 || listed[0] != "/a" {
		t.Errorf("listed %d time(s) as %q, want once as /a", got, listed)
	}
	if keys := store.keys(); len(keys) != 1 || keys[0] != key("dr1", "/a") {
		t.Errorf("listings stored under %v, want /a alone", keys)
	}

	// An edit through any spelling lands in that listing, and a lookup through
	// any other finds it.
	fs.upsert("dr1", "/a/", Node{ID: "n2", Name: "g", Type: TypeFile})
	if n, err := fs.Lookup(ctx, "dr1", "//a", "g"); err != nil || n.ID != "n2" {
		t.Errorf("Lookup(//a, g) after upsert(/a/) = (%+v, %v), want n2", n, err)
	}
	if id, ok := fs.cachedFileID("dr1", "a", "g"); !ok || id != "n2" {
		t.Errorf("cachedFileID(a, g) = (%q, %v), want n2", id, ok)
	}

	for _, p := range spellings {
		if _, err := fs.ReadDir(ctx, "dr1", "/a"); err != nil {
			t.Fatal(err)
		}
		fs.InvalidateListing("dr1", p)
		if nodeCacheHas(fs, "dr1", "/a") {
			t.Errorf("InvalidateListing(%q) left /a cached", p)
		}
	}
}

// invalidateSubtree drops the folder and what is below it whatever the
// spelling of its path, and nothing beside it.
func TestFS_InvalidateSubtreeNormalisesItsPath(t *testing.T) {
	for _, p := range []string{"/a", "/a/", "/a//", "//a", "a"} {
		fs := seeded(map[string]*nodeCacheEntry{
			"/":    {fetchedAt: time.Now()},
			"/a":   {fetchedAt: time.Now()},
			"/a/b": {fetchedAt: time.Now()},
			"/ab":  {fetchedAt: time.Now()},
		})
		fs.invalidateSubtree("dr1", p)
		if nodeCacheHas(fs, "dr1", "/a") || nodeCacheHas(fs, "dr1", "/a/b") {
			t.Errorf("invalidateSubtree(%q) left /a or /a/b cached", p)
		}
		if !nodeCacheHas(fs, "dr1", "/") || !nodeCacheHas(fs, "dr1", "/ab") {
			t.Errorf("invalidateSubtree(%q) dropped a listing outside /a", p)
		}
	}

	// The root, however it is spelled, is the whole dataroom.
	for _, p := range []string{"/", "", "//", "."} {
		fs := seeded(map[string]*nodeCacheEntry{"/": {fetchedAt: time.Now()}, "/a/b": {fetchedAt: time.Now()}})
		fs.invalidateSubtree("dr1", p)
		if nodeCacheHas(fs, "dr1", "/") || nodeCacheHas(fs, "dr1", "/a/b") {
			t.Errorf("invalidateSubtree(%q) left a listing of the dataroom cached", p)
		}
	}
}

// A fetch in flight below a folder is discarded when the folder is
// invalidated through another spelling of its path.
func TestFS_InvalidateSubtreeDiscardsFetchesBelowAnySpelling(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	list, _ := gatedListFn(t, gate, started)
	fs := New(nil, Options{List: list})
	done := make(chan error, 1)
	go func() {
		_, err := fs.ReadDir(context.Background(), "dr1", "/a/b")
		done <- err
	}()
	<-started
	fs.invalidateSubtree("dr1", "/a/")
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if nodeCacheHas(fs, "dr1", "/a/b") {
		t.Error("a listing fetched before the invalidation of its parent was cached")
	}
}

// A store that fails is set aside in silence for the requests, but not for
// the operator: the failure that suspends it is reported through
// Options.Logf, once (see TestFS_FailedStoreIsSuspendedThenUsedAgain).
func TestFS_FailedStoreWriteIsReportedOnce(t *testing.T) {
	store := &flakyStore{Store: memstore.New()}
	store.failWrites.Store(true)
	var logs logRecorder
	fs := New(nil, Options{Store: store, Logf: logs.logf})

	fs.InvalidateListing("dr1", "/")
	if got := logs.list(); len(got) != 1 || !strings.Contains(got[0], errStoreDown.Error()) {
		t.Fatalf("logs after the first failed write = %v, want it reported", got)
	}
	// The replacement store is in memory and does not fail.
	fs.InvalidateListing("dr1", "/")
	fs.invalidateSubtree("dr1", "/a")
	if got := logs.list(); len(got) != 1 {
		t.Errorf("logs after more writes = %v, want the first report only", got)
	}

	// Without Logf the failure stays silent.
	quiet := New(nil, Options{Store: store})
	quiet.InvalidateListing("dr1", "/")
}

// SessionsCached counts the sessions held, seeded or resolved.
func TestFS_SessionsCached(t *testing.T) {
	fs := New(nil, Options{Session: func(context.Context, string) (*service.DataroomSession, error) {
		return &service.DataroomSession{}, nil
	}})
	if got := fs.SessionsCached(); got != 0 {
		t.Fatalf("SessionsCached of a new FS = %d", got)
	}
	fs.SeedSession("dr1", &service.DataroomSession{})
	if _, err := fs.Session(context.Background(), "dr2"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Session(context.Background(), "dr1"); err != nil {
		t.Fatal(err)
	}
	if got := fs.SessionsCached(); got != 2 {
		t.Errorf("SessionsCached = %d, want 2", got)
	}
}
