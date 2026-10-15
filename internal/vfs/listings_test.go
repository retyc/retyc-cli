package vfs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
)

// — Helpers ———————————————————————————————————————————————————————————————————

func key(dataroomID, path string) ListingKey {
	return ListingKey{DataroomID: dataroomID, Path: path}
}

// cachedListingLocked returns the listing stored for a folder, nil when there
// is none. The caller holds fs.mu.
func cachedListingLocked(fs *FS, dataroomID, path string) *Listing {
	l, _ := fs.heldLocked(context.Background(), key(dataroomID, path))

	return l
}

// cachedListing returns the listing stored for a folder, nil when there is none.
func cachedListing(fs *FS, dataroomID, path string) *Listing {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return cachedListingLocked(fs, dataroomID, path)
}

func nodeCacheHas(fs *FS, dataroomID, path string) bool {
	return cachedListing(fs, dataroomID, path) != nil
}

// cachedNodes returns the nodes of the listing stored for a folder.
func cachedNodes(fs *FS, dataroomID, path string) []Node {
	return cachedListing(fs, dataroomID, path).Nodes
}

// nodeCacheEntry is a listing to seed the cache with.
type nodeCacheEntry struct {
	nodes     []service.DataroomNodeInfo
	fetchedAt time.Time
}

// seedNodeCache stores entries, keyed by path, as listings of dataroom "dr1".
func seedNodeCache(fs *FS, entries map[string]*nodeCacheEntry) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for path, e := range entries {
		_ = fs.store.PutListing(context.Background(), key("dr1", path),
			&Listing{Nodes: nodesFromInfos(e.nodes), FetchedAt: e.fetchedAt})
	}
}

// seeded returns an FS without client whose cache holds entries.
func seeded(entries map[string]*nodeCacheEntry) *FS {
	fs := New(nil, Options{})
	seedNodeCache(fs, entries)

	return fs
}

func testClient(srv *httptest.Server) *api.Client {
	return api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)
}

// callLog records the requests a fake API server receives. Handlers run on the
// server's goroutines, and the race detector cannot see through the socket, so
// every access is locked.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(call string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, call)
}

// list returns the recorded calls in arrival order.
func (l *callLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.calls)
}

// sorted returns the recorded calls sorted, for requests issued concurrently.
func (l *callLog) sorted() []string {
	calls := l.list()
	slices.Sort(calls)

	return calls
}

// nodesPageJSON renders one page of listing items for the fake API, with the
// names encrypted for pub. It may run on a server goroutine, so it reports a
// failure with t.Errorf, never t.Fatalf.
func nodesPageJSON(t *testing.T, pub string, nodes map[string]string) string {
	t.Helper()
	items := make([]string, 0, len(nodes))
	for id, name := range nodes {
		nameEnc, err := crypto.EncryptStringForKeys(name, []string{pub})
		if err != nil {
			t.Errorf("EncryptStringForKeys: %v", err)

			return ""
		}
		items = append(items, fmt.Sprintf(
			`{"node":{"id":%q,"name_enc":%q,"type_enc":null,"parent_id":null},"node_version":null}`, id, nameEnc))
	}

	return fmt.Sprintf(`{"items":[%s],"total":%d,"pages":1,"page":1}`, strings.Join(items, ","), len(items))
}

// newCachedListingsFS returns an FS on handler with an unlocked session for
// dataroom "dr1" and the given listings, keyed by path, cached.
func newCachedListingsFS(
	t *testing.T, handler http.HandlerFunc, listings map[string][]service.DataroomNodeInfo,
) (*FS, *age.HybridIdentity) {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	fs := New(testClient(srv), Options{})
	// An API without the lookup by name: these tests are those of the
	// listings, which is how a name is then found (see lookup_test.go for
	// the lookup by name).
	fs.SeedSession("dr1", (&service.DataroomSession{
		Identity: identity, PublicKey: identity.Recipient().String(),
	}).AssumeLegacyAPI())
	for path, nodes := range listings {
		seedNodeCache(fs, map[string]*nodeCacheEntry{path: {nodes: nodes, fetchedAt: time.Now()}})
	}

	return fs, identity
}

// goneStatuses are the answers of the API for a node that no longer exists:
// 404 once purged, 410 while its asynchronous purge is pending.
var goneStatuses = []int{http.StatusNotFound, http.StatusGone}

// — ReadDir: single-flight + generation check ————————————————————————————————

// gatedListFn returns a listFn that blocks on gate and counts its calls.
// started is signalled once per call, before blocking.
func gatedListFn(t *testing.T, gate <-chan struct{}, started chan<- struct{}) (
	func(context.Context, string, string) ([]service.DataroomNodeInfo, error), *int32,
) {
	t.Helper()
	var calls int32

	return func(_ context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
		atomic.AddInt32(&calls, 1)
		started <- struct{}{}
		<-gate

		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
	}, &calls
}

func TestListNodes_CacheHit(t *testing.T) {
	gate := make(chan struct{})
	close(gate)
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := New(nil, Options{List: listFn})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
			t.Fatalf("listNodes: %v", err)
		}
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Errorf("listing fetched %d times for 3 sequential calls, want 1", n)
	}
}

// Concurrent misses on the same URI must share one fetch.
func TestListNodes_SingleFlight(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := New(nil, Options{List: listFn})
	ctx := context.Background()

	const n = 5
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nodes, err := fs.ReadDir(ctx, "dr1", "/")
			if err == nil && len(nodes) != 1 {
				err = fmt.Errorf("got %d nodes, want 1", len(nodes))
			}
			errs <- err
		}()
	}
	<-started // the leader is inside the fetch; everyone else either joins it or hits the cache after
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("listing fetched %d times for %d concurrent callers, want 1", got, n)
	}
}

// A listing answered before a mutation landed must not be stored after that
// mutation invalidated the URI — otherwise a read racing a write from another
// client pins a pre-mutation listing for a whole TTL.
func TestListNodes_InvalidatedDuringFetchIsNotCached(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := New(nil, Options{List: listFn})
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		_, err := fs.ReadDir(ctx, "dr1", "/")
		done <- err
	}()
	<-started
	fs.InvalidateListing("dr1", "/") // mutation lands while the listing is in flight
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if nodeCacheHas(fs, "dr1", "/") {
		t.Fatal("listing that raced an invalidation was stored in the cache")
	}
	// The next call must fetch again.
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatalf("listNodes (refetch): %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("listing fetched %d times, want 2 (first result discarded, second stored)", got)
	}
	if !nodeCacheHas(fs, "dr1", "/") {
		t.Error("clean refetch was not stored")
	}
}

// A waiter whose own context is cancelled must not block on the leader.
func TestListNodes_WaiterHonoursContext(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, _ := gatedListFn(t, gate, started)
	fs := New(nil, Options{List: listFn})

	go func() { _, _ = fs.ReadDir(context.Background(), "dr1", "/") }()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fs.ReadDir(ctx, "dr1", "/"); !errors.Is(err, context.Canceled) {
		t.Errorf("waiter error = %v, want context.Canceled", err)
	}
	close(gate)
}

// getSession must go through the process-lifetime session cache: the second
// call for the same dataroom must not resolve again (see service.SessionCache).
func TestFS_Session_ResolvedOnce(t *testing.T) {
	var calls atomic.Int32
	fs := New(nil, Options{Session: func(_ context.Context, drID string) (*service.DataroomSession, error) {
		calls.Add(1)

		return &service.DataroomSession{PublicKey: "pub-" + drID}, nil
	}})
	ctx := context.Background()

	first, err := fs.Session(ctx, "dr1")
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	second, err := fs.Session(ctx, "dr1")
	if err != nil {
		t.Fatalf("getSession (cached): %v", err)
	}
	if first != second {
		t.Error("second getSession returned a different session: cache miss")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("sessionFn ran %d times, want 1", got)
	}
}

// Once the identity has been unlocked at startup, resolving a dataroom session
// must reuse it: no second fetch of the user key, no second scrypt.
func TestFS_Session_ReusesStartupIdentity(t *testing.T) {
	userKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessPrivEnc, err := crypto.EncryptStringForKeys(sessKey.String(), []string{userKey.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)

			return
		}
		_, _ = fmt.Fprintf(w, `{"id":"dr1","session_public_key":%q,"session_private_key_enc":%q}`,
			sessKey.Recipient().String(), sessPrivEnc)
	}))
	t.Cleanup(srv.Close)

	fs := New(testClient(srv), Options{Identity: userKey})
	sess, err := fs.Session(context.Background(), "dr1")
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if sess.PublicKey != sessKey.Recipient().String() {
		t.Errorf("PublicKey = %q, want %q", sess.PublicKey, sessKey.Recipient().String())
	}
}

// The shared listing must not run under the leader's request context: Finder
// fires PROPFINDs in parallel and aborting one of them must not fail the
// others with context.Canceled.
func TestListNodes_LeaderCancellationDoesNotFailWaiters(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn := func(ctx context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
		started <- struct{}{}
		<-gate
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
	}
	fs := New(nil, Options{List: listFn})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = fs.ReadDir(leaderCtx, "dr1", "/")
	}()
	<-started

	waiterErr := make(chan error, 1)
	go func() {
		_, err := fs.ReadDir(context.Background(), "dr1", "/")
		waiterErr <- err
	}()
	for {
		fs.mu.Lock()
		waiting := fs.inflight[key("dr1", "/")] != nil
		fs.mu.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond) // let the waiter block on f.done

	cancelLeader()
	close(gate)
	<-leaderDone

	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter error = %v, want the listing", err)
	}
}

// Same for a shared folder listing: a stalled one must not stay in flight and
// make every later request for the folder wait on it.
func TestListNodes_StalledFetchTimesOut(t *testing.T) {
	var calls atomic.Int32
	listFn := func(ctx context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()

			return nil, ctx.Err()
		}

		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
	}
	fs := New(nil, Options{FetchTimeout: 20 * time.Millisecond, List: listFn})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err == nil {
		t.Fatal("the stalled listing succeeded")
	}
	if nodes, err := fs.ReadDir(ctx, "dr1", "/"); err != nil || len(nodes) != 1 {
		t.Errorf("listNodes after a timed-out fetch = (%v, %v), want the new listing", nodes, err)
	}
}

// When the source listing no longer names the node (it expired meanwhile), the
// moved node's fields are unknown: the destination listing is dropped rather
// than given an entry with a made-up version.
func TestMoveInNodeCache_UnknownSourceDropsDestination(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{
		"/b": {nodes: []service.DataroomNodeInfo{{ID: "f-2", Name: "other.txt"}}, fetchedAt: time.Now()},
	})

	fs.move("dr1", "/a", "doc.txt", "/b", "new.txt", "d-b")

	if nodeCacheHas(fs, "dr1", "/b") {
		t.Error("the destination listing was kept although the moved node is unknown")
	}
}

// Listing a folder whose parent listing is cached must cost that folder's
// listing alone: resolving its path through the API walked every level from
// the root again, duplicating listings a concurrent PROPFIND was often fetching
// at the same moment.
func TestFS_FetchNodesUsesCachedParentListing(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path + " parent=" + r.URL.Query().Get("parent_id"))
		switch {
		case r.URL.Path == "/dataroom/dr1/nodes" && r.URL.Query().Get("parent_id") == "d-b":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt"}))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusInternalServerError)
		}
	}
	fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"/a": {{ID: "d-b", Name: "b", Type: "dir"}},
	})
	pub = identity.Recipient().String()

	nodes, err := fs.ReadDir(context.Background(), "dr1", "/a/b")
	if err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "doc.txt" {
		t.Errorf("nodes = %+v, want doc.txt", nodes)
	}
	want := []string{"GET /dataroom/dr1/nodes parent=d-b"}
	if calls := log.sorted(); !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

// The dataroom root has no node to check: listing it is the listing alone.
func TestFS_FetchNodesRootHasNoCheck(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path)
		fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt"}))
	}
	fs, identity := newCachedListingsFS(t, handler, nil)
	pub = identity.Recipient().String()

	if _, err := fs.ReadDir(context.Background(), "dr1", "/"); err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if calls := log.list(); !slices.Equal(calls, []string{"GET /dataroom/dr1/nodes"}) {
		t.Errorf("calls = %v, want the root listing only", calls)
	}
}

// With nothing cached, each level is listed once and kept: listing a sibling
// folder afterwards costs its own listing only.
func TestFS_FetchNodesCachesEveryLevel(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1/nodes" {
			log.add(r.Method + " " + r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)

			return
		}
		parent := r.URL.Query().Get("parent_id")
		log.add("parent=" + parent)
		switch parent {
		case "":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"d-a": "a"}))
		case "d-a":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"d-b": "b", "d-c": "c"}))
		case "d-b", "d-c":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{}))
		default:
			http.Error(w, "unexpected parent "+parent, http.StatusInternalServerError)
		}
	}
	fs, identity := newCachedListingsFS(t, handler, nil)
	pub = identity.Recipient().String()
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/a/b"); err != nil {
		t.Fatalf("listNodes /a/b: %v", err)
	}
	if _, err := fs.ReadDir(ctx, "dr1", "/a/c"); err != nil {
		t.Fatalf("listNodes /a/c: %v", err)
	}
	want := []string{"parent=", "parent=d-a", "parent=d-b", "parent=d-c"}
	if calls := log.list(); !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

// The cached parent listing can name a folder deleted elsewhere: listing its
// children answers 404, or 410 while its purge is pending. That listing must
// be discarded and retried once against a fresh parent listing.
func TestFS_FetchNodesRetriesOnStaleParent(t *testing.T) {
	for _, status := range goneStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var pub string
			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/dataroom/dr1/nodes" {
					http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusInternalServerError)

					return
				}
				switch r.URL.Query().Get("parent_id") {
				case "d-old":
					http.Error(w, "parent gone", status)
				case "":
					fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"d-new": "a"}))
				case "d-new":
					fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt"}))
				}
			}
			fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
				"/": {{ID: "d-old", Name: "a", Type: "dir"}},
			})
			pub = identity.Recipient().String()

			nodes, err := fs.ReadDir(context.Background(), "dr1", "/a")
			if err != nil {
				t.Fatalf("listNodes: %v", err)
			}
			if len(nodes) != 1 || nodes[0].Name != "doc.txt" {
				t.Errorf("nodes = %+v, want the re-created folder's doc.txt", nodes)
			}
		})
	}
}

// countingListFn returns a listFn serving a fixed tree and counting its calls.
func countingListFn(nodes map[string][]service.DataroomNodeInfo) (
	func(context.Context, string, string) ([]service.DataroomNodeInfo, error), *int32,
) {
	var calls int32

	return func(_ context.Context, _, nodePath string) ([]service.DataroomNodeInfo, error) {
		atomic.AddInt32(&calls, 1)

		return nodes[nodePath], nil
	}, &calls
}

// The dataroom root has no node ID and must cost no listing at all.
func TestParentNodeID_RootCostsNoListing(t *testing.T) {
	listFn, calls := countingListFn(nil)
	fs := New(nil, Options{List: listFn})

	id, err := fs.resolveFolderID(context.Background(), "dr1", "/")
	if err != nil {
		t.Fatalf("parentNodeID: %v", err)
	}
	if id != nil {
		t.Errorf("id = %v, want nil for the dataroom root", *id)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Errorf("root resolution issued %d listings, want 0", n)
	}
}

// The point of the change: repeated uploads into the same folder must reuse the
// cached listing instead of re-walking the tree through the API every time.
func TestParentNodeID_ReusesCachedListing(t *testing.T) {
	listFn, calls := countingListFn(map[string][]service.DataroomNodeInfo{
		"/": {{ID: "dir-1", Name: "sub", Type: "dir"}},
	})
	fs := New(nil, Options{List: listFn})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		id, err := fs.resolveFolderID(ctx, "dr1", "/sub")
		if err != nil {
			t.Fatalf("parentNodeID: %v", err)
		}
		if id == nil || *id != "dir-1" {
			t.Fatalf("id = %v, want dir-1", id)
		}
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Errorf("5 uploads issued %d listings, want 1", n)
	}
}

func TestParentNodeID_Errors(t *testing.T) {
	listFn, _ := countingListFn(map[string][]service.DataroomNodeInfo{
		"/": {{ID: "f-1", Name: "afile", Type: "file"}},
	})
	fs := New(nil, Options{List: listFn})
	ctx := context.Background()

	if _, err := fs.resolveFolderID(ctx, "dr1", "/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing parent: err = %v, want os.ErrNotExist", err)
	}
	// A file cannot be a parent directory; uploading "into" one must not silently
	// target the dataroom root.
	if _, err := fs.resolveFolderID(ctx, "dr1", "/afile"); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("file as parent: err = %v, want os.ErrInvalid", err)
	}
}

func TestUpsertNodeCache_ReplacesAndAppends(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{
		"/": {
			nodes: []service.DataroomNodeInfo{
				{ID: "n1", Name: "old.bin", Type: "file", Size: 10, ChunkCount: 1},
			},
			fetchedAt: time.Now().Add(-20 * time.Second),
		},
	})

	// Same name → the entry is replaced, not duplicated.
	fs.upsert("dr1", "/", Node{
		ID: "n1", Name: "old.bin", Type: "file", Size: 99, VersionID: "v2", ChunkCount: 3,
	})
	// New name → appended.
	fs.upsert("dr1", "/", Node{
		ID: "n2", Name: "new.bin", Type: "file", Size: 5, ChunkCount: 1,
	})

	got := cachedNodes(fs, "dr1", "/")
	if len(got) != 2 {
		t.Fatalf("cached %d nodes, want 2 (one replaced, one appended)", len(got))
	}
	if got[0].Size != 99 || got[0].VersionID != "v2" || got[0].ChunkCount != 3 {
		t.Errorf("replaced entry = %+v, want the post-upload values", got[0])
	}
	if got[1].Name != "new.bin" {
		t.Errorf("appended entry = %+v, want new.bin", got[1])
	}
}

// The TTL must keep running from the real fetch: the rest of the listing is no
// fresher than it was, so an upload must not extend its lifetime.
func TestUpsertNodeCache_DoesNotExtendTTL(t *testing.T) {
	fetchedAt := time.Now().Add(-20 * time.Second)
	fs := seeded(map[string]*nodeCacheEntry{
		"/": {nodes: nil, fetchedAt: fetchedAt},
	})

	fs.upsert("dr1", "/", Node{ID: "n1", Name: "f", Type: "file"})

	if got := cachedListing(fs, "dr1", "/").FetchedAt; !got.Equal(fetchedAt) {
		t.Errorf("fetchedAt = %v, want it carried over unchanged (%v)", got, fetchedAt)
	}
}

// listNodes hands its backing array to callers without copying, so an upsert
// must not write through it — a reader holding an earlier listing would
// otherwise observe the mutation.
func TestUpsertNodeCache_DoesNotMutateSharedSlice(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{
		"/": {
			nodes:     []service.DataroomNodeInfo{{ID: "n1", Name: "f.bin", Type: "file", Size: 10}},
			fetchedAt: time.Now(),
		},
	})
	held, err := fs.ReadDir(context.Background(), "dr1", "/")
	if err != nil || len(held) != 1 {
		t.Fatalf("ReadDir = (%+v, %v), want the seeded listing", held, err)
	}

	fs.upsert("dr1", "/", Node{
		ID: "n1", Name: "f.bin", Type: "file", Size: 4242,
	})

	if held[0].Size != 10 {
		t.Errorf("previously returned slice was mutated: size = %d, want 10", held[0].Size)
	}
}

// Nothing cached for that directory means there is nothing to refresh; the
// upsert must not fabricate a listing that was never fetched.
func TestUpsertNodeCache_NoEntryIsNoop(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{})

	fs.upsert("dr1", "/", Node{ID: "n1", Name: "f", Type: "file"})

	if nodeCacheHas(fs, "dr1", "/") {
		t.Error("upsert created a listing for a directory that was never fetched")
	}
}

// An upload that lands while a listing is in flight must win, exactly like an
// invalidation does: the in-flight listing was answered by the API before the
// upload, so storing it would hide a file the server already accepted — and,
// for a new version of an existing file, would serve the previous version's
// VersionID and ChunkCount for a whole TTL after a PUT returned 201.
func TestUpsertNodeCache_DuringFetchDiscardsStaleListing(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := New(nil, Options{List: listFn})
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		_, err := fs.ReadDir(ctx, "dr1", "/")
		done <- err
	}()
	<-started
	// The PUT completes while the listing is still in flight. Nothing is cached
	// yet for that URI — the fetch was triggered by a miss — so the upsert has
	// no entry to refresh and must at least invalidate the pending result.
	fs.upsert("dr1", "/", Node{
		ID: "n1", Name: "a", Type: "file", VersionID: "v2", ChunkCount: 2,
	})
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if nodeCacheHas(fs, "dr1", "/") {
		t.Fatal("pre-upload listing was stored, hiding the file that was just written")
	}
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatalf("listNodes (refetch): %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("listing fetched %d times, want 2 (first result discarded, second stored)", got)
	}
}

func TestCachedFileNodeID(t *testing.T) {
	fresh := []service.DataroomNodeInfo{
		{ID: "f-1", Name: "doc.txt", Type: "file"},
		{ID: "d-1", Name: "sub", Type: "dir"},
	}
	fs := seeded(map[string]*nodeCacheEntry{
		"/":        {nodes: fresh, fetchedAt: time.Now()},
		"/expired": {nodes: fresh, fetchedAt: time.Now().Add(-2 * DefaultCacheTTL)},
	})

	if id, ok := fs.cachedFileID("dr1", "/", "doc.txt"); !ok || id != "f-1" {
		t.Errorf("cached file: got (%q, %v), want (f-1, true)", id, ok)
	}
	// A folder of that name is a real conflict; the full path must handle it.
	if _, ok := fs.cachedFileID("dr1", "/", "sub"); ok {
		t.Error("a directory was reported as an overwritable file")
	}
	if _, ok := fs.cachedFileID("dr1", "/", "absent.txt"); ok {
		t.Error("an absent name was reported as cached")
	}
	// An expired listing must not be trusted for a node ID.
	if _, ok := fs.cachedFileID("dr1", "/expired", "doc.txt"); ok {
		t.Error("an expired listing was used")
	}
	if _, ok := fs.cachedFileID("dr1", "/never-listed", "doc.txt"); ok {
		t.Error("an unlisted folder returned a node ID")
	}
}

// ageNodeCache makes the cached listing of a folder the given age.
func ageNodeCache(fs *FS, dataroomID, path string, age time.Duration) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	aged := *cachedListingLocked(fs, dataroomID, path)
	aged.FetchedAt = time.Now().Add(-age)
	_ = fs.store.PutListing(context.Background(), key(dataroomID, path), &aged)
}

// versionedListFn returns a listFn answering one node whose ID is the call
// number ("n1", "n2", ...), so a test tells a refreshed listing from the old one.
// Calls after the first block on gate.
func versionedListFn(gate <-chan struct{}) (
	func(context.Context, string, string) ([]service.DataroomNodeInfo, error), *atomic.Int32,
) {
	var calls atomic.Int32

	return func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		n := calls.Add(1)
		if n > 1 {
			<-gate
		}

		return []service.DataroomNodeInfo{{ID: fmt.Sprintf("n%d", n), Name: "a", Type: "file"}}, nil
	}, &calls
}

// waitNodeID polls listNodes until it answers wantID.
func waitNodeID(t *testing.T, fs *FS, path, wantID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		nodes, err := fs.ReadDir(context.Background(), "dr1", path)
		if err == nil && len(nodes) == 1 && nodes[0].ID == wantID {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listing of %s never became %s (last: %+v, %v)", path, wantID, nodes, err)
		}
		time.Sleep(time.Millisecond)
	}
}

// An expired listing within max stale is served at once, without waiting for
// the API, while a single background refresh replaces it: a client walking a
// tree after a pause (PrivateBin's purge) is answered from memory.
func TestListNodes_StaleServedWhileRefreshing(t *testing.T) {
	gate := make(chan struct{})
	listFn, calls := versionedListFn(gate)
	fs := New(nil, Options{List: listFn, TTL: time.Minute, MaxStale: 5 * time.Minute})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 2*time.Minute)

	for range 10 {
		nodes, err := fs.ReadDir(ctx, "dr1", "/")
		if err != nil || len(nodes) != 1 || nodes[0].ID != "n1" {
			t.Fatalf("listNodes during the refresh = (%+v, %v), want the stale n1 at once", nodes, err)
		}
	}
	close(gate)
	waitNodeID(t, fs, "/", "n2")
	if got := calls.Load(); got != 2 {
		t.Errorf("listing fetched %d times, want 2 (initial + one shared refresh)", got)
	}
}

// Past TTL + max stale, the listing is too old to serve: the request waits.
func TestListNodes_PastMaxStaleWaits(t *testing.T) {
	gate := make(chan struct{})
	close(gate)
	listFn, _ := versionedListFn(gate)
	fs := New(nil, Options{List: listFn, TTL: time.Minute, MaxStale: 5 * time.Minute})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 7*time.Minute)

	nodes, err := fs.ReadDir(ctx, "dr1", "/")
	if err != nil || len(nodes) != 1 || nodes[0].ID != "n2" {
		t.Errorf("listNodes = (%+v, %v), want the fresh n2", nodes, err)
	}
}

// max stale 0 never serves an expired listing.
func TestListNodes_MaxStaleZeroWaits(t *testing.T) {
	gate := make(chan struct{})
	close(gate)
	listFn, _ := versionedListFn(gate)
	fs := New(nil, Options{List: listFn, TTL: time.Minute})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 2*time.Minute)

	nodes, err := fs.ReadDir(ctx, "dr1", "/")
	if err != nil || len(nodes) != 1 || nodes[0].ID != "n2" {
		t.Errorf("listNodes = (%+v, %v), want the fresh n2", nodes, err)
	}
}

// A refresh that finds the folder gone drops the expired listing: the next
// request answers 404 instead of replaying it until it is past max stale.
func TestListNodes_RefreshOfDeletedFolderDropsListing(t *testing.T) {
	var calls atomic.Int32
	fs := New(nil, Options{
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			if calls.Add(1) > 1 {
				return nil, os.ErrNotExist
			}

			return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/gone"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/gone", 2*time.Minute)
	if _, err := fs.ReadDir(ctx, "dr1", "/gone"); err != nil {
		t.Fatalf("stale listNodes: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := fs.ReadDir(ctx, "dr1", "/gone")
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listNodes = %v, want os.ErrNotExist once the refresh found the folder gone", err)
		}
		time.Sleep(time.Millisecond)
	}
}

// A failed refresh keeps the expired listing: a transient API error must not
// turn a folder into a miss that every request then waits for.
func TestListNodes_FailedRefreshKeepsListing(t *testing.T) {
	var calls atomic.Int32
	fs := New(nil, Options{
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			if calls.Add(1) > 1 {
				return nil, errors.New("api down")
			}

			return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 2*time.Minute)
	for range 3 {
		nodes, err := fs.ReadDir(ctx, "dr1", "/")
		if err != nil || len(nodes) != 1 || nodes[0].ID != "n1" {
			t.Fatalf("listNodes = (%+v, %v), want the expired n1 kept", nodes, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			fs.mu.Lock()
			_, running := fs.inflight[key("dr1", "/")]
			fs.mu.Unlock()
			if !running {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the refresh never finished")
			}
			time.Sleep(time.Millisecond)
		}
	}
}

// A mutation landing while a refresh runs wins: the refreshed listing,
// answered before the mutation, is not stored over it.
func TestListNodes_RefreshDiscardedAfterMutation(t *testing.T) {
	gate := make(chan struct{})
	listFn, calls := versionedListFn(gate)
	fs := New(nil, Options{List: listFn, TTL: time.Minute, MaxStale: 5 * time.Minute})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 2*time.Minute)
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil { // starts the refresh (call 2)
		t.Fatal(err)
	}
	// The mutation must land once the refresh is fetching: one landing before
	// it starts is in the API's answer, and the refresh is then kept.
	for deadline := time.Now().Add(2 * time.Second); calls.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("the refresh never started")
		}
		time.Sleep(time.Millisecond)
	}
	fs.upsert("dr1", "/", Node{ID: "up", Name: "b", Type: "file"})
	close(gate)

	deadline := time.Now().Add(2 * time.Second)
	for {
		fs.mu.Lock()
		_, running := fs.inflight[key("dr1", "/")]
		fs.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refresh never finished")
		}
		time.Sleep(time.Millisecond)
	}
	nodes := cachedNodes(fs, "dr1", "/")
	if len(nodes) != 2 || nodes[0].ID != "n1" || nodes[1].ID != "up" {
		t.Errorf("cache = %+v, want the upserted listing [n1 up], not the refresh", nodes)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("listing fetched %d times, want 2", got)
	}
}

// Background refreshes run at most api.concurrency.list at a time, and a
// request that misses a folder whose refresh is still queued starts it at
// once instead of waiting behind the queue.
func TestListNodes_RefreshesBoundedAndPromoted(t *testing.T) {
	gate := make(chan struct{})
	var running, peak atomic.Int32
	fs := New(nil, Options{
		List: func(_ context.Context, _, path string) ([]service.DataroomNodeInfo, error) {
			if path == "/urgent" {
				return []service.DataroomNodeInfo{{ID: "urgent", Name: "a", Type: "file"}}, nil
			}
			n := running.Add(1)
			defer running.Add(-1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			<-gate

			return []service.DataroomNodeInfo{{ID: "fresh", Name: "a", Type: "file"}}, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})
	ctx := context.Background()
	limit := int32(DefaultListConcurrency)

	stale := []service.DataroomNodeInfo{{ID: "old", Name: "a", Type: "file"}}
	expired := time.Now().Add(-2 * time.Minute)
	const folders = 20
	for i := range folders {
		seedNodeCache(fs, map[string]*nodeCacheEntry{fmt.Sprintf("/d%d", i): {nodes: stale, fetchedAt: expired}})
	}
	// A folder whose expired listing a mutation dropped while its refresh is
	// queued: the next request misses it and joins the queued refresh.
	seedNodeCache(fs, map[string]*nodeCacheEntry{"/urgent": {nodes: stale, fetchedAt: expired}})

	for i := range folders {
		if nodes, err := fs.ReadDir(ctx, "dr1", fmt.Sprintf("/d%d", i)); err != nil || nodes[0].ID != "old" {
			t.Fatalf("listNodes /d%d = (%+v, %v), want the stale listing at once", i, nodes, err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for running.Load() < limit {
		if time.Now().After(deadline) {
			t.Fatalf("%d refreshes running, want %d", running.Load(), limit)
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := fs.ReadDir(ctx, "dr1", "/urgent"); err != nil { // queued behind the full slots
		t.Fatal(err)
	}
	fs.InvalidateListing("dr1", "/urgent")

	done := make(chan []Node, 1)
	go func() {
		nodes, _ := fs.ReadDir(ctx, "dr1", "/urgent")
		done <- nodes
	}()
	select {
	case nodes := <-done:
		if len(nodes) != 1 || nodes[0].ID != "urgent" {
			t.Errorf("urgent listing = %+v", nodes)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a request waited behind the background refresh queue")
	}

	close(gate)
	for i := range folders {
		waitNodeID(t, fs, fmt.Sprintf("/d%d", i), "fresh")
	}
	if got := peak.Load(); got > limit {
		t.Errorf("%d refreshes ran at once, want at most %d", got, limit)
	}
}

// A name missing from an expired listing may be a node created elsewhere
// since: the lookup waits for the refresh instead of answering 404 from the
// old listing for up to ttl+max_stale. A name the listing holds is answered
// at once.
func TestFindListedNode_StaleMissWaitsForRefresh(t *testing.T) {
	var calls atomic.Int32
	fs := New(nil, Options{
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			nodes := []service.DataroomNodeInfo{{ID: "old", Name: "a", Type: "file"}}
			if calls.Add(1) > 1 {
				nodes = append(nodes, service.DataroomNodeInfo{ID: "new", Name: "b", Type: "file"})
			}

			return nodes, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 2*time.Minute)

	n, err := fs.Lookup(ctx, "dr1", "/", "b")
	if err != nil || n.ID != "new" {
		t.Fatalf("findListedNode(b) = (%+v, %v), want the node created since", n, err)
	}
	if _, err := fs.Lookup(ctx, "dr1", "/", "absent"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("findListedNode(absent) = %v, want os.ErrNotExist", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("listing fetched %d times, want 2 (the refreshed listing is fresh)", got)
	}
}

// A name the expired listing holds is answered from it, without waiting.
func TestFindListedNode_StaleHitDoesNotWait(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	listFn, _ := versionedListFn(gate)
	fs := New(nil, Options{List: listFn, TTL: time.Minute, MaxStale: 5 * time.Minute})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 2*time.Minute)

	n, err := fs.Lookup(ctx, "dr1", "/", "a")
	if err != nil || n.ID != "n1" {
		t.Errorf("findListedNode(a) = (%+v, %v), want the stale n1 at once", n, err)
	}
}

// A refresh queued behind the slots must not be discarded because of a
// mutation made before it started: its answer already includes it.
func TestListNodes_QueuedRefreshKeepsMutationBeforeStart(t *testing.T) {
	fs := New(nil, Options{
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			return []service.DataroomNodeInfo{{ID: "fresh", Name: "a", Type: "file"}}, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})
	fs.slots = make(chan struct{}, 1)
	fs.slots <- struct{}{} // every slot taken: the refresh queues
	seedNodeCache(fs, map[string]*nodeCacheEntry{
		"/": {nodes: []service.DataroomNodeInfo{{ID: "old", Name: "a", Type: "file"}},
			fetchedAt: time.Now().Add(-2 * time.Minute)},
	})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil { // queues the refresh
		t.Fatal(err)
	}
	fs.upsert("dr1", "/", Node{ID: "up", Name: "b", Type: "file"})
	<-fs.slots // the refresh starts now, after the mutation

	waitNodeID(t, fs, "/", "fresh")
}

// An expired listing is refreshed with the ETag it came with: an unchanged
// dataroom answers 304 and the listing is kept for another TTL; a listing
// this server edited in place has lost its ETag and is fetched again.
func TestListNodes_RevalidatesWithETag(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	nameEnc, _ := crypto.EncryptStringForKeys("doc.txt", []string{pub})
	var mu sync.Mutex
	var answers []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/dataroom/dr1/nodes" {
			http.Error(w, "unexpected "+r.URL.Path, http.StatusInternalServerError)

			return
		}
		w.Header().Set("ETag", `W/"r7"`)
		if r.Header.Get("If-None-Match") == `W/"r7"` {
			answers = append(answers, http.StatusNotModified)
			w.WriteHeader(http.StatusNotModified)

			return
		}
		answers = append(answers, http.StatusOK)
		fmt.Fprintf(w, `{"items":[{"node":{"id":"n1","type":"file","name_hash":"h","name_enc":%q,"type_enc":null,`+
			`"access_mode":"0644","parent_id":null},"node_version":{"id":"v1","node_id":"n1","original_size":3,`+
			`"chunk_count":1,"created_at":"2026-10-10T12:00:00Z"}}],"total":1,"page":1,"size":100,"pages":1}`, nameEnc)
	}))
	defer srv.Close()
	fs := New(testClient(srv), Options{})
	fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	ctx := context.Background()
	expire := func() {
		// Expired, still within ListingRetention: the store keeps it.
		ageNodeCache(fs, "dr1", "/", 2*time.Minute)
	}
	list := func(want int) {
		t.Helper()
		nodes, err := fs.ReadDir(ctx, "dr1", "/")
		if err != nil || len(nodes) != want {
			t.Fatalf("listing = %+v, %v; want %d node(s)", nodes, err, want)
		}
	}

	list(1)
	expire()
	list(1)
	fresh := time.Since(cachedListing(fs, "dr1", "/").FetchedAt) < time.Minute
	if !fresh {
		t.Error("a 304 did not renew the listing")
	}
	fs.forget("dr1", "/", "doc.txt")
	expire()
	list(1)

	mu.Lock()
	defer mu.Unlock()
	if want := []int{http.StatusOK, http.StatusNotModified, http.StatusOK}; fmt.Sprint(answers) != fmt.Sprint(want) {
		t.Errorf("API answers = %v, want %v", answers, want)
	}
}

// A background refresh of an expired listing runs after the request answered:
// it gets a root span of its own, linked to that request, with the API work as
// its children. A miss the request waits for stays in the request's trace.
func TestListNodes_BackgroundRefreshHasItsOwnTrace(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	fetchSpans := make(chan trace.SpanContext, 4)
	fs := New(nil, Options{
		List: func(ctx context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
			calls.Add(1)
			fetchSpans <- trace.SpanFromContext(ctx).SpanContext()

			return []service.DataroomNodeInfo{{ID: "n1", Name: sentinel, Type: "file"}}, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})

	reqCtx, reqSpan := telemetry.Tracer().Start(context.Background(), "WEBDAV PROPFIND")
	if _, err := fs.ReadDir(reqCtx, "dr1", "/"+sentinel); err != nil { // miss: waited for
		t.Fatal(err)
	}
	if got := <-fetchSpans; got.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("a miss the request waits for must run in the request span, got %v", got)
	}
	ageNodeCache(fs, "dr1", "/"+sentinel, 2*time.Minute)
	if _, err := fs.ReadDir(reqCtx, "dr1", "/"+sentinel); err != nil { // stale: background refresh
		t.Fatal(err)
	}
	reqSpan.End()
	refreshCtx := <-fetchSpans
	waitNodeID(t, fs, "/"+sentinel, "n1")
	for calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}

	var refresh *tracetest.SpanStub
	deadline := time.Now().Add(2 * time.Second)
	for refresh == nil {
		for _, s := range exp.GetSpans() {
			if s.Name == "cache.refresh" {
				refresh = &s

				break
			}
		}
		if refresh == nil && time.Now().After(deadline) {
			t.Fatal("no cache.refresh span exported")
		}
		time.Sleep(time.Millisecond)
	}
	if refresh.Parent.IsValid() {
		t.Errorf("cache.refresh has parent %v, want a root span", refresh.Parent)
	}
	if refresh.SpanContext.TraceID() == reqSpan.SpanContext().TraceID() {
		t.Error("cache.refresh shares the request's trace")
	}
	if refreshCtx.SpanID() != refresh.SpanContext.SpanID() {
		t.Error("the refresh's API work does not run under the cache.refresh span")
	}
	if len(refresh.Links) != 1 || refresh.Links[0].SpanContext.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("cache.refresh links = %+v, want one link to the request span", refresh.Links)
	}
	attrs := map[string]string{}
	for _, kv := range refresh.Attributes {
		attrs[string(kv.Key)] = kv.Value.String()
	}
	if attrs["retyc.cache.name"] != "nodes" || attrs["retyc.dataroom.id"] != "dr1" {
		t.Errorf("cache.refresh attributes = %v", attrs)
	}
	telemetrytest.AssertNoLeak(t, exp.GetSpans(), sentinel)
}

// A failed background refresh is recorded as an error by type only: its
// message (a name, a path) never reaches the span.
func TestListNodes_FailedRefreshSpanCarriesNoMessage(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	fs := New(nil, Options{
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			if calls.Add(1) > 1 {
				return nil, fmt.Errorf("listing %s: %w", sentinel, os.ErrNotExist)
			}

			return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})
	ctx := context.Background()
	if _, err := fs.ReadDir(ctx, "dr1", "/"+sentinel); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/"+sentinel, 2*time.Minute)
	if _, err := fs.ReadDir(ctx, "dr1", "/"+sentinel); err != nil {
		t.Fatal(err)
	}

	refresh := waitRefreshSpan(t, exp)
	if refresh.Status.Code != codes.Error || refresh.Status.Description != "" {
		t.Errorf("status = %+v, want Error with no description", refresh.Status)
	}
	if spanAttr(refresh, "error.type") == "" {
		t.Error("error.type not set on the failed refresh")
	}
	telemetrytest.AssertNoLeak(t, exp.GetSpans(), sentinel)
}

// A request that joins a background refresh and waits for it (a name missing
// from the expired listing) gets a link to the refresh's trace: the API work
// it waited for is there, not in its own trace.
func TestFindListedNode_JoinedRefreshIsLinked(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	fs := New(nil, Options{
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			nodes := []service.DataroomNodeInfo{{ID: "old", Name: "a", Type: "file"}}
			if calls.Add(1) > 1 {
				nodes = append(nodes, service.DataroomNodeInfo{ID: "new", Name: "b", Type: "file"})
			}

			return nodes, nil
		},
		TTL: time.Minute, MaxStale: 5 * time.Minute,
	})
	// Every slot taken: the background refresh stays queued until request B
	// joins it, so B is certain to wait for it.
	fs.slots = make(chan struct{}, 1)
	fs.slots <- struct{}{}
	ctx := context.Background()
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "dr1", "/", 2*time.Minute)

	ctxA, spanA := telemetry.Tracer().Start(ctx, "WEBDAV PROPFIND")
	if _, err := fs.ReadDir(ctxA, "dr1", "/"); err != nil { // queues the refresh
		t.Fatal(err)
	}
	spanA.End()
	ctxB, spanB := telemetry.Tracer().Start(ctx, "WEBDAV GET")
	if n, err := fs.Lookup(ctxB, "dr1", "/", "b"); err != nil || n.ID != "new" {
		t.Fatalf("findListedNode(b) = (%+v, %v)", n, err)
	}
	spanB.End()

	refresh := waitRefreshSpan(t, exp)
	var b *tracetest.SpanStub
	for _, s := range exp.GetSpans() {
		if s.Name == "WEBDAV GET" {
			b = &s
		}
	}
	if b == nil {
		t.Fatal("request B span not exported")
	}
	if len(b.Links) != 1 || b.Links[0].SpanContext.SpanID() != refresh.SpanContext.SpanID() {
		t.Errorf("request B links = %+v, want one link to cache.refresh", b.Links)
	}
}

func TestListNodes_CountsCacheHitsAndMisses(t *testing.T) {
	hits := metrics.CacheLookups.WithLabelValues("hit")
	misses := metrics.CacheLookups.WithLabelValues("miss")
	hitsBefore, missesBefore := testutil.ToFloat64(hits), testutil.ToFloat64(misses)
	fs := New(nil, Options{List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return nil, nil
	}})
	ctx := context.Background()
	for range 3 {
		if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
			t.Fatal(err)
		}
	}
	if got := testutil.ToFloat64(misses) - missesBefore; got != 1 {
		t.Errorf("miss delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(hits) - hitsBefore; got != 2 {
		t.Errorf("hit delta = %v, want 2", got)
	}
}

func TestListNodes_EmitsCacheLookupEvents(t *testing.T) {
	exp := telemetrytest.Install(t)
	ctx, parent := telemetry.Tracer().Start(context.Background(), "parent")
	fs := New(nil, Options{List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return nil, nil
	}})
	for range 2 {
		if _, err := fs.ReadDir(ctx, "dr1", "/SENTINEL"); err != nil {
			t.Fatal(err)
		}
	}
	parent.End()

	var hits []bool
	for _, ev := range exp.GetSpans()[0].Events {
		if ev.Name != "cache.lookup" {
			continue
		}
		for _, kv := range ev.Attributes {
			if kv.Key == "retyc.cache.hit" {
				hits = append(hits, kv.Value.AsBool())
			}
			if strings.Contains(kv.Value.String(), "SENTINEL") {
				t.Errorf("event attribute %s leaks the path", kv.Key)
			}
		}
	}
	if len(hits) != 2 || hits[0] || !hits[1] {
		t.Errorf("cache.hit sequence = %v, want [false true]", hits)
	}
}
