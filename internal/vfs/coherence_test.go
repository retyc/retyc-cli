package vfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// The tests of this file are about what the cache answers once a mutation made
// through the FS is over: never something the API said before it.

// — A listing function whose answer can be held ————————————————————————————————

// heldLister is an Options.List over a tree the test edits. The answer is read
// when the call arrives; holdNext makes the next call keep it until released,
// as a response of the API on its way while something else happens.
type heldLister struct {
	mu      sync.Mutex
	tree    map[string][]service.DataroomNodeInfo
	calls   int
	hold    chan struct{}
	arrived chan struct{}
}

func (l *heldLister) set(path string, nodes ...service.DataroomNodeInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tree[path] = nodes
}

// holdNext makes the next listing wait; it returns the channel closed once
// that listing has read its answer, and the function that lets it return.
func (l *heldLister) holdNext() (arrived <-chan struct{}, release func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	hold, waiting := make(chan struct{}), make(chan struct{})
	l.hold, l.arrived = hold, waiting

	return waiting, sync.OnceFunc(func() { close(hold) })
}

func (l *heldLister) list(_ context.Context, _, path string) ([]service.DataroomNodeInfo, error) {
	l.mu.Lock()
	l.calls++
	nodes := slices.Clone(l.tree[path])
	hold, arrived := l.hold, l.arrived
	l.hold, l.arrived = nil, nil
	l.mu.Unlock()
	if hold != nil {
		close(arrived)
		<-hold
	}

	return nodes, nil
}

// lookupResult is what a Lookup running in its own goroutine returned.
type lookupResult struct {
	node Node
	err  error
}

// lookupAside runs Lookup in a goroutine. A lookup that wrongly joins a held
// fetch only returns once the test releases it: the caller selects on the
// result, releases on a timeout, and then reads what the stale answer gave.
func lookupAside(fs *FS, parentPath, name string) <-chan lookupResult {
	out := make(chan lookupResult, 1)
	go func() {
		n, err := fs.Lookup(context.Background(), "dr1", parentPath, name)
		out <- lookupResult{n, err}
	}()

	return out
}

// settled returns the result of a call that must not depend on the held
// answer: when it does not come, the answer is released and the test fails
// with what the call then returned.
func settled[T any](t *testing.T, out <-chan T, release func(), what string) T {
	t.Helper()
	select {
	case res := <-out:
		return res
	case <-time.After(5 * time.Second):
		release()
		t.Fatalf("%s waited for the answer older than the mutation, and got %+v", what, <-out)

		panic("unreachable")
	}
}

// A refresh of an expired listing is on its way, answered before a removal
// made here. The name is gone from the edited listing, which is expired: the
// lookup waits for a refresh, and must not take the one that predates the
// removal, whose answer still names the node.
func TestLookup_DoesNotJoinARefreshOlderThanARemove(t *testing.T) {
	lister := &heldLister{tree: map[string][]service.DataroomNodeInfo{
		"/a": {{ID: "f-x", Name: "x.txt", Type: "file"}, {ID: "f-y", Name: "y.txt", Type: "file"}},
	}}
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.method != http.MethodDelete {
			return false
		}
		w.WriteHeader(http.StatusNoContent)

		return true
	}}
	fs := newAPIFS(t, fake, Options{TTL: time.Minute, MaxStale: time.Minute, List: lister.list},
		map[string][]service.DataroomNodeInfo{
			"/":  {{ID: "d-a", Name: "a", Type: "dir"}},
			"/a": lister.tree["/a"],
		})
	ageNodeCache(fs, "dr1", "/a", 90*time.Second)
	ctx := context.Background()

	arrived, release := lister.holdNext()
	defer release()
	if _, err := fs.ReadDir(ctx, "dr1", "/a"); err != nil { // served expired, starts the refresh
		t.Fatalf("ReadDir: %v", err)
	}
	<-arrived // the API has answered the refresh, x.txt included

	if err := fs.Remove(ctx, "dr1", "/a/x.txt", false); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	lister.set("/a", service.DataroomNodeInfo{ID: "f-y", Name: "y.txt", Type: "file"})

	res := settled(t, lookupAside(fs, "/a", "x.txt"), release, "the lookup of the removed name")
	if !errors.Is(res.err, ErrNotExist) {
		t.Fatalf("Lookup of the removed name = (%+v, %v), want ErrNotExist", res.node, res.err)
	}
	release()
	// The old answer, once in, is not kept either.
	mustMiss(t, fs, "/a", "x.txt")
	mustLookup(t, fs, "/a", "y.txt", "f-y")
}

// The first listing of a folder is on its way, answered before a folder was
// created in it here. A listing asked for after the creation must not share
// that answer; the one that asked before still gets it.
func TestReadDir_DoesNotJoinAFetchOlderThanAMkdir(t *testing.T) {
	lister := &heldLister{tree: map[string][]service.DataroomNodeInfo{
		"/a": {{ID: "f-x", Name: "x.txt", Type: "file"}},
	}}
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.String() != "POST /dataroom/dr1/node" {
			return false
		}
		fmt.Fprint(w, `{"id":"d-new","name_enc":"x"}`)

		return true
	}}
	fs := newAPIFS(t, fake, Options{TTL: time.Minute, MaxStale: time.Minute, List: lister.list},
		map[string][]service.DataroomNodeInfo{"/": {{ID: "d-a", Name: "a", Type: "dir"}}})
	ctx := context.Background()

	type listed struct {
		nodes []Node
		err   error
	}
	readDir := func() <-chan listed {
		out := make(chan listed, 1)
		go func() {
			nodes, err := fs.ReadDir(ctx, "dr1", "/a")
			out <- listed{nodes, err}
		}()

		return out
	}

	arrived, release := lister.holdNext()
	defer release()
	first := readDir()
	<-arrived // the API has answered, without the folder to come

	if _, err := fs.Mkdir(ctx, "dr1", "/a/new"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	lister.set("/a", service.DataroomNodeInfo{ID: "f-x", Name: "x.txt", Type: "file"},
		service.DataroomNodeInfo{ID: "d-new", Name: "new", Type: "dir"})

	second := settled(t, readDir(), release, "the listing asked for after the creation")
	if second.err != nil || !slices.Equal(names(second.nodes), []string{"new", "x.txt"}) {
		t.Fatalf("ReadDir after the creation = (%v, %v), want new and x.txt", names(second.nodes), second.err)
	}

	// Whoever asked before the creation gets the answer it was waiting for.
	release()
	if got := <-first; got.err != nil || !slices.Equal(names(got.nodes), []string{"x.txt"}) {
		t.Errorf("ReadDir that started first = (%v, %v), want its own answer, x.txt", names(got.nodes), got.err)
	}
	// And that answer does not replace the newer one in the cache.
	if got := names(cachedNodes(fs, "dr1", "/a")); !slices.Equal(got, []string{"new", "x.txt"}) {
		t.Errorf("cached listing = %v, want the one fetched after the creation", got)
	}
	lister.mu.Lock()
	calls := lister.calls
	lister.mu.Unlock()
	if calls != 2 {
		t.Errorf("%d listings, want 2: the one in flight and the one asked for after the creation", calls)
	}
}

// A fetch still queued for a refresh slot has read nothing yet: a request made
// after a mutation joins it (and starts it) instead of adding a second one.
func TestReadDir_JoinsAQueuedRefreshAfterAMutation(t *testing.T) {
	gate := make(chan struct{})
	var mu sync.Mutex
	calls := map[string]int{}
	listFn := func(_ context.Context, _, path string) ([]service.DataroomNodeInfo, error) {
		mu.Lock()
		calls[path]++
		mu.Unlock()
		if path == "/busy" {
			<-gate
		}

		return []service.DataroomNodeInfo{{ID: "n-" + strings.Trim(path, "/"), Name: "a", Type: "file"}}, nil
	}
	fs := New(nil, Options{TTL: time.Minute, MaxStale: time.Minute, ListConcurrency: 1, List: listFn})
	old := time.Now().Add(-90 * time.Second)
	seedNodeCache(fs, map[string]*nodeCacheEntry{
		"/busy":   {nodes: []service.DataroomNodeInfo{{ID: "old", Name: "a", Type: "file"}}, fetchedAt: old},
		"/queued": {nodes: []service.DataroomNodeInfo{{ID: "old", Name: "a", Type: "file"}}, fetchedAt: old},
	})
	ctx := context.Background()
	defer close(gate)

	// The refresh of /busy holds the only slot; the one of /queued waits for it.
	if _, err := fs.ReadDir(ctx, "dr1", "/busy"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		started := calls["/busy"] == 1
		mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refresh of /busy never started")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := fs.ReadDir(ctx, "dr1", "/queued"); err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	queued := fs.inflight[key("dr1", "/queued")]
	fs.mu.Unlock()
	if queued == nil {
		t.Fatal("no refresh queued for /queued")
	}

	fs.upsert("dr1", "/queued", Node{ID: "f-b", Name: "b", Type: TypeFile})
	fs.mu.Lock()
	joined := fs.fetchLocked(ctx, key("dr1", "/queued"), false)
	fs.unlock()
	if joined != queued {
		t.Fatal("a request after the mutation did not join the refresh still queued")
	}
	if _, err := joined.wait(ctx); err != nil {
		t.Fatalf("the promoted refresh: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["/queued"] != 1 {
		t.Errorf("%d listings of /queued, want 1", calls["/queued"])
	}
}

// — A fake API whose tree follows the mutations ————————————————————————————————

// liveNode is a node of liveAPI, kept as the client sent it: the server never
// reads a name, only its hash.
type liveNode struct {
	id, parent, kind  string
	nameEnc, nameHash string
}

// liveAPI is a fake API holding the tree of dataroom "dr1" and applying the
// mutations it receives: a creation, a rename or move, a deletion (with the
// subtree). A read is answered with the tree as it stood when the request
// arrived, after delay: an answer may reach the client after a mutation that
// came later, which is what the cache must cope with.
type liveAPI struct {
	t         *testing.T
	pub, salt string

	mu     sync.Mutex
	nodes  map[string]*liveNode
	nextID int
	rnd    *rand.Rand
	// maxDelay bounds the random delay of an answer; 0 for none.
	maxDelay time.Duration
	// hold, when set, is taken by the next listing (not a lookup by hash).
	hold    chan struct{}
	arrived chan struct{}
}

func newLiveAPI(t *testing.T, seed uint64, maxDelay time.Duration) (*liveAPI, func(Options) *FS) {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	a := &liveAPI{
		t: t, pub: identity.Recipient().String(), salt: "s4lt",
		nodes: make(map[string]*liveNode), rnd: seededRand(seed, 0), maxDelay: maxDelay,
	}
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	newFS := func(opts Options) *FS {
		fs := New(testClient(srv), opts)
		fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: a.pub, NameSalt: a.salt})

		return fs
	}

	return a, newFS
}

// seededRand returns a generator that replays: the delays of the fake API and
// the steps of a stress test are the same from one run to the next.
func seededRand(seed uint64, stream int) *rand.Rand {
	return rand.New(rand.NewPCG(seed, uint64(stream))) //nolint:gosec // G404, G115: a test that must replay
}

func (a *liveAPI) hash(name string) string {
	h := sha256.Sum256([]byte(a.salt + name))

	return hex.EncodeToString(h[:])
}

// add puts a node in the tree, as another client would, and returns its ID.
func (a *liveAPI) add(parent, name, kind string) string {
	nameEnc, err := crypto.EncryptStringForKeys(name, []string{a.pub})
	if err != nil {
		a.t.Fatalf("EncryptStringForKeys: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.addLocked(parent, kind, nameEnc, a.hash(name))
}

func (a *liveAPI) addLocked(parent, kind, nameEnc, nameHash string) string {
	a.nextID++
	id := "n" + strconv.Itoa(a.nextID)
	a.nodes[id] = &liveNode{id: id, parent: parent, kind: kind, nameEnc: nameEnc, nameHash: nameHash}

	return id
}

// holdNextListing makes the next listing keep its answer until released.
func (a *liveAPI) holdNextListing() (arrived <-chan struct{}, release func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hold, waiting := make(chan struct{}), make(chan struct{})
	a.hold, a.arrived = hold, waiting

	return waiting, sync.OnceFunc(func() { close(hold) })
}

// delayLocked draws the delay of an answer.
func (a *liveAPI) delayLocked() time.Duration {
	if a.maxDelay <= 0 {
		return 0
	}

	return time.Duration(a.rnd.Int64N(int64(a.maxDelay)))
}

func (a *liveAPI) takenLocked(parent, nameHash, except string) bool {
	for _, n := range a.nodes {
		if n.parent == parent && n.nameHash == nameHash && n.id != except {
			return true
		}
	}

	return false
}

func (a *liveAPI) deleteLocked(id string) {
	delete(a.nodes, id)
	for _, n := range a.nodes {
		if n.parent == id {
			a.deleteLocked(n.id)
		}
	}
}

func (a *liveAPI) itemsLocked(parent, hash string) []any {
	items := []any{}
	ids := make([]string, 0, len(a.nodes))
	for id, n := range a.nodes {
		if n.parent == parent && (hash == "" || n.nameHash == hash) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		n := a.nodes[id]
		node := map[string]any{
			"id": n.id, "type": n.kind, "name_enc": n.nameEnc, "name_hash": n.nameHash,
			"type_enc": nil, "parent_id": nil, "created_at": "2026-10-01T10:00:00Z",
		}
		if n.parent != "" {
			node["parent_id"] = n.parent
		}
		var version any
		if n.kind == api.NodeTypeFile {
			version = map[string]any{
				"id": "v-" + n.id, "node_id": n.id, "original_size": 5, "chunk_count": 1,
				"created_at": "2026-10-02T10:00:00Z",
			}
		}
		items = append(items, map[string]any{"node": node, "node_version": version})
	}

	return items
}

func (a *liveAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	str := func(key string) string {
		s, _ := body[key].(string)

		return s
	}
	nodeID := strings.TrimPrefix(r.URL.Path, "/dataroom/node/")

	// The request takes effect, or reads the tree, as it arrives; its answer
	// leaves after the delay.
	a.mu.Lock()
	code, reply := http.StatusOK, any(nil)
	var hold, arrived chan struct{}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/mime-types":
		reply = []any{}
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
		parent, hash := r.URL.Query().Get("parent_id"), r.URL.Query().Get("name_hash")
		if parent != "" && a.nodes[parent] == nil {
			code = http.StatusNotFound

			break
		}
		items := a.itemsLocked(parent, hash)
		reply = map[string]any{"items": items, "total": len(items), "pages": 1, "page": 1}
		if hash == "" {
			hold, arrived = a.hold, a.arrived
			a.hold, a.arrived = nil, nil
		}
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
		parent := str("parent_id")
		switch {
		case parent != "" && a.nodes[parent] == nil, a.takenLocked(parent, str("name_hash"), ""):
			code = http.StatusConflict
		default:
			id := a.addLocked(parent, str("type"), str("name_enc"), str("name_hash"))
			reply = map[string]any{"id": id, "name_enc": str("name_enc")}
		}
	case r.Method == http.MethodPut && nodeID != r.URL.Path:
		n := a.nodes[nodeID]
		if n == nil {
			code = http.StatusNotFound

			break
		}
		parent := n.parent
		if _, moved := body["parent_id"]; moved {
			parent = str("parent_id")
		}
		if (parent != "" && a.nodes[parent] == nil) || a.takenLocked(parent, str("name_hash"), n.id) {
			code = http.StatusConflict

			break
		}
		n.parent, n.nameEnc, n.nameHash = parent, str("name_enc"), str("name_hash")
		code = http.StatusNoContent
	case r.Method == http.MethodDelete && nodeID != r.URL.Path:
		if a.nodes[nodeID] == nil {
			code = http.StatusNotFound

			break
		}
		a.deleteLocked(nodeID)
		code = http.StatusNoContent
	default:
		code = http.StatusInternalServerError
	}
	delay := a.delayLocked()
	a.mu.Unlock()

	if hold != nil {
		close(arrived)
		<-hold
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	switch {
	case code == http.StatusNoContent:
		w.WriteHeader(code)
	case code != http.StatusOK:
		http.Error(w, `{"detail":"refused"}`, code)
	default:
		_ = json.NewEncoder(w).Encode(reply)
	}
}

// The refresh of the expired root listing is on its way, answered before a
// folder was renamed here. Looking a child up under the old path resolves the
// folder through the root: it must not find it in that old answer, reach the
// child through the old ID, and keep an entry for it under a path that no
// longer exists.
func TestLookup_DoesNotResolveAParentFromARefreshOlderThanARename(t *testing.T) {
	a, newFS := newLiveAPI(t, 1, 0)
	w1 := a.add("", "w1", api.NodeTypeFolder)
	f0 := a.add(w1, "f0", api.NodeTypeFile)
	fs := newFS(Options{TTL: time.Minute, MaxStale: time.Minute, NegativeTTL: time.Minute})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	ageNodeCache(fs, "dr1", "/", 90*time.Second)
	arrived, release := a.holdNextListing()
	defer release()
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil { // served expired, starts the refresh
		t.Fatalf("ReadDir: %v", err)
	}
	<-arrived // the API has answered the refresh: the root holds w1

	if err := fs.Rename(ctx, "dr1", "/w1", "/w1r", false); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	res := settled(t, lookupAside(fs, "/w1", "f0"), release, "the lookup under the old path")
	if !errors.Is(res.err, ErrNotExist) {
		t.Errorf("Lookup under the renamed folder's old path = (%+v, %v), want ErrNotExist", res.node, res.err)
	}
	release()
	if e, ok := cachedEntry(fs, "/w1", "f0"); ok && e.Node != nil {
		t.Errorf("an entry was kept under the old path: %+v", e.Node)
	}
	mustMiss(t, fs, "/", "w1")
	mustLookup(t, fs, "/", "w1r", w1)
	mustLookup(t, fs, "/w1r", "f0", f0)
}

// — Proof of the contrary ———————————————————————————————————————————————————————

// A name looked up and found missing, then created by another client: the
// API refuses to create it here (409). That refusal says the name exists, and
// the entry that says it does not must not outlive it.
func TestMkdir_ConflictDropsTheNegativeEntry(t *testing.T) {
	a, newFS := newLiveAPI(t, 1, 0)
	dirA := a.add("", "a", api.NodeTypeFolder)
	fs := newFS(Options{TTL: time.Minute, NegativeTTL: time.Minute})
	ctx := context.Background()

	// The root first: looking a name up in /a looks "a" up in the root, a
	// second name there, which starts the listing of the root (see
	// noteNameLookup), and that listing drops the entries this checks.
	for _, parent := range []string{"/", "/a"} {
		mustMiss(t, fs, parent, "d")
		if e, ok := cachedEntry(fs, parent, "d"); !ok || e.Node != nil {
			t.Fatalf("%s: entry = (%+v, %v), want a negative one", parent, e, ok)
		}
		parentID := dirA
		if parent == "/" {
			parentID = ""
		}
		created := a.add(parentID, "d", api.NodeTypeFolder) // by another client

		if _, err := fs.Mkdir(ctx, "dr1", joinPath(parent, "d")); !errors.Is(err, ErrExist) {
			t.Fatalf("%s: Mkdir = %v, want ErrExist", parent, err)
		}
		mustLookup(t, fs, parent, "d", created)
	}
}

// The same for a fresh listing that does not name the folder: the conflict
// shows it no longer describes the folder.
func TestMkdir_ConflictDropsTheListingThatMissesTheName(t *testing.T) {
	a, newFS := newLiveAPI(t, 1, 0)
	dirA := a.add("", "a", api.NodeTypeFolder)
	a.add(dirA, "x", api.NodeTypeFile)
	fs := newFS(Options{TTL: time.Minute, NegativeTTL: time.Minute})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	created := a.add(dirA, "d", api.NodeTypeFolder) // by another client
	if _, err := fs.Mkdir(ctx, "dr1", "/a/d"); !errors.Is(err, ErrExist) {
		t.Fatalf("Mkdir = %v, want ErrExist", err)
	}
	mustLookup(t, fs, "/a", "d", created)

	// A listing that names the folder is kept: the conflict taught nothing.
	if _, err := fs.ReadDir(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if _, err := fs.Mkdir(ctx, "dr1", "/a/d"); !errors.Is(err, ErrExist) {
		t.Fatalf("Mkdir = %v, want ErrExist", err)
	}
	if !nodeCacheHas(fs, "dr1", "/a") {
		t.Error("the listing that names the folder was dropped by the conflict")
	}
}

// A rename onto a name found missing, then taken by another client, is
// refused (409): the destination exists, whatever the entry said.
func TestRename_ConflictDropsTheNegativeEntry(t *testing.T) {
	a, newFS := newLiveAPI(t, 1, 0)
	dirA := a.add("", "a", api.NodeTypeFolder)
	a.add(dirA, "src", api.NodeTypeFile)
	fs := newFS(Options{TTL: time.Minute, NegativeTTL: time.Minute})

	mustMiss(t, fs, "/a", "dst")
	taken := a.add(dirA, "dst", api.NodeTypeFile) // by another client
	if err := fs.Rename(context.Background(), "dr1", "/a/src", "/a/dst", false); !errors.Is(err, ErrExist) {
		t.Fatalf("Rename = %v, want ErrExist", err)
	}
	mustLookup(t, fs, "/a", "dst", taken)
}

// A node the cache names and the API no longer has, twice in a row: once the
// mutation has given up, the cache does not name it any more.
func TestRemove_GoneNodeIsForgotten(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
	mustLookup(t, fs, "/a", "x.txt", "f-x")

	// The lookups keep answering the node (an index late on the deletion);
	// deleting it answers 404 each time.
	fail := func() {
		a.mu.Lock()
		a.failOnce = map[string]int{"DELETE /dataroom/node/f-x": http.StatusNotFound}
		a.mu.Unlock()
	}
	fail()
	arrived, release := a.holdNextLookup() // the retry's lookup, which comes after the first 404
	done := make(chan error, 1)
	go func() { done <- fs.Remove(context.Background(), "dr1", "/a/x.txt", true) }()
	<-arrived
	fail() // the first 404 is spent: arm the one of the retry
	release()
	if err := <-done; !errors.Is(err, ErrNotExist) {
		t.Fatalf("Remove = %v, want ErrNotExist", err)
	}
	if e, ok := cachedEntry(fs, "/a", "x.txt"); ok && e.Node != nil {
		t.Errorf("the entry of the node the API no longer has was kept: %+v", e.Node)
	}
}

// — Quota ———————————————————————————————————————————————————————————————————————

// A caller that gives up while the counters are fetched says nothing about
// them: nothing is cached, nothing is reported, and the next caller asks.
func TestQuota_CancelledCallerIsNotCached(t *testing.T) {
	arrived := make(chan struct{})
	var once sync.Once
	gate := make(chan struct{})
	fake := &fakeAPI{reply: func(w http.ResponseWriter, _ apiCall) bool {
		first := false
		once.Do(func() { first = true })
		if first {
			close(arrived)
			<-gate
		}
		fmt.Fprint(w, `{"dataroom_id":"dr1","files_count":1,"storage_used":9,"storage_free":991}`)

		return true
	}}
	var logs logRecorder
	fs := newAPIFS(t, fake, Options{TTL: time.Minute, Logf: logs.logf}, nil)
	defer close(gate)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-arrived
		cancel()
	}()
	if _, _, ok := fs.Quota(ctx, "dr1"); ok {
		t.Fatal("Quota answered counters to a caller that gave up")
	}
	if used, free, ok := fs.Quota(context.Background(), "dr1"); !ok || used != 9 || free != 991 {
		t.Errorf("Quota after a cancelled call = (%d, %d, %v), want (9, 991, true)", used, free, ok)
	}
	if got := logs.list(); len(got) != 0 {
		t.Errorf("logged %v for a caller that gave up, want nothing", got)
	}
}

// — Stress ——————————————————————————————————————————————————————————————————————

// Mutations, lookups and listings from many goroutines over listings that
// expire all the time and an API that answers late: whatever answer is on its
// way when a mutation ends, a lookup started after it reflects it. Each
// worker owns a folder of the root, which it also renames, and checks the
// invariant after every mutation; readers keep fetches and refreshes in
// flight under every path meanwhile.
func TestLookup_ReflectsEveryFinishedMutation(t *testing.T) {
	const (
		seed    = 20261012
		workers = 4
		steps   = 40
	)
	a, newFS := newLiveAPI(t, seed, 2*time.Millisecond)
	fs := newFS(Options{TTL: 3 * time.Millisecond, MaxStale: 25 * time.Millisecond, NegativeTTL: 3 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	type child struct{ name, id string }
	homes := make([]string, workers)
	seeded := make([][]child, workers)
	for w := range workers {
		homes[w] = a.add("", fmt.Sprintf("w%d", w), api.NodeTypeFolder)
		for i := range 2 {
			name := fmt.Sprintf("f%d", i)
			seeded[w] = append(seeded[w], child{name, a.add(homes[w], name, api.NodeTypeFile)})
		}
	}

	stop := make(chan struct{})
	var readers, mutators sync.WaitGroup
	for r := range 3 {
		readers.Go(func() {
			rnd := seededRand(seed, r+100)
			for {
				select {
				case <-stop:
					return
				default:
				}
				home := fmt.Sprintf("/w%d", rnd.IntN(workers))
				if rnd.IntN(2) == 0 {
					home += "r"
				}
				switch rnd.IntN(5) {
				case 0:
					_, _ = fs.ReadDir(ctx, "dr1", "/")
				case 1:
					_, _ = fs.ReadDir(ctx, "dr1", home)
				case 2:
					_, _ = fs.Lookup(ctx, "dr1", "/", strings.TrimPrefix(home, "/"))
				case 3:
					_, _ = fs.Lookup(ctx, "dr1", home, fmt.Sprintf("f%d", rnd.IntN(2)))
				case 4:
					_, _ = fs.Lookup(ctx, "dr1", home, fmt.Sprintf("d%d", rnd.IntN(steps)))
				}
				time.Sleep(time.Duration(rnd.IntN(300)) * time.Microsecond)
			}
		})
	}

	for w := range workers {
		mutators.Go(func() {
			rnd := seededRand(seed, w+1)
			home, homeID := fmt.Sprintf("w%d", w), homes[w]
			children := slices.Clone(seeded[w])
			failed := false
			present := func(step int, op, parent, name, id string) {
				if n, err := fs.Lookup(ctx, "dr1", parent, name); err != nil || n.ID != id {
					t.Errorf("worker %d step %d, after %s: Lookup(%s, %s) = (%+v, %v), want node %s",
						w, step, op, parent, name, n, err, id)
					failed = true
				}
			}
			absent := func(step int, op, parent, name string) {
				if n, err := fs.Lookup(ctx, "dr1", parent, name); !errors.Is(err, ErrNotExist) {
					t.Errorf("worker %d step %d, after %s: Lookup(%s, %s) = (%+v, %v), want ErrNotExist",
						w, step, op, parent, name, n, err)
					failed = true
				}
			}
			for step := 0; step < steps && !failed; step++ {
				op := rnd.IntN(4)
				if len(children) == 0 {
					op = 0
				}
				switch op {
				case 0: // create
					name := fmt.Sprintf("d%d", step)
					n, err := fs.Mkdir(ctx, "dr1", "/"+home+"/"+name)
					if err != nil {
						t.Errorf("worker %d step %d: Mkdir: %v", w, step, err)

						return
					}
					children = append(children, child{name, n.ID})
					present(step, "mkdir", "/"+home, name, n.ID)
				case 1: // remove
					i := rnd.IntN(len(children))
					c := children[i]
					if err := fs.Remove(ctx, "dr1", "/"+home+"/"+c.name, rnd.IntN(2) == 0); err != nil {
						t.Errorf("worker %d step %d: Remove: %v", w, step, err)

						return
					}
					children = slices.Delete(children, i, i+1)
					absent(step, "remove", "/"+home, c.name)
				case 2: // rename a child
					i := rnd.IntN(len(children))
					c := children[i]
					renamed := fmt.Sprintf("m%d", step)
					if err := fs.Rename(ctx, "dr1", "/"+home+"/"+c.name, "/"+home+"/"+renamed, false); err != nil {
						t.Errorf("worker %d step %d: Rename: %v", w, step, err)

						return
					}
					children[i].name = renamed
					absent(step, "rename", "/"+home, c.name)
					present(step, "rename", "/"+home, renamed, c.id)
				case 3: // rename the folder itself
					moved := fmt.Sprintf("w%dr", w)
					if home == moved {
						moved = fmt.Sprintf("w%d", w)
					}
					if err := fs.Rename(ctx, "dr1", "/"+home, "/"+moved, false); err != nil {
						t.Errorf("worker %d step %d: Rename of the folder: %v", w, step, err)

						return
					}
					c := children[rnd.IntN(len(children))]
					absent(step, "folder rename", "/", home)
					absent(step, "folder rename", "/"+home, c.name)
					present(step, "folder rename", "/", moved, homeID)
					present(step, "folder rename", "/"+moved, c.name, c.id)
					home = moved
				}
			}
		})
	}
	mutators.Wait()
	close(stop)
	readers.Wait()
}
