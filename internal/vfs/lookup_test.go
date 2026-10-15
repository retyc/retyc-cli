package vfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// — A fake API that holds a tree ————————————————————————————————————————————————

// fakeNode is a node of treeAPI.
type fakeNode struct {
	id     string
	kind   string // api.NodeTypeFolder, api.NodeTypeFile or api.NodeTypeSymlink
	target string // of a symlink
	mode   string // access_mode, "" for none
}

// treeAPI is a fake API holding the tree of dataroom "dr1": it answers the
// lookup by name hash and the listing from it, and counts each kind of
// request. Mutations are accepted without changing the tree: a test that
// needs the API to show one edits the tree itself (put, drop).
type treeAPI struct {
	t         *testing.T
	pub, salt string
	// legacy makes it the API that predates the MIME table (404 on the probe);
	// probeStatus, when set, is what the probe answers instead.
	legacy      bool
	probeStatus int

	mu       sync.Mutex
	children map[string]map[string]fakeNode // parent ID ("" for the root) → name → node
	gone     map[string]bool                // folder IDs answered 404
	lookups  int
	listings int
	probes   int
	other    []string // every other request, as "METHOD path"
	// failOnce answers the status to the next request of that "METHOD path".
	failOnce map[string]int
	// hold, when set, is taken by the next lookup, which closes waiting and
	// answers once hold is closed.
	hold    chan struct{}
	waiting chan struct{}
	// holdList and listWaiting are the same for the next listing.
	holdList    chan struct{}
	listWaiting chan struct{}
	// failListings answers 500 to every listing.
	failListings bool
	// claimTotal is the total a listing of that parent ID reports instead of
	// the number of its items (the size of a folder, without its nodes).
	claimTotal map[string]int
}

func newTreeAPI(t *testing.T) *treeAPI {
	return &treeAPI{t: t, children: make(map[string]map[string]fakeNode), gone: make(map[string]bool)}
}

// put adds or replaces the child name of parent.
func (a *treeAPI) put(parent, name string, n fakeNode) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.children[parent] == nil {
		a.children[parent] = make(map[string]fakeNode)
	}
	a.children[parent][name] = n
}

// drop removes the child name of parent.
func (a *treeAPI) drop(parent, name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.children[parent], name)
}

// counts returns the number of lookups by name, listings and probes received.
func (a *treeAPI) counts() (lookups, listings, probes int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.lookups, a.listings, a.probes
}

// holdNextLookup makes the next lookup wait; it returns the channel closed
// when that lookup has arrived, and the function that lets it answer.
func (a *treeAPI) holdNextLookup() (arrived <-chan struct{}, release func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hold, waiting := make(chan struct{}), make(chan struct{})
	a.hold, a.waiting = hold, waiting

	return waiting, func() { close(hold) }
}

// holdNextListing is holdNextLookup for the next listing.
func (a *treeAPI) holdNextListing() (arrived <-chan struct{}, release func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hold, waiting := make(chan struct{}), make(chan struct{})
	a.holdList, a.listWaiting = hold, waiting

	return waiting, func() { close(hold) }
}

func (a *treeAPI) hash(name string) string {
	h := sha256.Sum256([]byte(a.salt + name))

	return hex.EncodeToString(h[:])
}

// item renders the node name of parent as the API lists it.
func (a *treeAPI) item(parent, name string, n fakeNode) map[string]any {
	nameEnc, err := crypto.EncryptStringForKeys(name, []string{a.pub})
	if err != nil {
		a.t.Errorf("EncryptStringForKeys: %v", err)
	}
	node := map[string]any{
		"id": n.id, "type": n.kind, "name_enc": nameEnc, "name_hash": a.hash(name),
		"type_enc": nil, "parent_id": nil, "created_at": "2026-10-01T10:00:00Z",
	}
	if parent != "" {
		node["parent_id"] = parent
	}
	if n.mode != "" {
		node["access_mode"] = n.mode
	}
	var version any
	switch n.kind {
	case api.NodeTypeSymlink:
		targetEnc, err := crypto.EncryptStringForKeys(n.target, []string{a.pub})
		if err != nil {
			a.t.Errorf("EncryptStringForKeys: %v", err)
		}
		node["target_enc"] = targetEnc
	case api.NodeTypeFile:
		version = map[string]any{
			"id": "v-" + n.id, "node_id": n.id, "original_size": 5, "chunk_count": 1,
			"created_at": "2026-10-02T10:00:00Z",
		}
	}

	return map[string]any{"node": node, "node_version": version}
}

func (a *treeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/mime-types":
		a.mu.Lock()
		a.probes++
		legacy, probeStatus := a.legacy, a.probeStatus
		a.mu.Unlock()
		switch {
		case probeStatus != 0:
			http.Error(w, "probe", probeStatus)
		case legacy:
			http.Error(w, "Not Found", http.StatusNotFound)
		default:
			fmt.Fprint(w, `[]`)
		}
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
		a.nodes(w, r)
	default:
		call := r.Method + " " + r.URL.Path
		a.mu.Lock()
		a.other = append(a.other, call)
		fail := a.failOnce[call]
		delete(a.failOnce, call)
		a.mu.Unlock()
		if fail != 0 {
			http.Error(w, "failed", fail)

			return
		}
		a.mutation(w, r)
	}
}

// nodes answers a lookup by name hash or a listing.
func (a *treeAPI) nodes(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get("parent_id")
	hash := r.URL.Query().Get("name_hash")
	a.mu.Lock()
	var hold, waiting chan struct{}
	if hash != "" {
		a.lookups++
		hold, waiting = a.hold, a.waiting
		a.hold, a.waiting = nil, nil
	} else {
		a.listings++
		hold, waiting = a.holdList, a.listWaiting
		a.holdList, a.listWaiting = nil, nil
	}
	fail := hash == "" && a.failListings
	total := 0
	if hash == "" {
		total = a.claimTotal[parent]
	}
	a.mu.Unlock()
	if fail {
		http.Error(w, "listing failed", http.StatusInternalServerError)

		return
	}
	if hold != nil {
		// The answer is the tree as it stands when the request arrived: what a
		// mutation landing meanwhile must not be hidden by.
		a.mu.Lock()
		items, gone := a.itemsLocked(parent, hash)
		a.mu.Unlock()
		close(waiting)
		<-hold
		a.reply(w, items, gone, total)

		return
	}
	a.mu.Lock()
	items, gone := a.itemsLocked(parent, hash)
	a.mu.Unlock()
	a.reply(w, items, gone, total)
}

func (a *treeAPI) itemsLocked(parent, hash string) (items []any, gone bool) {
	if a.gone[parent] {
		return nil, true
	}
	items = []any{}
	names := make([]string, 0, len(a.children[parent]))
	for name := range a.children[parent] {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if hash == "" || a.hash(name) == hash {
			items = append(items, a.item(parent, name, a.children[parent][name]))
		}
	}

	return items, false
}

// reply answers items as the only page of a listing of total nodes, 0 for as
// many as there are items.
func (a *treeAPI) reply(w http.ResponseWriter, items []any, gone bool, total int) {
	if gone {
		http.Error(w, "Node not found", http.StatusNotFound)

		return
	}
	if total == 0 {
		total = len(items)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "total": total, "pages": 1, "page": 1})
}

// mutation accepts any mutation of the tree.
func (a *treeAPI) mutation(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
		fmt.Fprint(w, `{"id":"d-created","name_enc":"x"}`)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/copy"):
		copyReply(w)
	case r.Method == http.MethodDelete, r.Method == http.MethodPut, r.Method == http.MethodPatch:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
}

// deepTree fills a with /a/b/c/d (folders), a file /a/b/c/d/f.txt and a file
// /a/x.txt.
func deepTree(a *treeAPI) *treeAPI {
	a.put("", "a", fakeNode{id: "d-a", kind: api.NodeTypeFolder})
	a.put("d-a", "b", fakeNode{id: "d-b", kind: api.NodeTypeFolder})
	a.put("d-b", "c", fakeNode{id: "d-c", kind: api.NodeTypeFolder})
	a.put("d-c", "d", fakeNode{id: "d-d", kind: api.NodeTypeFolder})
	a.put("d-d", "f.txt", fakeNode{id: "f-f", kind: api.NodeTypeFile})
	a.put("d-a", "x.txt", fakeNode{id: "f-x", kind: api.NodeTypeFile, mode: "0640"})

	return a
}

// newTreeFS returns an FS on a, with an unlocked session for "dr1" and
// nothing cached.
func newTreeFS(t *testing.T, a *treeAPI, opts Options) *FS {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	a.pub = identity.Recipient().String()
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	fs := New(testClient(srv), opts)
	fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: a.pub, NameSalt: a.salt})

	return fs
}

// cachedEntry returns the Entry stored for name in the folder at parentPath,
// whatever its age.
func cachedEntry(fs *FS, parentPath, name string) (*Entry, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	e, ok, _ := fs.store.GetEntry(context.Background(), entryKey("dr1", parentPath, name))

	return e, ok
}

// mustLookup looks name up and fails the test unless it finds the node id.
func mustLookup(t *testing.T, fs *FS, parentPath, name, id string) Node {
	t.Helper()
	n, err := fs.Lookup(context.Background(), "dr1", parentPath, name)
	if err != nil || n.ID != id {
		t.Fatalf("Lookup(%s, %s) = (%+v, %v), want node %s", parentPath, name, n, err, id)
	}

	return n
}

// mustMiss looks name up and fails the test unless it does not exist.
func mustMiss(t *testing.T, fs *FS, parentPath, name string) {
	t.Helper()
	if n, err := fs.Lookup(context.Background(), "dr1", parentPath, name); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Lookup(%s, %s) = (%+v, %v), want ErrNotExist", parentPath, name, n, err)
	}
}

// — Resolution ——————————————————————————————————————————————————————————————————

// A path four folders deep that nothing cached costs four lookups by name and
// no listing; listing the folder found then costs its own listing only.
func TestLookup_ColdDeepPathIsOneLookupPerComponent(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute})
	ctx := context.Background()

	n := mustLookup(t, fs, "/a/b/c", "d", "d-d")
	if n.Type != TypeDir || n.Name != "d" || n.ParentID != "d-c" || n.CreatedAt.IsZero() {
		t.Errorf("node = %+v, want the folder d under d-c with its creation time", n)
	}
	if lookups, listings, probes := a.counts(); lookups != 4 || listings != 0 || probes != 1 {
		t.Errorf("cold: %d lookups, %d listings, %d probes; want 4, 0, 1", lookups, listings, probes)
	}

	// Every component is now an Entry: the same path costs nothing.
	mustLookup(t, fs, "/a/b/c", "d", "d-d")
	if id, err := fs.resolveFolderID(ctx, "dr1", "/a/b/c/d"); err != nil || id == nil || *id != "d-d" {
		t.Errorf("resolveFolderID = (%v, %v), want d-d", id, err)
	}
	if lookups, listings, _ := a.counts(); lookups != 4 || listings != 0 {
		t.Errorf("warm: %d lookups, %d listings; want 4, 0", lookups, listings)
	}

	nodes, err := fs.ReadDir(ctx, "dr1", "/a/b/c/d")
	if err != nil || !slices.Equal(names(nodes), []string{"f.txt"}) {
		t.Fatalf("ReadDir = (%+v, %v), want f.txt", nodes, err)
	}
	if lookups, listings, _ := a.counts(); lookups != 4 || listings != 1 {
		t.Errorf("after ReadDir: %d lookups, %d listings; want 4, 1", lookups, listings)
	}
	// A file found by name carries what a listing would say of it.
	f := mustLookup(t, fs, "/a", "x.txt", "f-x")
	if f.Type != TypeFile || f.VersionID != "v-f-x" || f.Size != 5 || f.ChunkCount != 1 ||
		f.Mode != 0640 || f.ParentID != "d-a" || f.ModTime.IsZero() || f.CreatedAt.Equal(f.ModTime) {
		t.Errorf("file = %+v, want its version, mode, parent and both times", f)
	}
}

// A listing and the stat of each of its entries: one listing, no lookup. The
// caller that has the listing in hand needs no FS at all (FindNode).
func TestLookup_ListedFolderAnswersWithoutTheAPI(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.put("", "top.txt", fakeNode{id: "f-top", kind: api.NodeTypeFile})
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute})

	nodes, err := fs.ReadDir(context.Background(), "dr1", "/")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		mustLookup(t, fs, "/", n.Name, n.ID)
		if got, ok := FindNode(nodes, n.Name); !ok || got != n {
			t.Errorf("FindNode(%s) = (%+v, %v), want the listed node", n.Name, got, ok)
		}
	}
	mustMiss(t, fs, "/", "nothing")
	if _, ok := FindNode(nodes, "nothing"); ok {
		t.Error("FindNode found a name the listing does not hold")
	}
	if lookups, listings, _ := a.counts(); lookups != 0 || listings != 1 {
		t.Errorf("%d lookups, %d listings; want 0, 1", lookups, listings)
	}
	if _, ok := cachedEntry(fs, "/", "nothing"); ok {
		t.Error("a name missing from a fresh listing was stored as an Entry")
	}
}

// A node found by name is trusted for the TTL of the listings, then asked
// again.
func TestLookup_PositiveEntryExpiresWithTheTTL(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: 40 * time.Millisecond})

	for range 3 {
		mustLookup(t, fs, "/", "a", "d-a")
	}
	if lookups, _, _ := a.counts(); lookups != 1 {
		t.Fatalf("%d lookups within the TTL, want 1", lookups)
	}
	time.Sleep(60 * time.Millisecond)
	mustLookup(t, fs, "/", "a", "d-a")
	if lookups, _, _ := a.counts(); lookups != 2 {
		t.Errorf("%d lookups past the TTL, want 2", lookups)
	}
}

// A name found missing is answered missing for NegativeTTL without a request,
// then asked again: a name created elsewhere shows up once it is over.
func TestLookup_NegativeEntry(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{NegativeTTL: 40 * time.Millisecond})

	for range 5 {
		mustMiss(t, fs, "/", ".git")
	}
	if lookups, listings, _ := a.counts(); lookups != 1 || listings != 0 {
		t.Fatalf("%d lookups, %d listings for a repeated probe; want 1, 0", lookups, listings)
	}
	if e, ok := cachedEntry(fs, "/", ".git"); !ok || e.Node != nil || e.FetchedAt.IsZero() {
		t.Errorf("entry = (%+v, %v), want a negative one", e, ok)
	}

	a.put("", ".git", fakeNode{id: "d-git", kind: api.NodeTypeFolder}) // created by another client
	mustMiss(t, fs, "/", ".git")
	time.Sleep(60 * time.Millisecond)
	mustLookup(t, fs, "/", ".git", "d-git")
	if lookups, _, _ := a.counts(); lookups != 2 {
		t.Errorf("%d lookups, want 2", lookups)
	}
}

// A zero NegativeTTL keeps no negative entry: every probe of a missing name
// asks the API. Nodes found are still kept.
func TestLookup_ZeroNegativeTTLCachesNoMiss(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{})

	for range 3 {
		mustMiss(t, fs, "/", "nothing")
	}
	if _, ok := cachedEntry(fs, "/", "nothing"); ok {
		t.Error("a negative entry was stored with NegativeTTL 0")
	}
	for range 3 {
		mustLookup(t, fs, "/", "a", "d-a")
	}
	if lookups, _, _ := a.counts(); lookups != 4 {
		t.Errorf("%d lookups, want 3 misses and 1 hit", lookups)
	}
}

// On an API without the lookup by name, a name is found by listing its
// folder, as before: one listing per level, kept, and no lookup.
func TestLookup_LegacyAPIListsTheParent(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.legacy = true
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute})

	mustLookup(t, fs, "/a/b/c", "d", "d-d")
	mustMiss(t, fs, "/a/b/c", "nothing")
	if lookups, listings, probes := a.counts(); lookups != 0 || listings != 4 || probes != 1 {
		t.Errorf("%d lookups, %d listings, %d probes; want 0, 4, 1", lookups, listings, probes)
	}
	if _, ok := cachedEntry(fs, "/a/b/c", "nothing"); ok {
		t.Error("an Entry was stored on an API without the lookup by name")
	}
	if !nodeCacheHas(fs, "dr1", "/a/b/c") {
		t.Error("the listing of the parent was not cached")
	}
}

// A probe that fails says nothing of the API: the name is found by listing,
// which both APIs answer, and the probe is made again on the next lookup.
func TestLookup_FailedProbeListsTheParent(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.probeStatus = http.StatusInternalServerError
	fs := newTreeFS(t, a, Options{})

	mustLookup(t, fs, "/", "a", "d-a")
	if lookups, listings, probes := a.counts(); lookups != 0 || listings != 1 || probes == 0 {
		t.Errorf("%d lookups, %d listings, %d probes; want 0, 1 and a probe", lookups, listings, probes)
	}
	a.mu.Lock()
	a.probeStatus = 0
	a.mu.Unlock()
	mustLookup(t, fs, "/a", "x.txt", "f-x")
	if lookups, listings, _ := a.counts(); lookups != 1 || listings != 1 {
		t.Errorf("once the probe answers: %d lookups, %d listings; want 1, 1", lookups, listings)
	}
}

// A dataroom without name salt hashes its names unsalted, as the service does
// everywhere else: the lookup finds them.
func TestLookup_DataroomWithoutNameSalt(t *testing.T) {
	for _, salt := range []string{"", "s4lt"} {
		a := newTreeAPI(t)
		a.salt = salt
		deepTree(a)
		fs := newTreeFS(t, a, Options{})
		mustLookup(t, fs, "/a", "b", "d-b")
		// In another folder: a second name of /a would start its listing.
		mustMiss(t, fs, "/a/b", "nothing")
		if lookups, listings, _ := a.counts(); lookups != 3 || listings != 0 {
			t.Errorf("salt %q: %d lookups, %d listings; want 3, 0", salt, lookups, listings)
		}
	}
}

// With HideSymlinks a symbolic link found by name does not exist, as in a
// listing; without, it is returned with its target. A symlink is no folder
// either way.
func TestLookup_SymlinkFoundByName(t *testing.T) {
	for _, hide := range []bool{true, false} {
		a := deepTree(newTreeAPI(t))
		a.put("", "link", fakeNode{id: "l-1", kind: api.NodeTypeSymlink, target: "a/x.txt"})
		fs := newTreeFS(t, a, Options{HideSymlinks: hide})
		ctx := context.Background()

		for range 2 {
			n, err := fs.Lookup(ctx, "dr1", "/", "link")
			if hide {
				if !errors.Is(err, ErrNotExist) {
					t.Errorf("hidden: Lookup = (%+v, %v), want ErrNotExist", n, err)
				}

				continue
			}
			if err != nil || n.Type != TypeSymlink || n.Target != "a/x.txt" || n.Size != 7 {
				t.Errorf("shown: Lookup = (%+v, %v), want the link and its target", n, err)
			}
		}
		_, err := fs.resolveFolderID(ctx, "dr1", "/link")
		if want := map[bool]error{true: os.ErrNotExist, false: os.ErrInvalid}[hide]; !errors.Is(err, want) {
			t.Errorf("hide=%v: resolveFolderID of a symlink = %v, want %v", hide, err, want)
		}
		if lookups, _, _ := a.counts(); lookups != 1 {
			t.Errorf("hide=%v: %d lookups, want 1 (the link is an Entry either way)", hide, lookups)
		}
		// A name looked up below a symlink or a file does not exist.
		if _, err := fs.Lookup(ctx, "dr1", "/link", "child"); !errors.Is(err, ErrNotExist) {
			t.Errorf("hide=%v: Lookup below a symlink = %v, want ErrNotExist", hide, err)
		}
		if _, err := fs.Lookup(ctx, "dr1", "/a/x.txt", "child"); !errors.Is(err, ErrNotExist) {
			t.Errorf("hide=%v: Lookup below a file = %v, want ErrNotExist", hide, err)
		}
		if _, err := fs.Lookup(ctx, "dr1", "/nowhere/deeper", "child"); !errors.Is(err, ErrNotExist) {
			t.Errorf("hide=%v: Lookup below a missing folder = %v, want ErrNotExist", hide, err)
		}
	}
}

// An Entry can name a folder deleted and re-created elsewhere: the API
// answers 404 to a lookup under the old ID, and the lookup is made once more
// with the folder resolved afresh.
func TestLookup_StaleParentEntryIsResolvedAgain(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute})
	mustLookup(t, fs, "/", "a", "d-a")

	// Another client replaces /a by a new folder holding y.txt.
	a.mu.Lock()
	a.gone["d-a"] = true
	a.mu.Unlock()
	a.put("", "a", fakeNode{id: "d-a2", kind: api.NodeTypeFolder})
	a.put("d-a2", "y.txt", fakeNode{id: "f-y", kind: api.NodeTypeFile})

	if n := mustLookup(t, fs, "/a", "y.txt", "f-y"); n.ParentID != "d-a2" {
		t.Errorf("node = %+v, want it under the new folder", n)
	}
	mustLookup(t, fs, "/", "a", "d-a2")

	// A folder that is simply gone is a path that does not exist.
	a.mu.Lock()
	a.gone["d-a2"] = true
	a.mu.Unlock()
	a.drop("", "a")
	mustMiss(t, fs, "/a", "z.txt")
}

// An error of the API crosses the lookup as it is, and is not cached.
func TestLookup_APIErrorIsReturnedAndNotCached(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.String() == "GET /dataroom/dr1/mime-types" {
			mimeTable(w, false)

			return true
		}
		http.Error(w, "viewer", http.StatusForbidden)

		return true
	}}
	fs := newAPIFS(t, fake, Options{NegativeTTL: time.Minute}, nil)
	for range 2 {
		_, err := fs.Lookup(context.Background(), "dr1", "/", "a")
		var httpErr *api.HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != http.StatusForbidden || !carriesNoSentinel(err) {
			t.Errorf("Lookup = %v, want the API's 403 as it is", err)
		}
	}
	if got := len(fake.only("GET /dataroom/dr1/nodes")); got != 2 {
		t.Errorf("%d lookups, want 2: a failure is not an answer to keep", got)
	}
}

// Concurrent lookups of one name share one request.
func TestLookup_ConcurrentLookupsShareOneRequest(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{})
	arrived, release := a.holdNextLookup()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			n, err := fs.Lookup(context.Background(), "dr1", "/", "a")
			if err == nil && n.ID != "d-a" {
				err = fmt.Errorf("node %+v", n)
			}
			errs <- err
		})
	}
	<-arrived
	// Give the others the time to join the lookup in flight.
	time.Sleep(20 * time.Millisecond)
	release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Lookup = %v", err)
		}
	}
	if lookups, _, _ := a.counts(); lookups != 1 {
		t.Errorf("%d lookups, want 1 shared by all", lookups)
	}
}

// A caller that gives up does not fail the lookup the others share.
func TestLookup_CancelledCallerLeavesTheLookupRunning(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{})
	arrived, release := a.holdNextLookup()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := fs.Lookup(ctx, "dr1", "/", "a")
		done <- err
	}()
	<-arrived
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Lookup of the caller that left = %v, want context.Canceled", err)
	}
	release()
	mustLookup(t, fs, "/", "a", "d-a")
	if lookups, _, _ := a.counts(); lookups != 1 {
		t.Errorf("%d lookups, want the one that was running", lookups)
	}
}

// — The entries of a folder are dropped by what changes it ——————————————————————

// A listing put in the cache drops the entries of its folder: it says all
// they say, and is the one consulted.
func TestEntries_DroppedWhenTheListingIsCached(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute})
	mustMiss(t, fs, "/a", "new.txt")
	// The second entry is put there, not looked up: a second name looked up
	// in the folder would start its listing (see noteNameLookup), and the
	// listing meant here is the one asked for below.
	fs.mu.Lock()
	err := fs.store.PutEntry(context.Background(), entryKey("dr1", "/a", "x.txt"),
		&Entry{Node: &Node{ID: "f-x", Name: "x.txt", Type: TypeFile}, FetchedAt: time.Now()})
	fs.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	a.put("d-a", "new.txt", fakeNode{id: "f-new", kind: api.NodeTypeFile})
	if _, err := fs.ReadDir(context.Background(), "dr1", "/a"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"new.txt", "x.txt"} {
		if e, ok := cachedEntry(fs, "/a", name); ok {
			t.Errorf("entry of %s = %+v, want it dropped by the listing", name, e)
		}
	}
	mustLookup(t, fs, "/a", "new.txt", "f-new")
	// The entry that names the folder itself belongs to its parent.
	if _, ok := cachedEntry(fs, "/", "a"); !ok {
		t.Error("the entry of the folder itself was dropped with those of its children")
	}
}

// Every mutation made through the FS drops the entries of the folders it
// changes: a name just created is never answered missing from a negative
// entry, a node just removed or renamed away never answered from a positive
// one. NegativeTTL and TTL are a minute: only the drop can make these pass.
func TestEntries_DroppedByEveryLocalMutation(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		// before warms the entries the mutation must drop.
		before func(t *testing.T, fs *FS)
		// mutate changes the tree through the FS; apply is what the API then
		// holds.
		mutate func(fs *FS) error
		apply  func(a *treeAPI)
		after  func(t *testing.T, fs *FS)
	}{
		"Mkdir": {
			before: func(t *testing.T, fs *FS) { mustMiss(t, fs, "/a", "new") },
			mutate: func(fs *FS) error {
				_, err := fs.Mkdir(ctx, "dr1", "/a/new")

				return err
			},
			apply: func(a *treeAPI) { a.put("d-a", "new", fakeNode{id: "d-created", kind: api.NodeTypeFolder}) },
			after: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a", "new", "d-created") },
		},
		"Remove": {
			before: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a", "x.txt", "f-x") },
			mutate: func(fs *FS) error { return fs.Remove(ctx, "dr1", "/a/x.txt", true) },
			apply:  func(a *treeAPI) { a.drop("d-a", "x.txt") },
			after:  func(t *testing.T, fs *FS) { mustMiss(t, fs, "/a", "x.txt") },
		},
		"Remove of a folder, entries below": {
			before: func(t *testing.T, fs *FS) {
				mustLookup(t, fs, "/a/b", "c", "d-c")
				mustLookup(t, fs, "/a/b/c", "d", "d-d")
			},
			mutate: func(fs *FS) error { return fs.Remove(ctx, "dr1", "/a/b", true) },
			apply: func(a *treeAPI) {
				// The folder is re-created by another client, empty.
				a.put("d-a", "b", fakeNode{id: "d-b2", kind: api.NodeTypeFolder})
			},
			after: func(t *testing.T, fs *FS) {
				mustLookup(t, fs, "/a", "b", "d-b2")
				mustMiss(t, fs, "/a/b", "c")
			},
		},
		"Rename, source side": {
			before: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a", "x.txt", "f-x") },
			mutate: func(fs *FS) error { return fs.Rename(ctx, "dr1", "/a/x.txt", "/a/b/y.txt", false) },
			apply: func(a *treeAPI) {
				a.drop("d-a", "x.txt")
				a.put("d-b", "y.txt", fakeNode{id: "f-x", kind: api.NodeTypeFile})
			},
			after: func(t *testing.T, fs *FS) { mustMiss(t, fs, "/a", "x.txt") },
		},
		"Rename, destination side": {
			before: func(t *testing.T, fs *FS) { mustMiss(t, fs, "/a/b", "y.txt") },
			mutate: func(fs *FS) error { return fs.Rename(ctx, "dr1", "/a/x.txt", "/a/b/y.txt", false) },
			apply: func(a *treeAPI) {
				a.drop("d-a", "x.txt")
				a.put("d-b", "y.txt", fakeNode{id: "f-x", kind: api.NodeTypeFile})
			},
			after: func(t *testing.T, fs *FS) {
				if n := mustLookup(t, fs, "/a/b", "y.txt", "f-x"); n.ParentID != "d-b" {
					t.Errorf("renamed node = %+v, want it under d-b", n)
				}
			},
		},
		"Rename of a folder, entries below": {
			before: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a/b", "c", "d-c") },
			mutate: func(fs *FS) error { return fs.Rename(ctx, "dr1", "/a/b", "/a/moved", false) },
			apply: func(a *treeAPI) {
				a.drop("d-a", "b")
				a.put("d-a", "moved", fakeNode{id: "d-b", kind: api.NodeTypeFolder})
				a.put("d-a", "b", fakeNode{id: "d-b2", kind: api.NodeTypeFolder}) // re-created elsewhere
			},
			after: func(t *testing.T, fs *FS) {
				mustMiss(t, fs, "/a/b", "c")
				mustLookup(t, fs, "/a/moved", "c", "d-c")
			},
		},
		"Copy": {
			before: func(t *testing.T, fs *FS) { mustMiss(t, fs, "/a/b", "copy.txt") },
			mutate: func(fs *FS) error {
				_, _, err := fs.Copy(ctx, "dr1", "/a/x.txt", "/a/b/copy.txt", false)

				return err
			},
			apply: func(a *treeAPI) { a.put("d-b", "copy.txt", fakeNode{id: "f-copy", kind: api.NodeTypeFile}) },
			after: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a/b", "copy.txt", "f-copy") },
		},
		"upsert (an upload a front end ran)": {
			before: func(t *testing.T, fs *FS) { mustMiss(t, fs, "/a", "up.bin") },
			mutate: func(fs *FS) error {
				fs.upsert("dr1", "/a", Node{ID: "f-up", ParentID: "d-a", Name: "up.bin", Type: TypeFile})

				return nil
			},
			apply: func(a *treeAPI) { a.put("d-a", "up.bin", fakeNode{id: "f-up", kind: api.NodeTypeFile}) },
			after: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a", "up.bin", "f-up") },
		},
		"Chmod": {
			before: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a", "x.txt", "f-x") },
			mutate: func(fs *FS) error { return fs.Chmod(ctx, "dr1", "/a/x.txt", 0600) },
			apply:  func(a *treeAPI) { a.put("d-a", "x.txt", fakeNode{id: "f-x", kind: api.NodeTypeFile, mode: "0600"}) },
			after: func(t *testing.T, fs *FS) {
				if n := mustLookup(t, fs, "/a", "x.txt", "f-x"); n.Mode != 0600 {
					t.Errorf("mode = %v, want the one just stored", n.Mode)
				}
			},
		},
		"SetModTime": {
			before: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a", "x.txt", "f-x") },
			mutate: func(fs *FS) error {
				return fs.SetModTime(ctx, "dr1", "/a/x.txt", time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC))
			},
			apply: func(*treeAPI) {},
			after: func(t *testing.T, fs *FS) {
				// The folder is not listed: the entry that carried the old
				// time is replaced by the node as it now is.
				set := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
				if e, ok := cachedEntry(fs, "/a", "x.txt"); !ok || e.Node == nil || !e.Node.ModTime.Equal(set) {
					t.Errorf("entry = %+v, want one carrying the new time", e)
				}
			},
		},
		"InvalidateListing": {
			before: func(t *testing.T, fs *FS) { mustMiss(t, fs, "/a", "elsewhere") },
			mutate: func(fs *FS) error {
				fs.InvalidateListing("dr1", "/a")

				return nil
			},
			apply: func(a *treeAPI) { a.put("d-a", "elsewhere", fakeNode{id: "f-e", kind: api.NodeTypeFile}) },
			after: func(t *testing.T, fs *FS) { mustLookup(t, fs, "/a", "elsewhere", "f-e") },
		},
		"invalidateSubtree, the folder and below": {
			before: func(t *testing.T, fs *FS) {
				mustMiss(t, fs, "/a", "elsewhere")
				mustMiss(t, fs, "/a/b/c", "deep")
			},
			mutate: func(fs *FS) error {
				fs.invalidateSubtree("dr1", "/a")

				return nil
			},
			apply: func(a *treeAPI) {
				a.put("d-a", "elsewhere", fakeNode{id: "f-e", kind: api.NodeTypeFile})
				a.put("d-c", "deep", fakeNode{id: "f-deep", kind: api.NodeTypeFile})
			},
			after: func(t *testing.T, fs *FS) {
				mustLookup(t, fs, "/a", "elsewhere", "f-e")
				mustLookup(t, fs, "/a/b/c", "deep", "f-deep")
			},
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			a := deepTree(newTreeAPI(t))
			fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
			tc.before(t, fs)
			if err := tc.mutate(fs); err != nil {
				t.Fatalf("mutation: %v", err)
			}
			tc.apply(a)
			tc.after(t, fs)
		})
	}
}

// A sibling folder keeps its entries: "/a" covers "/a/b", never "/ab".
func TestEntries_SubtreeDropStopsAtTheFolder(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.put("", "ab", fakeNode{id: "d-ab", kind: api.NodeTypeFolder})
	// Three lookups by name under the root would start its listing (see
	// noteNameLookup), which drops the entries the test looks at when it
	// arrives.
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute, NoListingAhead: true})
	mustMiss(t, fs, "/ab", "n")
	mustMiss(t, fs, "/a", "n")

	fs.invalidateSubtree("dr1", "/a")
	if _, ok := cachedEntry(fs, "/ab", "n"); !ok {
		t.Error("the entries of /ab went with the subtree of /a")
	}
	if _, ok := cachedEntry(fs, "/a", "n"); ok {
		t.Error("the entries of /a survived the invalidation of its subtree")
	}
	if _, ok := cachedEntry(fs, "/", "a"); !ok {
		t.Error("the entry naming /a, which belongs to the root, was dropped")
	}
}

// — A lookup and a mutation that cross ——————————————————————————————————————————

// A lookup the API answered "missing" before a creation made through the FS
// must not leave a negative entry behind, and a lookup started after the
// creation must not share its answer.
func TestLookup_AnswerOlderThanAMutationIsNotKept(t *testing.T) {
	mutations := map[string]func(fs *FS) error{
		"Mkdir": func(fs *FS) error {
			_, err := fs.Mkdir(context.Background(), "dr1", "/a/new")

			return err
		},
		"upsert": func(fs *FS) error {
			fs.upsert("dr1", "/a", Node{ID: "d-created", Name: "new", Type: TypeDir})

			return nil
		},
		"invalidateSubtree above": func(fs *FS) error {
			fs.invalidateSubtree("dr1", "/")

			return nil
		},
	}
	for label, mutate := range mutations {
		t.Run(label, func(t *testing.T) {
			a := deepTree(newTreeAPI(t))
			fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
			mustLookup(t, fs, "/", "a", "d-a") // the parent is resolved: the next lookup is the one held
			arrived, release := a.holdNextLookup()

			first := make(chan error, 1)
			go func() {
				_, err := fs.Lookup(context.Background(), "dr1", "/a", "new")
				first <- err
			}()
			<-arrived // the API has answered "missing", the answer is on its way

			if err := mutate(fs); err != nil {
				t.Fatalf("mutation: %v", err)
			}
			a.put("d-a", "new", fakeNode{id: "d-created", kind: api.NodeTypeFolder})

			// Started after the mutation, while the old lookup is still in
			// flight: it must ask again, not share the stale answer (which
			// it would wait for until the test releases it: hence the bound).
			bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			n, err := fs.Lookup(bounded, "dr1", "/a", "new")
			cancel()
			if err != nil || n.ID != "d-created" {
				release()
				t.Fatalf("Lookup after the mutation = (%+v, %v), want the node just created", n, err)
			}

			release()
			if err := <-first; !errors.Is(err, ErrNotExist) {
				t.Errorf("the lookup that started first = %v, want its own answer, ErrNotExist", err)
			}
			// And its answer was not kept over the fresh one.
			mustLookup(t, fs, "/a", "new", "d-created")
			if e, ok := cachedEntry(fs, "/a", "new"); !ok || e.Node == nil {
				t.Errorf("entry = (%+v, %v), want the node found after the mutation", e, ok)
			}
		})
	}
}

// Lookups, listings and mutations of one folder from many goroutines: nothing
// races (go test -race), and once they are over the tree is read as the API
// holds it, whatever interleaving happened.
func TestLookup_ConcurrentWithMutations(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 8 {
		name := fmt.Sprintf("n%d", i)
		wg.Go(func() {
			for range 20 {
				_, _ = fs.Lookup(ctx, "dr1", "/a", name)
				_, _ = fs.Lookup(ctx, "dr1", "/a/b/c", "d")
			}
		})
		wg.Go(func() {
			for j := range 20 {
				switch j % 4 {
				case 0:
					fs.upsert("dr1", "/a", Node{ID: "f-" + name, Name: name, Type: TypeFile})
				case 1:
					fs.invalidateSubtree("dr1", "/a/b")
				case 2:
					_, _ = fs.ReadDir(ctx, "dr1", "/a")
				case 3:
					fs.InvalidateListing("dr1", "/a")
				}
			}
		})
	}
	wg.Wait()

	// The API now holds every name: whatever the cache kept must agree.
	for i := range 8 {
		name := fmt.Sprintf("n%d", i)
		a.put("d-a", name, fakeNode{id: "f-" + name, kind: api.NodeTypeFile})
		fs.upsert("dr1", "/a", Node{ID: "f-" + name, Name: name, Type: TypeFile})
	}
	for i := range 8 {
		name := fmt.Sprintf("n%d", i)
		mustLookup(t, fs, "/a", name, "f-"+name)
	}
	mustLookup(t, fs, "/a/b/c", "d", "d-d")
}

// — Mutations resolve by name too ———————————————————————————————————————————————

// A node the Entry names and the API no longer has: the mutation answers 404,
// the entries of the folder are dropped with its listing, and the retry finds
// the node that took the name by asking the API for that name alone.
func TestRemove_RetriesByNameWhenTheEntryIsStale(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute})
	mustLookup(t, fs, "/a", "x.txt", "f-x")

	// Replaced elsewhere: f-x is gone, f-x2 holds the name.
	a.put("d-a", "x.txt", fakeNode{id: "f-x2", kind: api.NodeTypeFile})
	a.mu.Lock()
	a.failOnce = map[string]int{"DELETE /dataroom/node/f-x": http.StatusNotFound}
	a.mu.Unlock()
	before, _, _ := a.counts()

	if err := fs.Remove(context.Background(), "dr1", "/a/x.txt", true); err != nil {
		t.Fatalf("Remove = %v, want the node that took the name deleted", err)
	}
	a.mu.Lock()
	other := slices.Clone(a.other)
	a.mu.Unlock()
	if want := []string{"DELETE /dataroom/node/f-x", "DELETE /dataroom/node/f-x2"}; !slices.Equal(other, want) {
		t.Errorf("mutations = %v, want %v", other, want)
	}
	if lookups, listings, _ := a.counts(); lookups-before != 1 || listings != 0 {
		t.Errorf("%d lookups and %d listings for the retry, want 1 and 0", lookups-before, listings)
	}
}

// — Tracing —————————————————————————————————————————————————————————————————————

// A lookup by name leaves no name on a span: the events carry the name of the
// cache, the depth of the path and UUIDs.
func TestLookup_SpansCarryNoName(t *testing.T) {
	exp := telemetrytest.Install(t)
	a := newTreeAPI(t)
	a.put("", sentinel+"-dir", fakeNode{id: "019d7cba-c700-73c2-8eac-f3dc311d1b25", kind: api.NodeTypeFolder})
	a.put("019d7cba-c700-73c2-8eac-f3dc311d1b25", sentinel+".txt", fakeNode{id: "f-1", kind: api.NodeTypeFile})
	fs := newTreeFS(t, a, Options{NegativeTTL: time.Minute})

	ctx, span := telemetry.Tracer().Start(context.Background(), "request")
	mustLookup(t, fs, "/"+sentinel+"-dir", sentinel+".txt", "f-1")
	mustLookup(t, fs, "/"+sentinel+"-dir", sentinel+".txt", "f-1")
	if _, err := fs.Lookup(ctx, "dr1", "/"+sentinel+"-dir", sentinel+"-missing"); !errors.Is(err, ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := fs.Lookup(ctx, "dr1", "/"+sentinel+"-dir", sentinel+"-missing"); !errors.Is(err, ErrNotExist) {
		t.Fatal(err)
	}
	span.End()

	spans := exp.GetSpans()
	telemetrytest.AssertNoLeak(t, spans, sentinel)
	var events []string
	for _, s := range spans {
		if s.Name != "request" {
			continue
		}
		for _, ev := range s.Events {
			label := ev.Name
			for _, kv := range ev.Attributes {
				if kv.Key == "retyc.cache.name" || kv.Key == "retyc.cache.hit" {
					label += " " + kv.Value.String()
				}
			}
			events = append(events, label)
		}
	}
	// The first lookup of the missing name goes to the API, the second is
	// answered by its negative entry.
	if !slices.Contains(events, "cache.lookup entries false") || !slices.Contains(events, "cache.lookup entries true") ||
		!slices.Contains(events, "dataroom.resolve_path") {
		t.Errorf("events = %v, want an entries miss, an entries hit and a resolve_path", events)
	}
}

// LookupRemote asks the API whatever the cache says: a name created by
// another client is found under a negative entry and under a fresh listing
// that lacks it, at one lookup each, and that listing is dropped.
func TestLookupRemote_IgnoresWhatTheCacheSaysIsMissing(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
	ctx := context.Background()

	mustMiss(t, fs, "/", "new.txt")
	a.put("", "new.txt", fakeNode{id: "f-new", kind: api.NodeTypeFile})
	mustMiss(t, fs, "/", "new.txt") // the negative entry
	node, authoritative, err := fs.LookupRemote(ctx, "dr1", "/", "new.txt")
	if err != nil || !authoritative || node.ID != "f-new" {
		t.Fatalf("LookupRemote = (%+v, %v, %v), want f-new from the API", node, authoritative, err)
	}
	if lookups, listings, _ := a.counts(); lookups != 2 || listings != 0 {
		t.Errorf("%d lookups, %d listings; want 2, 0", lookups, listings)
	}
	mustLookup(t, fs, "/", "new.txt", "f-new") // the entry it kept

	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	a.put("", "later.txt", fakeNode{id: "f-later", kind: api.NodeTypeFile})
	mustMiss(t, fs, "/", "later.txt") // the fresh listing
	if node, _, err := fs.LookupRemote(ctx, "dr1", "/", "later.txt"); err != nil || node.ID != "f-later" {
		t.Fatalf("LookupRemote under a fresh listing = (%+v, %v)", node, err)
	}
	if nodeCacheHas(fs, "dr1", "/") {
		t.Error("the listing that lacked the name is still cached")
	}

	// A name the API does not hold either: missing, and still one request.
	_, before, _ := a.counts()
	_, authoritative, err = fs.LookupRemote(ctx, "dr1", "/", "nothing")
	if !authoritative || !errors.Is(err, ErrNotExist) {
		t.Errorf("LookupRemote of a missing name = (%v, %v)", authoritative, err)
	}
	if _, after, _ := a.counts(); after != before {
		t.Errorf("%d listings for a lookup", after-before)
	}
}

// On an API without the lookup by name, LookupRemote is Lookup and says so.
func TestLookupRemote_LegacyAPIIsNotAuthoritative(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	_, authoritative, err := fs.LookupRemote(context.Background(), "dr1", "/", "x")
	if authoritative || !errors.Is(err, ErrNotExist) {
		t.Errorf("LookupRemote = (%v, %v), want the answer of the cache", authoritative, err)
	}
}

// — Expired listing ————————————————————————————————————————————————————————————

// ageListing makes the cached listing of the folder at path of "dr1" look
// fetched age ago.
func ageListing(t *testing.T, fs *FS, path string, age time.Duration) {
	t.Helper()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	l, ok, err := fs.store.GetListing(context.Background(), key("dr1", path))
	if err != nil || !ok {
		t.Fatalf("no cached listing of %s to age (%v)", path, err)
	}
	aged := *l
	aged.FetchedAt = time.Now().Add(-age)
	if err := fs.store.PutListing(context.Background(), key("dr1", path), &aged); err != nil {
		t.Fatal(err)
	}
}

// sweepTree fills a with a folder /dir of files f0…f(n-1).
func sweepTree(a *treeAPI, n int) *treeAPI {
	a.put("", "dir", fakeNode{id: "d-dir", kind: api.NodeTypeFolder})
	for i := range n {
		a.put("d-dir", fmt.Sprintf("f%d", i), fakeNode{id: fmt.Sprintf("f-%d", i), kind: api.NodeTypeFile})
	}

	return a
}

// A folder that was listed and whose listing is no longer served (no MaxStale:
// a FUSE mount) is listed again by the first lookup of one of its names: a
// sweep of its files costs one listing, not one lookup by name each.
func TestLookup_ExpiredListingIsRefreshedForASweep(t *testing.T) {
	const files = 20
	a := sweepTree(newTreeAPI(t), files)
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})

	if _, err := fs.ReadDir(context.Background(), "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	lookups0, listings0, _ := a.counts()
	// Created and deleted elsewhere since the listing.
	a.put("d-dir", "new", fakeNode{id: "f-new", kind: api.NodeTypeFile})
	a.drop("d-dir", "f0")
	ageListing(t, fs, "/dir", 2*time.Minute)

	mustMiss(t, fs, "/dir", "f0")
	for i := 1; i < files; i++ {
		mustLookup(t, fs, "/dir", fmt.Sprintf("f%d", i), fmt.Sprintf("f-%d", i))
	}
	mustLookup(t, fs, "/dir", "new", "f-new")
	mustMiss(t, fs, "/dir", "nothing")
	lookups, listings, _ := a.counts()
	if lookups != lookups0 || listings != listings0+1 {
		t.Errorf("sweep of an expired listing: %d lookups by name, %d listings; want 0, 1",
			lookups-lookups0, listings-listings0)
	}

	// Still inside the window at its far end.
	ageListing(t, fs, "/dir", time.Minute+listingRefreshWindow(time.Minute)-10*time.Second)
	mustLookup(t, fs, "/dir", "f1", "f-1")
	if lookups, listings, _ := a.counts(); lookups != lookups0 || listings != listings0+2 {
		t.Errorf("end of the window: %d lookups by name, %d listings; want 0, 2",
			lookups-lookups0, listings-listings0)
	}
}

// Past the window the listing is forgotten: the stat of one name does not pay
// the listing of its folder, it is looked up by name.
func TestLookup_ListingExpiredPastTheWindowIsLookedUpByName(t *testing.T) {
	a := sweepTree(newTreeAPI(t), 3)
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})

	if _, err := fs.ReadDir(context.Background(), "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	lookups0, listings0, _ := a.counts()
	ageListing(t, fs, "/dir", time.Minute+listingRefreshWindow(time.Minute)+10*time.Second)

	mustLookup(t, fs, "/dir", "f1", "f-1")
	mustLookup(t, fs, "/dir", "f1", "f-1") // its Entry
	lookups, listings, _ := a.counts()
	if lookups != lookups0+1 || listings != listings0 {
		t.Errorf("past the window: %d lookups by name, %d listings; want 1, 0",
			lookups-lookups0, listings-listings0)
	}
}

// A fresh Entry answers before the expired listing is refreshed: it is what
// an upload under a folder whose listing is no longer served leaves.
func TestLookup_FreshEntryAnswersBeforeTheRefresh(t *testing.T) {
	a := sweepTree(newTreeAPI(t), 3)
	// A store that keeps every listing: the test takes the listing past the
	// window, then back inside it, which the store of an FS (see newMemStore)
	// would not let it do.
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute, Store: memstore.New()})

	if _, err := fs.ReadDir(context.Background(), "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	ageListing(t, fs, "/dir", time.Minute+listingRefreshWindow(time.Minute)+10*time.Second)
	mustLookup(t, fs, "/dir", "f1", "f-1") // by name: leaves an Entry
	lookups0, listings0, _ := a.counts()
	ageListing(t, fs, "/dir", 2*time.Minute) // back inside the window

	mustLookup(t, fs, "/dir", "f1", "f-1")
	if lookups, listings, _ := a.counts(); lookups != lookups0 || listings != listings0 {
		t.Errorf("fresh Entry: %d lookups by name, %d listings; want 0, 0",
			lookups-lookups0, listings-listings0)
	}
}
