package vfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// heldList is an Options.List whose answer waits: entered receives once per
// call that reached it, and the call returns nodes once release is closed.
type heldList struct {
	entered chan struct{}
	release chan struct{}
	nodes   []service.DataroomNodeInfo
}

func newHeldList(names ...string) *heldList {
	l := &heldList{entered: make(chan struct{}, 8), release: make(chan struct{})}
	for _, name := range names {
		l.nodes = append(l.nodes, service.DataroomNodeInfo{ID: "api-" + name, Name: name, Type: "file"})
	}

	return l
}

func (l *heldList) list(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
	l.entered <- struct{}{}
	<-l.release

	return l.nodes, nil
}

func nodeNames(nodes []Node) []string {
	names := make([]string, len(nodes))
	for i, n := range nodes {
		names[i] = n.Name
	}

	return names
}

// A listing asked of the API before another instance wrote to the folder in
// the shared store is answered to whoever waits for it, and not stored: this
// FS knows nothing of that write, the generation of the store does.
func TestFetch_NotStoredWhenTheStoreMovedElsewhere(t *testing.T) {
	writes := map[string]func(t *testing.T, store *memstore.Store, other *FS){
		"an edit by another FS": func(_ *testing.T, _ *memstore.Store, other *FS) {
			other.upsert("dr1", "/", Node{ID: "n-new", Name: "new", Type: TypeFile})
		},
		"a removal by another FS": func(_ *testing.T, _ *memstore.Store, other *FS) {
			other.forget("dr1", "/", "f")
		},
		"an invalidation by another FS": func(_ *testing.T, _ *memstore.Store, other *FS) {
			other.InvalidateListing("dr1", "/")
		},
		"a listing put by another instance": func(t *testing.T, store *memstore.Store, _ *FS) {
			err := store.PutListing(context.Background(), key("dr1", "/"),
				&Listing{Nodes: []Node{{ID: "n-theirs", Name: "theirs"}}, FetchedAt: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
		},
	}
	for label, write := range writes {
		t.Run(label, func(t *testing.T) {
			store := memstore.New()
			held := newHeldList("f")
			fs := New(nil, Options{Store: store, List: held.list})
			other := New(nil, Options{Store: store, List: newHeldList().list})

			got := make(chan []Node, 1)
			go func() {
				nodes, err := fs.ReadDir(context.Background(), "dr1", "/")
				if err != nil {
					t.Errorf("ReadDir: %v", err)
				}
				got <- nodes
			}()
			<-held.entered // the generation is read, the API is answering
			write(t, store, other)
			before, _, _ := store.GetListing(context.Background(), key("dr1", "/"))
			close(held.release)

			if nodes := <-got; len(nodes) != 1 || nodes[0].Name != "f" {
				t.Errorf("ReadDir = %v, want the answer of the API to whoever waited for it", nodeNames(nodes))
			}
			after, _, _ := store.GetListing(context.Background(), key("dr1", "/"))
			switch {
			case before == nil && after != nil:
				t.Errorf("the answer was stored over a write it may predate: %v", nodeNames(after.Nodes))
			case before != nil && (after == nil || len(after.Nodes) != 1 || after.Nodes[0].Name != "theirs"):
				t.Errorf("the listing of the other instance was replaced: %+v", after)
			}

			// The next request asks again, and that answer is stored.
			if before == nil {
				held.release = make(chan struct{})
				close(held.release)
				if _, err := fs.ReadDir(context.Background(), "dr1", "/"); err != nil {
					t.Fatal(err)
				}
				if !nodeCacheHas(fs, "dr1", "/") {
					t.Error("a listing asked for after the write was not stored")
				}
			}
		})
	}
}

// replayingFetch starts the fetch of the listing of "/" that replays the
// edits made meanwhile, and returns once the API is answering it.
func replayingFetch(t *testing.T, fs *FS, held *heldList) *listingFetch {
	t.Helper()
	fs.mu.Lock()
	f := fs.startFetchLocked(context.Background(), key("dr1", "/"), false, true)
	fs.unlock()
	<-held.entered

	return f
}

// Edits made through this FS while a listing that replays them is on its way
// are the only writes the store saw: the answer is stored, with them replayed.
func TestFetch_ReplayedEditsStillStoreTheListing(t *testing.T) {
	store := memstore.New()
	held := newHeldList("f", "h")
	fs := New(nil, Options{Store: store, List: held.list})
	f := replayingFetch(t, fs, held)

	fs.upsert("dr1", "/", Node{ID: "n-g", Name: "g", Type: TypeFile})
	fs.forget("dr1", "/", "f")
	fs.upsert("dr1", "/", Node{ID: "n-h", Name: "h", Type: TypeFile, Size: 7})
	fs.HideNode("dr1", "/", Node{ID: "n-absent", Name: "absent"}) // an edit that writes nothing to the store
	close(held.release)
	if _, err := f.wait(context.Background()); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	l := cachedListing(fs, "dr1", "/")
	if l == nil {
		t.Fatal("the listing was not stored although only this FS edited the folder")
	}
	byName := make(map[string]Node, len(l.Nodes))
	for _, n := range l.Nodes {
		byName[n.Name] = n
	}
	_, hasF := byName["f"]
	if hasF || len(byName) != 2 || byName["g"].ID != "n-g" || byName["h"].ID != "n-h" || byName["h"].Size != 7 {
		t.Errorf("listing = %+v, want h as written here and g, without f", l.Nodes)
	}
	if l.ETag != "" {
		t.Errorf("ETag = %q, want none on a listing edits were replayed on", l.ETag)
	}
}

// A write by another instance among the edits replayed is one the answer may
// predate: the listing is not stored, edits or not.
func TestFetch_ReplayedEditsDoNotHideAForeignWrite(t *testing.T) {
	for _, foreignFirst := range []bool{true, false} {
		store := memstore.New()
		held := newHeldList("f")
		fs := New(nil, Options{Store: store, List: held.list})
		other := New(nil, Options{Store: store, List: newHeldList().list})
		f := replayingFetch(t, fs, held)

		if foreignFirst {
			other.forget("dr1", "/", "f")
		}
		fs.upsert("dr1", "/", Node{ID: "n-g", Name: "g", Type: TypeFile})
		if !foreignFirst {
			other.forget("dr1", "/", "f")
		}
		fs.upsert("dr1", "/", Node{ID: "n-i", Name: "i", Type: TypeFile})
		close(held.release)
		nodes, err := f.wait(context.Background())
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if len(nodes) != 3 {
			t.Errorf("foreign first %v: the fetch answered %v, want the API's answer with the edits made here",
				foreignFirst, nodeNames(nodes))
		}
		if nodeCacheHas(fs, "dr1", "/") {
			t.Errorf("foreign first %v: the listing was stored over the write of another instance", foreignFirst)
		}
	}
}

// boundStore is a memstore that asks for the codec, as a store that seals
// what it holds does.
type boundStore struct {
	*memstore.Store
	codec metastore.Codec
	binds int
}

func (s *boundStore) Bind(c metastore.Codec) { s.codec, s.binds = c, s.binds+1 }

// The codec hashes with the dataroom's session, and never resolves one: a
// dataroom whose session is not held has no hash and opens nothing.
func TestCodec_NeedsTheSessionAndNeverResolvesIt(t *testing.T) {
	store := &boundStore{Store: memstore.New()}
	resolved := 0
	fs := New(nil, Options{Store: store, Session: func(context.Context, string) (*service.DataroomSession, error) {
		resolved++

		return nil, context.Canceled
	}})
	if store.binds != 1 || store.codec == nil {
		t.Fatalf("Bind called %d time(s), want once by New", store.binds)
	}
	if hash, ok := store.codec.Hash("dr1", "name"); ok || hash != "" {
		t.Errorf("Hash without a session = (%q, %v), want ok false", hash, ok)
	}
	if err := store.codec.Open(context.Background(), "dr1", &Node{Sealed: metastore.Sealed{Name: "x"}}); err == nil {
		t.Error("Open without a session succeeded")
	}
	if resolved != 0 {
		t.Errorf("the codec resolved the session %d time(s): it must never wait", resolved)
	}

	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	sess := &service.DataroomSession{Identity: identity, PublicKey: pub, NameSalt: "salt"}
	fs.SeedSession("dr1", sess.AssumeLegacyAPI())

	// Called as a store does, with mu held: the codec takes no lock of the FS.
	fs.mu.Lock()
	hash, ok := store.codec.Hash("dr1", "name")
	fs.unlock()
	sum := sha256.Sum256([]byte("salt" + "name"))
	if !ok || hash != hex.EncodeToString(sum[:]) {
		t.Errorf("Hash = (%q, %v), want SHA-256(salt + name), the name hash of a node", hash, ok)
	}
	if _, ok := store.codec.Hash("dr2", "name"); ok {
		t.Error("Hash answered for a dataroom whose session is not held")
	}

	seal := func(v string) string {
		enc, err := crypto.EncryptStringForKeys(v, []string{pub})
		if err != nil {
			t.Fatal(err)
		}

		return enc
	}
	n := Node{ID: "n1", Type: TypeSymlink, Sealed: metastore.Sealed{Name: seal("link"), Target: seal("../t")}}
	if err := store.codec.Open(context.Background(), "dr1", &n); err != nil || n.Name != "link" || n.Target != "../t" {
		t.Errorf("Open = %v, node %q -> %q, want link -> ../t", err, n.Name, n.Target)
	}
	n = Node{ID: "n2", Type: TypeFile, Sealed: metastore.Sealed{Name: seal("f.txt"), MIMEType: seal("text/plain")}}
	err = store.codec.Open(context.Background(), "dr1", &n)
	if err != nil || n.Name != "f.txt" || n.MIMEType != "text/plain" {
		t.Errorf("Open = %v, node %q (%q), want f.txt (text/plain)", err, n.Name, n.MIMEType)
	}
	if err := store.codec.Open(context.Background(), "dr1", &Node{}); err == nil {
		t.Error("Open of a node without a sealed name succeeded")
	}
}

// Options.KeepSealed makes the nodes built from an answer of the API carry
// what the API sent, which the codec opens back; without it they carry none.
func TestKeepSealed(t *testing.T) {
	for _, keep := range []bool{false, true} {
		a := deepTree(newTreeAPI(t))
		a.put("", "top.txt", fakeNode{id: "f-top", kind: api.NodeTypeFile})
		store := &boundStore{Store: memstore.New()}
		fs := newTreeFS(t, a, Options{Store: store, KeepSealed: keep, NoListingAhead: true})
		ctx := context.Background()

		byName, err := fs.Lookup(ctx, "dr1", "/", "top.txt")
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		fs.InvalidateListing("dr1", "/")
		nodes, err := fs.ReadDir(ctx, "dr1", "/")
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		listed, _ := FindNode(nodes, "top.txt")
		for label, n := range map[string]Node{"lookup by name": byName, "listing": listed} {
			if !keep {
				if n.Sealed != (metastore.Sealed{}) {
					t.Errorf("%s: a node carries its sealed form without KeepSealed", label)
				}

				continue
			}
			if n.Sealed.Name == "" {
				t.Fatalf("%s: no sealed name with KeepSealed", label)
			}
			opened := Node{ID: n.ID, Sealed: n.Sealed}
			if err := store.codec.Open(ctx, "dr1", &opened); err != nil || opened.Name != "top.txt" {
				t.Errorf("%s: Open of the sealed node = (%q, %v), want top.txt", label, opened.Name, err)
			}
		}

		// A rename leaves the node without the name it was sealed under.
		fs.move("dr1", "/", "top.txt", "/", "renamed.txt", "")
		if n, err := fs.Lookup(ctx, "dr1", "/", "renamed.txt"); err != nil || n.Sealed != (metastore.Sealed{}) {
			t.Errorf("after a rename: (%+v, %v), want the node without a sealed form", n.Sealed, err)
		}
	}
}

func TestListingRetention(t *testing.T) {
	want := 6*time.Minute + listingRefreshWindow(time.Minute)
	if got := ListingRetention(time.Minute, 5*time.Minute); got != want {
		t.Errorf("ListingRetention(1m, 5m) = %v, want %v", got, want)
	}
	if got, want := ListingRetention(0, 0), DefaultCacheTTL+listingRefreshWindow(DefaultCacheTTL); got != want {
		t.Errorf("ListingRetention(0, 0) = %v, want that of the default TTL, %v", got, want)
	}
}
