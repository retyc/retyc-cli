package vfs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// tripStore is a memstore that counts the reads of a name and the writes of
// a fetched listing: each is one round trip of a store over the network.
// refuseRenew makes RenewListingIf answer as a store whose listing is gone.
type tripStore struct {
	metastore.MetaStore

	mu          sync.Mutex
	calls       map[string]int
	refuseRenew bool
}

func newTripStore() *tripStore {
	return &tripStore{MetaStore: memstore.New(), calls: map[string]int{}}
}

func (s *tripStore) count(what string) {
	s.mu.Lock()
	s.calls[what]++
	s.mu.Unlock()
}

// take returns the calls counted since the last take.
func (s *tripStore) take() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.calls
	s.calls = map[string]int{}

	return out
}

func (s *tripStore) GetNode(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, error) {
	s.count("GetNode")

	return s.MetaStore.GetNode(ctx, key, name)
}

func (s *tripStore) GetEntry(ctx context.Context, key metastore.EntryKey) (*metastore.Entry, bool, error) {
	s.count("GetEntry")

	return s.MetaStore.GetEntry(ctx, key)
}

func (s *tripStore) GetNamed(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, *metastore.Entry, bool, error) {
	s.count("GetNamed")

	return s.MetaStore.GetNamed(ctx, key, name)
}

func (s *tripStore) PutListingIf(
	ctx context.Context, key metastore.ListingKey, l *metastore.Listing, gen uint64,
) (bool, error) {
	s.count("PutListingIf")

	return s.MetaStore.PutListingIf(ctx, key, l, gen)
}

func (s *tripStore) RenewListingIf(
	ctx context.Context, key metastore.ListingKey, etag string, fetchedAt time.Time, gen uint64,
) (bool, error) {
	s.count("RenewListingIf")
	s.mu.Lock()
	refuse := s.refuseRenew
	s.mu.Unlock()
	if refuse {
		return false, nil
	}

	return s.MetaStore.RenewListingIf(ctx, key, etag, fetchedAt, gen)
}

// Resolving a name reads its folder's listing and its Entry in one read of
// the store, where it made two: whether the API, the Entry or the listing
// ends up answering.
func TestLookup_ReadsTheStoreOncePerName(t *testing.T) {
	a := newTreeAPI(t)
	a.put("", "doc", fakeNode{id: "n1", kind: api.NodeTypeFile})
	a.put("", "dir", fakeNode{id: "d1", kind: api.NodeTypeFolder})
	a.put("d1", "sub", fakeNode{id: "d2", kind: api.NodeTypeFolder})
	a.put("d2", "leaf", fakeNode{id: "n2", kind: api.NodeTypeFile})
	store := newTripStore()
	fs := newTreeFS(t, a, Options{Store: store})
	ctx := context.Background()
	reads := func(what string, want int) {
		t.Helper()
		got := store.take()
		if got["GetNamed"] != want || got["GetNode"] != 0 || got["GetEntry"] != 0 {
			t.Errorf("%s: store reads = %v, want %d GetNamed and nothing else", what, got, want)
		}
	}
	lookup := func(parent, name, wantID string) {
		t.Helper()
		n, err := fs.Lookup(ctx, "dr1", parent, name)
		if err != nil || n.ID != wantID {
			t.Fatalf("Lookup(%s, %s) = (%+v, %v), want %s", parent, name, n, err, wantID)
		}
	}

	// Nothing cached: the API answers, by name.
	lookup("/", "doc", "n1")
	reads("a name nothing knows", 1)
	// The Entry answers.
	lookup("/", "doc", "n1")
	reads("a name an Entry holds", 1)
	if lookups, listings, _ := a.counts(); lookups != 1 || listings != 0 {
		t.Fatalf("API: %d lookups, %d listings, want 1 and 0", lookups, listings)
	}
	// One read per component of a path nothing knows.
	lookup("/dir/sub", "leaf", "n2")
	reads("a path three folders deep", 3)
	lookup("/dir/sub", "leaf", "n2")
	reads("the same path, its leaf cached", 1)
	// The listing answers, for a name it holds and for one it does not.
	if _, err := fs.ReadDir(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	store.take()
	lookup("/", "doc", "n1")
	reads("a name a listing holds", 1)
	if _, err := fs.Lookup(ctx, "dr1", "/", "absent"); err == nil {
		t.Fatal("Lookup of a name the listing does not hold succeeded")
	}
	reads("a name a fresh listing does not hold", 1)
}

// A 304 on a conditional listing renews the listing the store holds instead
// of writing the same nodes again; when the store did not renew it (the
// listing left it meanwhile), the nodes held are put as before.
func TestListNodes_A304RenewsWithoutRewriting(t *testing.T) {
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
	store := newTripStore()
	fs := New(testClient(srv), Options{Store: store})
	fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	ctx := context.Background()
	list := func() {
		t.Helper()
		nodes, err := fs.ReadDir(ctx, "dr1", "/")
		if err != nil || len(nodes) != 1 || nodes[0].Name != "doc.txt" {
			t.Fatalf("listing = %+v, %v; want doc.txt", nodes, err)
		}
	}
	renewed := func(what string) {
		t.Helper()
		l := cachedListing(fs, "dr1", "/")
		if l == nil || time.Since(l.FetchedAt) > time.Minute || l.ETag != `W/"r7"` ||
			len(l.Nodes) != 1 || l.Nodes[0].Name != "doc.txt" {
			t.Errorf("%s: listing held = %+v, want doc.txt, fresh, with its ETag", what, l)
		}
	}

	list()
	if got := store.take(); got["PutListingIf"] != 1 || got["RenewListingIf"] != 0 {
		t.Fatalf("first listing: %v, want one PutListingIf", got)
	}

	ageNodeCache(fs, "dr1", "/", time.Hour)
	list()
	if got := store.take(); got["RenewListingIf"] != 1 || got["PutListingIf"] != 0 {
		t.Errorf("a 304: %v, want one RenewListingIf and no PutListingIf", got)
	}
	renewed("after a renewal")

	ageNodeCache(fs, "dr1", "/", time.Hour)
	store.mu.Lock()
	store.refuseRenew = true
	store.mu.Unlock()
	list()
	if got := store.take(); got["RenewListingIf"] != 1 || got["PutListingIf"] != 1 {
		t.Errorf("a 304 the store did not renew: %v, want one RenewListingIf then one PutListingIf", got)
	}
	renewed("after the fallback")

	mu.Lock()
	defer mu.Unlock()
	want := []int{http.StatusOK, http.StatusNotModified, http.StatusNotModified}
	if fmt.Sprint(answers) != fmt.Sprint(want) {
		t.Errorf("API answers = %v, want %v", answers, want)
	}
}
