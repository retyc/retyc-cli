package memstore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

func key(dataroomID, path string) metastore.ListingKey {
	return metastore.ListingKey{DataroomID: dataroomID, Path: path}
}

func put(t *testing.T, s *Store, k metastore.ListingKey, names ...string) {
	t.Helper()
	nodes := make([]metastore.Node, len(names))
	for i, name := range names {
		nodes[i] = metastore.Node{ID: "id-" + name, Name: name, Type: metastore.TypeFile}
	}
	if err := s.PutListing(context.Background(), k, &metastore.Listing{Nodes: nodes, FetchedAt: time.Now()}); err != nil {
		t.Fatalf("PutListing: %v", err)
	}
}

func has(t *testing.T, s *Store, k metastore.ListingKey) bool {
	t.Helper()
	_, ok, err := s.GetListing(context.Background(), k)
	if err != nil {
		t.Fatalf("GetListing: %v", err)
	}

	return ok
}

func TestStore_PutGetDelete(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := key("dr1", "/a")

	if has(t, s, k) {
		t.Fatal("an empty store holds a listing")
	}
	fetchedAt := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	stored := &metastore.Listing{
		Nodes:     []metastore.Node{{ID: "n1", Name: "f", Type: metastore.TypeFile, Size: 3}},
		FetchedAt: fetchedAt,
		ETag:      `W/"r7"`,
	}
	if err := s.PutListing(ctx, k, stored); err != nil {
		t.Fatalf("PutListing: %v", err)
	}
	got, ok, err := s.GetListing(ctx, k)
	if err != nil || !ok {
		t.Fatalf("GetListing = (%v, %v), want the listing", ok, err)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].ID != "n1" || !got.FetchedAt.Equal(fetchedAt) || got.ETag != `W/"r7"` {
		t.Errorf("GetListing = %+v, want what was stored", got)
	}
	// Same path, another dataroom: another listing.
	if has(t, s, key("dr2", "/a")) {
		t.Error("a listing of dr1 answered for dr2")
	}

	if err := s.DeleteListing(ctx, k); err != nil {
		t.Fatalf("DeleteListing: %v", err)
	}
	if has(t, s, k) {
		t.Error("the listing survived DeleteListing")
	}
	if err := s.DeleteListing(ctx, k); err != nil {
		t.Errorf("DeleteListing of a missing listing = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

// An edit replaces the listing by an edited copy: a listing read before it is
// never written through, and what the edit leaves alone (FetchedAt) is kept,
// the ETag emptied.
func TestStore_UpsertAndRemoveWorkOnACopy(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := key("dr1", "/")
	fetchedAt := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	if err := s.PutListing(ctx, k, &metastore.Listing{
		Nodes:     []metastore.Node{{ID: "id-a", Name: "a"}, {ID: "id-c", Name: "c"}},
		FetchedAt: fetchedAt, ETag: `W/"r1"`,
	}); err != nil {
		t.Fatalf("PutListing: %v", err)
	}
	before, _, _ := s.GetListing(ctx, k)

	if _, err := s.UpsertNode(ctx, k, metastore.Node{ID: "id-a", Name: "a", Size: 42}); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if _, err := s.UpsertNode(ctx, k, metastore.Node{ID: "id-b", Name: "b"}); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if _, err := s.RemoveNode(ctx, k, "c"); err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	if len(before.Nodes) != 2 || before.Nodes[0].Size != 0 || before.Nodes[1].Name != "c" {
		t.Errorf("the listing read before the edits was modified: %+v", before.Nodes)
	}
	after, _, _ := s.GetListing(ctx, k)
	if len(after.Nodes) != 2 || after.Nodes[0].Size != 42 || after.Nodes[1].Name != "b" {
		t.Errorf("edited listing = %+v, want a (42 bytes) then b", after.Nodes)
	}
	if !after.FetchedAt.Equal(fetchedAt) || after.ETag != "" {
		t.Errorf("(FetchedAt, ETag) = (%v, %q), want the fetch time kept and no ETag", after.FetchedAt, after.ETag)
	}
}

// Without a listing an edit stores nothing, and still bumps the generation: a
// listing asked of the API before it must not be stored after it.
func TestStore_EditOfAMissingListing(t *testing.T) {
	s := New()
	ctx := context.Background()
	missing := key("dr1", "/never-listed")

	gen, err := s.UpsertNode(ctx, missing, metastore.Node{ID: "n", Name: "f"})
	if err != nil || gen != 1 {
		t.Fatalf("UpsertNode = (%d, %v), want generation 1", gen, err)
	}
	gen, err = s.RemoveNode(ctx, missing, "f")
	if err != nil || gen != 2 {
		t.Fatalf("RemoveNode = (%d, %v), want generation 2", gen, err)
	}
	if has(t, s, missing) {
		t.Error("an edit created a listing")
	}
	if n, _, held, _ := s.GetNode(ctx, missing, "f"); held || n != nil {
		t.Errorf("GetNode = (%v, held %v), want no listing", n, held)
	}
	stored, err := s.PutListingIf(ctx, missing, &metastore.Listing{FetchedAt: time.Now()}, 0)
	if err != nil || stored {
		t.Errorf("PutListingIf under the generation read before the edits = (%v, %v), want it refused", stored, err)
	}
}

// Every write to a listing changes its generation, by one; a read changes
// nothing; the generation of another listing does not move.
func TestStore_Generations(t *testing.T) {
	s := New()
	ctx := context.Background()
	k, other := key("dr1", "/a"), key("dr1", "/b")
	gen := func(k metastore.ListingKey) uint64 {
		t.Helper()
		g, err := s.Generation(ctx, k)
		if err != nil {
			t.Fatalf("Generation: %v", err)
		}

		return g
	}
	if gen(k) != 0 {
		t.Fatalf("generation of a listing never written = %d, want 0", gen(k))
	}
	writes := []struct {
		name string
		do   func() error
	}{
		{"PutListing", func() error { return s.PutListing(ctx, k, &metastore.Listing{FetchedAt: time.Now()}) }},
		{"UpsertNode", func() error {
			g, err := s.UpsertNode(ctx, k, metastore.Node{Name: "f"})
			if g != gen(k) {
				t.Errorf("UpsertNode returned generation %d, the listing has %d", g, gen(k))
			}

			return err
		}},
		{"RemoveNode", func() error {
			g, err := s.RemoveNode(ctx, k, "f")
			if g != gen(k) {
				t.Errorf("RemoveNode returned generation %d, the listing has %d", g, gen(k))
			}

			return err
		}},
		{"RemoveNode of a missing name", func() error {
			_, err := s.RemoveNode(ctx, k, "f")

			return err
		}},
		{"PutListingIf", func() error {
			stored, err := s.PutListingIf(ctx, k, &metastore.Listing{FetchedAt: time.Now()}, gen(k))
			if !stored {
				t.Error("PutListingIf under the current generation stored nothing")
			}

			return err
		}},
		{"DeleteListing", func() error { return s.DeleteListing(ctx, k) }},
		{"DeleteListing of a missing listing", func() error { return s.DeleteListing(ctx, k) }},
		{"DeleteSubtree", func() error { return s.DeleteSubtree(ctx, "dr1", "/a") }},
		{"DeleteSubtree from above", func() error { return s.DeleteSubtree(ctx, "dr1", "/") }},
	}
	for _, w := range writes {
		before := gen(k)
		if err := w.do(); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		if gen(k) != before+1 {
			t.Errorf("%s: generation %d → %d, want one bump", w.name, before, gen(k))
		}
	}
	before := gen(k)
	_, _, _ = s.GetListing(ctx, k)
	_, _, _ = s.ListingMeta(ctx, k)
	_, _, _, _ = s.GetNode(ctx, k, "f")
	if gen(k) != before {
		t.Errorf("a read moved the generation: %d → %d", before, gen(k))
	}
	if gen(other) != 0 {
		t.Errorf("generation of a listing none of the writes named = %d, want 0", gen(other))
	}
}

// PutListingIf stores under the generation it was given and no other, the
// comparison and the write being one step.
func TestStore_PutListingIf(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := key("dr1", "/")
	put(t, s, k, "old")
	gen, _ := s.Generation(ctx, k)

	// Another writer lands first: the answer asked for before it is refused.
	if _, err := s.UpsertNode(ctx, k, metastore.Node{ID: "id-new", Name: "new"}); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	stored, err := s.PutListingIf(ctx, k, &metastore.Listing{FetchedAt: time.Now()}, gen)
	if err != nil || stored {
		t.Fatalf("PutListingIf under an older generation = (%v, %v), want it refused", stored, err)
	}
	if l, _, _ := s.GetListing(ctx, k); len(l.Nodes) != 2 {
		t.Errorf("a refused PutListingIf changed the listing: %+v", l.Nodes)
	}
	gen, _ = s.Generation(ctx, k)
	stored, err = s.PutListingIf(ctx, k, &metastore.Listing{
		Nodes: []metastore.Node{{ID: "id-x", Name: "x"}}, FetchedAt: time.Now(), ETag: "e",
	}, gen)
	if err != nil || !stored {
		t.Fatalf("PutListingIf under the current generation = (%v, %v), want it stored", stored, err)
	}
	if after, _ := s.Generation(ctx, k); after != gen+1 {
		t.Errorf("generation after PutListingIf = %d, want %d", after, gen+1)
	}
	l, _, _ := s.GetListing(ctx, k)
	if len(l.Nodes) != 1 || l.Nodes[0].Name != "x" || l.ETag != "e" {
		t.Errorf("listing = %+v, want what PutListingIf stored", l)
	}
}

// ListingMeta and GetNode answer what GetListing would, without the nodes.
func TestStore_ListingMetaAndGetNode(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := key("dr1", "/")
	fetchedAt := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	if _, ok, _ := s.ListingMeta(ctx, k); ok {
		t.Fatal("ListingMeta of an empty store found a listing")
	}
	_ = s.PutListing(ctx, k, &metastore.Listing{
		Nodes: []metastore.Node{{ID: "id-a", Name: "a", Size: 3}}, FetchedAt: fetchedAt, ETag: "e",
	})
	want := metastore.ListingMeta{FetchedAt: fetchedAt, ETag: "e"}
	if meta, ok, err := s.ListingMeta(ctx, k); err != nil || !ok || meta != want {
		t.Errorf("ListingMeta = (%+v, %v, %v), want %+v", meta, ok, err, want)
	}
	n, meta, held, err := s.GetNode(ctx, k, "a")
	if err != nil || !held || n == nil || n.ID != "id-a" || n.Size != 3 || meta != want {
		t.Errorf("GetNode(a) = (%+v, %+v, %v, %v), want the node and the meta", n, meta, held, err)
	}
	n.Size = 99 // a copy: the store is not written through
	if again, _, _, _ := s.GetNode(ctx, k, "a"); again.Size != 3 {
		t.Error("the node GetNode returned is shared with the store")
	}
	if n, meta, held, _ := s.GetNode(ctx, k, "missing"); n != nil || !held || meta != want {
		t.Errorf("GetNode(missing) = (%+v, %+v, held %v), want no node of a held listing", n, meta, held)
	}
}

// UpsertNode is atomic: concurrent edits of one listing are all applied, none
// lost to a read-modify-write race. Readers run alongside, for the race
// detector.
func TestStore_UpsertNodeIsAtomic(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := key("dr1", "/")
	put(t, s, k)

	const writers, edits = 8, 200
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if l, ok, _ := s.GetListing(ctx, k); ok {
					for _, n := range l.Nodes {
						_ = n.Name
					}
				}
			}
		}()
	}
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range edits {
				_, _ = s.UpsertNode(ctx, k, metastore.Node{Name: fmt.Sprintf("w%d-%d", w, i)})
			}
		}()
	}
	wg.Wait()
	close(stop)
	readers.Wait()

	l, _, _ := s.GetListing(ctx, k)
	if len(l.Nodes) != writers*edits {
		t.Fatalf("%d nodes after %d concurrent appends: edits were lost", len(l.Nodes), writers*edits)
	}
	if gen, _ := s.Generation(ctx, k); gen != writers*edits+1 {
		t.Errorf("generation = %d, want one bump per write (%d)", gen, writers*edits+1)
	}
	seen := make(map[string]bool, len(l.Nodes))
	for _, n := range l.Nodes {
		if seen[n.Name] {
			t.Fatalf("node %s stored twice", n.Name)
		}
		seen[n.Name] = true
	}
}

// DeleteSubtree removes the folder's listing and those below it, and nothing
// else: a sibling whose name merely starts the same ("/ab" next to "/a"), the
// parent, and the same paths in another dataroom all stay.
func TestStore_DeleteSubtree(t *testing.T) {
	s := New()
	ctx := context.Background()
	kept := []metastore.ListingKey{
		key("dr1", "/"), key("dr1", "/ab"), key("dr1", "/ab/c"), key("dr1", "/b/a"), key("dr1", "/a.txt"),
		key("dr2", "/a"), key("dr2", "/a/b"),
	}
	gone := []metastore.ListingKey{key("dr1", "/a"), key("dr1", "/a/b"), key("dr1", "/a/b/c"), key("dr1", "/a/ab")}
	for _, k := range append(append([]metastore.ListingKey{}, kept...), gone...) {
		put(t, s, k, "x")
	}

	if err := s.DeleteSubtree(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("DeleteSubtree: %v", err)
	}
	for _, k := range gone {
		if has(t, s, k) {
			t.Errorf("%+v survived DeleteSubtree(dr1, /a)", k)
		}
	}
	for _, k := range kept {
		if !has(t, s, k) {
			t.Errorf("%+v was removed by DeleteSubtree(dr1, /a)", k)
		}
	}
}

// The root covers the whole dataroom, and that dataroom only.
func TestStore_DeleteSubtreeOfTheRoot(t *testing.T) {
	s := New()
	for _, k := range []metastore.ListingKey{key("dr1", "/"), key("dr1", "/a"), key("dr1", "/a/b"), key("dr2", "/")} {
		put(t, s, k, "x")
	}

	if err := s.DeleteSubtree(context.Background(), "dr1", "/"); err != nil {
		t.Fatalf("DeleteSubtree: %v", err)
	}
	for _, k := range []metastore.ListingKey{key("dr1", "/"), key("dr1", "/a"), key("dr1", "/a/b")} {
		if has(t, s, k) {
			t.Errorf("%+v survived DeleteSubtree(dr1, /)", k)
		}
	}
	if !has(t, s, key("dr2", "/")) {
		t.Error("DeleteSubtree(dr1, /) removed a listing of dr2")
	}
}

// GetListing hands out a copy of the listing's header: a caller writing its
// FetchedAt or ETag does not change what the store holds. The nodes are the
// stored slice, not a copy.
func TestStore_GetListingCopiesTheHeader(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := key("dr1", "/")
	put(t, s, k, "a")
	first, _, _ := s.GetListing(ctx, k)
	fetchedAt := first.FetchedAt

	first.FetchedAt = fetchedAt.Add(-time.Hour)
	first.ETag = "tampered"
	first.Nodes = nil

	second, ok, _ := s.GetListing(ctx, k)
	if !ok || !second.FetchedAt.Equal(fetchedAt) || second.ETag == "tampered" || len(second.Nodes) != 1 {
		t.Errorf("stored listing after the caller wrote its copy = %+v, want it untouched", second)
	}
	third, _, _ := s.GetListing(ctx, k)
	if second == third {
		t.Error("two reads returned the same header")
	}
	if &second.Nodes[0] != &third.Nodes[0] {
		t.Error("the nodes were copied: they are meant to be shared")
	}
}
