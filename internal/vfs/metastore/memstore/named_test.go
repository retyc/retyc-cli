package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// GetNamed answers what GetNode and GetEntry answer, each half on its own:
// listing held or not, with or without the name, entry positive, negative or
// absent.
func TestStore_GetNamed(t *testing.T) {
	ctx := context.Background()
	fetchedAt := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	node := metastore.Node{ID: "id-a", Name: "a", Size: 3}
	for _, listing := range []string{"none", "without the name", "with the name"} {
		for _, entry := range []string{"none", "negative", "positive"} {
			t.Run(listing+"/"+entry, func(t *testing.T) {
				s := New()
				k := key("dr1", "/d")
				switch listing {
				case "without the name":
					_ = s.PutListing(ctx, k, &metastore.Listing{
						Nodes: []metastore.Node{{ID: "id-b", Name: "b"}}, FetchedAt: fetchedAt, ETag: "e",
					})
				case "with the name":
					_ = s.PutListing(ctx, k, &metastore.Listing{
						Nodes: []metastore.Node{{ID: "id-b", Name: "b"}, node}, FetchedAt: fetchedAt, ETag: "e",
					})
				}
				switch entry {
				case "negative":
					_ = s.PutEntry(ctx, entryKey("dr1", "/d", "a"), &metastore.Entry{FetchedAt: fetchedAt})
				case "positive":
					_ = s.PutEntry(ctx, entryKey("dr1", "/d", "a"), &metastore.Entry{Node: &node, FetchedAt: fetchedAt})
				}
				// Neither another name nor another folder answers.
				_ = s.PutEntry(ctx, entryKey("dr1", "/d", "other"), &metastore.Entry{FetchedAt: fetchedAt})
				_ = s.PutEntry(ctx, entryKey("dr1", "/", "a"), &metastore.Entry{FetchedAt: fetchedAt})

				n, meta, held, e, hasEntry, err := s.GetNamed(ctx, k, "a")
				if err != nil {
					t.Fatal(err)
				}
				wantN, wantMeta, wantHeld, _ := s.GetNode(ctx, k, "a")
				wantE, wantHas, _ := s.GetEntry(ctx, entryKey("dr1", "/d", "a"))
				if held != wantHeld || meta != wantMeta || (n == nil) != (wantN == nil) || (n != nil && *n != *wantN) {
					t.Errorf("node half = (%+v, %+v, %v), GetNode says (%+v, %+v, %v)", n, meta, held, wantN, wantMeta, wantHeld)
				}
				if hasEntry != wantHas || e != wantE {
					t.Errorf("entry half = (%+v, %v), GetEntry says (%+v, %v)", e, hasEntry, wantE, wantHas)
				}
				if held != (listing != "none") || (n != nil) != (listing == "with the name") {
					t.Errorf("held = %v, node %+v for a listing %s", held, n, listing)
				}
				if hasEntry != (entry != "none") || (hasEntry && (e.Node != nil) != (entry == "positive")) {
					t.Errorf("entry = (%+v, %v) for an entry %s", e, hasEntry, entry)
				}
				if n != nil {
					n.Size = 99 // a copy: the store is not written through
					if again, _, _, _, _, _ := s.GetNamed(ctx, k, "a"); again.Size != 3 {
						t.Error("the node GetNamed returned is shared with the store")
					}
				}
			})
		}
	}
}

// RenewListingIf gives a held listing a new fetch time and ETag under the
// expected generation, and bumps it; it does nothing otherwise.
func TestStore_RenewListingIf(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := key("dr1", "/")
	old := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	now := old.Add(time.Hour)

	if renewed, err := s.RenewListingIf(ctx, k, "e2", now, 0); renewed || err != nil {
		t.Fatalf("renewing a listing that is not held = (%v, %v)", renewed, err)
	}
	if g, _ := s.Generation(ctx, k); g != 0 || has(t, s, k) {
		t.Fatalf("a refused renewal wrote something: gen %d", g)
	}
	_ = s.PutListing(ctx, k, &metastore.Listing{
		Nodes: []metastore.Node{{ID: "id-a", Name: "a"}}, FetchedAt: old, ETag: "e1",
	})
	before, _, _ := s.GetListing(ctx, k)

	if renewed, _ := s.RenewListingIf(ctx, k, "e2", now, 0); renewed {
		t.Fatal("renewed under a generation that moved")
	}
	if meta, _, _ := s.ListingMeta(ctx, k); meta.FetchedAt != old || meta.ETag != "e1" {
		t.Fatalf("a refused renewal changed the listing: %+v", meta)
	}
	renewed, err := s.RenewListingIf(ctx, k, "e2", now, 1)
	if !renewed || err != nil {
		t.Fatalf("RenewListingIf = (%v, %v), want renewed", renewed, err)
	}
	l, ok, _ := s.GetListing(ctx, k)
	if !ok || l.FetchedAt != now || l.ETag != "e2" || len(l.Nodes) != 1 || l.Nodes[0].ID != "id-a" {
		t.Errorf("listing after the renewal = %+v", l)
	}
	if g, _ := s.Generation(ctx, k); g != 2 {
		t.Errorf("generation = %d after the renewal, want 2", g)
	}
	// The listing handed out before is not written through.
	if before.FetchedAt != old || before.ETag != "e1" {
		t.Errorf("the listing read before the renewal changed: %+v", before)
	}
	// A fetch that started before the renewal is refused, as after a put.
	if stored, _ := s.PutListingIf(ctx, k, &metastore.Listing{}, 1); stored {
		t.Error("PutListingIf under the generation the renewal left was stored")
	}
}
