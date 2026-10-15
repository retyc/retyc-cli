package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// GetNamed answers what GetNode and GetEntry answer, each half on its own, in
// both forms of the values: listing held or not, with or without the name,
// entry positive, negative or absent.
func TestGetNamed_Conformance(t *testing.T) {
	for _, high := range []bool{false, true} {
		for _, listing := range []string{"none", "without the name", "with the name"} {
			for _, entry := range []string{"none", "negative", "positive"} {
				name := "clear/"
				if high {
					name = "sealed/"
				}
				t.Run(name+listing+"/"+entry, func(t *testing.T) {
					e := newEnv(t)
					s := e.store(high)
					ctx := context.Background()
					a, b := seal(file("a")), seal(file("b"))
					switch listing {
					case "without the name":
						must(t, s.PutListing(ctx, lk("/d"), &metastore.Listing{
							Nodes: []metastore.Node{b}, FetchedAt: time.Now(), ETag: "e",
						}))
					case "with the name":
						must(t, s.PutListing(ctx, lk("/d"), &metastore.Listing{
							Nodes: []metastore.Node{a, b}, FetchedAt: time.Now(), ETag: "e",
						}))
					}
					switch entry {
					case "negative":
						must(t, s.PutEntry(ctx, ek("/d", "a"), &metastore.Entry{FetchedAt: time.Now()}))
					case "positive":
						must(t, s.PutEntry(ctx, ek("/d", "a"), &metastore.Entry{Node: &a, FetchedAt: time.Now()}))
					}
					// Neither another name nor another folder answers.
					must(t, s.PutEntry(ctx, ek("/d", "other"), &metastore.Entry{Node: &b, FetchedAt: time.Now()}))
					must(t, s.PutEntry(ctx, ek("/", "a"), &metastore.Entry{Node: &b, FetchedAt: time.Now()}))

					n, meta, held, en, hasEntry, err := s.GetNamed(ctx, lk("/d"), "a")
					must(t, err)
					wantN, wantMeta, wantHeld, err := s.GetNode(ctx, lk("/d"), "a")
					must(t, err)
					wantE, wantHas, err := s.GetEntry(ctx, ek("/d", "a"))
					must(t, err)

					if held != (listing != "none") || (n != nil) != (listing == "with the name") {
						t.Fatalf("held = %v, node %+v for a listing %s", held, n, listing)
					}
					if held != wantHeld || meta.ETag != wantMeta.ETag || (n == nil) != (wantN == nil) {
						t.Fatalf("node half = (%+v, %+v, %v), GetNode says (%+v, %+v, %v)",
							n, meta, held, wantN, wantMeta, wantHeld)
					}
					if held {
						if meta.ETag != "e" || time.Since(meta.FetchedAt) > 5*time.Second ||
							meta.FetchedAt.Sub(wantMeta.FetchedAt).Abs() > 200*time.Millisecond {
							t.Errorf("meta = %+v, GetNode says %+v", meta, wantMeta)
						}
					}
					if n != nil && (*n != *wantN || n.ID != "id-a" || n.Name != "a" || n.Size != 1234) {
						t.Errorf("node = %+v, GetNode says %+v", n, wantN)
					}
					if hasEntry != (entry != "none") || hasEntry != wantHas {
						t.Fatalf("entry = (%+v, %v) for an entry %s (GetEntry: %v)", en, hasEntry, entry, wantHas)
					}
					if hasEntry {
						if (en.Node != nil) != (entry == "positive") || (en.Node == nil) != (wantE.Node == nil) {
							t.Fatalf("entry node = %+v for an entry %s", en.Node, entry)
						}
						if en.Node != nil && (*en.Node != *wantE.Node || en.Node.ID != "id-a" || en.Node.Name != "a") {
							t.Errorf("entry node = %+v, GetEntry says %+v", en.Node, wantE.Node)
						}
						if time.Since(en.FetchedAt) > 5*time.Second {
							t.Errorf("entry fetched at %v", en.FetchedAt)
						}
					}
				})
			}
		}
	}
}

// A dataroom whose keys cannot be named, and a node that cannot be opened,
// are read by GetNamed as by the two methods it stands for.
func TestGetNamed_UnreadableHalves(t *testing.T) {
	e := newEnv(t)
	s := e.store(true)
	ctx := context.Background()
	a := seal(file("a"))
	put(t, s, "/d", a)
	must(t, s.PutEntry(ctx, ek("/d", "a"), &metastore.Entry{Node: &a, FetchedAt: time.Now()}))
	must(t, s.PutEntry(ctx, ek("/d", "gone"), &metastore.Entry{FetchedAt: time.Now()}))

	e.codec.failOpen.Store(true)
	n, _, held, en, hasEntry, err := s.GetNamed(ctx, lk("/d"), "a")
	if err != nil || n != nil || held || en != nil || hasEntry {
		t.Errorf("a node that does not open = (%+v, held %v, %+v, %v, %v), want nothing held", n, held, en, hasEntry, err)
	}
	// A negative entry holds nothing to open, and a name the listing lacks neither.
	n, _, held, en, hasEntry, err = s.GetNamed(ctx, lk("/d"), "gone")
	if err != nil || n != nil || !held || !hasEntry || en.Node != nil {
		t.Errorf("a missing name = (%+v, held %v, %+v, %v, %v), want a held listing and a negative entry",
			n, held, en, hasEntry, err)
	}
	e.codec.failOpen.Store(false)

	e.codec.unresolved.Store(true)
	n, _, held, en, hasEntry, err = s.GetNamed(ctx, lk("/d"), "a")
	if err != nil || n != nil || held || en != nil || hasEntry {
		t.Errorf("an unresolved dataroom = (%+v, held %v, %+v, %v, %v), want nothing and no error",
			n, held, en, hasEntry, err)
	}
}

// RenewListingIf gives a held listing its full lifetime again and the ETag,
// nodes untouched, under the expected generation, which it bumps; it writes
// nothing when the generation moved or the listing is gone.
func TestRenewListingIf(t *testing.T) {
	for _, high := range []bool{false, true} {
		name := "clear"
		if high {
			name = "sealed"
		}
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			s := e.store(high) // ListingLife is 30 s
			ctx := context.Background()
			f, _ := s.folder(dr, "/a/b")
			parent, _ := s.folder(dr, "/a")
			x, y := seal(file("x")), seal(file("y"))

			// Fetched 20 s ago: 10 s left to live.
			must(t, s.PutListing(ctx, lk("/a/b"), &metastore.Listing{
				Nodes: []metastore.Node{x, y}, FetchedAt: time.Now().Add(-20 * time.Second), ETag: "e1",
			}))
			if left := e.raw.PTTL(ctx, f.ls).Val(); left > 11*time.Second || left < 8*time.Second {
				t.Fatalf("lifetime before the renewal = %v, want about 10s", left)
			}
			g := gen(t, s, "/a/b")

			// Another generation: nothing moves.
			renewed, err := s.RenewListingIf(ctx, lk("/a/b"), "e2", time.Now(), g+1)
			if renewed || err != nil {
				t.Fatalf("renewed under another generation: (%v, %v)", renewed, err)
			}
			meta, _, err := s.ListingMeta(ctx, lk("/a/b"))
			must(t, err)
			if meta.ETag != "e1" || time.Since(meta.FetchedAt) < 15*time.Second || gen(t, s, "/a/b") != g {
				t.Fatalf("a refused renewal wrote: %+v, generation %d (was %d)", meta, gen(t, s, "/a/b"), g)
			}

			renewed, err = s.RenewListingIf(ctx, lk("/a/b"), "e2", time.Now(), g)
			if !renewed || err != nil {
				t.Fatalf("RenewListingIf = (%v, %v), want renewed", renewed, err)
			}
			if left := e.raw.PTTL(ctx, f.ls).Val(); left > 30*time.Second || left < 28*time.Second {
				t.Errorf("lifetime after the renewal = %v, want the full 30s", left)
			}
			l, ok, err := s.GetListing(ctx, lk("/a/b"))
			must(t, err)
			if !ok || names(l.Nodes) != names([]metastore.Node{x, y}) || l.ETag != "e2" ||
				time.Since(l.FetchedAt) > 2*time.Second {
				t.Errorf("listing after the renewal = %+v (ok %v), want x and y, e2, fetched now", l, ok)
			}
			if ok && (l.Nodes[0].ID != "id-x" || l.Nodes[0].Size != 1234) {
				t.Errorf("node after the renewal = %+v", l.Nodes[0])
			}
			if got := gen(t, s, "/a/b"); got != g+1 {
				t.Errorf("generation = %d after the renewal, want %d", got, g+1)
			}
			if left := e.raw.PTTL(ctx, f.gen).Val(); left < time.Hour {
				t.Errorf("the generation lives %v after the renewal", left)
			}
			// A fetch that started before the renewal is refused, as after a put.
			late := &metastore.Listing{Nodes: []metastore.Node{x}, FetchedAt: time.Now()}
			if stored, err := s.PutListingIf(ctx, lk("/a/b"), late, g); stored || err != nil {
				t.Errorf("PutListingIf under the generation the renewal left = (%v, %v)", stored, err)
			}

			// The renewal keeps the tokens the listing was written under: a
			// DeleteSubtree above still makes it stale.
			renewed, err = s.RenewListingIf(ctx, lk("/a/b"), "", time.Now().Add(-10*time.Second), g+1)
			if !renewed || err != nil {
				t.Fatalf("second renewal = (%v, %v)", renewed, err)
			}
			if left := e.raw.PTTL(ctx, parent.tl[len(parent.tl)-1]).Val(); left <= 0 {
				t.Errorf("the token of the parent has no lifetime after a renewal: %v", left)
			}
			meta, _, err = s.ListingMeta(ctx, lk("/a/b"))
			must(t, err)
			if age := time.Since(meta.FetchedAt); meta.ETag != "" || age < 9*time.Second || age > 12*time.Second {
				t.Errorf("renewed without ETag as fetched 10s ago: %+v (age %v)", meta, age)
			}
			must(t, s.DeleteSubtree(ctx, dr, "/a"))
			if _, ok := held(t, s, "/a/b"); ok {
				t.Error("the renewed listing survived a DeleteSubtree of its parent")
			}

			// No listing: nothing is created, nothing is bumped.
			g = gen(t, s, "/a/b")
			renewed, err = s.RenewListingIf(ctx, lk("/a/b"), "e3", time.Now(), g)
			if renewed || err != nil {
				t.Errorf("renewing a listing that is gone = (%v, %v)", renewed, err)
			}
			if _, ok := held(t, s, "/a/b"); ok || gen(t, s, "/a/b") != g {
				t.Errorf("a refused renewal brought the listing back (%v) or bumped the generation", ok)
			}
			// A fetch older than a listing's lifetime renews nothing.
			put(t, s, "/a/b", x)
			g = gen(t, s, "/a/b")
			if renewed, err := s.RenewListingIf(ctx, lk("/a/b"), "e3", time.Now().Add(-time.Minute), g); renewed || err != nil {
				t.Errorf("renewed as fetched before a whole lifetime: (%v, %v)", renewed, err)
			}
			// A hash another wire version wrote is not a listing held.
			must(t, e.raw.HSet(ctx, f.ls, metaField, "99:30000").Err())
			if renewed, err := s.RenewListingIf(ctx, lk("/a/b"), "e3", time.Now(), g); renewed || err != nil {
				t.Errorf("renewed a listing of another wire version: (%v, %v)", renewed, err)
			}
		})
	}
}
