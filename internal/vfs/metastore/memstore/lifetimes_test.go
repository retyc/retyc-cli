package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// clock is a settable clock for Options.Now.
type clock struct{ t time.Time }

func (c *clock) now() time.Time              { return c.t }
func (c *clock) advance(d time.Duration)     { c.t = c.t.Add(d) }
func newClock() *clock                       { return &clock{t: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)} }
func (c *clock) listing() *metastore.Listing { return &metastore.Listing{FetchedAt: c.t} }

const (
	listingLife  = 11 * time.Minute
	entryLife    = time.Minute
	negativeLife = time.Second
	genLife      = 4 * time.Minute
	// sweepEvery is the interval between two sweeps: a quarter of the
	// longest lifetime.
	sweepEvery = listingLife / 4
)

func boundedStore(c *clock) *Store {
	return NewWithOptions(Options{
		ListingLife:       listingLife,
		EntryLife:         entryLife,
		NegativeEntryLife: negativeLife,
		GenerationLife:    genLife,
		Now:               c.now,
	})
}

func wantHeld(t *testing.T, s *Store, listings, entries, gens int) {
	t.Helper()
	if l, e, g := s.Held(); l != listings || e != entries || g != gens {
		t.Errorf("Held = %d listings, %d entries, %d generations; want %d, %d, %d", l, e, g, listings, entries, gens)
	}
}

// A listing past its lifetime reads as absent on every read path, before any
// sweep removed it.
func TestLifetimes_ExpiredListingReadsAsAbsent(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	k := key("dr1", "/a")
	l := c.listing()
	l.Nodes = []metastore.Node{{ID: "n1", Name: "f", Type: metastore.TypeFile}}
	if err := s.PutListing(ctx, k, l); err != nil {
		t.Fatal(err)
	}
	c.advance(listingLife - time.Millisecond)
	if !has(t, s, k) {
		t.Fatal("a listing within its lifetime is absent")
	}
	// No sweep from here on: the read paths alone must hide what expired.
	s.nextSweep = c.t.Add(1000 * time.Hour)
	c.advance(time.Millisecond)
	if has(t, s, k) {
		t.Error("GetListing answered an expired listing")
	}
	if err := s.PutListing(ctx, k, &metastore.Listing{FetchedAt: c.t.Add(-listingLife)}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ListingMeta(ctx, k); ok {
		t.Error("ListingMeta answered an expired listing")
	}
	if err := s.PutListing(ctx, k, &metastore.Listing{FetchedAt: c.t.Add(-listingLife)}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := s.GetNode(ctx, k, "f"); ok {
		t.Error("GetNode answered an expired listing")
	}
	if err := s.PutListing(ctx, k, &metastore.Listing{FetchedAt: c.t.Add(-listingLife)}); err != nil {
		t.Fatal(err)
	}
	if _, _, held, _, _, _ := s.GetNamed(ctx, k, "f"); held {
		t.Error("GetNamed answered an expired listing")
	}
	if err := s.PutListing(ctx, k, &metastore.Listing{FetchedAt: c.t.Add(-listingLife)}); err != nil {
		t.Fatal(err)
	}
	gen, _ := s.Generation(ctx, k)
	if ok, _ := s.RenewListingIf(ctx, k, "e", c.t, gen); ok {
		t.Error("RenewListingIf renewed an expired listing back to life")
	}
	// An edit of an expired listing edits nothing, as on a missing one.
	if err := s.PutListing(ctx, k, &metastore.Listing{FetchedAt: c.t.Add(-listingLife)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertNode(ctx, k, metastore.Node{ID: "n2", Name: "g"}); err != nil {
		t.Fatal(err)
	}
	if has(t, s, k) {
		t.Error("UpsertNode brought an expired listing back")
	}
}

// A listing put without FetchedAt lives from the time it is put; an edit
// keeps its lifetime, a renewal starts it again.
func TestLifetimes_ListingLifetimeFollowsItsFetch(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	k := key("dr1", "/a")
	if err := s.PutListing(ctx, k, &metastore.Listing{}); err != nil {
		t.Fatal(err)
	}
	c.advance(listingLife / 2)
	if !has(t, s, k) {
		t.Fatal("a listing put without FetchedAt expired at once")
	}
	if _, err := s.UpsertNode(ctx, k, metastore.Node{ID: "n1", Name: "f"}); err != nil {
		t.Fatal(err)
	}
	c.advance(listingLife / 2)
	if has(t, s, k) {
		t.Error("an edit in place extended the listing's lifetime")
	}

	if err := s.PutListing(ctx, k, c.listing()); err != nil {
		t.Fatal(err)
	}
	c.advance(listingLife - time.Minute)
	gen, _ := s.Generation(ctx, k)
	if ok, _ := s.RenewListingIf(ctx, k, "e", c.t, gen); !ok {
		t.Fatal("RenewListingIf refused a live listing")
	}
	c.advance(listingLife - time.Minute)
	if !has(t, s, k) {
		t.Error("a renewed listing kept its first lifetime")
	}
}

// Positive and negative entries have their own lifetimes.
func TestLifetimes_Entries(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	pos := metastore.EntryKey{DataroomID: "dr1", ParentPath: "/", Name: "f"}
	neg := metastore.EntryKey{DataroomID: "dr1", ParentPath: "/", Name: "g"}
	_ = s.PutEntry(ctx, pos, &metastore.Entry{Node: &metastore.Node{ID: "n1", Name: "f"}, FetchedAt: c.t})
	_ = s.PutEntry(ctx, neg, &metastore.Entry{FetchedAt: c.t})
	c.advance(negativeLife)
	if _, ok, _ := s.GetEntry(ctx, neg); ok {
		t.Error("a negative entry outlived NegativeEntryLife")
	}
	if _, ok, _ := s.GetEntry(ctx, pos); !ok {
		t.Error("a positive entry went with the negative lifetime")
	}
	if _, _, _, _, ok, _ := s.GetNamed(ctx, key("dr1", "/"), "g"); ok {
		t.Error("GetNamed answered an expired entry")
	}
	c.advance(entryLife)
	if _, ok, _ := s.GetEntry(ctx, pos); ok {
		t.Error("a positive entry outlived EntryLife")
	}
}

// A folder deleted or renamed elsewhere is never read again: its listing,
// the listings below it, their entries and generations all leave the store.
func TestLifetimes_OrphansAreSwept(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	for _, p := range []string{"/gone", "/gone/a", "/gone/a/b"} {
		if err := s.PutListing(ctx, key("dr1", p), c.listing()); err != nil {
			t.Fatal(err)
		}
		_ = s.PutEntry(ctx, metastore.EntryKey{DataroomID: "dr1", ParentPath: p, Name: "x"},
			&metastore.Entry{Node: &metastore.Node{ID: "x", Name: "x"}, FetchedAt: c.t})
	}
	wantHeld(t, s, 3, 3, 3)

	c.advance(max(entryLife, sweepEvery))
	wantHeld(t, s, 3, 0, 3)
	c.advance(listingLife)
	// The listings are gone; their generations stay GenerationLife after
	// the listings left, then go too.
	wantHeld(t, s, 0, 0, 3)
	c.advance(genLife + sweepEvery)
	wantHeld(t, s, 0, 0, 0)
}

// A generation is kept for GenerationLife after it last moved once its
// listing is gone, and one dropped is never answered again: a write
// conditioned on it is refused, and the listing starts above it.
func TestLifetimes_DroppedGenerationRefusesStaleWrites(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	k := key("dr1", "/a")
	if err := s.PutListing(ctx, k, c.listing()); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteListing(ctx, k); err != nil {
		t.Fatal(err)
	}
	read, _ := s.Generation(ctx, k) // a fetch starts
	if read == 0 {
		t.Fatal("a listing written then deleted has generation 0")
	}
	c.advance(genLife - time.Second)
	wantHeld(t, s, 0, 0, 1)
	c.advance(time.Second + sweepEvery)
	wantHeld(t, s, 0, 0, 0)

	floor, _ := s.Generation(ctx, k)
	if floor <= read {
		t.Errorf("Generation of a dropped generation = %d, want above %d", floor, read)
	}
	if ok, _ := s.PutListingIf(ctx, k, c.listing(), read); ok {
		t.Error("PutListingIf stored under a generation that was dropped")
	}
	if ok, _ := s.PutEntryIf(ctx, metastore.EntryKey{DataroomID: "dr1", ParentPath: "/a", Name: "f"},
		&metastore.Entry{FetchedAt: c.t}, read); ok {
		t.Error("PutEntryIf stored under a generation that was dropped")
	}
	// The listing written again under the floor it reads moves one above it.
	if ok, _ := s.PutListingIf(ctx, k, c.listing(), floor); !ok {
		t.Fatal("PutListingIf refused the generation a listing without one reads")
	}
	if gen, _ := s.Generation(ctx, k); gen != floor+1 {
		t.Errorf("generation after a drop and a write = %d, want %d", gen, floor+1)
	}
	if ok, _ := s.PutListingIf(ctx, k, c.listing(), read); ok {
		t.Error("a generation read before the drop matched again")
	}
}

// Once a generation was dropped, a listing that never had one reads the
// floor, and a write during a fetch moves it by exactly one: a fetch that
// read the floor recognises the edit as the only write (vfs editedLocked).
// A value read before the drop, the old floor included, is never answered
// again for a listing that changed.
func TestLifetimes_FloorAfterADrop(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	fresh := key("dr1", "/fresh")
	before, _ := s.Generation(ctx, fresh) // a fetch reads the floor, 0
	if _, err := s.UpsertNode(ctx, fresh, metastore.Node{ID: "n1", Name: "f"}); err != nil {
		t.Fatal(err)
	}
	// Another listing's generation is dropped.
	if err := s.DeleteListing(ctx, key("dr1", "/old")); err != nil {
		t.Fatal(err)
	}
	c.advance(genLife + sweepEvery)
	wantHeld(t, s, 0, 0, 0)

	// The write that /fresh saw before the drop: its fetch's value is gone.
	if ok, _ := s.PutListingIf(ctx, fresh, c.listing(), before); ok {
		t.Error("a floor read before an edit and a drop matched again")
	}
	k := key("dr1", "/other")
	read, _ := s.Generation(ctx, k)
	if read == 0 {
		t.Fatal("the floor did not rise above the generations dropped")
	}
	gen, _ := s.UpsertNode(ctx, k, metastore.Node{ID: "n2", Name: "g"})
	if gen != read+1 {
		t.Errorf("first write of a listing without generation = %d, want the floor %d + 1", gen, read)
	}
}

// A listing that ages out untouched keeps its generation GenerationLife
// after it left, however long ago it last moved: a fetch started while it
// was held is not refused for a drop that came with the listing's expiry.
func TestLifetimes_GenerationOutlivesItsListing(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	k := key("dr1", "/a")
	if err := s.PutListing(ctx, k, c.listing()); err != nil {
		t.Fatal(err)
	}
	c.advance(listingLife - time.Second)
	read, _ := s.Generation(ctx, k) // a fetch starts, the listing still held
	c.advance(time.Second + sweepEvery)
	wantHeld(t, s, 0, 0, 1)
	c.advance(genLife - sweepEvery - time.Second)
	if ok, _ := s.PutListingIf(ctx, k, c.listing(), read); !ok {
		t.Error("the answer of a fetch started while the listing was held was refused")
	}

	// Deleted: the same.
	if err := s.DeleteListing(ctx, k); err != nil {
		t.Fatal(err)
	}
	read, _ = s.Generation(ctx, k)
	c.advance(genLife - time.Second)
	wantHeld(t, s, 0, 0, 1)
	if ok, _ := s.PutListingIf(ctx, k, c.listing(), read); !ok {
		t.Error("the answer of a fetch started after a delete was refused")
	}
}

// A generation is not dropped while its listing is held, whatever its age.
func TestLifetimes_GenerationOfAHeldListingStays(t *testing.T) {
	c := newClock()
	s := boundedStore(c)
	ctx := context.Background()
	k := key("dr1", "/a")
	if err := s.PutListing(ctx, k, c.listing()); err != nil {
		t.Fatal(err)
	}
	gen, _ := s.Generation(ctx, k)
	c.advance(genLife + sweepEvery)
	wantHeld(t, s, 1, 0, 1)
	if got, _ := s.Generation(ctx, k); got != gen {
		t.Errorf("Generation = %d, want %d", got, gen)
	}
}

// New keeps everything, whatever the time.
func TestLifetimes_ZeroKeepsForever(t *testing.T) {
	c := newClock()
	s := NewWithOptions(Options{Now: c.now})
	ctx := context.Background()
	k := key("dr1", "/a")
	if err := s.PutListing(ctx, k, c.listing()); err != nil {
		t.Fatal(err)
	}
	_ = s.PutEntry(ctx, metastore.EntryKey{DataroomID: "dr1", ParentPath: "/a", Name: "g"},
		&metastore.Entry{FetchedAt: c.t})
	if err := s.DeleteListing(ctx, key("dr1", "/b")); err != nil {
		t.Fatal(err)
	}
	c.advance(1000 * time.Hour)
	wantHeld(t, s, 1, 1, 2)
}
