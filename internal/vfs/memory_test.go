package vfs

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// heldByStore counts what the in-memory store of fs holds, once a sweep that
// is due has run.
func heldByStore(t *testing.T, fs *FS) (listings, entries, gens int) {
	t.Helper()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	s, ok := fs.store.(*memstore.Store)
	if !ok {
		t.Fatalf("the store of the FS is a %T, not a memstore", fs.store)
	}

	return s.Held()
}

// An FS that read N folders and then nothing for longer than a listing is of
// use holds nothing of them: folders deleted or renamed elsewhere, which
// nobody reads again, do not stay for the life of the process.
func TestFS_MemoryIsBoundedByRetention(t *testing.T) {
	const folders = 50
	opts := Options{
		TTL: time.Minute, MaxStale: 2 * time.Minute, FetchTimeout: 30 * time.Second,
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
		},
	}
	fs := New(nil, opts)
	clock := &testClock{now: time.Now()}
	fs.now = clock.Now
	ctx := context.Background()
	for i := range folders {
		if _, err := fs.ReadDir(ctx, "dr1", fmt.Sprintf("/d%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	fs.InvalidateListing("dr1", "/d0")
	if l, _, g := heldByStore(t, fs); l != folders-1 || g != folders {
		t.Fatalf("after the walk: %d listings, %d generations; want %d, %d", l, g, folders-1, folders)
	}

	// Within the retention, everything is still there.
	clock.advance(ListingRetention(opts.TTL, opts.MaxStale) - time.Second)
	if l, _, _ := heldByStore(t, fs); l != folders-1 {
		t.Errorf("within the retention: %d listings, want %d", l, folders-1)
	}
	clock.advance(time.Second + ListingRetention(opts.TTL, opts.MaxStale)/4)
	if l, e, _ := heldByStore(t, fs); l != 0 || e != 0 {
		t.Errorf("past the retention: %d listings, %d entries; want none", l, e)
	}
	// The generations outlive their listings by the time a fetch may take.
	clock.advance(ListingRetention(opts.TTL, opts.MaxStale) / 4)
	if l, e, g := heldByStore(t, fs); l != 0 || e != 0 || g != 0 {
		t.Errorf("past the retention: %d listings, %d entries, %d generations; want none", l, e, g)
	}
}

// Once the store dropped a generation, a folder that never had one reads a
// generation above 0, and an edit made while its listing ahead is on its way
// moves it by one: that listing is stored, with the edit replayed.
func TestFS_ListingAheadIsStoredAfterAGenerationDrop(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	opts := Options{TTL: time.Minute, NegativeTTL: time.Minute}
	fs := newTreeFS(t, a, opts)
	// The clock starts in the past and catches up with the wall clock, which
	// some paths of the FS read.
	aged := 2 * ListingRetention(opts.TTL, opts.MaxStale)
	clock := &testClock{now: time.Now().Add(-aged)}
	fs.now = clock.Now
	ctx := context.Background()

	// A generation leaves the store: the floor rises.
	fs.InvalidateListing("dr1", "/gone")
	clock.advance(aged)
	if _, _, g := heldByStore(t, fs); g != 0 {
		t.Fatalf("%d generations held, want the one of /gone dropped", g)
	}
	fs.mu.Lock()
	floor, _ := fs.store.Generation(ctx, key("dr1", "/a"))
	fs.mu.Unlock()
	if floor == 0 {
		t.Fatal("a generation was dropped, and a folder without one still reads 0")
	}

	mustLookup(t, fs, "/", "a", "d-a")
	mustMiss(t, fs, "/a", "d0")
	arrived, release := a.holdNextListing()
	mustMiss(t, fs, "/a", "d1") // starts the listing ahead
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the second lookup of the folder started no listing")
	}
	if _, err := fs.Mkdir(ctx, "dr1", "/a/d1"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	release()
	waitListed(t, fs, "/a")
	if got := names(cachedNodes(fs, "dr1", "/a")); !slices.Contains(got, "d1") {
		t.Errorf("cached listing = %v, want the folder created during the fetch in it", got)
	}
}

// The generations an FS keeps in process are pruned to the folders being
// fetched: invalidating many folders does not grow FS.gen without bound.
func TestFS_GenerationsArePruned(t *testing.T) {
	fs := New(nil, Options{List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return nil, nil
	}})
	for i := range 10 * minGenSweep {
		fs.InvalidateListing("dr1", fmt.Sprintf("/d%d", i))
	}
	fs.mu.Lock()
	n := len(fs.gen)
	fs.mu.Unlock()
	if n >= minGenSweep {
		t.Errorf("FS.gen holds %d generations after %d invalidations, want fewer than %d", n, 10*minGenSweep, minGenSweep)
	}
}

// A prune keeps the generation of a fetch in flight: its answer is stored
// when nothing changed the folder meanwhile, and not when something did,
// prune or not.
func TestFS_GenerationPruneKeepsFetchesInFlight(t *testing.T) {
	for _, edited := range []bool{false, true} {
		t.Run(fmt.Sprintf("edited=%v", edited), func(t *testing.T) {
			gate, started := make(chan struct{}), make(chan struct{})
			fs := New(nil, Options{List: func(_ context.Context, _, path string) ([]service.DataroomNodeInfo, error) {
				if path == "/busy" {
					close(started)
					<-gate
				}

				return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
			}})
			done := make(chan error, 1)
			go func() {
				_, err := fs.ReadDir(context.Background(), "dr1", "/busy")
				done <- err
			}()
			// The fetch read its generation before it asked the API.
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("the fetch never asked the API")
			}
			if edited {
				fs.InvalidateListing("dr1", "/busy")
			}
			for i := range 2 * minGenSweep {
				fs.InvalidateListing("dr1", fmt.Sprintf("/d%d", i))
			}
			close(gate)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if stored := nodeCacheHas(fs, "dr1", "/busy"); stored == edited {
				t.Errorf("listing stored = %v, want %v", stored, !edited)
			}
		})
	}
}
