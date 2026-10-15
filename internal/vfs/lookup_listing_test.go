package vfs

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
)

// waitListed waits for the listing of the folder at path to be cached and
// for no fetch of it to be running.
func waitListed(t *testing.T, fs *FS, path string) {
	t.Helper()
	key := listingKey("dr1", path)
	deadline := time.Now().Add(5 * time.Second)
	for {
		fs.mu.Lock()
		_, running := fs.inflight[key]
		fs.mu.Unlock()
		if !running && nodeCacheHas(fs, "dr1", path) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the listing of %s was never cached", path)
		}
		time.Sleep(time.Millisecond)
	}
}

// fetching reports whether a listing of the folder at path is queued or
// running.
func fetching(fs *FS, path string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	_, ok := fs.inflight[listingKey("dr1", path)]

	return ok
}

// Names looked up one after the other in a folder nobody listed (the kernel
// looks a name up before creating it): the second starts the listing of the
// folder in the background, and the lookups that follow cost nothing.
func TestLookup_RepeatedMissesLoadTheListing(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
	mustLookup(t, fs, "/", "a", "d-a")
	before, _, _ := a.counts()

	mustMiss(t, fs, "/a", "n0")
	if fetching(fs, "/a") {
		t.Fatal("the first lookup started the listing of the folder")
	}
	// The second still goes by name: it does not wait for the listing.
	mustMiss(t, fs, "/a", "n1")
	if lookups, _, _ := a.counts(); lookups-before != 2 {
		t.Errorf("%d lookups by name for the first two names, want 2", lookups-before)
	}
	waitListed(t, fs, "/a")

	for i := 2; i < 8; i++ {
		mustMiss(t, fs, "/a", fmt.Sprintf("n%d", i))
	}
	mustLookup(t, fs, "/a", "x.txt", "f-x")
	if lookups, listings, _ := a.counts(); lookups-before != 2 || listings != 1 {
		t.Errorf("%d lookups by name and %d listings, want 2 and 1", lookups-before, listings)
	}
	fs.mu.Lock()
	counted := len(fs.nameLookups)
	fs.mu.Unlock()
	if counted != 1 { // the root, where "a" was looked up
		t.Errorf("%d folders still counted, want the count of /a dropped with its listing cached", counted)
	}
}

// One lookup lists nothing, and neither does one name looked up again and
// again: an isolated stat does not pay the listing of a large folder.
func TestLookup_SingleMissLoadsNoListing(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute}) // no negative entry: every lookup asks
	mustLookup(t, fs, "/", "a", "d-a")

	for range 3 {
		mustMiss(t, fs, "/a", "n0")
		if fetching(fs, "/a") {
			t.Fatal("the lookup of one name started the listing of the folder")
		}
	}
	if lookups, listings, _ := a.counts(); lookups != 4 || listings != 0 {
		t.Errorf("%d lookups by name and %d listings, want 4 and 0", lookups, listings)
	}

	// A run is over after the TTL: the next name is the first of a new one.
	fs.mu.Lock()
	run := fs.nameLookups[listingKey("dr1", "/a")]
	run.since = time.Now().Add(-2 * time.Minute)
	fs.nameLookups[listingKey("dr1", "/a")] = run
	fs.mu.Unlock()
	mustMiss(t, fs, "/a", "n1")
	if fetching(fs, "/a") {
		t.Fatal("a lookup made a TTL after the last started the listing of the folder")
	}
	if _, listings, _ := a.counts(); listings != 0 {
		t.Errorf("%d listings, want none", listings)
	}
}

// The table of the folders counted is bounded.
func TestLookup_NameLookupRunsAreBounded(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute})
	fs.mu.Lock()
	for i := range maxNameLookupRuns {
		fs.nameLookups[listingKey("dr1", fmt.Sprintf("/other/%d", i))] = nameLookupRun{since: time.Now(), n: 1}
	}
	fs.mu.Unlock()

	mustLookup(t, fs, "/", "a", "d-a")
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.nameLookups) != 1 {
		t.Errorf("%d folders counted, want the table emptied when full", len(fs.nameLookups))
	}
}

// The loop the listing is for: look a name up, find it missing, create it,
// again. Each creation changes the folder while its listing is on its way.
// That listing is neither discarded by them (every lookup of the loop would
// start another, as lost as the one before) nor stored without them: it
// lands once, with every node created meanwhile, and the lookups that follow
// do not reach the API.
func TestLookup_ListingLandsDuringALoopOfCreations(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
	ctx := context.Background()
	create := func(name string) {
		t.Helper()
		if _, err := fs.Mkdir(ctx, "dr1", "/a/"+name); err != nil {
			t.Fatalf("Mkdir(%s): %v", name, err)
		}
	}

	mustMiss(t, fs, "/a", "d0")
	create("d0")
	a.put("d-a", "d0", fakeNode{id: "d-0", kind: api.NodeTypeFolder})

	// The listing the second lookup starts is answered with the folder as it
	// is now, and held until the loop is over.
	arrived, release := a.holdNextListing()
	mustMiss(t, fs, "/a", "d1")
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the second lookup of the folder started no listing")
	}
	create("d1")
	for i := 2; i < 6; i++ {
		name := fmt.Sprintf("d%d", i)
		mustMiss(t, fs, "/a", name)
		create(name)
	}
	if _, listings, _ := a.counts(); listings != 1 {
		t.Errorf("%d listings during the loop, want the one the second lookup started", listings)
	}
	release()
	waitListed(t, fs, "/a")

	got := names(cachedNodes(fs, "dr1", "/a"))
	slices.Sort(got)
	if want := []string{"b", "d0", "d1", "d2", "d3", "d4", "d5", "x.txt"}; !slices.Equal(got, want) {
		t.Errorf("cached listing = %v, want %v", got, want)
	}
	lookups, listings, _ := a.counts()
	mustMiss(t, fs, "/a", "d6")
	mustLookup(t, fs, "/a", "d3", "d-created")
	mustLookup(t, fs, "/a", "x.txt", "f-x")
	if l, ls, _ := a.counts(); l != lookups || ls != listings || listings != 1 {
		t.Errorf("after the loop: %d lookups and %d listings more, %d listings in all; want 0, 0 and 1",
			l-lookups, ls-listings, ls)
	}
}

// The same loop left to run against an API that answers at once: whenever
// the listing lands, the names created before and after it are all found,
// and the folder ends up listed.
func TestLookup_LoopOfCreationsEndsListed(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
	ctx := context.Background()

	for i := range 10 {
		name := fmt.Sprintf("d%d", i)
		mustMiss(t, fs, "/a", name)
		if _, err := fs.Mkdir(ctx, "dr1", "/a/"+name); err != nil {
			t.Fatalf("Mkdir(%s): %v", name, err)
		}
		a.put("d-a", name, fakeNode{id: "d-created", kind: api.NodeTypeFolder})
		mustLookup(t, fs, "/a", name, "d-created")
	}
	waitListed(t, fs, "/a")
	if got := len(cachedNodes(fs, "dr1", "/a")); got != 12 {
		t.Errorf("%d nodes listed, want the 2 of the tree and the 10 created", got)
	}
	lookups, listings, _ := a.counts()
	for i := range 10 {
		mustLookup(t, fs, "/a", fmt.Sprintf("d%d", i), "d-created")
	}
	mustMiss(t, fs, "/a", "d10")
	if l, ls, _ := a.counts(); l != lookups || ls != listings {
		t.Errorf("%d lookups and %d listings once listed, want none", l-lookups, ls-listings)
	}
}

// waitNotFetching waits for no listing of the folder at path to be queued or
// running.
func waitNotFetching(t *testing.T, fs *FS, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for fetching(fs, path) {
		if time.Now().After(deadline) {
			t.Fatalf("the listing of %s never ended", path)
		}
		time.Sleep(time.Millisecond)
	}
}

// missMany looks up n names of /a nobody looked up before, from the from-th,
// and fails the test if one of them starts a listing of the folder.
func missMany(t *testing.T, fs *FS, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		mustMiss(t, fs, "/a", fmt.Sprintf("n%d", i))
		if fetching(fs, "/a") {
			t.Fatalf("lookup %d started a listing of the folder", i)
		}
	}
}

// heldFor returns for how long the lookups of the folder at path still start
// no listing of it.
func heldFor(fs *FS, path string) time.Duration {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return time.Until(fs.nameLookups[listingKey("dr1", path)].held)
}

// A listing started by the lookups of a folder and that failed is not started
// again by each lookup that follows: the folder gets one per TTL, and its
// lookups go by name meanwhile.
func TestLookup_FailedListingAheadIsNotStartedAgain(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.failListings = true
	fs := newTreeFS(t, a, Options{TTL: time.Minute})
	mustLookup(t, fs, "/", "a", "d-a")

	mustMiss(t, fs, "/a", "n0")
	mustMiss(t, fs, "/a", "n1")
	waitNotFetching(t, fs, "/a")
	lookups, listings, _ := a.counts()
	if listings == 0 {
		t.Fatal("the second lookup of the folder started no listing")
	}
	missMany(t, fs, 2, 10)
	if l, ls, _ := a.counts(); l-lookups != 10 || ls != listings {
		t.Errorf("%d lookups by name and %d listings more, want 10 and none", l-lookups, ls-listings)
	}
	if nodeCacheHas(fs, "dr1", "/a") {
		t.Error("a failed listing was cached")
	}

	// A new run within the TTL of that listing starts none either.
	key := listingKey("dr1", "/a")
	fs.mu.Lock()
	run := fs.nameLookups[key]
	run.since = time.Now().Add(-2 * time.Minute)
	fs.nameLookups[key] = run
	fs.mu.Unlock()
	missMany(t, fs, 12, 3)

	// A TTL after it was started, the next lookup starts one again.
	fs.mu.Lock()
	run = fs.nameLookups[key]
	run.held = time.Now().Add(-time.Second)
	fs.nameLookups[key] = run
	fs.mu.Unlock()
	mustMiss(t, fs, "/a", "n15")
	waitNotFetching(t, fs, "/a")
	if _, ls, _ := a.counts(); ls == listings {
		t.Error("no listing started a TTL after the failed one")
	}
}

// The same when the listing was answered and its answer discarded by an
// invalidation of the folder made meanwhile.
func TestLookup_DiscardedListingAheadIsNotStartedAgain(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	fs := newTreeFS(t, a, Options{TTL: time.Minute})
	mustLookup(t, fs, "/", "a", "d-a")

	arrived, release := a.holdNextListing()
	mustMiss(t, fs, "/a", "n0")
	mustMiss(t, fs, "/a", "n1")
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the second lookup of the folder started no listing")
	}
	fs.InvalidateListing("dr1", "/a")
	release()
	waitNotFetching(t, fs, "/a")
	if nodeCacheHas(fs, "dr1", "/a") {
		t.Fatal("a listing answered before the invalidation was cached")
	}

	lookups, _, _ := a.counts()
	missMany(t, fs, 2, 10)
	if l, ls, _ := a.counts(); l-lookups != 10 || ls != 1 {
		t.Errorf("%d lookups by name more and %d listings, want 10 and 1", l-lookups, ls)
	}
}

// A folder larger than maxListingAhead is not listed for its lookups: the
// first page says so and is the only one requested, nothing is cached, and
// the folder is left alone for much longer than a TTL. Listing it is still
// possible for whoever asks.
func TestLookup_LargeFolderIsNotListedAhead(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.claimTotal = map[string]int{"d-a": maxListingAhead + 1}
	fs := newTreeFS(t, a, Options{TTL: time.Minute})
	mustLookup(t, fs, "/", "a", "d-a")

	mustMiss(t, fs, "/a", "n0")
	mustMiss(t, fs, "/a", "n1")
	waitNotFetching(t, fs, "/a")
	if nodeCacheHas(fs, "dr1", "/a") {
		t.Fatal("the listing of a folder over the cap was cached")
	}
	if _, ls, _ := a.counts(); ls != 1 {
		t.Errorf("%d pages requested, want the first one only", ls)
	}
	if held, want := heldFor(fs, "/a"), listingRefreshWindow(time.Minute); held < want-time.Minute || held > want {
		t.Errorf("the folder is left alone for %v, want %v", held, want)
	}
	lookups, _, _ := a.counts()
	missMany(t, fs, 2, 10)
	if l, ls, _ := a.counts(); l-lookups != 10 || ls != 1 {
		t.Errorf("%d lookups by name more and %d listing requests, want 10 and 1", l-lookups, ls)
	}

	// The cap is on that listing alone.
	nodes, err := fs.ReadDir(context.Background(), "dr1", "/a")
	if err != nil || len(nodes) != 2 {
		t.Fatalf("ReadDir = (%v, %v), want the 2 nodes of the folder", names(nodes), err)
	}
	if !nodeCacheHas(fs, "dr1", "/a") {
		t.Error("the listing somebody asked for was not cached")
	}
}

// A folder of exactly maxListingAhead nodes is listed.
func TestLookup_FolderAtTheCapIsListedAhead(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.claimTotal = map[string]int{"d-a": maxListingAhead}
	fs := newTreeFS(t, a, Options{TTL: time.Minute, NegativeTTL: time.Minute})
	mustLookup(t, fs, "/", "a", "d-a")

	mustMiss(t, fs, "/a", "n0")
	mustMiss(t, fs, "/a", "n1")
	waitListed(t, fs, "/a")
	lookups, listings, _ := a.counts()
	mustMiss(t, fs, "/a", "n2")
	if l, ls, _ := a.counts(); l != lookups || ls != listings {
		t.Errorf("%d lookups and %d listings once listed, want none", l-lookups, ls-listings)
	}
}

// Somebody lists the folder while the capped listing of its lookups runs:
// that one cannot answer them, so a listing without cap takes its place, and
// the capped one, when it ends, neither fails them nor replaces what they
// cached.
func TestLookup_ReadDirDoesNotJoinACappedListing(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.claimTotal = map[string]int{"d-a": maxListingAhead + 1}
	fs := newTreeFS(t, a, Options{TTL: time.Minute})
	mustLookup(t, fs, "/", "a", "d-a")

	arrived, release := a.holdNextListing()
	mustMiss(t, fs, "/a", "n0")
	mustMiss(t, fs, "/a", "n1")
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the second lookup of the folder started no listing")
	}
	nodes, err := fs.ReadDir(context.Background(), "dr1", "/a")
	if err != nil || len(nodes) != 2 {
		t.Fatalf("ReadDir = (%v, %v), want the 2 nodes of the folder", names(nodes), err)
	}
	release()
	// The capped fetch is no longer the one in place: wait for its verdict.
	deadline := time.Now().Add(5 * time.Second)
	for heldFor(fs, "/a") <= time.Minute {
		if time.Now().After(deadline) {
			t.Fatal("the capped listing never reported the folder too large")
		}
		time.Sleep(time.Millisecond)
	}
	if got := len(cachedNodes(fs, "dr1", "/a")); got != 2 {
		t.Errorf("%d nodes cached, want the 2 the ReadDir listed", got)
	}
}
