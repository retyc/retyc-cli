package vfs

import (
	"context"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// revalidateFS returns an FS on a with a TTL of one minute, revalidating the
// listings served from 30 seconds of age.
func revalidateFS(t *testing.T, a *treeAPI, opts Options) *FS {
	t.Helper()
	opts.TTL = time.Minute
	fs := newTreeFS(t, a, opts)
	fs.revalidateAfter = 30 * time.Second

	return fs
}

// waitListings waits until a has answered want listings.
func waitListings(t *testing.T, a *treeAPI, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, listings, _ := a.counts(); listings == want {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("listings = %d, want %d", listings, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// listingAge returns the age of the listing cached for path.
func listingAge(t *testing.T, fs *FS, path string) time.Duration {
	t.Helper()
	l := cachedListing(fs, "dr1", path)
	if l == nil {
		t.Fatalf("no cached listing of %s", path)
	}

	return time.Since(l.FetchedAt)
}

// The drawn threshold stays within [0.3, 0.5) of the TTL.
func TestRevalidateAfter_IsAFractionOfTheTTL(t *testing.T) {
	for range 100 {
		fs := New(nil, Options{TTL: time.Minute})
		if got := fs.revalidateAfter; got < 18*time.Second || got >= 30*time.Second {
			t.Fatalf("revalidateAfter = %s, want in [18s, 30s)", got)
		}
	}
}

// A listing served younger than the threshold starts nothing; past it, it is
// still served from the cache, and renewed in the background.
func TestRevalidate_ReadDirRenewsAListingInUse(t *testing.T) {
	a := sweepTree(newTreeAPI(t), 3)
	fs := revalidateFS(t, a, Options{})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	_, listings0, _ := a.counts()

	ageListing(t, fs, "/dir", 20*time.Second)
	if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	if _, listings, _ := a.counts(); listings != listings0 {
		t.Fatalf("below the threshold: %d listings, want 0", listings-listings0)
	}

	ageListing(t, fs, "/dir", 40*time.Second)
	arrived, release := a.holdNextListing()
	nodes, err := fs.ReadDir(ctx, "dr1", "/dir") // answered while the API holds
	if err != nil || len(nodes) != 3 {
		t.Fatalf("ReadDir = %d nodes, %v; want 3", len(nodes), err)
	}
	waitArrived(t, arrived)
	release()
	waitListings(t, a, listings0+1)
	eventuallyTrue(t, "the listing renewed", func() bool { return listingAge(t, fs, "/dir") < 10*time.Second })
}

// A lookup answered by a listing past the threshold renews it too.
func TestRevalidate_LookupRenewsAListingInUse(t *testing.T) {
	a := sweepTree(newTreeAPI(t), 3)
	fs := revalidateFS(t, a, Options{})

	if _, err := fs.ReadDir(context.Background(), "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	lookups0, listings0, _ := a.counts()
	ageListing(t, fs, "/dir", 40*time.Second)

	mustLookup(t, fs, "/dir", "f1", "f-1")
	waitListings(t, a, listings0+1)
	eventuallyTrue(t, "the listing renewed", func() bool { return listingAge(t, fs, "/dir") < 10*time.Second })
	if lookups, _, _ := a.counts(); lookups != lookups0 {
		t.Errorf("%d lookups by name, want 0", lookups-lookups0)
	}
}

// Requests served while a revalidation is in flight start no other.
func TestRevalidate_OneFetchForManyRequests(t *testing.T) {
	a := sweepTree(newTreeAPI(t), 3)
	fs := revalidateFS(t, a, Options{})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	_, listings0, _ := a.counts()
	ageListing(t, fs, "/dir", 40*time.Second)
	arrived, release := a.holdNextListing()
	for range 5 {
		if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
			t.Fatal(err)
		}
		mustLookup(t, fs, "/dir", "f1", "f-1")
	}
	waitArrived(t, arrived)
	release()
	waitListings(t, a, listings0+1)
	eventuallyTrue(t, "the listing renewed", func() bool { return listingAge(t, fs, "/dir") < 10*time.Second })
	if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	if _, listings, _ := a.counts(); listings != listings0+1 {
		t.Errorf("%d listings, want 1", listings-listings0)
	}
}

// Two instances sharing a store: the one whose threshold comes first renews
// the listing, the other reads it young and asks nothing.
func TestRevalidate_SharedStoreRenewsOnce(t *testing.T) {
	a := sweepTree(newTreeAPI(t), 3)
	store := memstore.New()
	first := revalidateFS(t, a, Options{Store: store})
	second := New(first.client, Options{TTL: time.Minute, Store: store})
	second.revalidateAfter = 40 * time.Second
	sess, _ := first.sessions.Peek("dr1")
	second.SeedSession("dr1", sess)
	ctx := context.Background()

	if _, err := first.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	_, listings0, _ := a.counts()
	ageListing(t, first, "/dir", 45*time.Second)

	if _, err := first.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	waitListings(t, a, listings0+1)
	eventuallyTrue(t, "the listing renewed", func() bool { return listingAge(t, second, "/dir") < 10*time.Second })

	if _, err := second.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	mustLookup(t, second, "/dir", "f1", "f-1")
	// A revalidation is registered before the request returns.
	second.mu.Lock()
	inflight := len(second.inflight)
	second.mu.Unlock()
	if inflight != 0 {
		t.Errorf("the second instance started %d fetches, want 0", inflight)
	}
}

// A revalidation that fails is tried once per listing: the requests that
// follow are served from the cache and start nothing until the listing
// expires.
func TestRevalidate_FailureIsNotRetriedByEveryRequest(t *testing.T) {
	a := sweepTree(newTreeAPI(t), 3)
	fs := revalidateFS(t, a, Options{})
	ctx := context.Background()

	if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	_, listings0, _ := a.counts()
	ageListing(t, fs, "/dir", 40*time.Second)
	a.mu.Lock()
	a.failListings = true
	a.mu.Unlock()

	if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
		t.Fatal(err)
	}
	waitListings(t, a, listings0+1)
	eventuallyTrue(t, "the failed fetch to end", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()

		return len(fs.inflight) == 0
	})
	for range 3 {
		if _, err := fs.ReadDir(ctx, "dr1", "/dir"); err != nil {
			t.Fatal(err)
		}
		mustLookup(t, fs, "/dir", "f1", "f-1")
	}
	fs.mu.Lock()
	inflight := len(fs.inflight)
	fs.mu.Unlock()
	if _, listings, _ := a.counts(); listings != listings0+1 || inflight != 0 {
		t.Errorf("after a failure: %d listings, %d in flight; want 1, 0", listings-listings0, inflight)
	}
}

// A capped listing of lookups by name in flight stays capped: a request the
// folder's listing answers meanwhile does not join it.
func TestRevalidate_LeavesACappedListingCapped(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	a.claimTotal = map[string]int{"d-a": maxListingAhead + 1}
	fs := revalidateFS(t, a, Options{})
	mustLookup(t, fs, "/", "a", "d-a")

	arrived, release := a.holdNextListing()
	defer release()
	mustMiss(t, fs, "/a", "n0")
	mustMiss(t, fs, "/a", "n1")
	waitArrived(t, arrived)
	// A listing past the threshold lands meanwhile (another instance).
	listing := &Listing{FetchedAt: time.Now().Add(-40 * time.Second)}
	if err := fs.store.PutListing(context.Background(), key("dr1", "/a"), listing); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadDir(context.Background(), "dr1", "/a"); err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	f := fs.inflight[key("dr1", "/a")]
	capped := f != nil && f.capped
	fs.mu.Unlock()
	if !capped {
		t.Error("the capped listing in flight lost its cap")
	}
}

// waitArrived waits for the listing held to reach the API.
func waitArrived(t *testing.T, arrived <-chan struct{}) {
	t.Helper()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("no listing reached the API")
	}
}

// eventuallyTrue waits until cond holds.
func eventuallyTrue(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
