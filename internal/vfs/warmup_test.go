package vfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// warmTree is a dataroom of four folders and three files, and a symbolic
// link the walk must not follow.
var warmTree = map[string][]service.DataroomNodeInfo{
	"/": {
		{ID: "a", Name: "a", Type: "dir"}, {ID: "c", Name: "c", Type: "dir"},
		{ID: "f1", Name: "f1", Type: "file"}, {ID: "l", Name: "l", Type: "symlink"},
	},
	"/a":   {{ID: "b", Name: "b", Type: "dir"}, {ID: "f2", Name: "f2", Type: "file"}},
	"/a/b": {{ID: "f3", Name: "f3", Type: "file"}},
	"/c":   {},
}

// After a walk, every folder is answered from the cache.
func TestWarmup_FillsTheCache(t *testing.T) {
	listFn, calls := countingListFn(warmTree)
	fs := New(nil, Options{List: listFn})
	before := testutil.ToFloat64(metrics.WarmupFolders.WithLabelValues("ok"))

	stats := fs.Warmup(context.Background(), "dr1", 0)
	if stats.Folders != 4 || stats.Files != 3 || stats.Errors != 0 || stats.Interrupted {
		t.Errorf("stats = %+v, want 4 folders, 3 files, no error", stats)
	}
	if n := atomic.LoadInt32(calls); n != 4 {
		t.Errorf("%d listings for 4 folders", n)
	}
	if got := testutil.ToFloat64(metrics.WarmupFolders.WithLabelValues("ok")) - before; got != 4 {
		t.Errorf("retycfs_warmup_folders_total{result=ok} += %v, want 4", got)
	}
	for p := range warmTree {
		if _, err := fs.ReadDir(context.Background(), "dr1", p); err != nil {
			t.Fatalf("ReadDir(%s): %v", p, err)
		}
	}
	if n := atomic.LoadInt32(calls); n != 4 {
		t.Errorf("ReadDir after the warmup made %d listings, want none", n-4)
	}
}

// A listing still fresh is not fetched again: a second walk, or the walk of
// an instance sharing the store with one that walked, costs no listing.
func TestWarmup_SkipsFreshListings(t *testing.T) {
	store := memstore.New()
	listA, callsA := countingListFn(warmTree)
	a := New(nil, Options{List: listA, Store: store})
	if stats := a.Warmup(context.Background(), "dr1", 0); stats.Folders != 4 {
		t.Fatalf("first walk: %+v", stats)
	}
	if stats := a.Warmup(context.Background(), "dr1", 0); stats.Folders != 4 || atomic.LoadInt32(callsA) != 4 {
		t.Errorf("second walk: %+v, %d listings in all, want 4", stats, atomic.LoadInt32(callsA))
	}

	listB, callsB := countingListFn(warmTree)
	b := New(nil, Options{List: listB, Store: store})
	if stats := b.Warmup(context.Background(), "dr1", 0); stats.Folders != 4 || stats.Files != 3 {
		t.Errorf("walk sharing the store: %+v", stats)
	}
	if n := atomic.LoadInt32(callsB); n != 0 {
		t.Errorf("walk sharing a warm store made %d listings, want none", n)
	}
}

// A folder that cannot be listed is counted and told, its subtree skipped,
// and the walk goes on with the others.
func TestWarmup_AFailingFolderDoesNotStopTheWalk(t *testing.T) {
	var logs []string
	var logMu sync.Mutex
	fs := New(nil, Options{
		List: func(_ context.Context, _, p string) ([]service.DataroomNodeInfo, error) {
			if p == "/a" {
				return nil, errors.New("boom")
			}

			return warmTree[p], nil
		},
		Logf: func(format string, args ...any) {
			logMu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			logMu.Unlock()
		},
	})
	before := testutil.ToFloat64(metrics.WarmupFolders.WithLabelValues("error"))

	stats := fs.Warmup(context.Background(), "dr1", 0)
	// /a fails, /a/b is never reached; / and /c are listed.
	if stats.Folders != 2 || stats.Errors != 1 || stats.Files != 1 || stats.Interrupted {
		t.Errorf("stats = %+v, want 2 folders, 1 file, 1 error", stats)
	}
	if got := testutil.ToFloat64(metrics.WarmupFolders.WithLabelValues("error")) - before; got != 1 {
		t.Errorf("retycfs_warmup_folders_total{result=error} += %v, want 1", got)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "dr1") || strings.Contains(logs[0], "/a") {
		t.Errorf("logs = %q, want one line naming the dataroom, never the path", logs)
	}
}

// A lost login stops the walk: every listing after it would fail the same way.
func TestWarmup_StopsOnALostLogin(t *testing.T) {
	var calls atomic.Int32
	fs := New(nil, Options{
		ListConcurrency: 1,
		List: func(_ context.Context, _, p string) ([]service.DataroomNodeInfo, error) {
			calls.Add(1)
			if p == "/" {
				return warmTree[p], nil
			}

			return nil, fmt.Errorf("listing: %w", auth.ErrNoRefreshToken)
		},
	})
	stats := fs.Warmup(context.Background(), "dr1", 0)
	if !stats.Interrupted || stats.Errors != 1 || calls.Load() != 2 {
		t.Errorf("stats = %+v after %d listings, want the walk interrupted at the first failure", stats, calls.Load())
	}
}

// maxDepth bounds the levels listed, the root being the first.
func TestWarmup_Depth(t *testing.T) {
	for depth, want := range map[int]int{1: 1, 2: 3, 3: 4, 0: 4} {
		listFn, calls := countingListFn(warmTree)
		fs := New(nil, Options{List: listFn})
		stats := fs.Warmup(context.Background(), "dr1", depth)
		if listed := int(atomic.LoadInt32(calls)); stats.Folders != want || listed != want {
			t.Errorf("depth %d: %+v after %d listings, want %d folders", depth, stats, listed, want)
		}
	}
}

// Without a dataroom, every dataroom of the user is walked.
func TestWarmup_AllDatarooms(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	fs := New(nil, Options{List: func(_ context.Context, id, p string) ([]service.DataroomNodeInfo, error) {
		mu.Lock()
		seen[id]++
		mu.Unlock()

		return warmTree[p], nil
	}})
	fs.SeedDatarooms([]Dataroom{{ID: "dr1", Title: "one"}, {ID: "dr2", Title: "two"}})

	if stats := fs.Warmup(context.Background(), "", 0); stats.Folders != 8 || stats.Errors != 0 {
		t.Errorf("stats = %+v, want 8 folders", stats)
	}
	if seen["dr1"] != 4 || seen["dr2"] != 4 {
		t.Errorf("listings per dataroom = %v, want 4 each", seen)
	}
}

// The walk never runs more listings at once than Options.ListConcurrency,
// the refreshes of expired listings included.
func TestWarmup_BoundedByListConcurrency(t *testing.T) {
	const limit = 2
	wide := map[string][]service.DataroomNodeInfo{"/": nil}
	for i := range 20 {
		name := fmt.Sprintf("d%02d", i)
		wide["/"] = append(wide["/"], service.DataroomNodeInfo{ID: name, Name: name, Type: "dir"})
		wide["/"+name] = nil
	}
	var running, peak atomic.Int32
	fs := New(nil, Options{
		ListConcurrency: limit,
		List: func(_ context.Context, _, p string) ([]service.DataroomNodeInfo, error) {
			n := running.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			running.Add(-1)

			return wide[p], nil
		},
	})
	if stats := fs.Warmup(context.Background(), "dr1", 0); stats.Folders != 21 {
		t.Fatalf("stats = %+v, want 21 folders", stats)
	}
	if got := peak.Load(); got > limit {
		t.Errorf("%d listings at once, want at most %d", got, limit)
	}
}

// The end of the context stops the walk, without an error, and Warmup
// returns without waiting for the listings in flight.
func TestWarmup_Cancelled(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	started := make(chan struct{}, 8)
	fs := New(nil, Options{List: func(_ context.Context, _, p string) ([]service.DataroomNodeInfo, error) {
		if p == "/" {
			return warmTree[p], nil
		}
		started <- struct{}{}
		<-gate

		return warmTree[p], nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan WarmupStats, 1)
	go func() { result <- fs.Warmup(ctx, "dr1", 0) }()
	<-started
	cancel()
	select {
	case stats := <-result:
		if !stats.Interrupted || stats.Errors != 0 || stats.Folders != 1 {
			t.Errorf("stats = %+v, want the walk interrupted after the root, no error", stats)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Warmup did not return once its context ended")
	}
}

// A request for a folder the walk is fetching joins the fetch, and does not
// wait for a refresh slot: the walk never makes a request slower.
func TestWarmup_ARequestJoinsTheWalk(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan string, 8)
	var calls atomic.Int32
	fs := New(nil, Options{
		ListConcurrency: 1,
		List: func(_ context.Context, _, p string) ([]service.DataroomNodeInfo, error) {
			calls.Add(1)
			if p != "/" {
				started <- p
				<-gate
			}

			return warmTree[p], nil
		},
	})
	done := make(chan WarmupStats, 1)
	go func() { done <- fs.Warmup(context.Background(), "dr1", 0) }()
	// The one slot is held by the walk's listing of /a; /c is queued behind it.
	if p := <-started; p != "/a" {
		t.Fatalf("first folder walked: %s", p)
	}
	read := make(chan error, 1)
	go func() {
		_, err := fs.ReadDir(context.Background(), "dr1", "/c")
		read <- err
	}()
	select {
	case p := <-started:
		if p != "/c" {
			t.Fatalf("the request started a listing of %s", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request waited for the slot the walk holds")
	}
	close(gate)
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if stats := <-done; stats.Folders != 4 || calls.Load() != 4 {
		t.Errorf("stats = %+v after %d listings, want each folder listed once", stats, calls.Load())
	}
}
