package vfs

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/core/service"
)

// countingLister is an Options.List that counts the listings asked, per
// dataroom and folder, and answers empty folders.
type countingLister struct {
	mu    sync.Mutex
	calls map[ListingKey]int
}

func (l *countingLister) list(_ context.Context, dataroomID, path string) ([]service.DataroomNodeInfo, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.calls == nil {
		l.calls = make(map[ListingKey]int)
	}
	l.calls[ListingKey{DataroomID: dataroomID, Path: path}]++

	return nil, nil
}

func (l *countingLister) count(dataroomID, path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.calls[ListingKey{DataroomID: dataroomID, Path: path}]
}

// readAll lists every folder of keys, failing the test on an error.
func readAll(t *testing.T, fs *FS, keys []ListingKey) {
	t.Helper()
	for _, k := range keys {
		if _, err := fs.ReadDir(context.Background(), k.DataroomID, k.Path); err != nil {
			t.Fatalf("ReadDir(%s, %s): %v", k.DataroomID, k.Path, err)
		}
	}
}

// InvalidateSubtree makes the folder and those below it listed again, and
// none beside it.
func TestFS_InvalidateSubtreeRefetchesBelowOnly(t *testing.T) {
	lister := &countingLister{}
	fs := New(nil, Options{TTL: time.Minute, List: lister.list})
	keys := []ListingKey{
		{DataroomID: "dr1", Path: "/"},
		{DataroomID: "dr1", Path: "/a"},
		{DataroomID: "dr1", Path: "/a/b"},
		{DataroomID: "dr1", Path: "/c"},
		{DataroomID: "dr1", Path: "/ab"},
		{DataroomID: "dr2", Path: "/a"},
	}
	readAll(t, fs, keys)
	fs.InvalidateSubtree("dr1", "/a")
	readAll(t, fs, keys)

	want := map[ListingKey]int{
		{DataroomID: "dr1", Path: "/"}: 1, {DataroomID: "dr1", Path: "/a"}: 2, {DataroomID: "dr1", Path: "/a/b"}: 2,
		{DataroomID: "dr1", Path: "/c"}: 1, {DataroomID: "dr1", Path: "/ab"}: 1, {DataroomID: "dr2", Path: "/a"}: 1,
	}
	for k, n := range want {
		if got := lister.count(k.DataroomID, k.Path); got != n {
			t.Errorf("%s %s listed %d times, want %d", k.DataroomID, k.Path, got, n)
		}
	}
}

// InvalidateAll makes the list of datarooms and every listing of the
// datarooms it names fetched again, and keeps the sessions.
func TestFS_InvalidateAllRefetches(t *testing.T) {
	lister := &countingLister{}
	var listed atomic.Int32
	fs := New(nil, Options{
		TTL: time.Minute, MaxStale: time.Minute, List: lister.list,
		ListDatarooms: func(context.Context) ([]Dataroom, error) {
			listed.Add(1)

			return []Dataroom{{ID: "dr1", Title: "One"}, {ID: "dr2", Title: "Two"}}, nil
		},
	})
	fs.SeedSession("dr1", &service.DataroomSession{})
	ctx := context.Background()
	if _, err := fs.Datarooms(ctx); err != nil {
		t.Fatal(err)
	}
	keys := []ListingKey{{DataroomID: "dr1", Path: "/"}, {DataroomID: "dr1", Path: "/a/b"}, {DataroomID: "dr2", Path: "/"}}
	readAll(t, fs, keys)

	fs.InvalidateAll()

	if _, err := fs.DataroomByName(ctx, "Two"); err != nil {
		t.Fatal(err)
	}
	if n := listed.Load(); n != 2 {
		t.Errorf("datarooms listed %d times, want 2: the list held was forgotten", n)
	}
	readAll(t, fs, keys)
	for _, k := range keys {
		if got := lister.count(k.DataroomID, k.Path); got != 2 {
			t.Errorf("%s %s listed %d times, want 2", k.DataroomID, k.Path, got)
		}
	}
	if n := fs.SessionsCached(); n != 1 {
		t.Errorf("SessionsCached = %d after InvalidateAll, want 1: sessions are kept", n)
	}
}

// A fetch of the list of datarooms in flight when the list is invalidated
// answers those waiting for it, and is not kept: the next request fetches
// again.
func TestDataroomCache_InvalidateDiscardsFetchInFlight(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	fs := New(nil, Options{
		TTL: time.Minute, MaxStale: time.Minute,
		ListDatarooms: func(context.Context) ([]Dataroom, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-release

				return []Dataroom{{ID: "old", Title: "Old"}}, nil
			}

			return []Dataroom{{ID: "new", Title: "New"}}, nil
		},
	})
	ctx := context.Background()
	first := make(chan []DataroomInfo, 1)
	go func() {
		list, _ := fs.Datarooms(ctx)
		first <- list
	}()
	<-started
	fs.InvalidateAll()
	close(release)
	if got := <-first; len(got) != 1 || got[0].ID != "old" {
		t.Errorf("first Datarooms = %+v, want its own answer, old", got)
	}

	list, err := fs.Datarooms(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(list))
	for i, d := range list {
		ids[i] = d.ID
	}
	if !slices.Equal(ids, []string{"new"}) {
		t.Errorf("Datarooms after the invalidation = %v, want new", ids)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("listed %d times, want 2", n)
	}
}
