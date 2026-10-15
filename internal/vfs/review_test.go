package vfs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// — Rename with replace —————————————————————————————————————————————————————————

// A probe of the API that fails says nothing of it: a rename asked to replace
// returns that failure as it is, a rate limit staying one, where it used to
// pass for an API that cannot replace. Nothing is renamed.
func TestRename_ReplaceReturnsTheProbeFailure(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
			if call.String() != "GET /dataroom/dr1/mime-types" {
				return false
			}
			http.Error(w, "No more requests allowed", code)

			return true
		}}
		fs := newAPIFS(t, fake, Options{}, tree())

		err := fs.Rename(context.Background(), "dr1", "/doc.txt", "/old.txt", true)
		if err == nil || errors.Is(err, ErrReplaceUnsupported) || errors.Is(err, service.ErrReplaceUnsupported) {
			t.Errorf("%d: Rename(replace) = %v, want the failure of the probe", code, err)
		}
		if limited := errors.Is(err, api.ErrRateLimited); limited != (code == http.StatusTooManyRequests) {
			t.Errorf("%d: Rename(replace) = %v, rate limited = %v", code, err, limited)
		}
		if code == http.StatusTooManyRequests && !carriesNoSentinel(err) {
			t.Errorf("Rename(replace) = %v, want the rate limit without a sentinel", err)
		}
		var httpErr *api.HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != code {
			t.Errorf("%d: Rename(replace) = %v, want the API's answer in the chain", code, err)
		}
		if len(fake.only("PUT")) != 0 {
			t.Errorf("%d: requests = %v, want no PUT", code, fake.list())
		}
	}
}

// Two replaces of one destination that cross: the API answers one of them 409
// without naming a folder. It is tried once more; a second 409 is ErrExist.
func TestRename_ReplaceRetriesAConflictOnce(t *testing.T) {
	for label, conflicts := range map[string]int32{"the other replace has landed": 1, "still taken": 2} {
		t.Run(label, func(t *testing.T) {
			var left atomic.Int32
			left.Store(conflicts)
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				switch {
				case call.String() == "GET /dataroom/dr1/mime-types":
					mimeTable(w, false)
				case call.method == http.MethodPut && left.Add(-1) >= 0:
					http.Error(w, `{"detail":"Duplicate node name hash in the same folder"}`, http.StatusConflict)
				case call.method == http.MethodPut:
					w.WriteHeader(http.StatusNoContent)
				default:
					return false
				}

				return true
			}}
			fs := newAPIFS(t, fake, Options{}, tree())

			err := fs.Rename(context.Background(), "dr1", "/doc.txt", "/old.txt", true)
			if conflicts == 1 && err != nil {
				t.Errorf("Rename(replace) = %v, want the second attempt to pass", err)
			}
			if conflicts == 2 && (!errors.Is(err, ErrExist) || !errors.Is(err, api.ErrConflict)) {
				t.Errorf("Rename(replace) = %v, want ErrExist carrying the 409", err)
			}
			if got := len(fake.only("PUT")); got != 2 {
				t.Errorf("%d PUT(s) %v, want 2: one retry, no more", got, fake.list())
			}
		})
	}
}

// A replace onto a folder is ErrIsDir whatever the listings: the answer names
// the folder, there is nothing to resolve again. The destination is in a
// sub-folder here, where a 409 used to have the folder listed afresh, and the
// failure of that listing took the place of ErrIsDir.
func TestRename_ReplaceOntoAFolderSkipsTheStaleCheck(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		switch {
		case call.String() == "GET /dataroom/dr1/mime-types":
			mimeTable(w, false)
		case call.method == http.MethodPut:
			http.Error(w, `{"detail":"Cannot replace a folder"}`, http.StatusConflict)
		default:
			return false // a listing would answer 500
		}

		return true
	}}
	listings := tree()
	listings["/full"] = append(listings["/full"], service.DataroomNodeInfo{ID: "d-sub", Name: "sub", Type: "dir"})
	fs := newAPIFS(t, fake, Options{}, listings)

	err := fs.Rename(context.Background(), "dr1", "/doc.txt", "/full/sub", true)
	if !errors.Is(err, ErrIsDir) || !errors.Is(err, api.ErrConflict) {
		t.Errorf("Rename(replace) onto a folder = %v, want ErrIsDir carrying the 409", err)
	}
	if got := fake.list(); len(fake.only("PUT")) != 1 || len(fake.only("GET /dataroom/dr1/nodes")) != 0 {
		t.Errorf("requests = %v, want one PUT and no listing", got)
	}
	if !nodeCacheHas(fs, "dr1", "/") {
		t.Error("the root listing was dropped for a conflict that is not stale")
	}
}

// — Copy ————————————————————————————————————————————————————————————————————————

// Only a destination that does not exist is free. When its lookup fails,
// nothing is known of it: the copy is not sent, the failure is the one of the
// destination step, and a rate limit crosses bare.
func TestCopy_DestinationLookupFailureIsNotAFreeName(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
			switch call.String() {
			case "GET /dataroom/dr1/mime-types":
				mimeTable(w, true) // the destination is looked up by listing its folder
			case "GET /dataroom/dr1/nodes":
				http.Error(w, "No more requests allowed", code)
			default:
				return false
			}

			return true
		}}
		listings := tree()
		delete(listings, "/full") // the folder of the destination is not cached
		fs := newAPIFS(t, fake, Options{}, listings)

		_, _, err := fs.Copy(context.Background(), "dr1", "/doc.txt", "/full/copy.txt", false)
		if len(fake.only("POST")) != 0 {
			t.Fatalf("%d: requests = %v, want no copy sent", code, fake.list())
		}
		var failed *CopyError
		switch code {
		case http.StatusTooManyRequests:
			if !errors.Is(err, api.ErrRateLimited) || errors.As(err, &failed) {
				t.Errorf("Copy = %v, want the bare rate limit", err)
			}
		default:
			var httpErr *api.HTTPError
			if !errors.As(err, &failed) || failed.Step != CopyDestination || !errors.As(err, &httpErr) ||
				errors.Is(err, ErrExist) || errors.Is(err, ErrIsDir) || errors.Is(err, ErrSameNode) {
				t.Errorf("Copy = %v (%+v), want the API's failure at the destination step", err, failed)
			}
		}
	}
}

// — Options.Logf ————————————————————————————————————————————————————————————————

// Options.Logf is the caller's code: it is called once the FS has released
// its lock, so it may call back into the FS.
func TestFS_LogfIsCalledOutsideTheLock(t *testing.T) {
	store := &flakyStore{Store: memstore.New()}
	store.failWrites.Store(true)
	var fs *FS
	called := make(chan struct{}, 4)
	fs = New(nil, Options{Store: store, Logf: func(string, ...any) {
		// Both take the lock: under it, this would never return.
		fs.InvalidateListing("dr1", "/elsewhere")
		_, _ = fs.cachedFileID("dr1", "/", "x")
		called <- struct{}{}
	}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		fs.InvalidateListing("dr1", "/")
		fs.upsert("dr1", "/", Node{ID: "n", Name: "n", Type: TypeFile})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the FS called Options.Logf with its lock held")
	}
	if len(called) != 1 {
		t.Errorf("Logf called %d times, want once", len(called))
	}
}

// — Datarooms ———————————————————————————————————————————————————————————————————

// The FS lists the datarooms, names them apart, resolves a name to its ID and
// keeps the list in its store.
func TestFS_Datarooms(t *testing.T) {
	var calls atomic.Int32
	store := memstore.New()
	fs := New(nil, Options{Store: store, ListDatarooms: func(context.Context) ([]Dataroom, error) {
		calls.Add(1)

		return []Dataroom{{ID: "id-2", Title: "Docs"}, {ID: "id-1", Title: "Docs"}, {ID: "id-0", Title: "Alpha"}}, nil
	}})
	ctx := context.Background()

	list, err := fs.Datarooms(ctx)
	want := []DataroomInfo{
		{ID: "id-0", Title: "Alpha", DisplayName: "Alpha"},
		{ID: "id-1", Title: "Docs", DisplayName: "Docs"},
		{ID: "id-2", Title: "Docs", DisplayName: "Docs (2)"},
	}
	if err != nil || !slices.Equal(list, want) {
		t.Fatalf("Datarooms = (%+v, %v), want %+v", list, err, want)
	}
	list[0].ID = "mine" // the slice is the caller's
	for name, id := range map[string]string{"Alpha": "id-0", "Docs": "id-1", "Docs (2)": "id-2"} {
		if got, err := fs.DataroomByName(ctx, name); err != nil || got != id {
			t.Errorf("DataroomByName(%s) = (%q, %v), want %s", name, got, err, id)
		}
	}
	if _, err := fs.DataroomByName(ctx, "Nothing"); !errors.Is(err, ErrNotExist) {
		t.Errorf("DataroomByName of an unknown name = %v, want ErrNotExist", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("the datarooms were listed %d times, want once for the TTL", got)
	}
	stored, ok, _ := store.GetDatarooms(ctx)
	if !ok || !slices.Equal(stored.Items, want) || stored.FetchedAt.IsZero() {
		t.Errorf("stored list = (%+v, %v), want the list with its display names", stored, ok)
	}

	// A list another process put in the store is the one served.
	_ = store.PutDatarooms(ctx, &metastore.DataroomList{
		Items: []DataroomInfo{{ID: "id-9", Title: "Other", DisplayName: "Other"}}, FetchedAt: time.Now(),
	})
	if got, err := fs.DataroomByName(ctx, "Other"); err != nil || got != "id-9" {
		t.Errorf("DataroomByName after the store changed = (%q, %v), want id-9", got, err)
	}

	// SeedDatarooms stands for a fetch.
	fs.SeedDatarooms([]Dataroom{{ID: "id-s", Title: "Seeded"}})
	if got, err := fs.DataroomByName(ctx, "Seeded"); err != nil || got != "id-s" || calls.Load() != 1 {
		t.Errorf("DataroomByName after a seed = (%q, %v) with %d fetch(es)", got, err, calls.Load())
	}
}

// Without a client nor Options.ListDatarooms there is nothing to list with: an
// error, not a panic.
func TestFS_DataroomsWithoutAClient(t *testing.T) {
	if _, err := New(nil, Options{}).Datarooms(context.Background()); err == nil {
		t.Error("Datarooms succeeded without a client")
	}
}

// By default the datarooms are listed through the API.
func TestFS_DataroomsThroughTheAPI(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.String() != "GET /dataroom" {
			return false
		}
		fmt.Fprint(w, `{"items":[{"id":"dr1","title":"DR"}],"total":1,"pages":1,"page":1}`)

		return true
	}}
	fs := newAPIFS(t, fake, Options{}, nil)
	if id, err := fs.DataroomByName(context.Background(), "DR"); err != nil || id != "dr1" {
		t.Errorf("DataroomByName = (%q, %v), want dr1 (requests %v)", id, err, fake.list())
	}
}

// failingDataroomStore refuses to store the list of datarooms.
type failingDataroomStore struct{ *memstore.Store }

func (failingDataroomStore) PutDatarooms(context.Context, *metastore.DataroomList) error {
	return errStoreDown
}

// A store that refuses the list is set aside like one that refuses a
// listing: the list is served from memory, and the failure reported once.
func TestFS_DataroomStoreFailure(t *testing.T) {
	var logs logRecorder
	var calls atomic.Int32
	fs := New(nil, Options{
		Store: failingDataroomStore{memstore.New()}, Logf: logs.logf,
		ListDatarooms: func(context.Context) ([]Dataroom, error) {
			calls.Add(1)

			return []Dataroom{{ID: "id-1", Title: "Docs"}}, nil
		},
	})
	for range 3 {
		if id, err := fs.DataroomByName(context.Background(), "Docs"); err != nil || id != "id-1" {
			t.Fatalf("DataroomByName = (%q, %v), want id-1", id, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("listed %d times, want 1: the replacement store holds the list", calls.Load())
	}
	if got := logs.list(); len(got) != 1 || !strings.Contains(got[0], errStoreDown.Error()) {
		t.Errorf("logs = %v, want the failure once", got)
	}
}

// — Node.ParentID and Node.CreatedAt ————————————————————————————————————————————

// The nodes the mutations record carry the folder that holds them.
func TestMutations_FillParentID(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		switch {
		case call.String() == "POST /dataroom/dr1/node":
			fmt.Fprint(w, `{"id":"d-new","name_enc":"x"}`)
		case call.method == http.MethodPost:
			copyReply(w) // answers parent_id null, whatever the folder asked
		case call.method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)
		default:
			return false
		}

		return true
	}}
	fs := newAPIFS(t, fake, Options{}, tree())
	ctx := context.Background()

	if n, err := fs.Mkdir(ctx, "dr1", "/full/new"); err != nil || n.ParentID != "d-full" || !n.CreatedAt.IsZero() {
		t.Errorf("Mkdir = (%+v, %v), want it under d-full, its creation time unknown", n, err)
	}
	if n, err := fs.Mkdir(ctx, "dr1", "/top"); err != nil || n.ParentID != "" {
		t.Errorf("Mkdir at the root = (%+v, %v), want no parent ID", n, err)
	}
	if n, _, err := fs.Copy(ctx, "dr1", "/doc.txt", "/full/copy.txt", false); err != nil || n.ParentID != "d-full" {
		t.Errorf("Copy = (%+v, %v), want it under d-full", n, err)
	}
	if err := fs.Rename(ctx, "dr1", "/doc.txt", "/empty/moved.txt", false); err != nil {
		t.Fatal(err)
	}
	n, ok := FindNode(cachedNodes(fs, "dr1", "/empty"), "moved.txt")
	if !ok || n.ParentID != "d-empty" || n.ID != "f-doc" {
		t.Errorf("renamed node = (%+v, %v), want f-doc under d-empty", n, ok)
	}
}

// An upsert that does not know the creation time of the node it writes keeps
// the one its listing gave it, as it keeps the mode; another node under the
// same name keeps nothing.
func TestFS_UpsertKeepsTheCreationTime(t *testing.T) {
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	fs := New(nil, Options{})
	seedNodeCache(fs, map[string]*nodeCacheEntry{"/": {fetchedAt: time.Now()}})
	fs.upsert("dr1", "/", Node{ID: "f-1", Name: "a.txt", Type: TypeFile, CreatedAt: created})

	fs.upsert("dr1", "/", Node{ID: "f-1", Name: "a.txt", Type: TypeFile, VersionID: "v2"})
	if n, _ := FindNode(cachedNodes(fs, "dr1", "/"), "a.txt"); !n.CreatedAt.Equal(created) || n.VersionID != "v2" {
		t.Errorf("node = %+v, want the new version with the creation time kept", n)
	}
	fs.upsert("dr1", "/", Node{ID: "f-2", Name: "a.txt", Type: TypeFile})
	if n, _ := FindNode(cachedNodes(fs, "dr1", "/"), "a.txt"); !n.CreatedAt.IsZero() {
		t.Errorf("node = %+v, want no creation time borrowed from the node it replaced", n)
	}
}
