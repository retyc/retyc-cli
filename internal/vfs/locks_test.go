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
)

// lockAPI fakes the lock routes of the file n-doc: each lock taken gets the
// next ID ("l-1", "l-2", ...) and the token "tok-<id>".
type lockAPI struct {
	fakeAPI
	taken atomic.Int32
	// refuse is the status answered to the next lock creations, 0 to accept.
	refuse atomic.Int32
	// lost is the status answered to a refresh, 0 to accept: 404 or 410 for a
	// lease that ended.
	lost atomic.Int32
}

func newLockAPI() *lockAPI {
	a := &lockAPI{}
	a.reply = func(w http.ResponseWriter, call apiCall) bool {
		switch {
		case call.String() == "POST /dataroom/node/n-doc/lock":
			if code := a.refuse.Load(); code != 0 {
				http.Error(w, `{"detail":"Another lock excludes this one"}`, int(code))

				return true
			}
			id := fmt.Sprintf("l-%d", a.taken.Add(1))
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":%q,"node_id":"n-doc","kind":"exclusive","token":"tok-%s"}`, id, id)
		case call.method == http.MethodPut && strings.HasPrefix(call.path, "/dataroom/node/lock/"):
			if code := a.lost.Load(); code != 0 {
				http.Error(w, "lease ended", int(code))

				return true
			}
			id := strings.TrimPrefix(call.path, "/dataroom/node/lock/")
			fmt.Fprintf(w, `{"id":%q,"node_id":"n-doc","kind":"exclusive"}`, id)
		case call.method == http.MethodDelete && strings.HasPrefix(call.path, "/dataroom/node/lock/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			return false
		}

		return true
	}

	return a
}

func newLockFS(t *testing.T, opts Options) (*LockManager, *lockAPI) {
	t.Helper()
	fake := newLockAPI()

	return newAPIFS(t, &fake.fakeAPI, opts, nil).Locks(), fake
}

// A lock is taken at the longest lease, renewed and released under the key its
// front end gave it.
func TestLocks_TakeRefreshRelease(t *testing.T) {
	locks, fake := newLockFS(t, Options{})
	ctx := context.Background()

	if err := locks.Take(ctx, "key-1", "n-doc", "label", time.Time{}); err != nil {
		t.Fatalf("Take: %v", err)
	}
	take := fake.only("POST")
	if locks.Held() != 1 || len(take) != 1 || take[0].body["kind"] != api.LockExclusive ||
		take[0].body["timeout"] != float64(api.LockTimeoutMax) {
		t.Fatalf("held = %d, requests = %+v, want one exclusive lock at the longest lease", locks.Held(), take)
	}

	locks.Refresh(ctx, "key-1", "n-doc", "label", time.Time{})
	locks.Release(ctx, "key-1")
	locks.Release(ctx, "key-1") // nothing left: no request
	want := []string{"POST /dataroom/node/n-doc/lock", "PUT /dataroom/node/lock/l-1", "DELETE /dataroom/node/lock/l-1"}
	if got := fake.list(); locks.Held() != 0 || !slices.Equal(got, want) {
		t.Errorf("held = %d, requests = %v, want %v", locks.Held(), got, want)
	}
}

// A file another client holds refuses the lock with the API's error, and
// nothing is held.
func TestLocks_TakeRefused(t *testing.T) {
	locks, fake := newLockFS(t, Options{})
	fake.refuse.Store(http.StatusLocked)
	err := locks.Take(context.Background(), "key-1", "n-doc", "label", time.Time{})
	if !errors.Is(err, api.ErrLocked) || locks.Held() != 0 {
		t.Errorf("Take = %v, held = %d; want api.ErrLocked and nothing held", err, locks.Held())
	}
}

// The API holds one lock per token: a lock still held for the node under
// another key (its front-end lock lapsed in silence) is released before the
// new one is taken, instead of refusing it.
func TestLocks_TakeReleasesStaleLocksOfTheNode(t *testing.T) {
	locks, fake := newLockFS(t, Options{})
	ctx := context.Background()
	if err := locks.Take(ctx, "old-key", "n-doc", "label", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := locks.Take(ctx, "new-key", "n-doc", "label", time.Time{}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /dataroom/node/n-doc/lock", "DELETE /dataroom/node/lock/l-1", "POST /dataroom/node/n-doc/lock",
	}
	if got := fake.list(); locks.Held() != 1 || !slices.Equal(got, want) {
		t.Errorf("held = %d, requests = %v, want %v", locks.Held(), got, want)
	}
}

// A lock whose front-end lock lapsed without being released stops being
// renewed: its API lock is released. One that stands is renewed.
// (Migrated from cmd TestLockMirror_ReleasesLapsedLocks.)
func TestLocks_RefreshAllReleasesLapsedLocks(t *testing.T) {
	locks, fake := newLockFS(t, Options{})
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	if err := locks.Take(ctx, "key-1", "n-doc", "label", expires); err != nil {
		t.Fatal(err)
	}

	locks.RefreshAll(ctx)
	if locks.Held() != 1 || len(fake.only("PUT /dataroom/node/lock/l-1")) != 1 {
		t.Fatalf("a standing lock: held = %d, requests = %v, want it renewed", locks.Held(), fake.list())
	}

	locks.mu.Lock()
	for _, held := range locks.locks {
		if !held.expires.Equal(expires) {
			t.Errorf("expiry = %v, want the one given to Take", held.expires)
		}
		held.expires = time.Now().Add(-time.Second)
	}
	locks.mu.Unlock()
	locks.RefreshAll(ctx)
	if locks.Held() != 0 || len(fake.only("DELETE /dataroom/node/lock/l-1")) != 1 {
		t.Errorf("a lapsed lock: held = %d, requests = %v, want it released", locks.Held(), fake.list())
	}
}

// A refresh from the front end records the new expiry of its lock.
func TestLocks_RefreshRecordsTheExpiry(t *testing.T) {
	locks, _ := newLockFS(t, Options{})
	ctx := context.Background()
	if err := locks.Take(ctx, "key-1", "n-doc", "label", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	locks.Refresh(ctx, "key-1", "n-doc", "label", time.Now().Add(-time.Second))
	locks.RefreshAll(ctx)
	if locks.Held() != 0 {
		t.Error("a lock refreshed with an expiry in the past is still held after RefreshAll")
	}
}

// The periodic renewal never takes a lock for a key released since it was
// read. (Migrated from cmd TestLockMirror_BackgroundRefreshSkipsReleasedToken.)
func TestLocks_BackgroundRefreshSkipsReleasedKey(t *testing.T) {
	locks, fake := newLockFS(t, Options{})

	locks.refresh(context.Background(), "gone", "n-doc", "label", time.Time{}, true)
	if locks.Held() != 0 || len(fake.list()) != 0 {
		t.Errorf("held = %d, requests = %v, want nothing taken", locks.Held(), fake.list())
	}
}

// A refresh from the front end takes the lock that could not be taken before.
func TestLocks_RefreshTakesAMissingLock(t *testing.T) {
	locks, fake := newLockFS(t, Options{})
	locks.Refresh(context.Background(), "key-1", "n-doc", "label", time.Time{})
	if locks.Held() != 1 || !slices.Equal(fake.list(), []string{"POST /dataroom/node/n-doc/lock"}) {
		t.Errorf("held = %d, requests = %v, want the lock taken", locks.Held(), fake.list())
	}
}

// A lease that ended (404, or 410) is taken again; when the API then refuses,
// the lock is forgotten and the operator told, by the label the front end gave.
func TestLocks_LostLeaseIsRetakenOrForgotten(t *testing.T) {
	for _, code := range []int32{http.StatusNotFound, http.StatusGone} {
		var logs logRecorder
		locks, fake := newLockFS(t, Options{Logf: logs.logf})
		ctx := context.Background()
		if err := locks.Take(ctx, "key-1", "n-doc", "the label", time.Time{}); err != nil {
			t.Fatal(err)
		}
		fake.lost.Store(code)

		locks.RefreshAll(ctx)
		if locks.Held() != 1 || len(fake.only("POST")) != 2 || len(logs.list()) != 0 {
			t.Fatalf("%d: held = %d, requests = %v, logs = %v; want the lock retaken in silence",
				code, locks.Held(), fake.list(), logs.list())
		}

		fake.refuse.Store(http.StatusLocked)
		locks.RefreshAll(ctx)
		if locks.Held() != 0 {
			t.Errorf("%d: a lock the API refused to retake is still held", code)
		}
		if got := logs.list(); len(got) != 1 || !strings.HasPrefix(got[0], "LOCK the label: server lock not retaken: ") {
			t.Errorf("%d: logs = %v, want the refusal, named by the label", code, got)
		}
	}
}

// A refresh the API fails for another reason keeps the lock and tells the
// operator.
func TestLocks_FailedRefreshKeepsTheLock(t *testing.T) {
	var logs logRecorder
	locks, fake := newLockFS(t, Options{Logf: logs.logf})
	ctx := context.Background()
	if err := locks.Take(ctx, "key-1", "n-doc", "the label", time.Time{}); err != nil {
		t.Fatal(err)
	}
	fake.lost.Store(http.StatusInternalServerError)
	locks.RefreshAll(ctx)
	if got := logs.list(); locks.Held() != 1 || len(fake.only("POST")) != 1 ||
		len(got) != 1 || !strings.HasPrefix(got[0], "LOCK the label: server lock not refreshed: ") {
		t.Errorf("held = %d, requests = %v, logs = %v; want the lock kept and the failure logged",
			locks.Held(), fake.list(), got)
	}
}

// Run releases every lock when its context ends.
func TestLocks_RunReleasesAllOnShutdown(t *testing.T) {
	locks, fake := newLockFS(t, Options{})
	if err := locks.Take(context.Background(), "key-1", "n-doc", "label", time.Time{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { locks.Run(ctx); close(done) }()
	cancel()
	<-done
	if locks.Held() != 0 || len(fake.only("DELETE /dataroom/node/lock/l-1")) != 1 {
		t.Errorf("held = %d, requests = %v, want the lock released", locks.Held(), fake.list())
	}
}
