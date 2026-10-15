package vfs

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// logRecorder collects what an FS reports through Options.Logf.
type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (l *logRecorder) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logRecorder) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.lines...)
}

// The counters are fetched once per TTL and per dataroom.
func TestQuota_CachedForTheTTL(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.String() != "GET /dataroom/dr1/stats" {
			return false
		}
		fmt.Fprint(w, `{"dataroom_id":"dr1","files_count":1,"versions_count":1,"files_encrypted_size":9,`+
			`"allowed_storage_size":1000,"storage_capacity":null,"storage_used":9,"storage_free":991}`)

		return true
	}}
	fs := newAPIFS(t, fake, Options{TTL: 20 * time.Millisecond}, nil)
	ctx := context.Background()

	for range 3 {
		if used, free, ok := fs.Quota(ctx, "dr1"); !ok || used != 9 || free != 991 {
			t.Fatalf("Quota = (%d, %d, %v), want (9, 991, true)", used, free, ok)
		}
	}
	if got := len(fake.list()); got != 1 {
		t.Errorf("stats fetched %d times, want 1 within the TTL", got)
	}
	time.Sleep(30 * time.Millisecond)
	if _, _, ok := fs.Quota(ctx, "dr1"); !ok {
		t.Fatal("Quota failed past the TTL")
	}
	if got := len(fake.list()); got != 2 {
		t.Errorf("stats fetched %d times, want 2 once the TTL is over", got)
	}
}

// Counters the API does not report, or could not be asked for, are no quota.
// A failed fetch is told to the operator and kept for the TTL like an answer:
// a listing asks the quota of every sub-folder, and an API that fails must
// not be asked, nor its failure logged, once per sub-folder.
func TestQuota_Unavailable(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, _ apiCall) bool {
		fmt.Fprint(w, `{"dataroom_id":"dr1","files_count":1,"storage_free":0}`)

		return true
	}}
	var logs logRecorder
	fs := newAPIFS(t, fake, Options{Logf: logs.logf}, nil)
	if _, _, ok := fs.Quota(context.Background(), "dr1"); ok {
		t.Error("Quota reported counters an older API does not have")
	}
	if got := logs.list(); len(got) != 0 {
		t.Errorf("logged %v for an API without counters, want nothing", got)
	}

	if got := len(fake.list()); got != 1 {
		t.Errorf("stats fetched %d times, want 1", got)
	}
	if _, _, ok := fs.Quota(context.Background(), "dr1"); ok || len(fake.list()) != 1 {
		t.Errorf("an API without counters was asked again within the TTL: %v", fake.list())
	}

	fake = &fakeAPI{reply: status(http.StatusInternalServerError, "boom")}
	fs = newAPIFS(t, fake, Options{Logf: logs.logf, TTL: 40 * time.Millisecond}, nil)
	for range 20 {
		if _, _, ok := fs.Quota(context.Background(), "dr1"); ok {
			t.Error("Quota reported counters from a failed fetch")
		}
	}
	if got := logs.list(); len(got) != 1 || !strings.HasPrefix(got[0], "dataroom quota: ") {
		t.Errorf("logged %v, want the failure once for the TTL", got)
	}
	if got := len(fake.list()); got != 1 {
		t.Errorf("stats fetched %d times within the TTL, want 1", got)
	}
	// Another dataroom is another window.
	if _, _, ok := fs.Quota(context.Background(), "dr2"); ok || len(logs.list()) != 2 {
		t.Errorf("a second dataroom: logged %v, want its own failure", logs.list())
	}
	// Once the TTL is over the API is asked again, and the failure told again.
	time.Sleep(60 * time.Millisecond)
	if _, _, ok := fs.Quota(context.Background(), "dr1"); ok {
		t.Error("Quota reported counters from a failed fetch")
	}
	if got := logs.list(); len(got) != 3 {
		t.Errorf("logged %v, want the failure again past the TTL", got)
	}
	// Without Logf the failure is silent, not a panic.
	fs = newAPIFS(t, fake, Options{}, nil)
	if _, _, ok := fs.Quota(context.Background(), "dr1"); ok {
		t.Error("Quota reported counters from a failed fetch")
	}
}
