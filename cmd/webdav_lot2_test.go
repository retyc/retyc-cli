package cmd

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// lot2API fakes the copy, lock and stats routes of one dataroom.
type lot2API struct {
	t  *testing.T
	mu sync.Mutex
	// lockStatus is answered to a lock creation (201 by default).
	lockStatus int
	// copyConflicts is the number of copies answered 409 before one is
	// accepted: a destination deleted and not purged yet.
	copyConflicts int
	calls      []string
	statsCalls int
}

func (a *lot2API) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/n-src/copy":
		if a.copyConflicts > 0 {
			a.copyConflicts--
			http.Error(w, `{"detail":"Duplicate node name hash in the same folder"}`, http.StatusConflict)

			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		parent, _ := body["parent_id"].(string)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"node":{"id":"n-copy","type":"file","name_enc":"x","type_enc":null,"mime_type_id":null,`+
			`"access_mode":"0644","parent_id":%q},"node_version":{"id":"v-copy","node_id":"n-copy",`+
			`"original_size":9,"chunk_count":2,"chunk_count_expected":2,"version_number":1,`+
			`"created_at":"2026-10-10T12:00:00Z"}}`, parent)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/dataroom/node/n-old"):
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/n-doc/lock":
		status := a.lockStatus
		if status == 0 {
			status = http.StatusCreated
		}
		if status != http.StatusCreated {
			http.Error(w, `{"detail":"Another lock excludes this one"}`, status)

			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"l-1","node_id":"n-doc","dataroom_id":"dr1","user_id":"u","kind":"exclusive",`+
			`"expires_at":"2026-10-10T12:05:00Z","created_at":"2026-10-10T12:00:00Z","token":"api-tok"}`)
	case r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/lock/l-1":
		if r.Header.Get("X-Lock-Token") != "api-tok" {
			http.Error(w, "wrong token", http.StatusForbidden)

			return
		}
		fmt.Fprint(w, `{"id":"l-1","node_id":"n-doc","dataroom_id":"dr1","user_id":"u","kind":"exclusive",`+
			`"expires_at":"2026-10-10T12:10:00Z","created_at":"2026-10-10T12:00:00Z"}`)
	case r.Method == http.MethodDelete && r.URL.Path == "/dataroom/node/lock/l-1":
		if r.Header.Get("X-Lock-Token") != "api-tok" {
			http.Error(w, "wrong token", http.StatusForbidden)

			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/stats":
		a.statsCalls++
		fmt.Fprint(w, `{"dataroom_id":"dr1","files_count":1,"versions_count":1,"files_encrypted_size":9,`+
			`"allowed_storage_size":1000,"storage_capacity":null,"storage_used":9,"storage_free":991}`)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
}

func (a *lot2API) count(prefix string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}

	return n
}

// newLot2FS builds a webdavFS over the fake, with a warm session and a root
// listing holding a file, a folder and a file inside that folder.
func newLot2FS(t *testing.T, fake *lot2API) *webdavFS {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fake.handle))
	t.Cleanup(srv.Close)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fs := newWebdavTestFS(srv)
	fs.cache = newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{{id: "dr1", title: "DR"}}, nil
	})
	fs.nodeCache = map[string]*nodeCacheEntry{
		"retyc://dr1/": {
			nodes: []service.DataroomNodeInfo{
				{ID: "n-src", Name: "doc.txt", Type: "file", VersionID: "v-src", Size: 9, ChunkCount: 2},
				{ID: "n-doc", Name: "locked.txt", Type: "file", VersionID: "v-doc"},
				{ID: "n-old", Name: "old.txt", Type: "file", VersionID: "v-old"},
				{ID: "n-dir", Name: "sub", Type: "dir"},
			},
			fetchedAt: time.Now(),
		},
		"retyc://dr1/sub": {nodes: []service.DataroomNodeInfo{}, fetchedAt: time.Now()},
	}
	fs.sessions.Store("dr1", &service.DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()})

	return fs
}

func copyRequest(src, dst string, overwrite string) *http.Request {
	r := httptest.NewRequest("COPY", src, nil)
	r.Header.Set("Destination", dst)
	if overwrite != "" {
		r.Header.Set("Overwrite", overwrite)
	}

	return r
}

// A COPY of a file goes through the server-side copy, answers 201 and lands
// the new node in the destination's cached listing.
func TestHandleCopy_File(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	w := httptest.NewRecorder()

	fs.handleCopy(w, copyRequest("/dataroom/DR/doc.txt", "/dataroom/DR/sub/copy.txt", ""))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s), want 201", w.Code, w.Body.String())
	}
	if fake.count("POST /dataroom/node/n-src/copy") != 1 {
		t.Errorf("calls = %v, want one copy", fake.calls)
	}
	nodes, err := fs.listNodes(context.Background(), "dr1", "/sub")
	if err != nil || len(nodes) != 1 || nodes[0].Name != "copy.txt" || nodes[0].ID != "n-copy" || nodes[0].Size != 9 {
		t.Errorf("destination listing = %+v, %v; want the copy", nodes, err)
	}
}

// A COPY onto an existing file replaces it (204) unless Overwrite: F (412);
// a folder source is refused (501); a missing destination folder is a 409.
func TestHandleCopy_Refusals(t *testing.T) {
	cases := []struct {
		name      string
		src, dst  string
		overwrite string
		want      int
		deletes   int
	}{
		{"overwrite", "/dataroom/DR/doc.txt", "/dataroom/DR/old.txt", "", http.StatusNoContent, 1},
		{"overwrite refused", "/dataroom/DR/doc.txt", "/dataroom/DR/old.txt", "F", http.StatusPreconditionFailed, 0},
		{"folder source", "/dataroom/DR/sub", "/dataroom/DR/sub2", "", http.StatusNotImplemented, 0},
		{"missing destination folder", "/dataroom/DR/doc.txt", "/dataroom/DR/nowhere/x", "", http.StatusConflict, 0},
		{"onto a folder", "/dataroom/DR/doc.txt", "/dataroom/DR/sub", "", http.StatusConflict, 0},
		{"same path", "/dataroom/DR/doc.txt", "/dataroom/DR/doc.txt", "", http.StatusForbidden, 0},
		{"dataroom root", "/dataroom/DR/doc.txt", "/dataroom/DR/", "", http.StatusForbidden, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &lot2API{t: t}
			fs := newLot2FS(t, fake)
			w := httptest.NewRecorder()
			fs.handleCopy(w, copyRequest(tc.src, tc.dst, tc.overwrite))
			if w.Code != tc.want {
				t.Errorf("status = %d (%s), want %d", w.Code, strings.TrimSpace(w.Body.String()), tc.want)
			}
			if got := fake.count("DELETE /dataroom/node/n-old"); got != tc.deletes {
				t.Errorf("old node deleted %d times, want %d", got, tc.deletes)
			}
		})
	}
}

// The API keeps the name of the replaced file until its purge has run: the
// copy is tried again while it answers 409, and the 409 is reported once the
// wait is over.
func TestHandleCopy_ReplaceWaitsForPurge(t *testing.T) {
	copyReplaceRetry, copyReplaceWait = time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { copyReplaceRetry, copyReplaceWait = 500*time.Millisecond, 15*time.Second })

	fake := &lot2API{t: t, copyConflicts: 2}
	w := httptest.NewRecorder()
	newLot2FS(t, fake).handleCopy(w, copyRequest("/dataroom/DR/doc.txt", "/dataroom/DR/old.txt", ""))
	if w.Code != http.StatusNoContent || fake.count("POST /dataroom/node/n-src/copy") != 3 {
		t.Errorf("status = %d after %d copies, want 204 after 3", w.Code, fake.count("POST /dataroom/node/n-src/copy"))
	}

	fake = &lot2API{t: t, copyConflicts: 1000}
	w = httptest.NewRecorder()
	newLot2FS(t, fake).handleCopy(w, copyRequest("/dataroom/DR/doc.txt", "/dataroom/DR/old.txt", ""))
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 once the wait is over", w.Code)
	}

	// A name held by a file this server did not delete is not waited for.
	fake = &lot2API{t: t, copyConflicts: 1}
	w = httptest.NewRecorder()
	newLot2FS(t, fake).handleCopy(w, copyRequest("/dataroom/DR/doc.txt", "/dataroom/DR/sub/new.txt", ""))
	if w.Code != http.StatusConflict || fake.count("POST /dataroom/node/n-src/copy") != 1 {
		t.Errorf("status = %d after %d copies, want 409 after 1", w.Code, fake.count("POST /dataroom/node/n-src/copy"))
	}
}

// A folder inside a dataroom reports the RFC 4331 quota properties from the
// dataroom's stats, fetched once per TTL whatever the number of folders.
func TestDirHandle_QuotaProps(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	ctx := context.Background()
	for _, p := range []string{"/dataroom/DR/", "/dataroom/DR/sub"} {
		f, err := fs.OpenFile(ctx, p, 0, 0)
		if err != nil {
			t.Fatalf("OpenFile(%s): %v", p, err)
		}
		props, err := f.(webdav.DeadPropsHolder).DeadProps()
		if err != nil {
			t.Fatal(err)
		}
		used := props[xml.Name{Space: "DAV:", Local: "quota-used-bytes"}]
		free := props[xml.Name{Space: "DAV:", Local: "quota-available-bytes"}]
		if string(used.InnerXML) != "9" || string(free.InnerXML) != "991" {
			t.Errorf("%s: quota props = %s / %s, want 9 / 991", p, used.InnerXML, free.InnerXML)
		}
		_ = f.Close()
	}
	if fake.statsCalls != 1 {
		t.Errorf("stats fetched %d times, want 1 (cached for the TTL)", fake.statsCalls)
	}
	// Folders outside a dataroom report nothing.
	f, _ := fs.OpenFile(ctx, "/", 0, 0)
	if props, _ := f.(webdav.DeadPropsHolder).DeadProps(); props != nil {
		t.Errorf("root reports %v", props)
	}
}

// newLockedHandler wires a WebDAV handler with the lock mirror over fs.
func newLockedHandler(fs *webdavFS) (http.Handler, *lockMirror) {
	ls := webdav.NewMemLS()
	handler := &webdav.Handler{FileSystem: fs, LockSystem: ls}
	mirror := newLockMirror(fs, ls)

	return mirror.middleware(handler), mirror
}

const lockBody = `<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:">` +
	`<D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner>me</D:owner></D:lockinfo>`

func lockRequest(path, ifHeader string) *http.Request {
	var r *http.Request
	if ifHeader != "" {
		r = httptest.NewRequest("LOCK", path, nil)
		r.Header.Set("If", ifHeader)
	} else {
		r = httptest.NewRequest("LOCK", path, strings.NewReader(lockBody))
	}
	r.Header.Set("Timeout", "Second-3600")
	r.Header.Set("Depth", "0")

	return r
}

// A WebDAV LOCK on a listed file takes the matching server lock; a refresh
// renews it; an UNLOCK releases it.
func TestLockMirror_LockRefreshUnlock(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	handler, mirror := newLockedHandler(fs)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, lockRequest("/dataroom/DR/locked.txt", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("LOCK status = %d (%s)", w.Code, w.Body.String())
	}
	token := w.Header().Get("Lock-Token")
	if token == "" || mirror.held() != 1 || fake.count("POST /dataroom/node/n-doc/lock") != 1 {
		t.Fatalf("token = %q, held = %d, calls = %v", token, mirror.held(), fake.calls)
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, lockRequest("/dataroom/DR/locked.txt", "("+token+")"))
	if w.Code != http.StatusOK || fake.count("PUT /dataroom/node/lock/l-1") != 1 {
		t.Errorf("refresh: status = %d, calls = %v", w.Code, fake.calls)
	}

	w = httptest.NewRecorder()
	r := httptest.NewRequest("UNLOCK", "/dataroom/DR/locked.txt", nil)
	r.Header.Set("Lock-Token", token)
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || mirror.held() != 0 || fake.count("DELETE /dataroom/node/lock/l-1") != 1 {
		t.Errorf("unlock: status = %d, held = %d, calls = %v", w.Code, mirror.held(), fake.calls)
	}
}

// A file locked by another client on the server answers 423 and leaves no
// local lock behind: the next LOCK, once the server accepts, succeeds.
func TestLockMirror_ServerLocked(t *testing.T) {
	fake := &lot2API{t: t, lockStatus: http.StatusLocked}
	fs := newLot2FS(t, fake)
	handler, mirror := newLockedHandler(fs)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, lockRequest("/dataroom/DR/locked.txt", ""))
	if w.Code != webdav.StatusLocked || mirror.held() != 0 {
		t.Fatalf("status = %d, held = %d, want 423 and nothing held", w.Code, mirror.held())
	}

	fake.mu.Lock()
	fake.lockStatus = http.StatusCreated
	fake.mu.Unlock()
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, lockRequest("/dataroom/DR/locked.txt", ""))
	if w.Code != http.StatusOK || mirror.held() != 1 {
		t.Errorf("after the server lock lifted: status = %d, held = %d", w.Code, mirror.held())
	}
}

// A LOCK on a folder, or on a resource that is not a listed file, stays
// local: the server locks files only.
func TestLockMirror_FolderStaysLocal(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	handler, mirror := newLockedHandler(fs)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, lockRequest("/dataroom/DR/sub", ""))
	if w.Code != http.StatusOK || mirror.held() != 0 || fake.count("POST") != 0 {
		t.Errorf("status = %d, held = %d, calls = %v", w.Code, mirror.held(), fake.calls)
	}
}

// Shutting the mirror down releases every mirrored lock.
func TestLockMirror_ReleaseAllOnShutdown(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	handler, mirror := newLockedHandler(fs)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, lockRequest("/dataroom/DR/locked.txt", ""))
	if mirror.held() != 1 {
		t.Fatalf("held = %d", mirror.held())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { mirror.run(ctx); close(done) }()
	cancel()
	<-done
	if mirror.held() != 0 || fake.count("DELETE /dataroom/node/lock/l-1") != 1 {
		t.Errorf("held = %d, calls = %v", mirror.held(), fake.calls)
	}
}
