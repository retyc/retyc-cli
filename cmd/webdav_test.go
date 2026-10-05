package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
)

// — webdavFileInfo ————————————————————————————————————————————————————————————

func TestWebdavFileInfo_Dir(t *testing.T) {
	fi := &webdavFileInfo{name: "mydir", isDir: true}
	if !fi.IsDir() {
		t.Error("IsDir() = false, want true")
	}
	if fi.Mode()&os.ModeDir == 0 {
		t.Error("Mode() does not have ModeDir set")
	}
	if fi.Name() != "mydir" {
		t.Errorf("Name() = %q, want %q", fi.Name(), "mydir")
	}
	if fi.Sys() != nil {
		t.Error("Sys() != nil")
	}
}

func TestWebdavFileInfo_File(t *testing.T) {
	fi := &webdavFileInfo{name: "file.txt", size: 42}
	if fi.IsDir() {
		t.Error("IsDir() = true, want false")
	}
	if fi.Size() != 42 {
		t.Errorf("Size() = %d, want 42", fi.Size())
	}
	if fi.Mode()&os.ModeDir != 0 {
		t.Error("Mode() has ModeDir set for a file")
	}
}

// — parseWebdavPath ———————————————————————————————————————————————————————————

func TestParseWebdavPath(t *testing.T) {
	cases := []struct {
		in      string
		kind    webdavPathKind
		drName  string
		subPath string
	}{
		{"/", pathRoot, "", ""},
		{"/dataroom", pathDataroomRoot, "", ""},
		{"/dataroom/", pathDataroomRoot, "", ""},
		{"/dataroom/My Dataroom", pathDataroomNode, "My Dataroom", "/"},
		{"/dataroom/My Dataroom/", pathDataroomNode, "My Dataroom", "/"},
		{"/dataroom/My Dataroom/folder/file.txt", pathDataroomNode, "My Dataroom", "/folder/file.txt"},
		{"/other", pathUnknown, "", ""},
		{"/other/sub/path", pathUnknown, "", ""},
		{"/datarooms", pathUnknown, "", ""},
	}
	for _, c := range cases {
		kind, drName, subPath := parseWebdavPath(c.in)
		if kind != c.kind || drName != c.drName || subPath != c.subPath {
			t.Errorf("parseWebdavPath(%q) = (%v, %q, %q), want (%v, %q, %q)",
				c.in, kind, drName, subPath, c.kind, c.drName, c.subPath)
		}
	}
}

// — splitWebdavPath ———————————————————————————————————————————————————————————

func TestSplitWebdavPath_RootFile(t *testing.T) {
	parent, name := splitWebdavPath("/file.txt")
	if parent != "/" || name != "file.txt" {
		t.Errorf("splitWebdavPath(\"/file.txt\") = (%q, %q), want (\"/\", \"file.txt\")", parent, name)
	}
}

func TestSplitWebdavPath_NestedFile(t *testing.T) {
	parent, name := splitWebdavPath("/folder/sub/file.txt")
	if parent != "/folder/sub" || name != "file.txt" {
		t.Errorf("splitWebdavPath(\"/folder/sub/file.txt\") = (%q, %q)", parent, name)
	}
}

func TestSplitWebdavPath_RootDir(t *testing.T) {
	parent, name := splitWebdavPath("/")
	if parent != "/" || name != "" {
		t.Errorf("splitWebdavPath(\"/\") = (%q, %q), want (\"/\", \"\")", parent, name)
	}
}

func TestSplitWebdavPath_Relative(t *testing.T) {
	parent, name := splitWebdavPath("foo")
	if parent != "/" || name != "foo" {
		t.Errorf("splitWebdavPath(\"foo\") = (%q, %q), want (\"/\", \"foo\")", parent, name)
	}
}

// — dataroomCache —————————————————————————————————————————————————————————————

func TestDataroomCache_BasicResolution(t *testing.T) {
	calls := 0
	cache := newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		calls++

		return []dataroomCacheItem{
			{id: "id-1", title: "Alpha"},
			{id: "id-2", title: "Beta"},
		}, nil
	})

	id, err := cache.idForName(context.Background(), "Alpha")
	if err != nil || id != "id-1" {
		t.Fatalf("idForName(\"Alpha\") = (%q, %v), want (\"id-1\", nil)", id, err)
	}
	if calls != 1 {
		t.Errorf("fetch called %d times, want 1", calls)
	}
}

func TestDataroomCache_CacheHit(t *testing.T) {
	calls := 0
	cache := newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		calls++

		return []dataroomCacheItem{{id: "id-1", title: "Alpha"}}, nil
	})

	_, _ = cache.idForName(context.Background(), "Alpha")
	_, _ = cache.idForName(context.Background(), "Alpha")
	if calls != 1 {
		t.Errorf("fetch called %d times, want 1 (second call should hit cache)", calls)
	}
}

func TestDataroomCache_NotFound(t *testing.T) {
	cache := newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{{id: "id-1", title: "Alpha"}}, nil
	})

	_, err := cache.idForName(context.Background(), "Unknown")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("idForName(\"Unknown\") error = %v, want os.ErrNotExist", err)
	}
}

func TestDataroomCache_TitleCollision(t *testing.T) {
	cache := newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{
			{id: "id-1", title: "Docs"},
			{id: "id-2", title: "Docs"},
			{id: "id-3", title: "Docs"},
		}, nil
	})

	id1, err := cache.idForName(context.Background(), "Docs")
	if err != nil || id1 != "id-1" {
		t.Fatalf("first collision: got (%q, %v), want (\"id-1\", nil)", id1, err)
	}
	id2, err := cache.idForName(context.Background(), "Docs (2)")
	if err != nil || id2 != "id-2" {
		t.Fatalf("second collision: got (%q, %v), want (\"id-2\", nil)", id2, err)
	}
	id3, err := cache.idForName(context.Background(), "Docs (3)")
	if err != nil || id3 != "id-3" {
		t.Fatalf("third collision: got (%q, %v), want (\"id-3\", nil)", id3, err)
	}
}

// TestDataroomCache_CollisionStableAcrossOrder verifies that the collision suffix
// for two same-titled datarooms is assigned by ID, so the name→ID mapping is
// identical regardless of the order the API returns the items in.
func TestDataroomCache_CollisionStableAcrossOrder(t *testing.T) {
	forward := newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{
			{id: "id-aaa", title: "Docs"},
			{id: "id-bbb", title: "Docs"},
		}, nil
	})
	reversed := newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{
			{id: "id-bbb", title: "Docs"},
			{id: "id-aaa", title: "Docs"},
		}, nil
	})

	ctx := context.Background()
	for _, name := range []string{"Docs", "Docs (2)"} {
		idF, errF := forward.idForName(ctx, name)
		idR, errR := reversed.idForName(ctx, name)
		if errF != nil || errR != nil {
			t.Fatalf("idForName(%q): forward=%v reversed=%v", name, errF, errR)
		}
		if idF != idR {
			t.Errorf("name %q maps to %q (forward) vs %q (reversed); should be stable", name, idF, idR)
		}
	}
	// Lowest ID gets the unsuffixed name.
	if id, _ := forward.idForName(ctx, "Docs"); id != "id-aaa" {
		t.Errorf("Docs = %q, want id-aaa (lowest ID)", id)
	}
}

// TestStreamWriteHandle_ShortUploadFails verifies that committing fewer bytes than
// the declared size is reported as an error (truncated PUT must not look like success).
func TestStreamWriteHandle_ShortUploadFails(t *testing.T) {
	_, pipeW := io.Pipe()
	done := make(chan error, 1)
	done <- nil // upload goroutine "succeeded" (clean pipe EOF)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h := &streamWriteHandle{
		wfs:       newWebdavTestFS(srv),
		newNode:   false,
		pipeW:     pipeW,
		done:      done,
		parentURI: "retyc://dr/",
		info:      &webdavFileInfo{name: "f.bin", size: 100, versionID: "v-2"},
		written:   40, // only 40 of 100 bytes arrived
	}

	err := h.Close()
	if err == nil {
		t.Fatal("expected error for short upload, got nil")
	}
	if !strings.Contains(err.Error(), "incomplete upload") {
		t.Errorf("error = %v, want it to mention incomplete upload", err)
	}
}

// TestStreamWriteHandle_CleanupDiscardsWhatTheUploadCreated verifies that a
// failed PUT removes the node it created, but only its own version on a node
// that already existed, and that a refused delete (contributors lack
// can_delete) still surfaces the upload error rather than the cleanup one.
func TestStreamWriteHandle_CleanupDiscardsWhatTheUploadCreated(t *testing.T) {
	cases := []struct {
		name       string
		newNode    bool
		deleteCode int
		wantCall   string
	}{
		{"new node", true, http.StatusNoContent, "DELETE /dataroom/node/n1"},
		{"existing node", false, http.StatusNoContent, "DELETE /dataroom/node/version/v2"},
		{"delete refused", false, http.StatusForbidden, "DELETE /dataroom/node/version/v2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var calls []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				w.WriteHeader(c.deleteCode)
			}))
			defer srv.Close()

			done := make(chan error, 1)
			done <- errors.New("chunk upload failed")
			_, pipeW := io.Pipe()
			h := &streamWriteHandle{
				wfs:       newWebdavTestFS(srv),
				nodeID:    "n1",
				newNode:   c.newNode,
				pipeW:     pipeW,
				done:      done,
				parentURI: "retyc://dr1/",
				info:      &webdavFileInfo{name: "f.bin", size: 100, versionID: "v2"},
				written:   100,
			}
			err := h.Close()
			if err == nil || !strings.Contains(err.Error(), "chunk upload failed") {
				t.Errorf("Close() = %v, want the upload error", err)
			}
			if len(calls) != 1 || calls[0] != c.wantCall {
				t.Errorf("calls = %v, want [%s]", calls, c.wantCall)
			}
		})
	}
}

// TestWriteFileHandle_LockSkipsEmptyUpload verifies that a zero-byte create that
// did not originate from a PUT (i.e. a LOCK lock-null resource) is dropped without
// an upload attempt, and the temp dir is cleaned up.
func TestWriteFileHandle_LockSkipsEmptyUpload(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "retyc-webdav-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	tempFilePath := filepath.Join(tempDir, "f.txt")
	//nolint:gosec // G304: tempFilePath is our own MkdirTemp + a constant name
	f, err := os.OpenFile(tempFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}

	h := &writeFileHandle{
		file:         f,
		tempDir:      tempDir,
		tempFilePath: tempFilePath,
		fileName:     "f.txt",
		wfs:          &webdavFS{},
		isPut:        false, // LOCK-driven create — must not upload
	}

	// nil cfg/client are never dereferenced on the skip path.
	if err := h.Close(); err != nil {
		t.Fatalf("Close (LOCK empty) = %v, want nil", err)
	}
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Error("temp dir should have been removed after skipping the empty upload")
	}
}

// TestStreamWriteHandle_FullUploadSucceeds verifies the happy path: written == size.
func TestStreamWriteHandle_FullUploadSucceeds(t *testing.T) {
	_, pipeW := io.Pipe()
	done := make(chan error, 1)
	done <- nil

	h := &streamWriteHandle{
		wfs:       &webdavFS{},
		newNode:   true,
		pipeW:     pipeW,
		done:      done,
		parentURI: "retyc://dr/",
		info:      &webdavFileInfo{name: "f.bin", size: 100},
		written:   100,
	}

	if err := h.Close(); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

// — Basic auth ————————————————————————————————————————————————————————————————

func authTestHandler() http.Handler {
	return basicAuthMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		"retyc", "s3cret",
	)
}

func TestBasicAuthMiddleware_NoCredentials(t *testing.T) {
	rec := httptest.NewRecorder()
	authTestHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if h := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(h, "Basic ") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge", h)
	}
}

func TestBasicAuthMiddleware_WrongPassword(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("retyc", "wrong")
	rec := httptest.NewRecorder()
	authTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBasicAuthMiddleware_WrongUser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	authTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBasicAuthMiddleware_ValidCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("retyc", "s3cret")
	rec := httptest.NewRecorder()
	authTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGenerateWebdavPassword(t *testing.T) {
	p1, err := generateWebdavPassword()
	if err != nil {
		t.Fatalf("generateWebdavPassword() error = %v", err)
	}
	if len(p1) < 20 {
		t.Errorf("password %q too short for 128 bits of entropy", p1)
	}
	p2, err := generateWebdavPassword()
	if err != nil {
		t.Fatalf("generateWebdavPassword() error = %v", err)
	}
	if p1 == p2 {
		t.Error("two generated passwords are identical")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8888":    true,
		"localhost:8888":    true,
		"[::1]:8888":        true,
		"0.0.0.0:8888":      false,
		":8888":             false, // empty host = every interface
		"192.168.1.10:8888": false,
		"127.0.0.1":         false, // no port: not a valid bind address
		"":                  false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

// ageDataroomCache makes the cached entry expired.
func ageDataroomCache(c *dataroomCache) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry.fetchedAt = time.Now().Add(-2 * dataroomCacheTTL)
}

// An expired list is served at once while a single background refresh
// replaces it: the refresh used to hold the cache lock, so every request of
// the server waited for the /dataroom round trip once a minute.
func TestDataroomCache_StaleEntryServedWhileRefreshing(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	cache := newDataroomCache(func(context.Context) ([]dataroomCacheItem, error) {
		if calls.Add(1) == 1 {
			return []dataroomCacheItem{{id: "id-1", title: "Alpha"}}, nil
		}
		<-gate

		return []dataroomCacheItem{{id: "id-9", title: "Alpha"}}, nil
	})
	ctx := context.Background()
	if _, err := cache.idForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)

	for range 10 {
		id, err := cache.idForName(ctx, "Alpha")
		if err != nil || id != "id-1" {
			t.Fatalf("idForName during the refresh = (%q, %v), want the stale id-1", id, err)
		}
	}
	close(gate)
	deadline := time.Now().Add(time.Second)
	for {
		if id, _ := cache.idForName(ctx, "Alpha"); id == "id-9" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background refresh never replaced the stale entry")
		}
		time.Sleep(time.Millisecond)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("fetch called %d times, want 2 (initial + one shared refresh)", got)
	}
}

// A name missing from an expired list may be a dataroom created since: the
// lookup waits for the refresh instead of answering 404 from the old list.
func TestDataroomCache_MissOnStaleEntryWaitsForRefresh(t *testing.T) {
	var calls atomic.Int32
	cache := newDataroomCache(func(context.Context) ([]dataroomCacheItem, error) {
		items := []dataroomCacheItem{{id: "id-1", title: "Alpha"}}
		if calls.Add(1) > 1 {
			items = append(items, dataroomCacheItem{id: "id-2", title: "Beta"})
		}

		return items, nil
	})
	ctx := context.Background()
	if _, err := cache.idForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)

	if id, err := cache.idForName(ctx, "Beta"); err != nil || id != "id-2" {
		t.Errorf("idForName(Beta) = (%q, %v), want id-2 from the refreshed list", id, err)
	}
}

// A failed refresh keeps the stale list: the API being briefly unreachable
// must not turn every dataroom into a 404.
func TestDataroomCache_RefreshErrorKeepsStaleEntry(t *testing.T) {
	var calls atomic.Int32
	cache := newDataroomCache(func(context.Context) ([]dataroomCacheItem, error) {
		if calls.Add(1) == 1 {
			return []dataroomCacheItem{{id: "id-1", title: "Alpha"}}, nil
		}

		return nil, errors.New("API down")
	})
	ctx := context.Background()
	if _, err := cache.idForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)

	// The miss waits for the refresh, which fails: the error is reported.
	if _, err := cache.idForName(ctx, "Beta"); err == nil {
		t.Error("idForName(Beta) succeeded although the refresh failed")
	}
	if id, err := cache.idForName(ctx, "Alpha"); err != nil || id != "id-1" {
		t.Errorf("idForName(Alpha) after a failed refresh = (%q, %v), want the stale id-1", id, err)
	}
}

// A fetch that never completes (an API that sends its headers then stalls)
// must time out: otherwise it stays in flight forever and no later lookup can
// start another refresh.
func TestDataroomCache_StalledFetchTimesOut(t *testing.T) {
	var calls atomic.Int32
	cache := newDataroomCache(func(ctx context.Context) ([]dataroomCacheItem, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()

			return nil, ctx.Err()
		}

		return []dataroomCacheItem{{id: "id-1", title: "Alpha"}}, nil
	})
	cache.fetchTimeout = 20 * time.Millisecond
	ctx := context.Background()

	if _, err := cache.idForName(ctx, "Alpha"); err == nil {
		t.Fatal("the stalled fetch succeeded")
	}
	if id, err := cache.idForName(ctx, "Alpha"); err != nil || id != "id-1" {
		t.Errorf("idForName after a timed-out fetch = (%q, %v), want id-1 from a new fetch", id, err)
	}
}

func TestDataroomCache_AllNames(t *testing.T) {
	cache := newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{
			{id: "id-2", title: "Zebra"},
			{id: "id-1", title: "Alpha"},
		}, nil
	})

	names, err := cache.allNames(context.Background())
	if err != nil {
		t.Fatalf("allNames() error = %v", err)
	}
	if len(names) != 2 || names[0] != "Alpha" || names[1] != "Zebra" {
		t.Errorf("allNames() = %v, want [Alpha Zebra]", names)
	}
}

// — Stale listing cache after an out-of-band delete ————————————————————————————

// newWebdavTestFS builds a webdavFS whose API client points at srv, with the
// listing and session caches pre-warmed for dataroom "dr1" — the state the server
// is in when a file is deleted from the web app while our cache is still warm.
func newWebdavTestFS(srv *httptest.Server) *webdavFS {
	client := api.New(srv.URL, "retyc-test/1.0", oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}), false, false)

	fs := &webdavFS{
		client: client,
		nodeCache: map[string]*nodeCacheEntry{
			"retyc://dr1/": {
				nodes:     []service.DataroomNodeInfo{{ID: "n1", Name: "log.txt", Type: "file"}},
				fetchedAt: time.Now(),
			},
		},
	}
	fs.sessions.Store("dr1", &service.DataroomSession{})

	return fs
}

// newStaleReadHandle returns a handle built from the stale listing: its versionID
// points at a node that no longer exists server-side.
func newStaleReadHandle(fs *webdavFS) *readFileHandle {
	return &readFileHandle{
		ctx:        context.Background(),
		wfs:        fs,
		drID:       "dr1",
		versionID:  "v-deleted",
		chunkCount: 1,
		parentURI:  "retyc://dr1/",
		info:       &webdavFileInfo{name: "log.txt", size: 42},
	}
}

func nodeCacheHas(fs *webdavFS, uri string) bool {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	_, ok := fs.nodeCache[uri]

	return ok
}

// cachedNodeID looks a node up by name in the cached listing of uri. listed
// is false when uri has no cached listing at all.
func cachedNodeID(fs *webdavFS, uri, name string) (id string, listed bool) {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	entry, ok := fs.nodeCache[uri]
	if !ok {
		return "", false
	}
	for _, n := range entry.nodes {
		if n.Name == name {
			return n.ID, true
		}
	}

	return "", true
}

// cachedDirID looks a folder up by name in the cached listing of uri.
func cachedDirID(fs *webdavFS, uri, name string) (string, bool) {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	entry, ok := fs.nodeCache[uri]
	if !ok {
		return "", false
	}
	for _, n := range entry.nodes {
		if n.Name == name && n.Type == "dir" {
			return n.ID, true
		}
	}

	return "", false
}

func notFoundServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "node not found", http.StatusNotFound)
	}))
}

// TestReadFileHandle_StreamErrorInvalidatesNodeCache covers the streaming read path:
// a failed chunk download must drop the parent listing from the cache so the next
// request re-lists and answers 404, instead of replaying the dead version for the
// rest of nodeCacheTTL.
func TestReadFileHandle_StreamErrorInvalidatesNodeCache(t *testing.T) {
	srv := notFoundServer()
	defer srv.Close()

	fs := newWebdavTestFS(srv)
	h := newStaleReadHandle(fs)

	if _, err := h.Read(make([]byte, 16)); err == nil {
		t.Fatal("Read() = nil error, want the 404 from the chunk download")
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("listing cache entry still present after a failed chunk download")
	}
}

// TestReadFileHandle_BufferedErrorInvalidatesNodeCache covers the buffered read path,
// which a Range request takes (Seek to a non-zero offset).
func TestReadFileHandle_BufferedErrorInvalidatesNodeCache(t *testing.T) {
	srv := notFoundServer()
	defer srv.Close()

	fs := newWebdavTestFS(srv)
	h := newStaleReadHandle(fs)

	if _, err := h.Seek(8, io.SeekStart); err == nil {
		t.Fatal("Seek() = nil error, want the 404 from the chunk download")
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("listing cache entry still present after a failed chunk download")
	}
}

// TestReadFileHandle_BufferedControlCharacterName: the buffered path downloads
// into a temp dir and reopens the file. The service sanitizes on-disk names, so
// reopening under the decrypted name would miss a file named with an ESC.
func TestReadFileHandle_BufferedControlCharacterName(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	plain := []byte("hello, world")
	chunk, err := crypto.EncryptBinaryForKey(plain, identity.Recipient().String())
	if err != nil {
		t.Fatalf("EncryptBinaryForKey: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(chunk)
	}))
	defer srv.Close()

	fs := newWebdavTestFS(srv)
	fs.sessions.Store("dr1", &service.DataroomSession{Identity: identity})
	h := &readFileHandle{
		ctx:        context.Background(),
		wfs:        fs,
		drID:       "dr1",
		versionID:  "v1",
		chunkCount: 1,
		parentURI:  "retyc://dr1/",
		info:       &webdavFileInfo{name: "log\x1b[2K.txt", size: int64(len(plain))},
	}
	defer func() { _ = h.Close() }()

	// A non-zero Seek takes the buffered path (Range request).
	if _, err := h.Seek(7, io.SeekStart); err != nil {
		t.Fatalf("Seek() = %v, want the buffered download to succeed", err)
	}
	got, err := io.ReadAll(h)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plain[7:]) {
		t.Errorf("read %q, want %q", got, plain[7:])
	}
}

// TestIsClientGoneErr guards against invalidating the cache when the reader side
// simply went away (client disconnect, or a Range seek tearing down the stream) —
// that is not evidence the node was deleted.
func TestIsClientGoneErr(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("writing chunk 0: %w", context.Canceled), true},
		{fmt.Errorf("writing chunk 0: %w", io.ErrClosedPipe), true},
		{errors.New("downloading chunk 0: API error 404: node not found"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isClientGoneErr(c.err); got != c.want {
			t.Errorf("isClientGoneErr(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// — dirHandle: lazy listing ———————————————————————————————————————————————————

// PROPFIND calls OpenFile + Stat + Close on every listed resource (x/net/webdav
// props()); only walkFS goes on to Readdir. A directory handle must therefore
// not list its children until Readdir is actually called, or listing a folder
// with K sub-folders costs K extra API listings.
func TestDirHandle_LazyLoad(t *testing.T) {
	calls := 0
	h := &dirHandle{
		info: &webdavFileInfo{name: "d", isDir: true},
		load: func() ([]os.FileInfo, error) {
			calls++

			return []os.FileInfo{&webdavFileInfo{name: "a"}, &webdavFileInfo{name: "b"}}, nil
		},
	}

	if _, err := h.Stat(); err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("Stat() triggered the listing (%d calls); it must stay lazy until Readdir", calls)
	}

	first, err := h.Readdir(1)
	if err != nil || len(first) != 1 || first[0].Name() != "a" {
		t.Fatalf("Readdir(1) = (%v, %v), want [a]", first, err)
	}
	rest, err := h.Readdir(0)
	if err != nil || len(rest) != 1 || rest[0].Name() != "b" {
		t.Fatalf("Readdir(0) = (%v, %v), want [b]", rest, err)
	}
	if _, err := h.Readdir(1); err != io.EOF {
		t.Errorf("Readdir(1) at end = %v, want io.EOF", err)
	}
	if calls != 1 {
		t.Errorf("listing fetched %d times, want exactly 1", calls)
	}
}

func TestDirHandle_LoadError(t *testing.T) {
	want := errors.New("listing failed")
	h := &dirHandle{
		info: &webdavFileInfo{name: "d", isDir: true},
		load: func() ([]os.FileInfo, error) { return nil, want },
	}
	if _, err := h.Stat(); err != nil {
		t.Fatalf("Stat() error = %v, want nil (no listing needed)", err)
	}
	if _, err := h.Readdir(0); !errors.Is(err, want) {
		t.Errorf("Readdir() error = %v, want %v", err, want)
	}
}

// Static handles (root, dataroom index) are built with entries and no loader.
func TestDirHandle_StaticEntries(t *testing.T) {
	h := &dirHandle{
		info:    &webdavFileInfo{name: "/", isDir: true},
		entries: []os.FileInfo{&webdavFileInfo{name: "dataroom", isDir: true}},
	}
	got, err := h.Readdir(0)
	if err != nil || len(got) != 1 {
		t.Fatalf("Readdir(0) = (%v, %v), want 1 entry", got, err)
	}
}

// — ETag / Last-Modified ——————————————————————————————————————————————————————

// The ETag is the client's freshness signal. The x/net/webdav default derives it
// from ModTime+Size, which collapses two versions of equal size into one ETag; the
// version ID is a true content identifier, so it must be used for files.
func TestWebdavFileInfo_ETag(t *testing.T) {
	ctx := context.Background()

	file := &webdavFileInfo{name: "f.txt", size: 5, versionID: "v-123"}
	etag, err := file.ETag(ctx)
	if err != nil {
		t.Fatalf("ETag() error = %v", err)
	}
	if etag != `"v-123"` {
		t.Errorf("ETag() = %s, want %s", etag, `"v-123"`)
	}

	dir := &webdavFileInfo{name: "d", isDir: true}
	if _, err := dir.ETag(ctx); !errors.Is(err, webdav.ErrNotImplemented) {
		t.Errorf("dir ETag() error = %v, want webdav.ErrNotImplemented (fall back to default)", err)
	}
	versionless := &webdavFileInfo{name: "empty"}
	if _, err := versionless.ETag(ctx); !errors.Is(err, webdav.ErrNotImplemented) {
		t.Errorf("versionless ETag() error = %v, want webdav.ErrNotImplemented", err)
	}
}

// Stat and directory listings must carry the version time through so that
// PROPFIND getlastmodified and GET Last-Modified are meaningful.
func TestWebdavFS_StatCarriesModTime(t *testing.T) {
	created := time.Date(2026, 9, 4, 10, 30, 0, 0, time.UTC)
	fileNode := service.DataroomNodeInfo{ID: "n1", Name: "f.txt", Type: "file", VersionID: "v1"}.WithModTime(created)
	fs := &webdavFS{
		cache: newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
			return []dataroomCacheItem{{id: "dr1", title: "DR"}}, nil
		}),
		nodeCache: map[string]*nodeCacheEntry{
			"retyc://dr1/": {
				nodes:     []service.DataroomNodeInfo{fileNode},
				fetchedAt: time.Now(),
			},
		},
	}

	info, err := fs.Stat(context.Background(), "/dataroom/DR/f.txt")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.ModTime().Equal(created) {
		t.Errorf("Stat().ModTime() = %v, want %v", info.ModTime(), created)
	}
	entries := nodesToFileInfos([]service.DataroomNodeInfo{fileNode})
	if len(entries) != 1 || !entries[0].ModTime().Equal(created) {
		t.Errorf("nodesToFileInfos ModTime = %v, want %v", entries[0].ModTime(), created)
	}
}

// — Mutations reuse the cached session ————————————————————————————————————————

// Every mutation used to re-resolve the dataroom session (2 API calls + AGE
// crypto) although the server already caches it. With the session cache warm,
// MKCOL / DELETE / MOVE must hit only the node endpoints.
func TestWebdavFS_MutationsUseCachedSession(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub := identity.Recipient().String()
	xNameEnc, err := crypto.EncryptStringForKeys("x", []string{pub})
	if err != nil {
		t.Fatalf("EncryptStringForKeys: %v", err)
	}

	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/dataroom/dr1" || r.URL.Path == "/user/me/key/active":
			t.Errorf("session re-resolved through %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
			fmt.Fprint(w, `{"id":"n-new","name_enc":"x"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
			fmt.Fprintf(w, `{"items":[{"node":{"id":"n-x","name_enc":%q,"type_enc":null,"parent_id":null},`+
				`"node_version":null}],"total":1,"pages":1,"page":1}`, xNameEnc)
		case r.Method == http.MethodDelete && r.URL.Path == "/dataroom/node/n-x":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/n-x":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	fs := newWebdavTestFS(srv)
	fs.cache = newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{{id: "dr1", title: "DR"}}, nil
	})
	fs.sessions.Store("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	ctx := context.Background()

	if err := fs.Mkdir(ctx, "/dataroom/DR/newdir", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if id, ok := cachedDirID(fs, "retyc://dr1/", "newdir"); !ok || id != "n-new" {
		t.Error("Mkdir did not add the new folder to the cached parent listing")
	}
	// The pre-warmed listing does not hold "x", which only the API serves.
	fs.invalidateNodeCache("retyc://dr1/")
	if err := fs.Rename(ctx, "/dataroom/DR/x", "/dataroom/DR/y"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	// The rename updated the cached listing: the node is now "y".
	if err := fs.RemoveAll(ctx, "/dataroom/DR/y"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "GET /dataroom/dr1/nodes") || strings.HasPrefix(c, "POST /dataroom/dr1/node") ||
			strings.HasPrefix(c, "DELETE /dataroom/node/") || strings.HasPrefix(c, "PUT /dataroom/node/") {
			continue
		}
		t.Errorf("unexpected API call %s", c)
	}
}

// — listNodes: single-flight + generation check ———————————————————————————————

// gatedListFn returns a listFn that blocks on gate and counts its calls.
// started is signalled once per call, before blocking.
func gatedListFn(t *testing.T, gate <-chan struct{}, started chan<- struct{}) (
	func(context.Context, string, string) ([]service.DataroomNodeInfo, error), *int32,
) {
	t.Helper()
	var calls int32

	return func(_ context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
		atomic.AddInt32(&calls, 1)
		started <- struct{}{}
		<-gate

		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
	}, &calls
}

func TestListNodes_CacheHit(t *testing.T) {
	gate := make(chan struct{})
	close(gate)
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := &webdavFS{listFn: listFn}
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := fs.listNodes(ctx, "dr1", "/"); err != nil {
			t.Fatalf("listNodes: %v", err)
		}
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Errorf("listing fetched %d times for 3 sequential calls, want 1", n)
	}
}

// Concurrent misses on the same URI must share one fetch.
func TestListNodes_SingleFlight(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := &webdavFS{listFn: listFn}
	ctx := context.Background()

	const n = 5
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nodes, err := fs.listNodes(ctx, "dr1", "/")
			if err == nil && len(nodes) != 1 {
				err = fmt.Errorf("got %d nodes, want 1", len(nodes))
			}
			errs <- err
		}()
	}
	<-started // the leader is inside the fetch; everyone else either joins it or hits the cache after
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("listing fetched %d times for %d concurrent callers, want 1", got, n)
	}
}

// A listing answered before a mutation landed must not be stored after that
// mutation invalidated the URI — otherwise a read racing a write from another
// client pins a pre-mutation listing for a whole TTL.
func TestListNodes_InvalidatedDuringFetchIsNotCached(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := &webdavFS{listFn: listFn}
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		_, err := fs.listNodes(ctx, "dr1", "/")
		done <- err
	}()
	<-started
	fs.invalidateNodeCache("retyc://dr1/") // mutation lands while the listing is in flight
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Fatal("listing that raced an invalidation was stored in the cache")
	}
	// The next call must fetch again.
	if _, err := fs.listNodes(ctx, "dr1", "/"); err != nil {
		t.Fatalf("listNodes (refetch): %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("listing fetched %d times, want 2 (first result discarded, second stored)", got)
	}
	if !nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("clean refetch was not stored")
	}
}

// A waiter whose own context is cancelled must not block on the leader.
func TestListNodes_WaiterHonoursContext(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, _ := gatedListFn(t, gate, started)
	fs := &webdavFS{listFn: listFn}

	go func() { _, _ = fs.listNodes(context.Background(), "dr1", "/") }()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fs.listNodes(ctx, "dr1", "/"); !errors.Is(err, context.Canceled) {
		t.Errorf("waiter error = %v, want context.Canceled", err)
	}
	close(gate)
}

// — Session cache wiring ——————————————————————————————————————————————————————

// getSession must go through the process-lifetime session cache: the second
// call for the same dataroom must not resolve again (see service.SessionCache).
func TestWebdavFS_GetSession_ResolvedOnce(t *testing.T) {
	var calls atomic.Int32
	fs := &webdavFS{sessionFn: func(_ context.Context, drID string) (*service.DataroomSession, error) {
		calls.Add(1)

		return &service.DataroomSession{PublicKey: "pub-" + drID}, nil
	}}
	ctx := context.Background()

	first, err := fs.getSession(ctx, "dr1")
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	second, err := fs.getSession(ctx, "dr1")
	if err != nil {
		t.Fatalf("getSession (cached): %v", err)
	}
	if first != second {
		t.Error("second getSession returned a different session: cache miss")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("sessionFn ran %d times, want 1", got)
	}
}

// — Startup checks ————————————————————————————————————————————————————————————

// newStartupTestServer serves the two endpoints hit at webdav serve startup:
// the dataroom listing (connectivity check) and the user's active key, whose
// private half is encrypted under keyPassphrase.
func newStartupTestServer(t *testing.T, keyPassphrase string) *httptest.Server {
	t.Helper()
	userKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	userPrivEnc, err := crypto.EncryptWithPassphrase([]byte(userKey.String()), keyPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dataroom":
			_, _ = io.WriteString(w, `{"items":[],"total":0}`)
		case "/user/me/key/active":
			_, _ = fmt.Fprintf(w, `{"id":"k1","public_key":%q,"private_key_enc":%q}`,
				userKey.Recipient().String(), userPrivEnc)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

func newStartupTestClient(srv *httptest.Server) *api.Client {
	return api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)
}

func TestWebdavStartupCheck_OK(t *testing.T) {
	srv := newStartupTestServer(t, "good-pw")

	identity, err := webdavStartupCheck(context.Background(), newStartupTestClient(srv), func() (string, error) {
		return "good-pw", nil
	})
	if err != nil {
		t.Fatalf("webdavStartupCheck() error = %v, want nil", err)
	}
	if identity == nil {
		t.Fatal("webdavStartupCheck() returned a nil identity")
	}
}

func TestWebdavStartupCheck_WrongPassphrase(t *testing.T) {
	srv := newStartupTestServer(t, "good-pw")

	_, err := webdavStartupCheck(context.Background(), newStartupTestClient(srv), func() (string, error) {
		return "bad-pw", nil
	})
	if err == nil || !strings.Contains(err.Error(), "wrong key passphrase") {
		t.Fatalf("webdavStartupCheck() error = %v, want wrong key passphrase", err)
	}
}

func TestWebdavStartupCheck_APIUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	_, err := webdavStartupCheck(context.Background(), newStartupTestClient(srv), func() (string, error) {
		return "good-pw", nil
	})
	if err == nil || !strings.Contains(err.Error(), "API connectivity check failed") {
		t.Fatalf("webdavStartupCheck() error = %v, want connectivity failure", err)
	}
}

// Once the identity has been unlocked at startup, resolving a dataroom session
// must reuse it: no second fetch of the user key, no second scrypt.
func TestWebdavFS_ResolveSession_ReusesStartupIdentity(t *testing.T) {
	userKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessPrivEnc, err := crypto.EncryptStringForKeys(sessKey.String(), []string{userKey.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)

			return
		}
		_, _ = fmt.Fprintf(w, `{"id":"dr1","session_public_key":%q,"session_private_key_enc":%q}`,
			sessKey.Recipient().String(), sessPrivEnc)
	}))
	t.Cleanup(srv.Close)

	fs := &webdavFS{client: newStartupTestClient(srv), identity: userKey}
	sess, err := fs.getSession(context.Background(), "dr1")
	if err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if sess.PublicKey != sessKey.Recipient().String() {
		t.Errorf("PublicKey = %q, want %q", sess.PublicKey, sessKey.Recipient().String())
	}
}

// The shared listing must not run under the leader's request context: Finder
// fires PROPFINDs in parallel and aborting one of them must not fail the
// others with context.Canceled.
func TestListNodes_LeaderCancellationDoesNotFailWaiters(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn := func(ctx context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
		started <- struct{}{}
		<-gate
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
	}
	fs := &webdavFS{listFn: listFn}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = fs.listNodes(leaderCtx, "dr1", "/")
	}()
	<-started

	waiterErr := make(chan error, 1)
	go func() {
		_, err := fs.listNodes(context.Background(), "dr1", "/")
		waiterErr <- err
	}()
	for {
		fs.nodeMu.Lock()
		waiting := fs.nodeInflight[dataroomURI("dr1", "/")] != nil
		fs.nodeMu.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond) // let the waiter block on f.done

	cancelLeader()
	close(gate)
	<-leaderDone

	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter error = %v, want the listing", err)
	}
}

// Same for a shared folder listing: a stalled one must not stay in flight and
// make every later request for the folder wait on it.
func TestListNodes_StalledFetchTimesOut(t *testing.T) {
	var calls atomic.Int32
	listFn := func(ctx context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()

			return nil, ctx.Err()
		}

		return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
	}
	fs := &webdavFS{fetchTimeout: 20 * time.Millisecond, listFn: listFn}
	ctx := context.Background()

	if _, err := fs.listNodes(ctx, "dr1", "/"); err == nil {
		t.Fatal("the stalled listing succeeded")
	}
	if nodes, err := fs.listNodes(ctx, "dr1", "/"); err != nil || len(nodes) != 1 {
		t.Errorf("listNodes after a timed-out fetch = (%v, %v), want the new listing", nodes, err)
	}
}

// — Directory invalidation ————————————————————————————————————————————————————

// Deleting or renaming a DIRECTORY must drop its own listing and every
// sub-listing, not only the parent's: within the TTL a re-created folder of
// the same name would otherwise serve the ghost children of the deleted tree.
func TestWebdavFS_RemoveAllInvalidatesDirectorySubtree(t *testing.T) {
	fs := newSubtreeTestFS(t)
	ctx := context.Background()

	if err := fs.RemoveAll(ctx, "/dataroom/DR/x"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	for _, uri := range []string{"retyc://dr1/x", "retyc://dr1/x/sub"} {
		if nodeCacheHas(fs, uri) {
			t.Errorf("%s still cached after RemoveAll of the directory", uri)
		}
	}
	if id, listed := cachedNodeID(fs, "retyc://dr1/", "x"); !listed || id != "" {
		t.Errorf("parent listing: x = %q (listed %v), want kept without x", id, listed)
	}
	if !nodeCacheHas(fs, "retyc://dr1/xy") {
		t.Error("sibling retyc://dr1/xy was invalidated although it is not under /x")
	}
}

func TestWebdavFS_RenameInvalidatesDirectorySubtrees(t *testing.T) {
	fs := newSubtreeTestFS(t)
	ctx := context.Background()

	if err := fs.Rename(ctx, "/dataroom/DR/x", "/dataroom/DR/y"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	gone := []string{"retyc://dr1/x", "retyc://dr1/x/sub", "retyc://dr1/y", "retyc://dr1/y/old"}
	for _, uri := range gone {
		if nodeCacheHas(fs, uri) {
			t.Errorf("%s still cached after Rename of the directory", uri)
		}
	}
	if id, _ := cachedNodeID(fs, "retyc://dr1/", "x"); id != "" {
		t.Error("parent listing still names x after the rename")
	}
	if id, _ := cachedNodeID(fs, "retyc://dr1/", "y"); id != "n-x" {
		t.Errorf("parent listing: y = %q, want n-x", id)
	}
	if !nodeCacheHas(fs, "retyc://dr1/xy") {
		t.Error("sibling retyc://dr1/xy was invalidated although it is not under /x or /y")
	}
}

// newSubtreeTestFS serves one root folder "x" (node n-x) and pre-fills the
// listing cache with entries under /x, under /y and for the sibling /xy.
func newSubtreeTestFS(t *testing.T) *webdavFS {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	xNameEnc, err := crypto.EncryptStringForKeys("x", []string{pub})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
			fmt.Fprintf(w, `{"items":[{"node":{"id":"n-x","name_enc":%q,"type_enc":null,"parent_id":null},`+
				`"node_version":null}],"total":1,"pages":1,"page":1}`, xNameEnc)
		case r.Method == http.MethodDelete && r.URL.Path == "/dataroom/node/n-x",
			r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/n-x":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	fs := newWebdavTestFS(srv)
	fs.cache = newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{{id: "dr1", title: "DR"}}, nil
	})
	fs.sessions.Store("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	fs.nodeMu.Lock()
	fs.nodeCache = map[string]*nodeCacheEntry{}
	for _, uri := range []string{"retyc://dr1/", "retyc://dr1/x", "retyc://dr1/x/sub", "retyc://dr1/xy",
		"retyc://dr1/y", "retyc://dr1/y/old"} {
		fs.nodeCache[uri] = &nodeCacheEntry{fetchedAt: time.Now()}
	}
	// The root listing names /x, as the PROPFIND preceding a DELETE would have.
	fs.nodeCache["retyc://dr1/"].nodes = []service.DataroomNodeInfo{{ID: "n-x", Name: "x", Type: "dir"}}
	fs.nodeMu.Unlock()

	return fs
}

// — Fake API helpers for the cached-listing tests —————————————————————————————

// callLog records the requests a fake API server receives. Handlers run on the
// server's goroutines, and the race detector cannot see through the socket, so
// every access is locked.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(call string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, call)
}

// list returns the recorded calls in arrival order.
func (l *callLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.calls)
}

// sorted returns the recorded calls sorted, for requests issued concurrently.
func (l *callLog) sorted() []string {
	calls := l.list()
	slices.Sort(calls)

	return calls
}

// nodesPageJSON renders one page of listing items for the fake API, with the
// names encrypted for pub. It may run on a server goroutine, so it reports a
// failure with t.Errorf, never t.Fatalf.
func nodesPageJSON(t *testing.T, pub string, nodes map[string]string) string {
	t.Helper()
	items := make([]string, 0, len(nodes))
	for id, name := range nodes {
		nameEnc, err := crypto.EncryptStringForKeys(name, []string{pub})
		if err != nil {
			t.Errorf("EncryptStringForKeys: %v", err)

			return ""
		}
		items = append(items, fmt.Sprintf(
			`{"node":{"id":%q,"name_enc":%q,"type_enc":null,"parent_id":null},"node_version":null}`, id, nameEnc))
	}

	return fmt.Sprintf(`{"items":[%s],"total":%d,"pages":1,"page":1}`, strings.Join(items, ","), len(items))
}

// newCachedListingsFS returns a webdavFS on handler with an unlocked session for
// dataroom "dr1" (title "DR") and the given listings cached.
func newCachedListingsFS(
	t *testing.T, handler http.HandlerFunc, listings map[string][]service.DataroomNodeInfo,
) (*webdavFS, *age.HybridIdentity) {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	fs := newWebdavTestFS(srv)
	fs.cache = newDataroomCache(func(_ context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{{id: "dr1", title: "DR"}}, nil
	})
	fs.sessions.Store("dr1", &service.DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()})
	fs.nodeCache = map[string]*nodeCacheEntry{}
	for uri, nodes := range listings {
		fs.nodeCache[uri] = &nodeCacheEntry{nodes: nodes, fetchedAt: time.Now()}
	}

	return fs, identity
}

// goneStatuses are the answers of the API for a node that no longer exists:
// 404 once purged, 410 while its asynchronous purge is pending.
var goneStatuses = []int{http.StatusNotFound, http.StatusGone}

// — RemoveAll resolves the node from the cached listing ———————————————————————

// A DELETE is always preceded by a Stat that the cached parent listing
// answers: the node ID is already known, so deleting must cost the DELETE
// alone, not one uncached listing per path level on top of it.
func TestWebdavFS_RemoveAllUsesCachedListing(t *testing.T) {
	var log callLog
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path)
		if r.Method == http.MethodDelete && r.URL.Path == "/dataroom/node/f-1" {
			w.WriteHeader(http.StatusNoContent)

			return
		}
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/a/b": {{ID: "f-1", Name: "doc.txt", Type: "file"}},
	})

	if err := fs.RemoveAll(context.Background(), "/dataroom/DR/a/b/doc.txt"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if calls := log.list(); len(calls) != 1 {
		t.Errorf("issued %d API calls (%v), want 1 (the DELETE only)", len(calls), calls)
	}
	// The listing is updated in place: the PROPFIND that follows a DELETE
	// must not re-list the folder.
	if id, listed := cachedNodeID(fs, "retyc://dr1/a/b", "doc.txt"); !listed || id != "" {
		t.Errorf("parent listing: doc.txt = %q (listed %v), want kept without it", id, listed)
	}
}

// The cached listing can be up to nodeCacheTTL stale: when the node it names
// is gone (deleted, or replaced by a new node of the same name elsewhere), the
// DELETE answers 404 or 410 and must be retried against a fresh listing.
func TestWebdavFS_RemoveAllRetriesOnStaleListing(t *testing.T) {
	for _, status := range goneStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var log callLog
			var pub string
			handler := func(w http.ResponseWriter, r *http.Request) {
				log.add(r.Method + " " + r.URL.Path)
				switch {
				case r.Method == http.MethodDelete && r.URL.Path == "/dataroom/node/f-old":
					http.Error(w, "gone", status)
				case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
					fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-new": "doc.txt"}))
				case r.Method == http.MethodDelete && r.URL.Path == "/dataroom/node/f-new":
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
				}
			}
			fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
				"retyc://dr1/": {{ID: "f-old", Name: "doc.txt", Type: "file"}},
			})
			pub = identity.Recipient().String()

			if err := fs.RemoveAll(context.Background(), "/dataroom/DR/doc.txt"); err != nil {
				t.Fatalf("RemoveAll: %v", err)
			}
			want := []string{"DELETE /dataroom/node/f-old", "GET /dataroom/dr1/nodes", "DELETE /dataroom/node/f-new"}
			if calls := log.list(); !slices.Equal(calls, want) {
				t.Errorf("calls = %v, want %v", calls, want)
			}
			if id, _ := cachedNodeID(fs, "retyc://dr1/", "doc.txt"); id != "" {
				t.Error("the parent listing still names the deleted file")
			}
		})
	}
}

// A file absent from the listing is reported as not existing, which the
// WebDAV handler turns into a 404, and nothing is deleted.
func TestWebdavFS_RemoveAllMissingNode(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/": {{ID: "f-1", Name: "doc.txt", Type: "file"}},
	})

	err := fs.RemoveAll(context.Background(), "/dataroom/DR/nope.txt")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("RemoveAll error = %v, want os.ErrNotExist", err)
	}
}

// — Rename resolves source and destination from the cached listings ———————————

// moveBody is the JSON body of PUT /dataroom/node/{id}.
type moveBody struct {
	NameEnc  string  `json:"name_enc"`
	NameHash string  `json:"name_hash"`
	ParentID *string `json:"parent_id"`
}

// decodeMove decodes a PUT body; it runs on a server goroutine.
func decodeMove(t *testing.T, r *http.Request) moveBody {
	t.Helper()
	var body moveBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("decoding PUT body: %v", err)
	}

	return body
}

func parentLabel(id *string) string {
	if id == nil {
		return "root"
	}

	return *id
}

// The source listing is normally cached (the client listed the folder before
// moving from it) and the handler Stats the destination, which caches its
// parent listing: the rename must then cost the PUT alone, not one uncached
// listing per level of both paths.
func TestWebdavFS_RenameUsesCachedListings(t *testing.T) {
	var log callLog
	var mu sync.Mutex
	var body moveBody
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path)
		if r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/f-1" {
			b := decodeMove(t, r)
			mu.Lock()
			body = b
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

			return
		}
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
	fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/a": {{ID: "f-1", Name: "doc.txt", Type: "file", Size: 42, VersionID: "v-1"}},
		"retyc://dr1/b": {},
		"retyc://dr1/":  {{ID: "d-a", Name: "a", Type: "dir"}, {ID: "d-b", Name: "b", Type: "dir"}},
	})

	if err := fs.Rename(context.Background(), "/dataroom/DR/a/doc.txt", "/dataroom/DR/b/new.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if calls := log.list(); len(calls) != 1 {
		t.Errorf("issued %d API calls (%v), want 1 (the PUT only)", len(calls), calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if body.ParentID == nil || *body.ParentID != "d-b" {
		t.Errorf("parent_id = %v, want d-b", body.ParentID)
	}
	if name, err := crypto.DecryptToString(body.NameEnc, identity); err != nil || name != "new.txt" {
		t.Errorf("name_enc decrypts to %q (err %v), want new.txt", name, err)
	}
	// Both listings are updated in place rather than dropped.
	if id, listed := cachedNodeID(fs, "retyc://dr1/a", "doc.txt"); !listed || id != "" {
		t.Errorf("source listing: doc.txt = %q (listed %v), want kept without it", id, listed)
	}
	if id, _ := cachedNodeID(fs, "retyc://dr1/b", "new.txt"); id != "f-1" {
		t.Errorf("destination listing: new.txt = %q, want f-1", id)
	}
}

// When the source listing no longer names the node (it expired meanwhile), the
// moved node's fields are unknown: the destination listing is dropped rather
// than given an entry with a made-up version.
func TestMoveInNodeCache_UnknownSourceDropsDestination(t *testing.T) {
	fs := &webdavFS{nodeCache: map[string]*nodeCacheEntry{
		"retyc://dr1/b": {nodes: []service.DataroomNodeInfo{{ID: "f-2", Name: "other.txt"}}, fetchedAt: time.Now()},
	}}

	fs.moveInNodeCache("retyc://dr1/a", "doc.txt", "retyc://dr1/b", "new.txt")

	if nodeCacheHas(fs, "retyc://dr1/b") {
		t.Error("the destination listing was kept although the moved node is unknown")
	}
}

// A stale source listing makes the PUT answer 404 or 410: the rename must be
// retried against a fresh listing, which names the node that now holds the path.
func TestWebdavFS_RenameRetriesOnStaleListing(t *testing.T) {
	for _, status := range goneStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var log callLog
			var pub string
			handler := func(w http.ResponseWriter, r *http.Request) {
				log.add(r.Method + " " + r.URL.Path)
				switch {
				case r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/f-old":
					http.Error(w, "gone", status)
				case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
					fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-new": "doc.txt"}))
				case r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/f-new":
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
				}
			}
			fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
				"retyc://dr1/": {{ID: "f-old", Name: "doc.txt", Type: "file"}},
			})
			pub = identity.Recipient().String()

			if err := fs.Rename(context.Background(), "/dataroom/DR/doc.txt", "/dataroom/DR/new.txt"); err != nil {
				t.Fatalf("Rename: %v", err)
			}
			want := []string{"PUT /dataroom/node/f-old", "GET /dataroom/dr1/nodes", "PUT /dataroom/node/f-new"}
			if calls := log.list(); !slices.Equal(calls, want) {
				t.Errorf("calls = %v, want %v", calls, want)
			}
		})
	}
}

// The API answers 409 both for a name already taken in the destination and
// for a destination folder deleted since its listing was cached (the dangling
// parent_id fails a foreign key). A destination re-created under the same name
// has a new ID: the rename must be retried into it.
func TestWebdavFS_RenameRetriesWhenDestinationWasRecreated(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/f-1":
			parent := parentLabel(decodeMove(t, r).ParentID)
			log.add("PUT f-1 into " + parent)
			if parent == "d-old" {
				http.Error(w, "Duplicate node name hash", http.StatusConflict)

				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
			log.add("GET listing " + r.URL.Query().Get("parent_id"))
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt", "d-new": "b"}))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}
	fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/": {{ID: "f-1", Name: "doc.txt", Type: "file"}, {ID: "d-old", Name: "b", Type: "dir"}},
	})
	pub = identity.Recipient().String()

	if err := fs.Rename(context.Background(), "/dataroom/DR/doc.txt", "/dataroom/DR/b/doc.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	want := []string{"PUT f-1 into d-old", "GET listing ", "PUT f-1 into d-new"}
	if calls := log.list(); !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

// A 409 whose destination folder is unchanged is a genuine name conflict: it is
// returned after one fresh listing, without repeating the PUT.
func TestWebdavFS_RenameReturnsGenuineConflict(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/dataroom/node/f-1":
			log.add("PUT f-1 into " + parentLabel(decodeMove(t, r).ParentID))
			http.Error(w, "Duplicate node name hash", http.StatusConflict)
		case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
			log.add("GET listing " + r.URL.Query().Get("parent_id"))
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt", "d-b": "b"}))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}
	fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/": {{ID: "f-1", Name: "doc.txt", Type: "file"}, {ID: "d-b", Name: "b", Type: "dir"}},
	})
	pub = identity.Recipient().String()

	err := fs.Rename(context.Background(), "/dataroom/DR/doc.txt", "/dataroom/DR/b/doc.txt")
	if !errors.Is(err, api.ErrConflict) {
		t.Errorf("Rename error = %v, want api.ErrConflict", err)
	}
	want := []string{"PUT f-1 into d-b", "GET listing "}
	if calls := log.list(); !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

// A 409 for a destination at the dataroom root cannot come from a deleted
// folder: it is returned as is, without any re-resolution.
func TestWebdavFS_RenameConflictAtRootIsNotRetried(t *testing.T) {
	var log callLog
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path)
		http.Error(w, "Duplicate node name hash", http.StatusConflict)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/": {{ID: "f-1", Name: "doc.txt", Type: "file"}},
	})

	err := fs.Rename(context.Background(), "/dataroom/DR/doc.txt", "/dataroom/DR/new.txt")
	if !errors.Is(err, api.ErrConflict) {
		t.Errorf("Rename error = %v, want api.ErrConflict", err)
	}
	if calls := log.list(); len(calls) != 1 {
		t.Errorf("calls = %v, want the single PUT", calls)
	}
}

// A source absent from its listing is reported as not existing, and a
// destination whose parent is a file is refused, both without any API call.
func TestWebdavFS_RenameMissingSourceOrInvalidDestination(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/": {{ID: "f-1", Name: "doc.txt", Type: "file"}},
	})
	ctx := context.Background()

	if err := fs.Rename(ctx, "/dataroom/DR/nope.txt", "/dataroom/DR/new.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Rename of a missing source: error = %v, want os.ErrNotExist", err)
	}
	if err := fs.Rename(ctx, "/dataroom/DR/doc.txt", "/dataroom/DR/doc.txt/new.txt"); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("Rename under a file: error = %v, want os.ErrInvalid", err)
	}
}

// — fetchNodes resolves the folder from its parent's cached listing ————————————

// Listing a folder whose parent listing is cached must cost that folder's
// listing alone: resolving its path through the API walked every level from
// the root again, duplicating listings a concurrent PROPFIND was often fetching
// at the same moment.
func TestWebdavFS_FetchNodesUsesCachedParentListing(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path + " parent=" + r.URL.Query().Get("parent_id"))
		switch {
		case r.URL.Path == "/dataroom/dr1/nodes" && r.URL.Query().Get("parent_id") == "d-b":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt"}))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusInternalServerError)
		}
	}
	fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"retyc://dr1/a": {{ID: "d-b", Name: "b", Type: "dir"}},
	})
	pub = identity.Recipient().String()

	nodes, err := fs.listNodes(context.Background(), "dr1", "/a/b")
	if err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "doc.txt" {
		t.Errorf("nodes = %+v, want doc.txt", nodes)
	}
	want := []string{"GET /dataroom/dr1/nodes parent=d-b"}
	if calls := log.sorted(); !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

// The dataroom root has no node to check: listing it is the listing alone.
func TestWebdavFS_FetchNodesRootHasNoCheck(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path)
		fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt"}))
	}
	fs, identity := newCachedListingsFS(t, handler, nil)
	pub = identity.Recipient().String()

	if _, err := fs.listNodes(context.Background(), "dr1", "/"); err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if calls := log.list(); !slices.Equal(calls, []string{"GET /dataroom/dr1/nodes"}) {
		t.Errorf("calls = %v, want the root listing only", calls)
	}
}

// With nothing cached, each level is listed once and kept: listing a sibling
// folder afterwards costs its own listing only.
func TestWebdavFS_FetchNodesCachesEveryLevel(t *testing.T) {
	var log callLog
	var pub string
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1/nodes" {
			log.add(r.Method + " " + r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)

			return
		}
		parent := r.URL.Query().Get("parent_id")
		log.add("parent=" + parent)
		switch parent {
		case "":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"d-a": "a"}))
		case "d-a":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"d-b": "b", "d-c": "c"}))
		case "d-b", "d-c":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{}))
		default:
			http.Error(w, "unexpected parent "+parent, http.StatusInternalServerError)
		}
	}
	fs, identity := newCachedListingsFS(t, handler, nil)
	pub = identity.Recipient().String()
	ctx := context.Background()

	if _, err := fs.listNodes(ctx, "dr1", "/a/b"); err != nil {
		t.Fatalf("listNodes /a/b: %v", err)
	}
	if _, err := fs.listNodes(ctx, "dr1", "/a/c"); err != nil {
		t.Fatalf("listNodes /a/c: %v", err)
	}
	want := []string{"parent=", "parent=d-a", "parent=d-b", "parent=d-c"}
	if calls := log.list(); !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

// The cached parent listing can name a folder deleted elsewhere: listing its
// children answers 404, or 410 while its purge is pending. That listing must
// be discarded and retried once against a fresh parent listing.
func TestWebdavFS_FetchNodesRetriesOnStaleParent(t *testing.T) {
	for _, status := range goneStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var pub string
			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/dataroom/dr1/nodes" {
					http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusInternalServerError)

					return
				}
				switch r.URL.Query().Get("parent_id") {
				case "d-old":
					http.Error(w, "parent gone", status)
				case "":
					fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"d-new": "a"}))
				case "d-new":
					fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-1": "doc.txt"}))
				}
			}
			fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
				"retyc://dr1/": {{ID: "d-old", Name: "a", Type: "dir"}},
			})
			pub = identity.Recipient().String()

			nodes, err := fs.listNodes(context.Background(), "dr1", "/a")
			if err != nil {
				t.Fatalf("listNodes: %v", err)
			}
			if len(nodes) != 1 || nodes[0].Name != "doc.txt" {
				t.Errorf("nodes = %+v, want the re-created folder's doc.txt", nodes)
			}
		})
	}
}

// A path under a file names nothing: it must answer not found (404), not
// os.ErrInvalid, which the WebDAV handler would turn into a 405.
func TestWebdavFS_FetchNodesUnderAFileIsNotFound(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/": {{ID: "f-1", Name: "doc.txt", Type: "file"}},
	})

	if _, err := fs.listNodes(context.Background(), "dr1", "/doc.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("listNodes under a file: error = %v, want os.ErrNotExist", err)
	}
	if _, err := fs.Stat(context.Background(), "/dataroom/DR/doc.txt/child"); !os.IsNotExist(err) {
		t.Errorf("Stat under a file: error = %v, want a bare not-exist error for the WebDAV handler", err)
	}
}

// — Cached parent resolution and cache upsert ————————————————————————————————

// countingListFn returns a listFn serving a fixed tree and counting its calls.
func countingListFn(nodes map[string][]service.DataroomNodeInfo) (
	func(context.Context, string, string) ([]service.DataroomNodeInfo, error), *int32,
) {
	var calls int32

	return func(_ context.Context, _, nodePath string) ([]service.DataroomNodeInfo, error) {
		atomic.AddInt32(&calls, 1)

		return nodes[nodePath], nil
	}, &calls
}

// The dataroom root has no node ID and must cost no listing at all.
func TestParentNodeID_RootCostsNoListing(t *testing.T) {
	listFn, calls := countingListFn(nil)
	fs := &webdavFS{listFn: listFn}

	id, err := fs.parentNodeID(context.Background(), "dr1", "/")
	if err != nil {
		t.Fatalf("parentNodeID: %v", err)
	}
	if id != nil {
		t.Errorf("id = %v, want nil for the dataroom root", *id)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Errorf("root resolution issued %d listings, want 0", n)
	}
}

// The point of the change: repeated uploads into the same folder must reuse the
// cached listing instead of re-walking the tree through the API every time.
func TestParentNodeID_ReusesCachedListing(t *testing.T) {
	listFn, calls := countingListFn(map[string][]service.DataroomNodeInfo{
		"/": {{ID: "dir-1", Name: "sub", Type: "dir"}},
	})
	fs := &webdavFS{listFn: listFn}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		id, err := fs.parentNodeID(ctx, "dr1", "/sub")
		if err != nil {
			t.Fatalf("parentNodeID: %v", err)
		}
		if id == nil || *id != "dir-1" {
			t.Fatalf("id = %v, want dir-1", id)
		}
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Errorf("5 uploads issued %d listings, want 1", n)
	}
}

func TestParentNodeID_Errors(t *testing.T) {
	listFn, _ := countingListFn(map[string][]service.DataroomNodeInfo{
		"/": {{ID: "f-1", Name: "afile", Type: "file"}},
	})
	fs := &webdavFS{listFn: listFn}
	ctx := context.Background()

	if _, err := fs.parentNodeID(ctx, "dr1", "/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing parent: err = %v, want os.ErrNotExist", err)
	}
	// A file cannot be a parent directory; uploading "into" one must not silently
	// target the dataroom root.
	if _, err := fs.parentNodeID(ctx, "dr1", "/afile"); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("file as parent: err = %v, want os.ErrInvalid", err)
	}
}

func TestUpsertNodeCache_ReplacesAndAppends(t *testing.T) {
	fs := &webdavFS{
		nodeCache: map[string]*nodeCacheEntry{
			"retyc://dr1/": {
				nodes: []service.DataroomNodeInfo{
					{ID: "n1", Name: "old.bin", Type: "file", Size: 10, ChunkCount: 1},
				},
				fetchedAt: time.Now().Add(-20 * time.Second),
			},
		},
	}

	// Same name → the entry is replaced, not duplicated.
	fs.upsertNodeCache("retyc://dr1/", service.DataroomNodeInfo{
		ID: "n1", Name: "old.bin", Type: "file", Size: 99, VersionID: "v2", ChunkCount: 3,
	})
	// New name → appended.
	fs.upsertNodeCache("retyc://dr1/", service.DataroomNodeInfo{
		ID: "n2", Name: "new.bin", Type: "file", Size: 5, ChunkCount: 1,
	})

	got := fs.nodeCache["retyc://dr1/"].nodes
	if len(got) != 2 {
		t.Fatalf("cached %d nodes, want 2 (one replaced, one appended)", len(got))
	}
	if got[0].Size != 99 || got[0].VersionID != "v2" || got[0].ChunkCount != 3 {
		t.Errorf("replaced entry = %+v, want the post-upload values", got[0])
	}
	if got[1].Name != "new.bin" {
		t.Errorf("appended entry = %+v, want new.bin", got[1])
	}
}

// The TTL must keep running from the real fetch: the rest of the listing is no
// fresher than it was, so an upload must not extend its lifetime.
func TestUpsertNodeCache_DoesNotExtendTTL(t *testing.T) {
	fetchedAt := time.Now().Add(-20 * time.Second)
	fs := &webdavFS{
		nodeCache: map[string]*nodeCacheEntry{
			"retyc://dr1/": {nodes: nil, fetchedAt: fetchedAt},
		},
	}

	fs.upsertNodeCache("retyc://dr1/", service.DataroomNodeInfo{ID: "n1", Name: "f", Type: "file"})

	if got := fs.nodeCache["retyc://dr1/"].fetchedAt; !got.Equal(fetchedAt) {
		t.Errorf("fetchedAt = %v, want it carried over unchanged (%v)", got, fetchedAt)
	}
}

// listNodes hands its backing array to callers without copying, so an upsert
// must not write through it — a reader holding an earlier listing would
// otherwise observe the mutation.
func TestUpsertNodeCache_DoesNotMutateSharedSlice(t *testing.T) {
	fs := &webdavFS{
		nodeCache: map[string]*nodeCacheEntry{
			"retyc://dr1/": {
				nodes:     []service.DataroomNodeInfo{{ID: "n1", Name: "f.bin", Type: "file", Size: 10}},
				fetchedAt: time.Now(),
			},
		},
	}
	held := fs.nodeCache["retyc://dr1/"].nodes

	fs.upsertNodeCache("retyc://dr1/", service.DataroomNodeInfo{
		ID: "n1", Name: "f.bin", Type: "file", Size: 4242,
	})

	if held[0].Size != 10 {
		t.Errorf("previously returned slice was mutated: size = %d, want 10", held[0].Size)
	}
}

// Nothing cached for that directory means there is nothing to refresh; the
// upsert must not fabricate a listing that was never fetched.
func TestUpsertNodeCache_NoEntryIsNoop(t *testing.T) {
	fs := &webdavFS{nodeCache: map[string]*nodeCacheEntry{}}

	fs.upsertNodeCache("retyc://dr1/", service.DataroomNodeInfo{ID: "n1", Name: "f", Type: "file"})

	if _, ok := fs.nodeCache["retyc://dr1/"]; ok {
		t.Error("upsert created a listing for a directory that was never fetched")
	}
}

// An upload that lands while a listing is in flight must win, exactly like an
// invalidation does: the in-flight listing was answered by the API before the
// upload, so storing it would hide a file the server already accepted — and,
// for a new version of an existing file, would serve the previous version's
// VersionID and ChunkCount for a whole TTL after a PUT returned 201.
func TestUpsertNodeCache_DuringFetchDiscardsStaleListing(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	listFn, calls := gatedListFn(t, gate, started)
	fs := &webdavFS{listFn: listFn}
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		_, err := fs.listNodes(ctx, "dr1", "/")
		done <- err
	}()
	<-started
	// The PUT completes while the listing is still in flight. Nothing is cached
	// yet for that URI — the fetch was triggered by a miss — so the upsert has
	// no entry to refresh and must at least invalidate the pending result.
	fs.upsertNodeCache("retyc://dr1/", service.DataroomNodeInfo{
		ID: "n1", Name: "a", Type: "file", VersionID: "v2", ChunkCount: 2,
	})
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("listNodes: %v", err)
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Fatal("pre-upload listing was stored, hiding the file that was just written")
	}
	if _, err := fs.listNodes(ctx, "dr1", "/"); err != nil {
		t.Fatalf("listNodes (refetch): %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("listing fetched %d times, want 2 (first result discarded, second stored)", got)
	}
}

// The cached mtime must be the version's creation time, as a later listing will
// report it — not the local clock at close time. A large upload closing minutes
// after the version was created would otherwise cache a timestamp that jumps
// backwards once the TTL expires and the API is asked again.
func TestStreamWriteHandle_CachesVersionCreationTime(t *testing.T) {
	createdAt := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	fetchedAt := time.Now()
	fs := &webdavFS{
		nodeCache: map[string]*nodeCacheEntry{
			"retyc://dr1/": {nodes: nil, fetchedAt: fetchedAt},
		},
	}
	done := make(chan error, 1)
	done <- nil
	_, pipeW := io.Pipe()

	h := &streamWriteHandle{
		wfs:       fs,
		nodeID:    "n1",
		pipeW:     pipeW,
		done:      done,
		mimeType:  "text/plain",
		createdAt: createdAt,
		parentURI: "retyc://dr1/",
		info:      &webdavFileInfo{name: "f.txt", size: service.UploadChunkSize + 1, nodeID: "n1", versionID: "v1"},
		written:   service.UploadChunkSize + 1,
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	nodes := fs.nodeCache["retyc://dr1/"].nodes
	if len(nodes) != 1 {
		t.Fatalf("cached %d nodes, want 1", len(nodes))
	}
	if got := nodes[0].ModTime(); !got.Equal(createdAt) {
		t.Errorf("cached ModTime = %v, want the version creation time %v", got, createdAt)
	}
	if nodes[0].MIMEType != "text/plain" || nodes[0].VersionID != "v1" {
		t.Errorf("cached entry = %+v, want the stored MIME type and version", nodes[0])
	}
	// Downloads read exactly ChunkCount chunks: it must be the announced count.
	if nodes[0].ChunkCount != 2 {
		t.Errorf("cached ChunkCount = %d, want 2", nodes[0].ChunkCount)
	}
}

// A failed upload must leave the cache exactly as it was: the node either never
// existed or still holds its previous version, and inventing an entry for it
// would serve a file the server never accepted.
func TestStreamWriteHandle_FailedUploadLeavesCacheUntouched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	previous := []service.DataroomNodeInfo{{ID: "n1", Name: "f.bin", Type: "file", Size: 10, VersionID: "v1"}}
	fs := newWebdavTestFS(srv)
	fs.nodeCache = map[string]*nodeCacheEntry{
		"retyc://dr1/": {nodes: previous, fetchedAt: time.Now()},
	}
	done := make(chan error, 1)
	done <- errors.New("chunk upload failed")
	_, pipeW := io.Pipe()

	h := &streamWriteHandle{
		wfs:       fs,
		nodeID:    "n1",
		newNode:   false,
		pipeW:     pipeW,
		done:      done,
		parentURI: "retyc://dr1/",
		info:      &webdavFileInfo{name: "f.bin", size: 100, versionID: "v2"},
		written:   100,
	}
	if err := h.Close(); err == nil {
		t.Fatal("expected the upload error to surface, got nil")
	}

	nodes := fs.nodeCache["retyc://dr1/"].nodes
	if len(nodes) != 1 || nodes[0].VersionID != "v1" || nodes[0].Size != 10 {
		t.Errorf("cache = %+v, want the pre-upload entry untouched", nodes)
	}
}

// — Overwrite shortcut ————————————————————————————————————————————————————————

func TestCachedFileNodeID(t *testing.T) {
	fresh := []service.DataroomNodeInfo{
		{ID: "f-1", Name: "doc.txt", Type: "file"},
		{ID: "d-1", Name: "sub", Type: "dir"},
	}
	fs := &webdavFS{nodeCache: map[string]*nodeCacheEntry{
		"retyc://dr1/":        {nodes: fresh, fetchedAt: time.Now()},
		"retyc://dr1/expired": {nodes: fresh, fetchedAt: time.Now().Add(-2 * nodeCacheTTL)},
	}}

	if id, ok := fs.cachedFileNodeID("dr1", "/", "doc.txt"); !ok || id != "f-1" {
		t.Errorf("cached file: got (%q, %v), want (f-1, true)", id, ok)
	}
	// A folder of that name is a real conflict; the full path must handle it.
	if _, ok := fs.cachedFileNodeID("dr1", "/", "sub"); ok {
		t.Error("a directory was reported as an overwritable file")
	}
	if _, ok := fs.cachedFileNodeID("dr1", "/", "absent.txt"); ok {
		t.Error("an absent name was reported as cached")
	}
	// An expired listing must not be trusted for a node ID.
	if _, ok := fs.cachedFileNodeID("dr1", "/expired", "doc.txt"); ok {
		t.Error("an expired listing was used")
	}
	if _, ok := fs.cachedFileNodeID("dr1", "/never-listed", "doc.txt"); ok {
		t.Error("an unlisted folder returned a node ID")
	}
}

// Overwriting a file whose node is in the cached listing must create the new
// version directly: no CreateDataroomNode answering 409, and no uncached
// listing to find the node again.
func TestInitUpload_OverwriteSkipsConflictAndRelisting(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub := identity.Recipient().String()

	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/f-1/version" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			// The API rejects any chunk beyond the announced count: 10 bytes is one chunk.
			if body["chunk_count_expected"] != float64(1) {
				t.Errorf("chunk_count_expected = %v, want 1", body["chunk_count_expected"])
			}
			fmt.Fprint(w, `{"id":"v-2","created_at":"2026-09-08T10:00:00Z"}`)

			return
		}
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}))
	defer srv.Close()

	fs := newWebdavTestFS(srv)
	fs.nodeCache = map[string]*nodeCacheEntry{
		"retyc://dr1/": {
			nodes:     []service.DataroomNodeInfo{{ID: "f-1", Name: "doc.txt", Type: "file", VersionID: "v-1"}},
			fetchedAt: time.Now(),
		},
	}
	sess := &service.DataroomSession{Identity: identity, PublicKey: pub}

	init, err := fs.initUpload(context.Background(), "dr1", "/", "doc.txt", nil, 10, sess)
	if err != nil {
		t.Fatalf("initUpload: %v", err)
	}
	if init.NodeID != "f-1" || init.VersionID != "v-2" {
		t.Errorf("init = %+v, want node f-1 / version v-2", init)
	}
	// A pre-existing node must never be deleted if the upload then fails.
	if init.NewNode {
		t.Error("NewNode is true for an overwrite; a failed upload would delete the node")
	}
	if len(calls) != 1 {
		t.Errorf("issued %d API calls (%v), want 1 (version creation only)", len(calls), calls)
	}
}

// The cached listing can be up to nodeCacheTTL stale: if the node was deleted
// elsewhere, the shortcut gets a 404 and the upload must still succeed through
// the full path, which recreates the node.
func TestInitUpload_FallsBackWhenCachedNodeIsGone(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub := identity.Recipient().String()

	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/dataroom/node/f-1/version": // the stale node is gone
			http.Error(w, "no such node", http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
			fmt.Fprint(w, `{"id":"f-2","name_enc":"x"}`)
		case r.URL.Path == "/dataroom/node/f-2/version":
			fmt.Fprint(w, `{"id":"v-1","created_at":"2026-09-08T10:00:00Z"}`)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	fs := newWebdavTestFS(srv)
	fs.nodeCache = map[string]*nodeCacheEntry{
		"retyc://dr1/": {
			nodes:     []service.DataroomNodeInfo{{ID: "f-1", Name: "doc.txt", Type: "file"}},
			fetchedAt: time.Now(),
		},
	}
	sess := &service.DataroomSession{Identity: identity, PublicKey: pub}

	init, err := fs.initUpload(context.Background(), "dr1", "/", "doc.txt", nil, 10, sess)
	if err != nil {
		t.Fatalf("initUpload fell back but still failed: %v", err)
	}
	if init.NodeID != "f-2" || !init.NewNode {
		t.Errorf("init = %+v, want the recreated node f-2 with NewNode true", init)
	}
	// The listing that named a dead node must not be served to anyone else.
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("the stale listing was kept after its node turned out to be gone")
	}
}

// — Mkdir resolves the parent from the cached listing ——————————————————————————

// A folder under a file has no collection to land in: 409 Conflict (the
// handler maps os.ErrNotExist), without any API call.
func TestWebdavFS_MkdirUnderAFileIsConflict(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/": {{ID: "f-1", Name: "doc.txt", Type: "file"}},
	})

	if err := fs.Mkdir(context.Background(), "/dataroom/DR/doc.txt/d", 0o755); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Mkdir under a file: error = %v, want os.ErrNotExist", err)
	}
}

// The cached listing can name a parent deleted elsewhere: the creation answers
// 404 or 410, the client gets 409 Conflict and the stale listing is dropped.
func TestWebdavFS_MkdirUnderDeletedParent(t *testing.T) {
	for _, status := range goneStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			handler := func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "parent gone", status)
			}
			fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
				"retyc://dr1/": {{ID: "d-old", Name: "a", Type: "dir"}},
			})

			if err := fs.Mkdir(context.Background(), "/dataroom/DR/a/b", 0o755); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Mkdir: error = %v, want os.ErrNotExist", err)
			}
			if nodeCacheHas(fs, "retyc://dr1/") {
				t.Error("the listing naming the deleted parent was kept")
			}
		})
	}
}

// The API also answers 409 for a parent_id naming a deleted folder (the
// dangling reference fails a foreign key), not only for a name already taken.
// The parent is re-resolved from a fresh listing: gone → 409 Conflict for the
// client; re-created under another ID → one retry there; unchanged → the
// conflict is genuine and returned as is (405 for the client).
func TestWebdavFS_MkdirConflictRechecksParent(t *testing.T) {
	cases := map[string]struct {
		freshRoot map[string]string // root listing the API now serves
		wantErr   error             // nil: created
		wantCalls []string
	}{
		"parent gone": {
			freshRoot: map[string]string{},
			wantErr:   os.ErrNotExist,
			wantCalls: []string{"POST /dataroom/dr1/node parent=d-old", "GET /dataroom/dr1/nodes parent="},
		},
		"parent re-created": {
			freshRoot: map[string]string{"d-new": "a"},
			wantCalls: []string{
				"POST /dataroom/dr1/node parent=d-old",
				"GET /dataroom/dr1/nodes parent=",
				"POST /dataroom/dr1/node parent=d-new",
			},
		},
		"name taken": {
			freshRoot: map[string]string{"d-old": "a"},
			wantErr:   api.ErrConflict,
			wantCalls: []string{"POST /dataroom/dr1/node parent=d-old", "GET /dataroom/dr1/nodes parent="},
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			var log callLog
			var pub string
			handler := func(w http.ResponseWriter, r *http.Request) {
				var parent string
				if r.Method == http.MethodPost {
					var body struct {
						ParentID *string `json:"parent_id"`
					}
					_ = json.NewDecoder(r.Body).Decode(&body)
					parent = parentLabel(body.ParentID)
				} else {
					parent = r.URL.Query().Get("parent_id")
				}
				log.add(r.Method + " " + r.URL.Path + " parent=" + parent)
				switch {
				case r.Method == http.MethodPost && parent == "d-old":
					http.Error(w, "conflict", http.StatusConflict)
				case r.Method == http.MethodPost && parent == "d-new":
					fmt.Fprint(w, `{"id":"d-b","name_enc":"x"}`)
				case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
					fmt.Fprint(w, nodesPageJSON(t, pub, tc.freshRoot))
				default:
					http.Error(w, "unexpected", http.StatusInternalServerError)
				}
			}
			fs, identity := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
				"retyc://dr1/":  {{ID: "d-old", Name: "a", Type: "dir"}},
				"retyc://dr1/a": {{ID: "f-ghost", Name: "ghost.txt", Type: "file"}},
			})
			pub = identity.Recipient().String()

			err := fs.Mkdir(context.Background(), "/dataroom/DR/a/b", 0o755)
			if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("Mkdir: error = %v, want %v", err, tc.wantErr)
			}
			if calls := log.list(); !slices.Equal(calls, tc.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, tc.wantCalls)
			}
			if _, ghost := fs.cachedFileNodeID("dr1", "/a", "ghost.txt"); ghost && !errors.Is(tc.wantErr, api.ErrConflict) {
				t.Error("the deleted parent's listing still serves its ghost children")
			}
		})
	}
}

// A folder deleted elsewhere and re-created here under the same name within the
// TTL must not inherit the listings cached below the old one: a PUT deeper in
// the tree would otherwise resolve a parent ID of the deleted tree.
func TestWebdavFS_MkdirDropsListingsOfTheOldFolder(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node" {
			fmt.Fprint(w, `{"id":"d-new","name_enc":"x"}`)

			return
		}
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/":      {},
		"retyc://dr1/a":     {{ID: "d-sub-old", Name: "sub", Type: "dir"}},
		"retyc://dr1/a/sub": {{ID: "f-ghost", Name: "ghost.txt", Type: "file"}},
	})

	if err := fs.Mkdir(context.Background(), "/dataroom/DR/a", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if nodeCacheHas(fs, "retyc://dr1/a/sub") {
		t.Error("a listing below the re-created folder survived")
	}
	if id, listed := cachedNodeID(fs, "retyc://dr1/a", "sub"); !listed || id != "" {
		t.Errorf("new folder listing: sub = %q (listed %v), want empty", id, listed)
	}
}

// smallFileReply is the answer of POST /dataroom/{id}/node/file.
func smallFileReply(nodeID, versionID string, number int) string {
	return fmt.Sprintf(`{"node":{"id":%q,"name_enc":"x","type_enc":"x","parent_id":null},`+
		`"node_version":{"id":%q,"node_id":%q,"original_size":0,"chunk_count":0,"version_number":%d,`+
		`"created_at":"2026-10-05T10:00:00Z"},"max_version_number":%d,"capabilities":{}}`,
		nodeID, versionID, nodeID, number, number)
}

// smallFileParent returns the parent_id of a POST /dataroom/{id}/node/file,
// "" for the root.
func smallFileParent(t *testing.T, r *http.Request) string {
	t.Helper()
	if err := r.ParseMultipartForm(10 << 20); err != nil { //nolint:gosec // G120: test server
		t.Errorf("ParseMultipartForm: %v", err)
	}

	return r.FormValue("parent_id")
}

// The sequence davfs2 sends for `mkdir -p a/b && echo x > a/b/f` (traced on the
// CSI): MKCOL a, MKCOL a/b, an empty PUT on create, then the PUT with content.
// Every folder ID is known from the cache — the root listing, then the folders
// just created — and each PUT fits in one chunk, so each request is a single
// API call: no listing to find a parent, no node, version and chunk in turn.
func TestWebdav_MkdirThenWriteUsesOnlyCachedParents(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	var log callLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
			var body struct {
				ParentID *string `json:"parent_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			next := map[string]string{"": "d-a", "d-a": "d-b", "d-b": "f-1"}
			parent := ""
			if body.ParentID != nil {
				parent = *body.ParentID
			}
			fmt.Fprintf(w, `{"id":%q,"name_enc":"x"}`, next[parent])
		case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node/file":
			if parent := smallFileParent(t, r); parent != "d-b" {
				t.Errorf("parent_id = %q, want d-b", parent)
			}
			n := len(log.list()) - 2 // 1 for the empty PUT, 2 for the next
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, smallFileReply("f-1", fmt.Sprintf("v-%d", n), n))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	fs := newWebdavTestFS(srv)
	fs.cache = newDataroomCache(func(context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{{id: "dr1", title: "Room"}}, nil
	})
	fs.sessions.Store("dr1", &service.DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()})
	ctx := context.Background()

	for _, dir := range []string{"/dataroom/Room/a", "/dataroom/Room/a/b"} {
		if err := fs.Mkdir(ctx, dir, 0o755); err != nil {
			t.Fatalf("Mkdir(%s): %v", dir, err)
		}
	}
	for _, body := range []string{"", "0123456789"} {
		putCtx := withContentLength(withIsPut(ctx), int64(len(body)))
		f, err := fs.OpenFile(putCtx, "/dataroom/Room/a/b/f", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			t.Fatalf("OpenFile (%d bytes): %v", len(body), err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close (%d bytes): %v", len(body), err)
		}
	}

	want := []string{
		"POST /dataroom/dr1/node",      // MKCOL a
		"POST /dataroom/dr1/node",      // MKCOL a/b
		"POST /dataroom/dr1/node/file", // empty PUT
		"POST /dataroom/dr1/node/file", // PUT with content: next version
	}
	if calls := log.list(); !slices.Equal(calls, want) {
		t.Errorf("API calls:\n  %s\nwant:\n  %s", strings.Join(calls, "\n  "), strings.Join(want, "\n  "))
	}
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	entry := fs.nodeCache["retyc://dr1/a/b"]
	if entry == nil || len(entry.nodes) != 1 || entry.nodes[0].VersionID != "v-2" || entry.nodes[0].Size != 10 {
		t.Errorf("listing of a/b = %+v, want f at version v-2, 10 bytes", entry)
	}
}

// A buffered PUT larger than one chunk whose upload fails cleans up what it
// created, like a streamed one: the node when it was new, only the new version
// of an existing node. (A file that fits in one chunk is created in a single
// request, which the server discards on failure.)
func TestWriteFileHandle_BufferedPutFailureCleansUp(t *testing.T) {
	cases := map[string]struct {
		listing []service.DataroomNodeInfo
		cleanup string
	}{
		"new file": {cleanup: "DELETE /dataroom/node/f-new"},
		"existing file": {
			listing: []service.DataroomNodeInfo{{ID: "f-1", Name: "doc.txt", Type: "file"}},
			cleanup: "DELETE /dataroom/node/version/v-2",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			var log callLog
			handler := func(w http.ResponseWriter, r *http.Request) {
				log.add(r.Method + " " + r.URL.Path)
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
					fmt.Fprint(w, `{"id":"f-new","name_enc":"x"}`)
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/version"):
					fmt.Fprint(w, `{"id":"v-2","created_at":"2026-10-04T10:00:00Z"}`)
				case r.Method == http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				default: // the chunk upload fails
					http.Error(w, "boom", http.StatusInternalServerError)
				}
			}
			fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
				"retyc://dr1/": tc.listing,
			})

			f, err := fs.OpenFile(withIsPut(context.Background()), "/dataroom/DR/doc.txt",
				os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			if _, err := f.Write(make([]byte, service.UploadChunkSize+1)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := f.Close(); err == nil {
				t.Fatal("Close succeeded although the chunk upload failed")
			}
			if calls := log.list(); !slices.Contains(calls, tc.cleanup) {
				t.Errorf("calls = %v, want the cleanup %s", calls, tc.cleanup)
			}
		})
	}
}

// A PUT without Content-Length (chunked, as macOS Finder sends it) is buffered
// to a temp file and uploaded on Close. It must resolve the folder and the
// existing node from the cached listings like a streamed PUT — not walk the
// path from the root, hit a 409 and re-list — and update the listing in place.
// A file that fits in one chunk is a single API call.
func TestWriteFileHandle_BufferedPutUsesCachedListings(t *testing.T) {
	var log callLog
	handler := func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Method + " " + r.URL.Path)
		if r.Method != http.MethodPost || r.URL.Path != "/dataroom/dr1/node/file" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)

			return
		}
		if parent := smallFileParent(t, r); parent != "d-a" {
			t.Errorf("parent_id = %q, want d-a", parent)
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, smallFileReply("f-1", "v-2", 2))
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"retyc://dr1/a": {{ID: "f-1", Name: "doc.txt", Type: "file", VersionID: "v-1"}},
	})

	uploaded := metrics.WebdavBytes.WithLabelValues("upload")
	uploadedBefore := testutil.ToFloat64(uploaded)
	f, err := fs.OpenFile(withIsPut(context.Background()), "/dataroom/DR/a/doc.txt",
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("0123456789")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The handler reads the ETag after Close from the info Stat returned
	// before it: it must be the new version's, not the ModTime+Size default,
	// or the client's next conditional GET downloads the file again.
	if etag, err := fi.(webdav.ETager).ETag(context.Background()); err != nil || etag != `"v-2"` {
		t.Errorf("ETag = (%q, %v), want the new version \"v-2\"", etag, err)
	}

	want := []string{"POST /dataroom/dr1/node/file"}
	if calls := log.list(); !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
	// The bytes were counted once, as they arrived; uploading the buffer must
	// not count them again.
	if got := counterDelta(t, uploaded, uploadedBefore); got != 10 {
		t.Errorf("upload bytes counted = %v, want 10", got)
	}
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	entry := fs.nodeCache["retyc://dr1/a"]
	if entry == nil || len(entry.nodes) != 1 || entry.nodes[0].VersionID != "v-2" || entry.nodes[0].Size != 10 {
		t.Errorf("listing after the upload = %+v, want doc.txt at version v-2, 10 bytes", entry)
	}
}

// — PUT of a file that fits in one chunk ——————————————————————————————————————

// The PUT response carries the new version's ETag, although the version only
// exists once Close has sent the file: the handler reads the ETag after Close,
// from the info Stat returned before it.
func TestSmallPut_ETagAndListing(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1/node/file" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)

			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, smallFileReply("f-9", "v-9", 1))
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{"retyc://dr1/": {}})
	ctx := withContentLength(withIsPut(context.Background()), 5)

	f, err := fs.OpenFile(ctx, "/dataroom/DR/doc.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	etag, err := fi.(webdav.ETager).ETag(context.Background())
	if err != nil || etag != `"v-9"` {
		t.Errorf("ETag = (%q, %v), want the new version \"v-9\"", etag, err)
	}
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	nodes := fs.nodeCache["retyc://dr1/"].nodes
	if len(nodes) != 1 || nodes[0].ID != "f-9" || nodes[0].VersionID != "v-9" || nodes[0].Size != 5 ||
		nodes[0].ChunkCount != 1 {
		t.Errorf("listing = %+v, want doc.txt as f-9 at v-9, 5 bytes in 1 chunk", nodes)
	}
}

// A body shorter than its Content-Length is not sent: the version would not
// hold what the client declared.
func TestSmallPut_ShortBodyIsNotSent(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{"retyc://dr1/": {}})
	ctx := withContentLength(withIsPut(context.Background()), 10)

	f, err := fs.OpenFile(ctx, "/dataroom/DR/doc.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("short")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err == nil {
		t.Error("Close succeeded with 5 of the 10 declared bytes")
	}
	if _, err := f.Write([]byte("0123456789")); err == nil {
		t.Error("Write accepted bytes after Close")
	}
}

// The cached listing can name a parent deleted elsewhere: the request answers
// 404, and the stale listings are dropped so the next request re-resolves.
func TestSmallPut_DeletedParentDropsListings(t *testing.T) {
	handler := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "parent not found", http.StatusNotFound)
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{
		"retyc://dr1/":  {{ID: "d-old", Name: "a", Type: "dir"}},
		"retyc://dr1/a": {},
	})
	ctx := withContentLength(withIsPut(context.Background()), 5)

	f, err := fs.OpenFile(ctx, "/dataroom/DR/a/doc.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err == nil {
		t.Fatal("Close succeeded although the parent is gone")
	}
	for _, uri := range []string{"retyc://dr1/", "retyc://dr1/a"} {
		if nodeCacheHas(fs, uri) {
			t.Errorf("%s still cached after the parent turned out to be gone", uri)
		}
	}
}
