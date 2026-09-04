package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
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

	h := &streamWriteHandle{
		wfs:       &webdavFS{},
		newNode:   false, // existing-node path: cleanup only warns, no client call
		pipeW:     pipeW,
		done:      done,
		parentURI: "retyc://dr/",
		info:      &webdavFileInfo{name: "f.bin", size: 100},
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
		parentURI:    "retyc://dr/",
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
		"127.0.0.1":    true,
		"localhost":    true,
		"::1":          true,
		"0.0.0.0":      false,
		"192.168.1.10": false,
		"":             false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
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

	return &webdavFS{
		client: client,
		nodeCache: map[string]*nodeCacheEntry{
			"retyc://dr1/": {
				nodes:     []service.DataroomNodeInfo{{ID: "n1", Name: "log.txt", Type: "file"}},
				fetchedAt: time.Now(),
			},
		},
		sessionCache: map[string]*sessionCacheEntry{
			"dr1": {sess: &service.DataroomSession{}, fetchedAt: time.Now()},
		},
	}
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
	fs.sessionCache["dr1"] = &sessionCacheEntry{
		sess:      &service.DataroomSession{Identity: identity, PublicKey: pub},
		fetchedAt: time.Now(),
	}
	ctx := context.Background()

	if err := fs.Mkdir(ctx, "/dataroom/DR/newdir", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("Mkdir did not invalidate the parent listing")
	}
	if err := fs.Rename(ctx, "/dataroom/DR/x", "/dataroom/DR/y"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := fs.RemoveAll(ctx, "/dataroom/DR/x"); err != nil {
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
