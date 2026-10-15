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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
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

// TestWriteFileHandle_LockSkipsEmptyUpload verifies that a zero-byte create that
// did not originate from a PUT (i.e. a LOCK lock-null resource) is dropped without
// an upload attempt, and the spool file is removed.
func TestWriteFileHandle_LockSkipsEmptyUpload(t *testing.T) {
	spoolDir := t.TempDir()
	// A nil client is never dereferenced on the skip path.
	fs := newTestFS(nil, vfs.Options{SpoolDir: spoolDir})
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})

	// No withIsPut: a LOCK-driven create, which must not upload.
	h, err := fs.OpenFile(context.Background(), "/dataroom/DR/f.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if entries, _ := os.ReadDir(spoolDir); len(entries) != 1 {
		t.Fatalf("spool dir holds %d files while the handle is open, want 1", len(entries))
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close (LOCK empty) = %v, want nil", err)
	}
	if entries, _ := os.ReadDir(spoolDir); len(entries) != 0 {
		t.Error("the spool file should have been removed after skipping the empty upload")
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

// — Stale listing cache after an out-of-band delete ————————————————————————————

// newWebdavTestFS builds a webdavFS whose API client points at srv, with the
// listing and session caches pre-warmed for dataroom "dr1" — the state the server
// is in when a file is deleted from the web app while our cache is still warm.
func newWebdavTestFS(srv *httptest.Server) *webdavFS {
	client := api.New(srv.URL, "retyc-test/1.0", oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}), false, false, api.WithMissingChunkRetries()) // a 404 fails at once

	fs := newTestFS(client, vfs.Options{})
	setNodeCache(fs, map[string]*nodeCacheEntry{
		"retyc://dr1/": {
			nodes:     []service.DataroomNodeInfo{{ID: "n1", Name: "log.txt", Type: "file"}},
			fetchedAt: time.Now(),
		},
	})
	fs.tree.SeedSession("dr1", &service.DataroomSession{})

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
		parentPath: "/",
		info:       &webdavFileInfo{name: "log.txt", size: 42},
	}
}

// testStores maps a webdavFS built by newTestFS to the store of its listing
// cache, which the helpers below seed and read without going through the API.
var testStores sync.Map

// newTestFS returns a webdavFS over client (nil when the test reaches no API)
// whose listing cache the helpers below can seed and read.
func newTestFS(client *api.Client, opts vfs.Options) *webdavFS {
	store := memstore.New()
	opts.Store = store
	fs := newWebdavFS(client, opts)
	testStores.Store(fs, store)

	return fs
}

// setClient points fs at another API, with an empty listing cache and no
// session. The list of datarooms is carried over.
func setClient(fs *webdavFS, client *api.Client) {
	fresh := newTestFS(client, vfs.Options{})
	if list, ok, _ := nodeStore(fs).GetDatarooms(context.Background()); ok {
		_ = nodeStore(fresh).PutDatarooms(context.Background(), list)
	}
	testStores.Store(fs, nodeStore(fresh))
	fs.client, fs.tree = fresh.client, fresh.tree
}

func nodeStore(fs *webdavFS) *memstore.Store {
	store, _ := testStores.Load(fs)

	return store.(*memstore.Store)
}

// listingKey is the cache key of the listing a retyc:// URI names.
func listingKey(uri string) vfs.ListingKey {
	drID, sub, _ := strings.Cut(strings.TrimPrefix(uri, "retyc://"), "/")

	return vfs.ListingKey{DataroomID: drID, Path: "/" + sub}
}

// nodeCacheEntry is a listing to seed the cache with.
type nodeCacheEntry struct {
	nodes     []service.DataroomNodeInfo
	fetchedAt time.Time
}

// putNodeCache stores entry as the cached listing of uri.
func putNodeCache(fs *webdavFS, uri string, entry *nodeCacheEntry) {
	var nodes []vfs.Node
	if entry.nodes != nil {
		nodes = make([]vfs.Node, len(entry.nodes))
	}
	for i, n := range entry.nodes {
		nodes[i] = vfs.NodeFromInfo(n)
	}
	_ = nodeStore(fs).PutListing(context.Background(), listingKey(uri),
		&vfs.Listing{Nodes: nodes, FetchedAt: entry.fetchedAt})
}

// setNodeCache makes entries, keyed by URI, the whole listing cache of
// dataroom "dr1" and of the datarooms they name.
func setNodeCache(fs *webdavFS, entries map[string]*nodeCacheEntry) {
	dropCached(fs, "dr1")
	for uri := range entries {
		dropCached(fs, listingKey(uri).DataroomID)
	}
	for uri, entry := range entries {
		putNodeCache(fs, uri, entry)
	}
}

// dropCached empties the listing cache of a dataroom, entries of single
// lookups included.
func dropCached(fs *webdavFS, dataroomID string) {
	_ = nodeStore(fs).DeleteSubtree(context.Background(), dataroomID, "/")
	_ = nodeStore(fs).DeleteEntriesBelow(context.Background(), dataroomID, "/")
}

// addCachedNode adds node to the cached listing of uri.
func addCachedNode(fs *webdavFS, uri string, node vfs.Node) {
	_, _ = nodeStore(fs).UpsertNode(context.Background(), listingKey(uri), node)
}

// cachedListing returns the cached listing of uri; listed is false when there
// is none.
func cachedListing(fs *webdavFS, uri string) (nodes []vfs.Node, listed bool) {
	l, ok, _ := nodeStore(fs).GetListing(context.Background(), listingKey(uri))
	if !ok {
		return nil, false
	}

	return l.Nodes, true
}

// cachedEntry returns the cached listing of uri as the tests read it, nil when
// there is none.
func cachedEntry(fs *webdavFS, uri string) *struct{ nodes []vfs.Node } {
	nodes, ok := cachedListing(fs, uri)
	if !ok {
		return nil
	}

	return &struct{ nodes []vfs.Node }{nodes}
}

// cachedNodes returns the nodes of the cached listing of uri.
func cachedNodes(fs *webdavFS, uri string) []vfs.Node {
	nodes, _ := cachedListing(fs, uri)

	return nodes
}

func nodeCacheHas(fs *webdavFS, uri string) bool {
	_, ok := cachedListing(fs, uri)

	return ok
}

// cachedNodeID looks a node up by name in the cached listing of uri. listed
// is false when uri has no cached listing at all.
func cachedNodeID(fs *webdavFS, uri, name string) (id string, listed bool) {
	nodes, ok := cachedListing(fs, uri)
	if !ok {
		return "", false
	}
	for _, n := range nodes {
		if n.Name == name {
			return n.ID, true
		}
	}

	return "", true
}

// cachedDirID looks a folder up by name in the cached listing of uri.
func cachedDirID(fs *webdavFS, uri, name string) (string, bool) {
	for _, n := range cachedNodes(fs, uri) {
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
// rest of the TTL.
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
	fs.tree.SeedSession("dr1", &service.DataroomSession{Identity: identity})
	h := &readFileHandle{
		ctx:        context.Background(),
		wfs:        fs,
		drID:       "dr1",
		versionID:  "v1",
		chunkCount: 1,
		parentPath: "/",
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
	fs := newTestFS(nil, vfs.Options{})
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})
	setNodeCache(fs, map[string]*nodeCacheEntry{
		"retyc://dr1/": {
			nodes:     []service.DataroomNodeInfo{fileNode},
			fetchedAt: time.Now(),
		},
	})

	info, err := fs.Stat(context.Background(), "/dataroom/DR/f.txt")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.ModTime().Equal(created) {
		t.Errorf("Stat().ModTime() = %v, want %v", info.ModTime(), created)
	}
	entries := nodesToFileInfos([]vfs.Node{vfs.NodeFromInfo(fileNode)})
	if len(entries) != 1 || !entries[0].ModTime().Equal(created) {
		t.Errorf("nodesToFileInfos ModTime = %v, want %v", entries[0].ModTime(), created)
	}
}

// PROPFIND reads a resource's properties from OpenFile(...).Stat(), not from
// FileSystem.Stat: a folder opened for reading must carry the modification
// time its listing gave it, or getlastmodified reports the zero time.
func TestWebdavFS_OpenFolderCarriesModTime(t *testing.T) {
	created := time.Date(2026, 10, 10, 12, 2, 32, 0, time.UTC)
	folder := service.DataroomNodeInfo{ID: "n-sub", Name: "sub", Type: "dir"}.WithModTime(created)
	fs := newTestFS(nil, vfs.Options{})
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})
	setNodeCache(fs, map[string]*nodeCacheEntry{
		"retyc://dr1/": {nodes: []service.DataroomNodeInfo{folder}, fetchedAt: time.Now()},
	})

	f, err := fs.OpenFile(context.Background(), "/dataroom/DR/sub", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer f.Close() //nolint:errcheck
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.IsDir() || !info.ModTime().Equal(created) {
		t.Errorf("opened folder: IsDir = %v, ModTime = %v, want dir at %v", info.IsDir(), info.ModTime(), created)
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
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})
	// An API without the lookup by name: the server answers listings only.
	fs.tree.SeedSession("dr1", (&service.DataroomSession{Identity: identity, PublicKey: pub}).AssumeLegacyAPI())
	ctx := context.Background()

	if err := fs.Mkdir(ctx, "/dataroom/DR/newdir", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if id, ok := cachedDirID(fs, "retyc://dr1/", "newdir"); !ok || id != "n-new" {
		t.Error("Mkdir did not add the new folder to the cached parent listing")
	}
	// The pre-warmed listing does not hold "x", which only the API serves.
	fs.tree.InvalidateListing("dr1", "/")
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

	identity, err := serveStartupCheck(context.Background(), newStartupTestClient(srv), func() (string, error) {
		return "good-pw", nil
	})
	if err != nil {
		t.Fatalf("serveStartupCheck() error = %v, want nil", err)
	}
	if identity == nil {
		t.Fatal("serveStartupCheck() returned a nil identity")
	}
}

func TestWebdavStartupCheck_WrongPassphrase(t *testing.T) {
	srv := newStartupTestServer(t, "good-pw")

	_, err := serveStartupCheck(context.Background(), newStartupTestClient(srv), func() (string, error) {
		return "bad-pw", nil
	})
	if err == nil || !strings.Contains(err.Error(), "wrong key passphrase") {
		t.Fatalf("serveStartupCheck() error = %v, want wrong key passphrase", err)
	}
}

func TestWebdavStartupCheck_APIUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	_, err := serveStartupCheck(context.Background(), newStartupTestClient(srv), func() (string, error) {
		return "good-pw", nil
	})
	if err == nil || !strings.Contains(err.Error(), "API connectivity check failed") {
		t.Fatalf("serveStartupCheck() error = %v, want connectivity failure", err)
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
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})
	fs.tree.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	setNodeCache(fs, map[string]*nodeCacheEntry{})
	for _, uri := range []string{"retyc://dr1/x", "retyc://dr1/x/sub", "retyc://dr1/xy",
		"retyc://dr1/y", "retyc://dr1/y/old"} {
		putNodeCache(fs, uri, &nodeCacheEntry{fetchedAt: time.Now()})
	}
	// The root listing names /x, as the PROPFIND preceding a DELETE would have.
	putNodeCache(fs, "retyc://dr1/", &nodeCacheEntry{
		nodes: []service.DataroomNodeInfo{{ID: "n-x", Name: "x", Type: "dir"}}, fetchedAt: time.Now(),
	})

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
// dataroom "dr1" (title "DR") and the given listings cached. The session is
// one of an API without the lookup by name: a name whose folder is not cached
// is found by listing the folder, which is what these handlers answer.
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
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})
	fs.tree.SeedSession("dr1", (&service.DataroomSession{
		Identity: identity, PublicKey: identity.Recipient().String(),
	}).AssumeLegacyAPI())
	setNodeCache(fs, map[string]*nodeCacheEntry{})
	for uri, nodes := range listings {
		putNodeCache(fs, uri, &nodeCacheEntry{nodes: nodes, fetchedAt: time.Now()})
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

// The cached listing can be up to the TTL old: when the node it names
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

// — A listing under a file ————————————————————————————————————————————————————

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

	if _, err := fs.tree.ReadDir(context.Background(), "dr1", "/doc.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("listNodes under a file: error = %v, want os.ErrNotExist", err)
	}
	if _, err := fs.Stat(context.Background(), "/dataroom/DR/doc.txt/child"); !os.IsNotExist(err) {
		t.Errorf("Stat under a file: error = %v, want a bare not-exist error for the WebDAV handler", err)
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
			if id, _ := cachedNodeID(fs, "retyc://dr1/a", "ghost.txt"); id != "" && !errors.Is(tc.wantErr, api.ErrConflict) {
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
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "Room"}})
	fs.tree.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()})
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
	entry := cachedEntry(fs, "retyc://dr1/a/b")
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
	entry := cachedEntry(fs, "retyc://dr1/a")
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
	nodes := cachedNodes(fs, "retyc://dr1/")
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

// — PUT above the single-request limit ————————————————————————————————————————

// A PUT above service.SmallUploadMaxSize, more than a chunk, is streamed into
// a version and its chunks.
func TestPut_AboveTheSingleRequestLimitIsStreamed(t *testing.T) {
	var log callLog
	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		log.add(r.Method + " " + r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
			fmt.Fprint(w, `{"id":"f-new","name_enc":"x","created_at":"2026-10-01T08:00:00Z"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/f-new/version":
			fmt.Fprint(w, `{"id":"v-1","created_at":"2026-10-04T10:00:00Z"}`)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/dataroom/node/version/v-1/chunk/"):
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}
	fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{"retyc://dr1/": {}})
	size := int64(service.SmallUploadMaxSize + 1)
	ctx := withContentLength(withIsPut(context.Background()), size)

	f, err := fs.OpenFile(ctx, "/dataroom/DR/doc.bin", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write(make([]byte, size)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	want := []string{
		"POST /dataroom/dr1/node",
		"POST /dataroom/node/f-new/version",
		"POST /dataroom/node/version/v-1/chunk/0",
		"POST /dataroom/node/version/v-1/chunk/1",
	}
	// The chunks are sent in parallel.
	calls := log.list()
	slices.Sort(calls[2:])
	if !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
	if etag, err := fi.(webdav.ETager).ETag(context.Background()); err != nil || etag != `"v-1"` {
		t.Errorf("ETag = (%q, %v), want the new version \"v-1\"", etag, err)
	}
	nodes := cachedNodes(fs, "retyc://dr1/")
	if len(nodes) != 1 || nodes[0].ID != "f-new" || nodes[0].VersionID != "v-1" || nodes[0].Size != size ||
		nodes[0].ChunkCount != 2 || nodes[0].CreatedAt.IsZero() {
		t.Errorf("listing = %+v, want doc.bin as f-new at v-1, in 2 chunks, with its creation time", nodes)
	}
}

// A streamed PUT whose body was received in full no longer ends with the
// request: a client that leaves between its last byte and the response does
// not throw the version away. A body still short does: the upload fails and
// what it created is discarded.
func TestPut_StreamedSurvivesAClientGoneOnceTheBodyIsComplete(t *testing.T) {
	size := int64(service.SmallUploadMaxSize + 1)
	for label, sent := range map[string]int64{"complete body": size, "short body": size - 1} {
		t.Run(label, func(t *testing.T) {
			var log callLog
			arrived, release, abandoned := make(chan struct{}, 1), make(chan struct{}), make(chan struct{}, 1)
			handler := func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				log.add(r.Method + " " + r.URL.Path)
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
					fmt.Fprint(w, `{"id":"f-new","name_enc":"x","created_at":"2026-10-01T08:00:00Z"}`)
				case r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/f-new/version":
					fmt.Fprint(w, `{"id":"v-1","created_at":"2026-10-04T10:00:00Z"}`)
				case r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/version/v-1/chunk/0":
					w.WriteHeader(http.StatusCreated)
				case r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/version/v-1/chunk/1":
					// The last chunk, held while the client of the PUT leaves.
					arrived <- struct{}{}
					select {
					case <-release:
						w.WriteHeader(http.StatusCreated)
					case <-r.Context().Done():
						abandoned <- struct{}{}
					}
				case r.Method == http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
				}
			}
			fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{"retyc://dr1/": {}})
			reqCtx, clientLeaves := context.WithCancel(context.Background())
			defer clientLeaves()
			ctx := withContentLength(withIsPut(reqCtx), size)

			f, err := fs.OpenFile(ctx, "/dataroom/DR/doc.bin", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			if _, err := f.Write(make([]byte, sent)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			clientLeaves()

			if sent < size {
				if err := f.Close(); err == nil {
					t.Fatal("Close succeeded with a body one byte short")
				}
				if calls := log.list(); !slices.Contains(calls, "DELETE /dataroom/node/f-new") {
					t.Errorf("calls = %v, want the node of the failed upload deleted", calls)
				}
				if nodes := cachedNodes(fs, "retyc://dr1/"); len(nodes) != 0 {
					t.Errorf("listing = %+v, want nothing of the failed upload", nodes)
				}

				return
			}

			// The last chunk is only sent once the content ends, which Close
			// tells: the handler closes the file right after the body, as
			// x/net/webdav does, the client being gone or not.
			closed := make(chan error, 1)
			go func() { closed <- f.Close() }()
			<-arrived
			select {
			case <-abandoned:
				t.Fatal("the chunk upload was cancelled when the client left, its body complete")
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			if err := <-closed; err != nil {
				t.Fatalf("Close: %v", err)
			}
			if calls := log.list(); slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "DELETE ") }) {
				t.Errorf("calls = %v, want nothing deleted", calls)
			}
			nodes := cachedNodes(fs, "retyc://dr1/")
			if len(nodes) != 1 || nodes[0].ID != "f-new" || nodes[0].VersionID != "v-1" || nodes[0].Size != size {
				t.Errorf("listing = %+v, want doc.bin as f-new at v-1", nodes)
			}
		})
	}
}

// Where the failure of a PUT with a Content-Length surfaces decides its
// status: x/net/webdav answers 404 to an OpenFile that fails (409 for a bare
// os.ErrNotExist) and 405 to a Close that does. A folder that cannot be
// resolved fails OpenFile; a refused upload fails OpenFile when the file is
// streamed (its version is created first) and Close when it is sent in a
// single request.
func TestPut_WhereAFailureSurfaces(t *testing.T) {
	handler := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"Create not allowed here"}`, http.StatusForbidden)
	}
	for label, size := range map[string]int64{"single request": 5, "streamed": service.SmallUploadMaxSize + 1} {
		t.Run(label, func(t *testing.T) {
			fs, _ := newCachedListingsFS(t, handler, map[string][]service.DataroomNodeInfo{"retyc://dr1/": {}})
			ctx := withContentLength(withIsPut(context.Background()), size)
			flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC

			_, err := fs.OpenFile(ctx, "/dataroom/DR/missing/doc.bin", flags, 0o644)
			if err == nil || os.IsNotExist(err) || !errors.Is(err, os.ErrNotExist) {
				t.Errorf("OpenFile under a missing folder = %v, want a wrapped not-exist error (404)", err)
			}

			f, err := fs.OpenFile(ctx, "/dataroom/DR/doc.bin", flags, 0o644)
			if size > service.SmallUploadMaxSize {
				if !errors.Is(err, vfs.ErrForbidden) {
					t.Errorf("OpenFile of a refused streamed upload = %v, want the refusal", err)
				}

				return
			}
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			if _, err := f.Write(make([]byte, size)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := f.Close(); !errors.Is(err, vfs.ErrForbidden) {
				t.Errorf("Close of a refused upload = %v, want the refusal", err)
			}
		})
	}
}

// — vfs defaults ——————————————————————————————————————————————————————————————

// vfs cannot import internal/config: its fallback TTL is a copy of the
// configuration default, and the two must not drift apart.
func TestVFSDefaultCacheTTLMatchesConfig(t *testing.T) {
	if vfs.DefaultCacheTTL != config.DefaultCacheTTL {
		t.Errorf("vfs.DefaultCacheTTL = %v, config.DefaultCacheTTL = %v",
			vfs.DefaultCacheTTL, config.DefaultCacheTTL)
	}
}

// Same for the negative cache: vfs.DefaultNegativeTTL is what an FS built
// outside a command passes, cache.negative_ttl what the commands pass.
func TestVFSDefaultNegativeTTLMatchesConfig(t *testing.T) {
	if vfs.DefaultNegativeTTL != config.DefaultCacheNegativeTTL {
		t.Errorf("vfs.DefaultNegativeTTL = %v, config.DefaultCacheNegativeTTL = %v",
			vfs.DefaultNegativeTTL, config.DefaultCacheNegativeTTL)
	}
}

// Same for the number of background refreshes: webdav serve passes
// api.concurrency.list, and an FS built without it must not differ.
func TestVFSDefaultListConcurrencyMatchesConfig(t *testing.T) {
	if vfs.DefaultListConcurrency != config.DefaultConcurrency {
		t.Errorf("vfs.DefaultListConcurrency = %d, config.DefaultConcurrency = %d",
			vfs.DefaultListConcurrency, config.DefaultConcurrency)
	}
}

func TestVFSDefaultUploadConcurrencyMatchesConfig(t *testing.T) {
	if vfs.DefaultUploadConcurrency != config.DefaultConcurrency {
		t.Errorf("vfs.DefaultUploadConcurrency = %d, config.DefaultConcurrency = %d",
			vfs.DefaultUploadConcurrency, config.DefaultConcurrency)
	}
}
