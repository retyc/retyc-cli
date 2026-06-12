package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestParseWebdavPath_Root(t *testing.T) {
	drName, subPath, isRoot := parseWebdavPath("/")
	if !isRoot || drName != "" || subPath != "" {
		t.Errorf("parseWebdavPath(\"/\") = (%q, %q, %v), want (\"\", \"\", true)", drName, subPath, isRoot)
	}
}

func TestParseWebdavPath_DataroomOnly(t *testing.T) {
	drName, subPath, isRoot := parseWebdavPath("/My Dataroom")
	if isRoot || drName != "My Dataroom" || subPath != "/" {
		t.Errorf("parseWebdavPath(\"/My Dataroom\") = (%q, %q, %v), want (\"My Dataroom\", \"/\", false)",
			drName, subPath, isRoot)
	}
}

func TestParseWebdavPath_DataroomTrailingSlash(t *testing.T) {
	drName, subPath, isRoot := parseWebdavPath("/My Dataroom/")
	if isRoot || drName != "My Dataroom" || subPath != "/" {
		t.Errorf("parseWebdavPath(\"/My Dataroom/\") = (%q, %q, %v), want (\"My Dataroom\", \"/\", false)",
			drName, subPath, isRoot)
	}
}

func TestParseWebdavPath_DeepPath(t *testing.T) {
	drName, subPath, isRoot := parseWebdavPath("/My Dataroom/folder/file.txt")
	if isRoot || drName != "My Dataroom" || subPath != "/folder/file.txt" {
		t.Errorf("parseWebdavPath(\"/My Dataroom/folder/file.txt\") = (%q, %q, %v)",
			drName, subPath, isRoot)
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
