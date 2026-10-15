package vfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// — The chunk size of a version: memo, request to the API, fallbacks —————————

// sizeAPI is a fake API holding file versions cut in chunks, encrypted for
// real: it answers the download of a chunk and, in the way head says, the
// request for its size. It records every request as "METHOD version/index".
type sizeAPI struct {
	t        *testing.T
	identity *age.HybridIdentity
	srv      *httptest.Server
	log      callLog

	mu       sync.Mutex
	versions map[string][][]byte // encrypted chunks
	// head is the status the size route answers, 200 when zero. 404 and 405
	// are an API without the route.
	head int
	// headCode is the X-Error-Code of a refused size request, none when empty.
	headCode string
}

func newSizeAPI(t *testing.T) *sizeAPI {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	a := &sizeAPI{t: t, identity: identity, versions: make(map[string][][]byte)}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)

	return a
}

// store adds a version of data cut in chunks of size bytes and returns the
// node of its file.
func (a *sizeAPI) store(versionID string, data []byte, size int) Node {
	a.t.Helper()
	var chunks [][]byte
	for _, plain := range cut(data, size) {
		enc, err := crypto.EncryptBinaryForKey(plain, a.identity.Recipient().String())
		if err != nil {
			a.t.Fatalf("EncryptBinaryForKey: %v", err)
		}
		chunks = append(chunks, enc)
	}
	a.mu.Lock()
	a.versions[versionID] = chunks
	a.mu.Unlock()

	return Node{Type: TypeFile, VersionID: versionID, Size: int64(len(data)), ChunkCount: len(chunks)}
}

func (a *sizeAPI) setHead(status int) {
	a.mu.Lock()
	a.head = status
	a.mu.Unlock()
}

func (a *sizeAPI) serve(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/dataroom/node/version/"), "/")
	if len(parts) != 3 || parts[1] != "chunk" {
		a.t.Errorf("unexpected API request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)

		return
	}
	a.log.add(r.Method + " " + parts[0] + "/" + parts[2])
	index, _ := strconv.Atoi(parts[2])
	a.mu.Lock()
	chunks, head, headCode := a.versions[parts[0]], a.head, a.headCode
	a.mu.Unlock()

	if r.Method == http.MethodHead && head != 0 && head != http.StatusOK {
		if headCode != "" {
			w.Header().Set(api.ErrorCodeHeader, headCode)
		}
		w.WriteHeader(head)

		return
	}
	if index >= len(chunks) {
		http.NotFound(w, r)

		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(chunks[index])))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(chunks[index])
}

// fs returns an FS reading through the fake API, which assumes chunks of
// testChunkSize bytes. A chunk download answered 404 fails at once.
func (a *sizeAPI) fs(opts Options) *FS {
	client := api.New(a.srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}),
		false, false, api.WithMissingChunkRetries())
	if opts.ChunkSize == 0 {
		opts.ChunkSize = testChunkSize
	}
	opts.Session = func(context.Context, string) (*service.DataroomSession, error) {
		return &service.DataroomSession{Identity: a.identity}, nil
	}
	fs := New(client, opts)
	a.t.Cleanup(func() { _ = fs.Close() })

	return fs
}

// requests returns, sorted, the requests received since the last call.
func (a *sizeAPI) requests() string {
	a.log.mu.Lock()
	calls := slices.Clone(a.log.calls)
	a.log.calls = nil
	a.log.mu.Unlock()
	slices.Sort(calls)

	return strings.Join(calls, " ")
}

// readOnce opens n, reads count bytes at off, checks them against data and
// closes the file.
func readOnce(t *testing.T, fs *FS, n Node, data []byte, off int64, count int) {
	t.Helper()
	f, err := fs.Open(context.Background(), "dr1", n)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	p := make([]byte, count)
	if _, err := f.ReadAt(p, off); err != nil {
		t.Fatalf("ReadAt(%d bytes at %d): %v", count, off, err)
	}
	if !bytes.Equal(p, data[off:off+int64(count)]) {
		t.Fatalf("ReadAt(%d bytes at %d) = %q, want %q", count, off, p, data[off:off+int64(count)])
	}
}

func wantRequests(t *testing.T, a *sizeAPI, want string) {
	t.Helper()
	if got := a.requests(); got != want {
		t.Fatalf("requests = %q, want %q", got, want)
	}
}

// The requests each way of knowing the chunk size costs, against an API that
// encrypts for real: the size it tells is that of the encrypted chunk.
func TestFile_ChunkSizeRequests(t *testing.T) {
	data := testData(23)

	t.Run("cut at the default size: no request for the size", func(t *testing.T) {
		a := newSizeAPI(t)
		fs := a.fs(Options{})
		n := a.store("v1", data, testChunkSize) // 6 chunks
		readOnce(t, fs, n, data, 21, 2)
		wantRequests(t, a, "GET v1/5")
		// Nor for an Open that reads nothing.
		f, err := fs.Open(context.Background(), "dr1", a.store("v2", data, 6))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		_ = f.Close()
		wantRequests(t, a, "")
	})

	t.Run("another cut: one request, chunk 0 not downloaded", func(t *testing.T) {
		a := newSizeAPI(t)
		fs := a.fs(Options{})
		n := a.store("v1", data, 6) // 4 chunks, where the default makes 6
		readOnce(t, fs, n, data, 21, 2)
		wantRequests(t, a, "GET v1/3 HEAD v1/0")

		// The same version again, on a new File: the FS remembers.
		readOnce(t, fs, n, data, 13, 2)
		wantRequests(t, a, "GET v1/2")
		// Another FS knows nothing of it.
		readOnce(t, a.fs(Options{}), n, data, 13, 2)
		wantRequests(t, a, "GET v1/2 HEAD v1/0")
	})

	t.Run("another cut, read from the start: chunk 0 tells", func(t *testing.T) {
		a := newSizeAPI(t)
		fs := a.fs(Options{})
		n := a.store("v1", data, 6)
		// Offset 5 is in chunk 0 for any chunk size that makes 4 chunks of 23
		// bytes: the chunk the read needs is the one that tells.
		readOnce(t, fs, n, data, 5, 1)
		wantRequests(t, a, "GET v1/0")
		// And what it told is remembered.
		readOnce(t, fs, n, data, 21, 2)
		wantRequests(t, a, "GET v1/3")
	})

	t.Run("a size proved by a chunk is remembered", func(t *testing.T) {
		a := newSizeAPI(t)
		a.setHead(http.StatusMethodNotAllowed)
		fs := a.fs(Options{})
		// 58 bytes in chunks of 20: 3 chunks, as ceil(58/3) = 20 makes.
		long := testData(58)
		n := a.store("v1", long, 20)
		readOnce(t, fs, n, long, 41, 2)
		wantRequests(t, a, "GET v1/2 HEAD v1/0")
		if got, ok := fs.chunkSizes.get("v1"); !ok || got != 20 {
			t.Errorf("remembered chunk size = %d, %v; want 20", got, ok)
		}
	})

	for name, status := range map[string]int{
		"API without the route, 405": http.StatusMethodNotAllowed,
		"API without the route, 404": http.StatusNotFound,
	} {
		t.Run(name, func(t *testing.T) {
			a := newSizeAPI(t)
			a.setHead(status)
			fs := a.fs(Options{})
			// ceil(23/4) = 6 is assumed, which is the cut.
			n := a.store("v1", data, 6)
			readOnce(t, fs, n, data, 21, 2)
			wantRequests(t, a, "GET v1/3 HEAD v1/0")
			if !fs.chunkSizes.routeAbsent() {
				t.Error("the route is not recorded as absent")
			}

			// Asked once for the FS: no other version asks again, and the
			// assumption is corrected by the chunk read when it is wrong
			// (7 where ceil(23/4) is 6).
			n2 := a.store("v2", data, 7)
			readOnce(t, fs, n2, data, 21, 2)
			wantRequests(t, a, "GET v2/3")
			n3 := a.store("v3", data, 6)
			readOnce(t, fs, n3, data, 13, 2)
			wantRequests(t, a, "GET v3/2")
		})
	}

	t.Run("chunk count unknown, the API tells", func(t *testing.T) {
		a := newSizeAPI(t)
		fs := a.fs(Options{})
		n := a.store("v1", data, 6)
		n.ChunkCount = 0
		readOnce(t, fs, n, data, 21, 2)
		wantRequests(t, a, "GET v1/3 HEAD v1/0")
		readOnce(t, fs, n, data, 13, 2)
		wantRequests(t, a, "GET v1/2")
	})

	t.Run("chunk count unknown, API without the route", func(t *testing.T) {
		a := newSizeAPI(t)
		a.setHead(http.StatusMethodNotAllowed)
		fs := a.fs(Options{})
		n := a.store("v1", data, 6)
		n.ChunkCount = 0
		// Nothing tells: chunk 0 is downloaded for its length.
		readOnce(t, fs, n, data, 21, 2)
		wantRequests(t, a, "GET v1/0 GET v1/3 HEAD v1/0")
		// Then the FS remembers, and knows the route is not there.
		readOnce(t, fs, n, data, 13, 2)
		wantRequests(t, a, "GET v1/2")
		n2 := a.store("v2", data, 6)
		n2.ChunkCount = 0
		readOnce(t, fs, n2, data, 13, 2)
		wantRequests(t, a, "GET v2/0 GET v2/2")
	})
}

// A 404 for the size of a chunk is a missing route only on a version that
// exists: one that does not leaves the route to be asked again, and a route
// that answered once is never taken for missing.
func TestFile_MissingChunkIsNotAMissingRoute(t *testing.T) {
	data := testData(23)
	a := newSizeAPI(t)
	fs := a.fs(Options{})

	// A version the API does not hold: the size route and the chunk both
	// answer 404.
	ghost := Node{Type: TypeFile, VersionID: "ghost", Size: 23, ChunkCount: 4}
	f, err := fs.Open(context.Background(), "dr1", ghost)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := f.ReadAt(make([]byte, 1), 21); !errors.Is(err, api.ErrChunkMissing) {
		t.Fatalf("ReadAt on a missing version: error = %v, want api.ErrChunkMissing", err)
	}
	_ = f.Close()
	wantRequests(t, a, "GET ghost/3 HEAD ghost/0")
	if fs.chunkSizes.routeAbsent() {
		t.Fatal("a missing version made the route absent")
	}

	// The route is asked for the next version, and answers.
	n := a.store("v1", data, 6)
	readOnce(t, fs, n, data, 21, 2)
	wantRequests(t, a, "GET v1/3 HEAD v1/0")

	// From now on a 404 is about the chunk, even on a version whose other
	// chunks download.
	a.setHead(http.StatusNotFound)
	n2 := a.store("v2", data, 6)
	readOnce(t, fs, n2, data, 21, 2)
	wantRequests(t, a, "GET v2/3 HEAD v2/0")
	if fs.chunkSizes.routeAbsent() {
		t.Error("a 404 made a route that had answered absent")
	}
}

// A refusal of the size request that is neither a missing route nor a
// missing chunk fails the read that needed it, as the refusal of a chunk
// does, and the next read asks again.
func TestFile_ChunkSizeRequestErrors(t *testing.T) {
	data := testData(23)
	for name, tc := range map[string]struct {
		status int
		is     error
	}{
		"410": {http.StatusGone, api.ErrGone},
		"403": {http.StatusForbidden, nil},
		"500": {http.StatusInternalServerError, nil},
	} {
		t.Run(name, func(t *testing.T) {
			a := newSizeAPI(t)
			a.setHead(tc.status)
			fs := a.fs(Options{})
			n := a.store("v1", data, 6)
			f, err := fs.Open(context.Background(), "dr1", n)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = f.Close() }()

			_, err = f.ReadAt(make([]byte, 1), 21)
			var httpErr *api.HTTPError
			if !errors.As(err, &httpErr) || httpErr.Status != tc.status {
				t.Fatalf("ReadAt: error = %v, want the API error %d", err, tc.status)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("error = %v, want it to match %v", err, tc.is)
			}
			if errors.Is(err, ErrChunkLayout) {
				t.Errorf("error = %v: a refused request is no unreadable layout", err)
			}
			wantRequests(t, a, "HEAD v1/0")

			// Not final: once the API answers, the same File reads.
			a.setHead(http.StatusOK)
			p := make([]byte, 2)
			if _, err := f.ReadAt(p, 21); err != nil || !bytes.Equal(p, data[21:]) {
				t.Fatalf("ReadAt after the refusal = %q, %v", p, err)
			}
			wantRequests(t, a, "GET v1/3 HEAD v1/0")
		})
	}
}

// What the API tells is checked against the node before anything is
// downloaded, and against every chunk read afterwards.
func TestFile_ChunkSizeToldByTheAPI(t *testing.T) {
	data := testData(23)
	sizeOf := func(size int64, calls *int) ChunkSizeFunc {
		return func(context.Context, string, int) (int64, error) {
			*calls++

			return size, nil
		}
	}
	open := func(t *testing.T, src *chunkSource, told int64, opts Options, count int) (*file, *int) {
		t.Helper()
		calls := new(int)
		opts.ChunkSizeOf = sizeOf(told, calls)
		if opts.ChunkSize == 0 {
			opts.ChunkSize = testChunkSize
		}

		return openFileWith(t, context.Background(), src, opts, count), calls
	}

	t.Run("a size that does not make the count is refused, nothing downloaded", func(t *testing.T) {
		src := newChunkSourceOf(cut(data, 6))
		for _, told := range []int64{5, 8, 0, 24} {
			f, calls := open(t, src, told, Options{}, 4)
			if _, err := f.ReadAt(make([]byte, 1), 21); !errors.Is(err, ErrChunkLayout) {
				t.Errorf("told %d: error = %v, want ErrChunkLayout", told, err)
			}
			if *calls != 1 {
				t.Errorf("told %d: %d size requests, want 1", told, *calls)
			}
		}
		wantCounts(t, src, map[int]int{})
	})

	t.Run("a size beyond the limit is refused, nothing downloaded", func(t *testing.T) {
		src := newChunkSourceOf(cut(data, 12))
		for _, count := range []int{2, 0} {
			f, _ := open(t, src, 12, Options{MaxChunkSize: 11, ChunkSize: 3}, count)
			if _, err := f.ReadAt(make([]byte, 1), 21); !errors.Is(err, ErrChunkLayout) {
				t.Errorf("count %d: error = %v, want ErrChunkLayout", count, err)
			}
		}
		wantCounts(t, src, map[int]int{})
	})

	t.Run("a wrong size the count allows is corrected by the chunk read", func(t *testing.T) {
		// 58 bytes in chunks of 20; the API says 21, which makes 3 chunks too.
		long := testData(58)
		src := newChunkSourceOf(cut(long, 20))
		f, _ := open(t, src, 21, Options{ChunkSize: 4}, 3)
		readAt(t, f, 41, 2, long)
		wantCounts(t, src, map[int]int{1: 1, 2: 1})
		if f.chunkSize != 20 || !f.measured {
			t.Errorf("chunk size = %d (measured %v), want 20, measured", f.chunkSize, f.measured)
		}
	})

	t.Run("chunk count unknown: a chunk that contradicts it is an error", func(t *testing.T) {
		src := newChunkSourceOf(cut(data, 6))
		f, _ := open(t, src, 8, Options{}, 0)
		if _, err := f.ReadAt(make([]byte, 1), 21); !errors.Is(err, ErrChunkLayout) {
			t.Errorf("error = %v, want ErrChunkLayout", err)
		}
	})

	t.Run("concurrent first reads share one request", func(t *testing.T) {
		src := newChunkSourceOf(cut(data, 6))
		release := make(chan struct{})
		var (
			mu    sync.Mutex
			calls int
		)
		opts := Options{ChunkSize: testChunkSize, ChunkSizeOf: func(ctx context.Context, _ string, _ int) (int64, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			select {
			case <-release:
			case <-ctx.Done():
				return 0, ctx.Err()
			}

			return 6, nil
		}}
		f := openFileWith(t, context.Background(), src, opts, 4)
		var wg sync.WaitGroup
		for _, off := range []int64{7, 13, 19, 22} {
			wg.Go(func() {
				p := make([]byte, 1)
				if _, err := f.ReadAt(p, off); err != nil || p[0] != data[off] {
					t.Errorf("ReadAt at %d = %q, %v", off, p, err)
				}
			})
		}
		waitFor(t, f, "the size request", func() bool { return f.probe != nil })
		close(release)
		wg.Wait()
		if calls != 1 {
			t.Errorf("%d size requests, want 1", calls)
		}
		if got := src.counts()[0]; got != 0 {
			t.Errorf("chunk 0 downloaded %d times, want 0", got)
		}
	})

	t.Run("a read that gives up leaves the request to the others", func(t *testing.T) {
		src := newChunkSourceOf(cut(data, 6))
		release := make(chan struct{})
		opts := Options{ChunkSize: testChunkSize, ChunkSizeOf: func(context.Context, string, int) (int64, error) {
			<-release

			return 6, nil
		}}
		f := openFileWith(t, context.Background(), src, opts, 4)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := f.ReadAtContext(ctx, make([]byte, 1), 21)
			done <- err
		}()
		waitFor(t, f, "the size request", func() bool { return f.probe != nil })
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled read: error = %v, want context.Canceled", err)
		}
		close(release)
		readAt(t, f, 21, 2, data)
	})

	t.Run("Close ends a read waiting for the size", func(t *testing.T) {
		src := newChunkSourceOf(cut(data, 6))
		opts := Options{ChunkSize: testChunkSize, ChunkSizeOf: func(ctx context.Context, _ string, _ int) (int64, error) {
			<-ctx.Done()

			return 0, ctx.Err()
		}}
		f := openFileWith(t, context.Background(), src, opts, 4)
		done := make(chan error, 1)
		go func() {
			_, err := f.ReadAt(make([]byte, 1), 21)
			done <- err
		}()
		waitFor(t, f, "the size request", func() bool { return f.probe != nil })
		_ = f.Close()
		if err := <-done; !errors.Is(err, ErrClosed) {
			t.Fatalf("read during Close: error = %v, want ErrClosed", err)
		}
	})
}

// A chunk larger than the limit is refused before it is held: the download
// is bounded by what a chunk of the limit makes once encrypted.
func TestFile_OversizedChunkIsNotDownloaded(t *testing.T) {
	data := testData(40)
	a := newSizeAPI(t)
	a.setHead(http.StatusMethodNotAllowed)
	fs := a.fs(Options{MaxChunkSize: 16})
	// The count is not known and the API does not tell: chunk 0, of 20
	// bytes, is asked for, and announces more than 16 bytes make.
	n := a.store("v1", data, 20)
	n.ChunkCount = 0
	f, err := fs.Open(context.Background(), "dr1", n)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrChunkLayout) {
		t.Fatalf("ReadAt: error = %v, want ErrChunkLayout", err)
	}
	// Final, like any unreadable layout.
	if _, err := f.ReadAt(make([]byte, 1), 30); !errors.Is(err, ErrChunkLayout) {
		t.Fatalf("second ReadAt: error = %v, want ErrChunkLayout", err)
	}
	wantRequests(t, a, "GET v1/0")
}

// The memo holds chunkSizeMemoMax versions, the oldest recorded leaving
// first, and FS.Close empties it.
func TestChunkSizes_Bounded(t *testing.T) {
	fs := New(nil, Options{})
	m := &fs.chunkSizes
	for i := range chunkSizeMemoMax + 10 {
		m.put(fmt.Sprintf("v%d", i), int64(i+1))
	}
	if got := m.len(); got != chunkSizeMemoMax {
		t.Fatalf("memo holds %d versions, want %d", got, chunkSizeMemoMax)
	}
	if _, ok := m.get("v9"); ok {
		t.Error("v9, among the oldest, is still held")
	}
	if got, ok := m.get("v10"); !ok || got != 11 {
		t.Errorf("v10 = %d, %v; want 11", got, ok)
	}
	last := fmt.Sprintf("v%d", chunkSizeMemoMax+9)
	if got, ok := m.get(last); !ok || got != chunkSizeMemoMax+10 {
		t.Errorf("%s = %d, %v; want %d", last, got, ok, chunkSizeMemoMax+10)
	}
	// Recording a version again takes no place.
	m.put(last, 7)
	if got, _ := m.get(last); got != 7 || m.len() != chunkSizeMemoMax {
		t.Errorf("after a second put: %d, %d versions", got, m.len())
	}
	m.put("", 4)
	m.put("zero", 0)
	if m.len() != chunkSizeMemoMax {
		t.Error("an empty version or a size of zero was recorded")
	}

	_ = fs.Close()
	if got := m.len(); got != 0 {
		t.Errorf("memo holds %d versions after Close, want 0", got)
	}
}

// Readers that arrive together while the chunk size is still an assumption,
// a wrong one, with chunks answered in any order: every byte read is the
// byte of the file.
func TestFile_ConcurrentReadsWhileTheChunkSizeIsCorrected(t *testing.T) {
	// 58 bytes in chunks of 20; 21 is assumed, which makes 3 chunks too.
	data := testData(58)
	chunks := cut(data, 20)

	t.Run("the last chunk arrives first", func(t *testing.T) {
		src := newChunkSourceOf(chunks)
		open1, open2 := src.gate(1), src.gate(2)
		f := openFileWith(t, context.Background(), src, Options{ChunkSize: 21}, 3)
		var wg sync.WaitGroup
		// 41 is in chunk 1 for chunks of 21, in chunk 2 in the version; 57
		// is in chunk 2 for both.
		for _, off := range []int64{41, 57, 40, 45} {
			wg.Go(func() {
				p := make([]byte, 1)
				if _, err := f.ReadAt(p, off); err != nil || p[0] != data[off] {
					t.Errorf("ReadAt at %d = %q, %v; want %q", off, p, err, data[off:off+1])
				}
			})
		}
		waitFor(t, f, "the downloads of chunks 1 and 2", func() bool {
			started := src.counts()

			return started[1] > 0 && started[2] > 0
		})
		open2() // 18 bytes where 16 were expected: the chunk size is 20
		waitFor(t, f, "the correction", func() bool { return f.measured })
		open1()
		wg.Wait()
		if f.chunkSize != 20 {
			t.Errorf("chunk size = %d, want 20", f.chunkSize)
		}
	})

	t.Run("random readers", func(t *testing.T) {
		for round := range 40 {
			src := newChunkSourceOf(chunks)
			f := openFileWith(t, context.Background(), src, Options{ChunkSize: 21}, 3)
			rng := rand.New(rand.NewPCG(uint64(round), 7)) //nolint:gosec // G404: test offsets
			var wg sync.WaitGroup
			for range 8 {
				off := rng.IntN(len(data))
				n := 1 + rng.IntN(len(data)-off)
				wg.Go(func() {
					p := make([]byte, n)
					if _, err := f.ReadAt(p, int64(off)); err != nil || !bytes.Equal(p, data[off:off+n]) {
						t.Errorf("round %d: ReadAt(%d bytes at %d) = %q, %v", round, n, off, p, err)
					}
				})
			}
			wg.Wait()
			_ = f.Close()
		}
	})
}
