package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// — Reading a file: stream and positioned reads ——————————————————————————————————

// chunkAPI is a fake API holding one file version, "v1", cut in chunks: it
// counts the downloads of each, and the requests for the size of each (HEAD),
// which it answers like the API unless noSize is set.
type chunkAPI struct {
	mu      sync.Mutex
	counts  map[int]int
	heads   map[int]int
	noSize  bool                  // the size route answers 405
	missing map[int]bool          // chunks answered 404
	held    map[int]chan struct{} // chunks answered once their channel is closed
	// started receives the index of every download of a held chunk, and
	// abandoned the index of each one the client gave up before its answer.
	started   chan int
	abandoned chan int
}

func (a *chunkAPI) downloads() map[int]int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return maps.Clone(a.counts)
}

// sizeRequests returns the number of requests for the size of each chunk.
func (a *chunkAPI) sizeRequests() map[int]int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return maps.Clone(a.heads)
}

// hold makes the downloads of index wait until the returned function is
// called, or their client gives up.
func (a *chunkAPI) hold(index int) (release func()) {
	ch := make(chan struct{})
	a.mu.Lock()
	a.held[index] = ch
	a.mu.Unlock()

	return sync.OnceFunc(func() { close(ch) })
}

// await returns the next index sent on ch.
func await(t *testing.T, ch <-chan int, what string) int {
	t.Helper()
	select {
	case index := <-ch:
		return index
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)

		return -1
	}
}

// readPath is the WebDAV path of the file newReadFS serves.
const readPath = "/dataroom/DR/big.bin"

// contextReaderAt makes an *os.File the positionedFile of a readFileHandle.
type contextReaderAt struct{ *os.File }

func (f contextReaderAt) ReadAtContext(_ context.Context, p []byte, off int64) (int, error) {
	return f.ReadAt(p, off)
}

// cutChunks returns data in chunks of size bytes, the last one shorter or
// equal.
func cutChunks(data []byte, size int) [][]byte {
	var chunks [][]byte
	for start := 0; start < len(data); start += size {
		chunks = append(chunks, data[start:min(start+size, len(data))])
	}

	return chunks
}

// newReadFS returns a webdavFS serving data as /dataroom/DR/big.bin, stored
// in chunks of chunkSize bytes, which is also the chunk size its reader
// assumes. Its listing and session are already cached.
func newReadFS(t *testing.T, data []byte, chunkSize int) (*webdavFS, *chunkAPI) {
	t.Helper()

	return newReadFSOf(t, cutChunks(data, chunkSize), vfs.Options{ChunkSize: int64(chunkSize)})
}

// newReadFSOf is newReadFS for a version stored as plain, whatever the chunk
// size opts makes the reader assume.
func newReadFSOf(t *testing.T, plain [][]byte, opts vfs.Options) (*webdavFS, *chunkAPI) {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	var (
		chunks [][]byte
		size   int64
	)
	for _, chunk := range plain {
		enc, err := crypto.EncryptBinaryForKey(chunk, identity.Recipient().String())
		if err != nil {
			t.Fatalf("EncryptBinaryForKey: %v", err)
		}
		chunks = append(chunks, enc)
		size += int64(len(chunk))
	}

	fake := &chunkAPI{
		counts: make(map[int]int), heads: make(map[int]int),
		missing: make(map[int]bool), held: make(map[int]chan struct{}),
		started: make(chan int, 64), abandoned: make(chan int, 64),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var index int
		if _, err := fmt.Sscanf(r.URL.Path, "/dataroom/node/version/v1/chunk/%d", &index); err != nil {
			t.Errorf("unexpected API request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)

			return
		}
		if r.Method == http.MethodHead {
			fake.mu.Lock()
			fake.heads[index]++
			noSize := fake.noSize
			fake.mu.Unlock()
			switch {
			case noSize:
				w.WriteHeader(http.StatusMethodNotAllowed)
			case index >= len(chunks):
				w.WriteHeader(http.StatusNotFound)
			default:
				w.Header().Set("Content-Length", strconv.Itoa(len(chunks[index])))
			}

			return
		}
		fake.mu.Lock()
		fake.counts[index]++
		missing, held := fake.missing[index], fake.held[index]
		fake.mu.Unlock()
		if held != nil {
			fake.started <- index
			select {
			case <-held:
			case <-r.Context().Done():
				fake.abandoned <- index

				return
			}
		}
		if missing || index >= len(chunks) {
			http.NotFound(w, r)

			return
		}
		_, _ = w.Write(chunks[index])
	}))
	t.Cleanup(srv.Close)

	client := api.New(srv.URL, "retyc-test/1.0", oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}), false, false, api.WithMissingChunkRetries()) // a 404 fails at once
	fs := newTestFS(client, opts)
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})
	fs.tree.SeedSession("dr1", &service.DataroomSession{Identity: identity})
	setNodeCache(fs, map[string]*nodeCacheEntry{
		"retyc://dr1/": {
			nodes: []service.DataroomNodeInfo{{
				ID: "n1", Name: "big.bin", Type: "file", MIMEType: "application/octet-stream",
				VersionID: "v1", ChunkCount: len(chunks), Size: size,
			}},
			fetchedAt: time.Now(),
		},
	})

	return fs, fake
}

// readData returns size bytes that differ from one offset to the next.
func readData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}

	return data
}

// serveRead sends a GET (or method) for the file through the WebDAV handler.
func serveRead(fs *webdavFS, method, rangeHeader string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, readPath, nil)
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}

	return serveReadRequest(fs, r)
}

// serveReadRequest sends r through the WebDAV handler, behind the middleware
// that tells the read handle what the request is (markReadRequests), as
// `webdav serve` mounts it.
func serveReadRequest(fs *webdavFS, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	markReadRequests(newWebdavHandler(fs, webdav.NewMemLS(), nil)).ServeHTTP(w, r)

	return w
}

// A GET without Range answers the whole file, each chunk downloaded once.
func TestWebdavGet_WholeFile(t *testing.T) {
	data := readData(4*4 + 2) // chunks 0 to 4, the last one short
	fs, fake := newReadFS(t, data, 4)

	w := serveRead(fs, http.MethodGet, "")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), data) {
		t.Errorf("body = %x, want %x", w.Body.Bytes(), data)
	}
	for header, want := range map[string]string{
		"Content-Length": strconv.Itoa(len(data)),
		"Content-Type":   "application/octet-stream",
		"Etag":           `"v1"`,
		"Accept-Ranges":  "bytes",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if got, want := fake.downloads(), map[int]int{0: 1, 1: 1, 2: 1, 3: 1, 4: 1}; !maps.Equal(got, want) {
		t.Errorf("downloads per chunk = %v, want %v", got, want)
	}
}

// A HEAD, and the two Seek calls http.ServeContent makes to learn the size,
// download nothing.
func TestWebdavRead_SizeProbeDownloadsNothing(t *testing.T) {
	data := readData(3 * 4)
	fs, fake := newReadFS(t, data, 4)

	w := serveRead(fs, http.MethodHead, "")
	if w.Code != http.StatusOK || w.Header().Get("Content-Length") != strconv.Itoa(len(data)) {
		t.Errorf("HEAD: status %d, Content-Length %q", w.Code, w.Header().Get("Content-Length"))
	}

	f, err := fs.OpenFile(context.Background(), readPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if size, err := f.Seek(0, io.SeekEnd); err != nil || size != int64(len(data)) {
		t.Errorf("Seek(0, End) = %d, %v; want %d", size, err, len(data))
	}
	if pos, err := f.Seek(0, io.SeekStart); err != nil || pos != 0 {
		t.Errorf("Seek(0, Start) = %d, %v; want 0", pos, err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	if got := fake.downloads(); len(got) != 0 {
		t.Errorf("downloads per chunk = %v, want none", got)
	}
}

// A Range request downloads the chunks its range covers, and no other: a
// range is no sequential read until it has gone on for a while (4 bytes for
// these chunks of 32, see vfs), and then one chunk ahead at most.
func TestWebdavGet_RangeDownloadsCoveredChunksOnly(t *testing.T) {
	const chunkSize = 32
	data := readData(4*chunkSize + 16) // 144 bytes: chunks 0 to 4, the last one short
	for _, tc := range []struct {
		name       string
		header     string
		start, end int // the bytes answered: data[start:end]
		downloads  map[int]int
		// ahead is a chunk the range does not cover and may have fetched
		// ahead, 0 when none.
		ahead int
	}{
		{"inside one chunk", "bytes=40-41", 40, 42, map[int]int{1: 1}, 0},
		{"one whole chunk", "bytes=64-95", 64, 96, map[int]int{2: 1}, 0},
		{"across two chunks", "bytes=62-65", 62, 66, map[int]int{1: 1, 2: 1}, 0},
		{"across three chunks", "bytes=24-103", 24, 104, map[int]int{0: 1, 1: 1, 2: 1, 3: 1}, 4},
		{"last bytes", "bytes=-18", 126, 144, map[int]int{3: 1, 4: 1}, 0},
		{"short last chunk", "bytes=143-", 143, 144, map[int]int{4: 1}, 0},
		{"to the end", "bytes=126-", 126, 144, map[int]int{3: 1, 4: 1}, 0},
		{"past the end", "bytes=127-999", 127, 144, map[int]int{3: 1, 4: 1}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, fake := newReadFS(t, data, chunkSize)

			w := serveRead(fs, http.MethodGet, tc.header)

			if w.Code != http.StatusPartialContent {
				t.Fatalf("status = %d (%s), want 206", w.Code, w.Body.String())
			}
			if want := data[tc.start:tc.end]; !bytes.Equal(w.Body.Bytes(), want) {
				t.Errorf("body = %x, want %x", w.Body.Bytes(), want)
			}
			if got, want := w.Header().Get("Content-Range"),
				fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end-1, len(data)); got != want {
				t.Errorf("Content-Range = %q, want %q", got, want)
			}
			if got := w.Header().Get("Content-Length"); got != strconv.Itoa(tc.end-tc.start) {
				t.Errorf("Content-Length = %q, want %d", got, tc.end-tc.start)
			}
			got := fake.downloads()
			ahead := 0
			if tc.ahead > 0 {
				ahead = got[tc.ahead]
				delete(got, tc.ahead)
			}
			if !maps.Equal(got, tc.downloads) || ahead > 1 {
				t.Errorf("downloads per chunk = %v and %d of chunk %d, want %v and one ahead at most",
					got, ahead, tc.ahead, tc.downloads)
			}
		})
	}
}

// A range that starts at offset 0 is read at its offsets like any other: the
// chunks it covers, where the stream would have started as many downloads as
// api.concurrency.download allows for the two bytes of a probe.
func TestWebdavGet_RangeFromTheStart(t *testing.T) {
	const chunkSize = 32
	data := readData(7*chunkSize + 2) // 8 chunks
	for _, tc := range []struct {
		header    string
		end       int
		downloads map[int]int
	}{
		{"bytes=0-1", 2, map[int]int{0: 1}},
		{"bytes=0-0", 1, map[int]int{0: 1}},
		{"bytes=0-31", 32, map[int]int{0: 1}},
	} {
		t.Run(tc.header, func(t *testing.T) {
			fs, fake := newReadFS(t, data, chunkSize)

			w := serveRead(fs, http.MethodGet, tc.header)

			if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), data[:tc.end]) {
				t.Errorf("status %d, body %x; want 206, %x", w.Code, w.Body.Bytes(), data[:tc.end])
			}
			if got, want := w.Header().Get("Content-Range"), fmt.Sprintf("bytes 0-%d/%d", tc.end-1, len(data)); got != want {
				t.Errorf("Content-Range = %q, want %q", got, want)
			}
			if got := fake.downloads(); !maps.Equal(got, tc.downloads) {
				t.Errorf("downloads per chunk = %v, want %v", got, tc.downloads)
			}
		})
	}
}

// A HEAD with a Range answers the headers of the range and downloads
// nothing: it reads no byte, wherever http.ServeContent seeks to.
func TestWebdavHead_RangeDownloadsNothing(t *testing.T) {
	data := readData(4*4 + 2)
	for _, header := range []string{"bytes=5-6", "bytes=0-1", "bytes=-3", "bytes=1-2,9-10"} {
		fs, fake := newReadFS(t, data, 4)

		w := serveRead(fs, http.MethodHead, header)

		if w.Code != http.StatusPartialContent || w.Body.Len() != 0 {
			t.Errorf("%s: status %d, %d bytes of body; want 206 and no body", header, w.Code, w.Body.Len())
		}
		if got := fake.downloads(); len(got) != 0 {
			t.Errorf("%s: downloads per chunk = %v, want none", header, got)
		}
	}

	fs, _ := newReadFS(t, data, 4)
	w := serveRead(fs, http.MethodHead, "bytes=5-6")
	for header, want := range map[string]string{
		"Content-Range": "bytes 5-6/18", "Content-Length": "2", "Etag": `"v1"`, "Accept-Ranges": "bytes",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// If-Range decides whether the Range is honoured. When it does not match, the
// whole file is answered, 200, through the reader the Range header selected:
// same bytes and headers as a plain GET, each chunk downloaded once.
func TestWebdavGet_IfRange(t *testing.T) {
	data := readData(4*4 + 2)
	get := func(t *testing.T, ifRange string) (*httptest.ResponseRecorder, map[int]int) {
		t.Helper()
		fs, fake := newReadFS(t, data, 4)
		r := httptest.NewRequest(http.MethodGet, readPath, nil)
		r.Header.Set("Range", "bytes=5-6")
		r.Header.Set("If-Range", ifRange)
		w := serveReadRequest(fs, r)

		return w, fake.downloads()
	}

	t.Run("not matching", func(t *testing.T) {
		for _, ifRange := range []string{`"another-version"`, "Mon, 02 Jan 2006 15:04:05 GMT"} {
			w, downloads := get(t, ifRange)
			if w.Code != http.StatusOK {
				t.Fatalf("If-Range %s: status = %d (%s), want 200", ifRange, w.Code, w.Body.String())
			}
			if !bytes.Equal(w.Body.Bytes(), data) {
				t.Errorf("If-Range %s: body = %x, want the whole file", ifRange, w.Body.Bytes())
			}
			for header, want := range map[string]string{
				"Content-Length": strconv.Itoa(len(data)), "Content-Range": "", "Etag": `"v1"`,
				"Content-Type": "application/octet-stream", "Accept-Ranges": "bytes",
			} {
				if got := w.Header().Get(header); got != want {
					t.Errorf("If-Range %s: %s = %q, want %q", ifRange, header, got, want)
				}
			}
			if want := map[int]int{0: 1, 1: 1, 2: 1, 3: 1, 4: 1}; !maps.Equal(downloads, want) {
				t.Errorf("If-Range %s: downloads per chunk = %v, want %v", ifRange, downloads, want)
			}
		}
	})
	t.Run("matching", func(t *testing.T) {
		w, downloads := get(t, `"v1"`)
		if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), data[5:7]) {
			t.Errorf("status %d, body %x; want 206, %x", w.Code, w.Body.Bytes(), data[5:7])
		}
		if want := map[int]int{1: 1}; !maps.Equal(downloads, want) {
			t.Errorf("downloads per chunk = %v, want %v", downloads, want)
		}
	})
}

// The chunk size belongs to the version: a file uploaded by a client that
// cuts at another size than this CLI is read at the right offsets. The first
// case is the bug this guards against (12 bytes stored as [0:8][8:12], read
// as chunks of 4: bytes 9-10 served for 5-6, with a 206).
func TestWebdavGet_RangeOnAnotherChunkSize(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		size, stored, assumed int
	}{
		{"larger than assumed", 12, 8, 4},
		{"larger, last chunk of the assumed length", 20, 8, 4},
		{"smaller than assumed", 14, 4, 8},
		{"larger, same chunk count", 8, 5, 4},
		{"smaller, same chunk count", 6, 3, 4},
		{"close to the assumed size", 58, 20, 21},
		{"one chunk", 7, 7, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := readData(tc.size)
			for start := range tc.size {
				for _, end := range []int{start, min(start+1, tc.size-1), tc.size - 1} {
					fs, _ := newReadFSOf(t, cutChunks(data, tc.stored), vfs.Options{ChunkSize: int64(tc.assumed)})

					w := serveRead(fs, http.MethodGet, fmt.Sprintf("bytes=%d-%d", start, end))

					if w.Code != http.StatusPartialContent {
						t.Fatalf("bytes=%d-%d: status = %d (%s), want 206", start, end, w.Code, w.Body.String())
					}
					if want := data[start : end+1]; !bytes.Equal(w.Body.Bytes(), want) {
						t.Fatalf("bytes=%d-%d: body = %x, want %x", start, end, w.Body.Bytes(), want)
					}
				}
			}

			fs, _ := newReadFSOf(t, cutChunks(data, tc.stored), vfs.Options{ChunkSize: int64(tc.assumed)})
			if w := serveRead(fs, http.MethodGet, ""); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), data) {
				t.Errorf("GET: status %d, body %x; want 200 and the file", w.Code, w.Body.Bytes())
			}
		})
	}
}

// A version that cannot be read at an offset (chunks that are not uniform, or
// larger than the reader allows) is still served: the handle falls back to
// the stream, read from the start up to the offset. The listing is kept, the
// version being there.
func TestWebdavGet_RangeFallsBackToTheStream(t *testing.T) {
	data := readData(14)
	// 5 chunks, which no chunk size makes of 14 bytes starting with a chunk of
	// 4: the reader refuses the version at its first chunk.
	uneven := [][]byte{data[:4], data[4:6], data[6:10], data[10:12], data[12:]}
	// Uniform up to chunk 2: the reader finds out in the middle of a range.
	lateUneven := [][]byte{data[:4], data[4:8], data[8:10], data[10:]}
	limit := vfs.Options{ChunkSize: 4, MaxChunkSize: 6}
	for _, tc := range []struct {
		name   string
		plain  [][]byte
		opts   vfs.Options
		header string
		want   []byte
	}{
		{"uneven chunks", uneven, vfs.Options{ChunkSize: 4}, "bytes=5-6", data[5:7]},
		{"uneven chunks, to the end", uneven, vfs.Options{ChunkSize: 4}, "bytes=9-", data[9:]},
		{"uneven chunks, last bytes", uneven, vfs.Options{ChunkSize: 4}, "bytes=-3", data[11:]},
		{"uneven chunks, from the start", uneven, vfs.Options{ChunkSize: 4}, "bytes=0-6", data[:7]},
		{"found out in the middle of a range", lateUneven, vfs.Options{ChunkSize: 4}, "bytes=2-12", data[2:13]},
		{"found out at the first byte", lateUneven, vfs.Options{ChunkSize: 4}, "bytes=9-12", data[9:13]},
		{"chunks beyond the limit", cutChunks(data, 7), limit, "bytes=8-9", data[8:10]},
		{"one chunk beyond the limit", cutChunks(data, 14), limit, "bytes=8-9", data[8:10]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, fake := newReadFSOf(t, tc.plain, tc.opts)

			w := serveRead(fs, http.MethodGet, tc.header)

			if w.Code != http.StatusPartialContent {
				t.Fatalf("status = %d (%s), want 206", w.Code, w.Body.String())
			}
			if !bytes.Equal(w.Body.Bytes(), tc.want) {
				t.Errorf("body = %x, want %x", w.Body.Bytes(), tc.want)
			}
			if !nodeCacheHas(fs, "retyc://dr1/") {
				t.Error("the listing was dropped: an unreadable layout is no missing version")
			}
			// The stream may be cut short by the end of the request, but
			// never asks for a chunk twice.
			for index, n := range fake.downloads() {
				if n > 2 {
					t.Errorf("chunk %d downloaded %d times", index, n)
				}
			}
		})
	}

	t.Run("several ranges, backwards", func(t *testing.T) {
		fs, _ := newReadFSOf(t, uneven, vfs.Options{ChunkSize: 4})

		w := serveRead(fs, http.MethodGet, "bytes=9-10,1-2")

		if w.Code != http.StatusPartialContent {
			t.Fatalf("status = %d (%s), want 206", w.Code, w.Body.String())
		}
		_, params, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
		if err != nil {
			t.Fatalf("Content-Type %q: %v", w.Header().Get("Content-Type"), err)
		}
		parts := multipart.NewReader(w.Body, params["boundary"])
		for _, want := range [][]byte{data[9:11], data[1:3]} {
			part, err := parts.NextPart()
			if err != nil {
				t.Fatalf("NextPart: %v", err)
			}
			if got, err := io.ReadAll(part); err != nil || !bytes.Equal(got, want) {
				t.Errorf("part = %x, %v; want %x", got, err, want)
			}
		}
	})

	t.Run("whole file", func(t *testing.T) {
		fs, fake := newReadFSOf(t, uneven, vfs.Options{ChunkSize: 4})

		w := serveRead(fs, http.MethodGet, "")

		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), data) {
			t.Errorf("status %d, body %x; want 200 and the file", w.Code, w.Body.Bytes())
		}
		if got, want := fake.downloads(), map[int]int{0: 1, 1: 1, 2: 1, 3: 1, 4: 1}; !maps.Equal(got, want) {
			t.Errorf("downloads per chunk = %v, want %v", got, want)
		}
	})
}

// A fallback that fails to download does report it: the stream drops the
// listing as it always did.
func TestWebdavGet_FallbackOnAMissingChunk(t *testing.T) {
	data := readData(14)
	fs, fake := newReadFSOf(t,
		[][]byte{data[:4], data[4:6], data[6:10], data[10:12], data[12:]}, vfs.Options{ChunkSize: 4})
	fake.missing[1] = true

	w := serveRead(fs, http.MethodGet, "bytes=7-8")

	if w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("status = %d, want the 416 http.ServeContent answers a failed Seek with", w.Code)
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("listing cache entry still present after a failed chunk download")
	}
}

// A short range read in several calls (net/http copies 32 KiB at a time)
// costs the chunk it is in and none ahead: this is what a media player or a
// preview asks for.
func TestWebdavGet_ShortRangeFetchesNothingAhead(t *testing.T) {
	const chunkSize = 512 << 10 // a reader is sequential after 64 KiB
	data := readData(3 * chunkSize)
	fs, fake := newReadFS(t, data, chunkSize)

	start, end := chunkSize, chunkSize+40<<10
	w := serveRead(fs, http.MethodGet, fmt.Sprintf("bytes=%d-%d", start, end-1))

	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), data[start:end]) {
		t.Fatalf("status %d, %d bytes; want 206 and the %d bytes of the range", w.Code, w.Body.Len(), end-start)
	}
	if got, want := fake.downloads(), map[int]int{1: 1}; !maps.Equal(got, want) {
		t.Errorf("downloads per chunk = %v, want %v", got, want)
	}
}

// Only the chunk a range starts in is downloaded before the headers leave. A
// later chunk that cannot be had cuts the body short, as it does for a GET of
// the whole file, and drops the listing.
func TestWebdavGet_RangeMissingALaterChunk(t *testing.T) {
	data := readData(3 * 4)
	fs, fake := newReadFS(t, data, 4)
	fake.missing[2] = true

	w := serveRead(fs, http.MethodGet, "bytes=5-10")

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206: the headers left before chunk 2 was asked for", w.Code)
	}
	if want := data[5:8]; !bytes.Equal(w.Body.Bytes(), want) {
		t.Errorf("body = %x, want the %x of chunk 1", w.Body.Bytes(), want)
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("listing cache entry still present after a failed chunk download")
	}
}

// A client that goes away does not keep its request waiting for a download:
// the read gives up with the request, and closing the handle stops the
// download.
func TestWebdavGet_ClientGoneStopsTheDownload(t *testing.T) {
	for name, header := range map[string]string{"range": "bytes=5-6", "range from the start": "bytes=0-1"} {
		t.Run(name, func(t *testing.T) {
			fs, fake := newReadFS(t, readData(3*4), 4)
			index := 0
			if header == "bytes=5-6" {
				index = 1
			}
			release := fake.hold(index)
			defer release()

			ctx, cancel := context.WithCancel(context.Background())
			r := httptest.NewRequest(http.MethodGet, readPath, nil).WithContext(ctx)
			r.Header.Set("Range", header)
			served := make(chan struct{})
			go func() {
				defer close(served)
				serveReadRequest(fs, r)
			}()
			if got := await(t, fake.started, "the download"); got != index {
				t.Fatalf("download of chunk %d started, want chunk %d", got, index)
			}
			cancel()

			select {
			case <-served:
			case <-time.After(5 * time.Second):
				t.Fatal("the request is still waiting for a download its client left")
			}
			if got := await(t, fake.abandoned, "the download to be given up"); got != index {
				t.Errorf("download of chunk %d given up, want chunk %d", got, index)
			}
			if !nodeCacheHas(fs, "retyc://dr1/") {
				t.Error("the listing was dropped for a client that went away")
			}
		})
	}
}

// Leaving the stream stops it: its goroutine returns and its downloads are
// given up, without waiting for the chunks in flight.
func TestReadFileHandle_LeavingTheStreamEndsIt(t *testing.T) {
	data := readData(5*4 + 1)
	fs, fake := newReadFS(t, data, 4)
	release := fake.hold(1)
	defer release()
	f, err := fs.OpenFile(context.Background(), readPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = f.Close() }()
	h := f.(*readFileHandle)

	p := make([]byte, 2)
	if _, err := io.ReadFull(f, p); err != nil || !bytes.Equal(p, data[:2]) {
		t.Fatalf("read %x, %v from the stream; want %x", p, err, data[:2])
	}
	await(t, fake.started, "the stream to ask for chunk 1")
	stream := h.streamDone

	if _, err := f.Seek(13, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	select {
	case <-stream:
	case <-time.After(5 * time.Second):
		t.Fatal("the goroutine of the stream is still running after the Seek that left it")
	}
	await(t, fake.abandoned, "the download of the stream to be given up")
	if h.pipeR != nil || h.file == nil {
		t.Errorf("after the Seek: stream %v, positioned reader %v", h.pipeR != nil, h.file != nil)
	}
	if _, err := io.ReadFull(f, p); err != nil || !bytes.Equal(p, data[13:15]) {
		t.Fatalf("read %x, %v at 13; want %x", p, err, data[13:15])
	}
	if nodeCacheHas(fs, "retyc://dr1/") == false {
		t.Error("the listing was dropped for a stream the handle left")
	}

	// Close ends a stream the same way.
	g, err := fs.OpenFile(context.Background(), readPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := io.ReadFull(g, p); err != nil {
		t.Fatalf("read from the stream: %v", err)
	}
	await(t, fake.started, "the stream to ask for chunk 1")
	stream = g.(*readFileHandle).streamDone
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-stream:
	case <-time.After(5 * time.Second):
		t.Fatal("the goroutine of the stream is still running after Close")
	}
}

// A range past the end of the file is refused without a download.
func TestWebdavGet_UnsatisfiableRange(t *testing.T) {
	fs, fake := newReadFS(t, readData(10), 4)

	w := serveRead(fs, http.MethodGet, "bytes=10-12")

	if w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("status = %d, want 416", w.Code)
	}
	if got := fake.downloads(); len(got) != 0 {
		t.Errorf("downloads per chunk = %v, want none", got)
	}
}

// Several ranges in one request: each part is read at its offset.
func TestWebdavGet_MultipleRanges(t *testing.T) {
	data := readData(4 * 4)
	fs, fake := newReadFS(t, data, 4)

	w := serveRead(fs, http.MethodGet, "bytes=1-2,9-10")

	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d (%s), want 206", w.Code, w.Body.String())
	}
	_, params, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
	if err != nil {
		t.Fatalf("Content-Type %q: %v", w.Header().Get("Content-Type"), err)
	}
	parts := multipart.NewReader(w.Body, params["boundary"])
	for _, want := range [][]byte{data[1:3], data[9:11]} {
		part, err := parts.NextPart()
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		got, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("reading a part: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("part = %x, want %x", got, want)
		}
	}
	if got, want := fake.downloads(), map[int]int{0: 1, 2: 1}; !maps.Equal(got, want) {
		t.Errorf("downloads per chunk = %v, want %v", got, want)
	}
}

// A range long enough to be read in several calls is a sequential read to the
// vfs.File, which fetches one chunk ahead: every chunk of the range once, and
// at most the one chunk that follows it.
func TestWebdavGet_LongRangeFetchesAtMostOneChunkAhead(t *testing.T) {
	const chunkSize = 16 << 10
	data := readData(6 * chunkSize)
	fs, fake := newReadFS(t, data, chunkSize)

	// 40 KiB from the start of chunk 1: more than the 32 KiB net/http copies
	// at a time, ending in chunk 3.
	start, end := chunkSize, chunkSize+40<<10
	w := serveRead(fs, http.MethodGet, fmt.Sprintf("bytes=%d-%d", start, end-1))

	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), data[start:end]) {
		t.Fatalf("status %d, %d bytes; want 206 and the %d bytes of the range", w.Code, w.Body.Len(), end-start)
	}
	got := fake.downloads()
	ahead := got[4]
	delete(got, 4)
	if want := map[int]int{1: 1, 2: 1, 3: 1}; !maps.Equal(got, want) || ahead > 1 {
		t.Errorf("downloads per chunk = %v and %d of chunk 4, want %v and one of chunk 4 at most", got, ahead, want)
	}
}

// A Seek that leaves the stream switches the handle to positioned reads, at
// any point and in any direction.
func TestReadFileHandle_SeekLeavesTheStream(t *testing.T) {
	data := readData(5*4 + 1)
	fs, _ := newReadFS(t, data, 4)
	f, err := fs.OpenFile(context.Background(), readPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = f.Close() }()

	read := func(n int, want []byte) {
		t.Helper()
		p := make([]byte, n)
		if _, err := io.ReadFull(f, p); err != nil {
			t.Fatalf("reading %d bytes: %v", n, err)
		}
		if !bytes.Equal(p, want) {
			t.Fatalf("read %x, want %x", p, want)
		}
	}
	seek := func(off int64, whence int, want int64) {
		t.Helper()
		if pos, err := f.Seek(off, whence); err != nil || pos != want {
			t.Fatalf("Seek(%d, %d) = %d, %v; want %d", off, whence, pos, err, want)
		}
	}

	read(3, data[:3]) // the stream
	seek(0, io.SeekCurrent, 3)
	read(2, data[3:5]) // still the stream: the Seek moved nothing
	seek(13, io.SeekStart, 13)
	read(5, data[13:18])
	seek(-16, io.SeekCurrent, 2) // backwards
	read(4, data[2:6])
	seek(-2, io.SeekEnd, int64(len(data)-2))
	read(2, data[len(data)-2:])
	if n, err := f.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("Read at the end = %d, %v; want 0, io.EOF", n, err)
	}
	seek(0, io.SeekStart, 0)
	rest, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(rest, data) {
		t.Fatalf("ReadAll from the start = %x, %v; want the file", rest, err)
	}

	if _, err := f.Seek(-1, io.SeekStart); err == nil {
		t.Error("Seek before the start: no error")
	}
	if _, err := f.Seek(0, 42); err == nil {
		t.Error("Seek with an unknown whence: no error")
	}
}

// A Range request whose first chunk the API no longer holds fails before the
// headers leave: the client gets an error status, not a 206 cut short, and
// the listing that named the version is dropped.
func TestWebdavGet_RangeOnAMissingChunk(t *testing.T) {
	fs, fake := newReadFS(t, readData(3*4), 4)
	fake.missing[1] = true

	w := serveRead(fs, http.MethodGet, "bytes=5-6")

	if w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("status = %d, want the 416 http.ServeContent answers a failed Seek with", w.Code)
	}
	if nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("listing cache entry still present after a failed chunk download")
	}
}

// A Range on a version cut at another size than this CLI's costs one request
// for the size of chunk 0 and the chunks the range covers: chunk 0 itself is
// not downloaded. The next request for the same version asks nothing.
func TestWebdavGet_RangeAsksTheChunkSizeOnce(t *testing.T) {
	data := readData(23)
	// 4 chunks of 6, where chunks of 4 would make 6.
	fs, fake := newReadFSOf(t, cutChunks(data, 6), vfs.Options{ChunkSize: 4})

	w := serveRead(fs, http.MethodGet, "bytes=13-19")
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), data[13:20]) {
		t.Fatalf("status %d, body %x; want 206, %x", w.Code, w.Body.Bytes(), data[13:20])
	}
	if got, want := fake.sizeRequests(), map[int]int{0: 1}; !maps.Equal(got, want) {
		t.Errorf("size requests per chunk = %v, want %v", got, want)
	}
	if got, want := fake.downloads(), map[int]int{2: 1, 3: 1}; !maps.Equal(got, want) {
		t.Errorf("downloads per chunk = %v, want %v", got, want)
	}

	w = serveRead(fs, http.MethodGet, "bytes=7-8")
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), data[7:9]) {
		t.Fatalf("second range: status %d, body %x; want 206, %x", w.Code, w.Body.Bytes(), data[7:9])
	}
	if got, want := fake.sizeRequests(), map[int]int{0: 1}; !maps.Equal(got, want) {
		t.Errorf("size requests per chunk after a second range = %v, want %v", got, want)
	}
	if got, want := fake.downloads(), map[int]int{1: 1, 2: 1, 3: 1}; !maps.Equal(got, want) {
		t.Errorf("downloads per chunk after a second range = %v, want %v", got, want)
	}

	// A HEAD, a GET of the whole file and a version cut at the default size
	// ask nothing.
	fs, fake = newReadFSOf(t, cutChunks(data, 6), vfs.Options{ChunkSize: 4})
	serveRead(fs, http.MethodHead, "bytes=13-19")
	serveRead(fs, http.MethodGet, "")
	if got := fake.sizeRequests(); len(got) != 0 {
		t.Errorf("size requests for a HEAD and a whole GET = %v, want none", got)
	}
	fs, fake = newReadFS(t, data, 4)
	serveRead(fs, http.MethodGet, "bytes=13-19")
	if got := fake.sizeRequests(); len(got) != 0 {
		t.Errorf("size requests for a version cut at the default size = %v, want none", got)
	}
}

// Against an API that does not tell chunk sizes the range is served all the
// same, from the chunk size the chunk count allows.
func TestWebdavGet_RangeWithoutTheSizeRoute(t *testing.T) {
	data := readData(23)
	fs, fake := newReadFSOf(t, cutChunks(data, 6), vfs.Options{ChunkSize: 4})
	fake.mu.Lock()
	fake.noSize = true
	fake.mu.Unlock()

	for _, header := range []string{"bytes=13-19", "bytes=7-8"} {
		w := serveRead(fs, http.MethodGet, header)
		if w.Code != http.StatusPartialContent {
			t.Fatalf("%s: status = %d (%s), want 206", header, w.Code, w.Body.String())
		}
	}
	if got, want := fake.sizeRequests(), map[int]int{0: 1}; !maps.Equal(got, want) {
		t.Errorf("size requests per chunk = %v, want %v: the route is asked once", got, want)
	}
	if got, want := fake.downloads(), map[int]int{1: 1, 2: 1, 3: 1}; !maps.Equal(got, want) {
		t.Errorf("downloads per chunk = %v, want %v", got, want)
	}
}

// The bug this guards against: 14 bytes stored as [2][4][4][4], four chunks
// as chunks of 4 make. Chunks 1 and 2 have the length expected of them, and
// lie two bytes before where the reader places them; chunk 3 tells. The read
// that finds out had already copied bytes of chunks 1 and 2: they are not
// served, the range is read from the stream.
func TestWebdavGet_FallbackServesNoByteOfTheWrongOffset(t *testing.T) {
	data := readData(14)
	uneven := [][]byte{data[:2], data[2:6], data[6:10], data[10:]}
	for _, header := range []string{"bytes=5-13", "bytes=5-12", "bytes=4-13", "bytes=9-13", "bytes=-9"} {
		fs, _ := newReadFSOf(t, uneven, vfs.Options{ChunkSize: 4})

		w := serveRead(fs, http.MethodGet, header)

		if w.Code != http.StatusPartialContent {
			t.Fatalf("%s: status = %d (%s), want 206", header, w.Code, w.Body.String())
		}
		var start, end int
		if _, err := fmt.Sscanf(w.Header().Get("Content-Range"), "bytes %d-%d/14", &start, &end); err != nil {
			t.Fatalf("%s: Content-Range %q: %v", header, w.Header().Get("Content-Range"), err)
		}
		if want := data[start : end+1]; !bytes.Equal(w.Body.Bytes(), want) {
			t.Errorf("%s: body = %x, want %x", header, w.Body.Bytes(), want)
		}
		if !nodeCacheHas(fs, "retyc://dr1/") {
			t.Errorf("%s: the listing was dropped", header)
		}
	}
}

// "bytes=0-" is the whole file: it is served like a GET without Range, by
// the stream and its parallel downloads, not chunk by chunk.
func TestWebdavGet_RangeOfTheWholeFileKeepsTheStream(t *testing.T) {
	for header, partial := range map[string]bool{
		"": false, "bytes=0-": false, " Bytes = 0- ": false,
		"bytes=0-0": true, "bytes=1-": true, "bytes=0-,5-6": true, "bytes=-5": true, "bytes=00-": true, "lines=0-": true,
	} {
		if got := isPartialRange(header); got != partial {
			t.Errorf("isPartialRange(%q) = %v, want %v", header, got, partial)
		}
	}

	data := readData(4 * 4)
	fs, fake := newReadFS(t, data, 4)
	var releases []func()
	for index := range 4 {
		releases = append(releases, fake.hold(index))
	}
	served := make(chan *httptest.ResponseRecorder, 1)
	go func() { served <- serveRead(fs, http.MethodGet, "bytes=0-") }()

	// The stream asks for the four chunks at once (api.concurrency.download);
	// the positioned reader would wait for chunk 0 before any other.
	started := make(map[int]bool)
	for range 4 {
		started[await(t, fake.started, "the downloads of the stream")] = true
	}
	if len(started) != 4 {
		t.Errorf("chunks asked for while chunk 0 is held: %v, want the four", started)
	}
	for _, release := range releases {
		release()
	}
	w := <-served
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), data) {
		t.Errorf("status %d, body %x; want 206 and the file", w.Code, w.Body.Bytes())
	}
	if got, want := w.Header().Get("Content-Range"), "bytes 0-15/16"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
}

// closedFile is a vfs.File whose FS was closed.
type closedFile struct{}

func (closedFile) ReadAtContext(context.Context, []byte, int64) (int, error) { return 0, vfs.ErrClosed }
func (closedFile) Close() error                                              { return nil }

// A read cut by the shutdown of the server (the vfs.FS closed under the
// handle) is no download failure: the listing is kept.
func TestReadFileHandle_ClosedFSIsNoDownloadError(t *testing.T) {
	fs, fake := newReadFS(t, readData(3*4), 4)
	open := func() *readFileHandle {
		f, err := fs.OpenFile(context.Background(), readPath, os.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		t.Cleanup(func() { _ = f.Close() })
		h := f.(*readFileHandle)
		h.file = closedFile{}

		return h
	}

	if _, err := open().Read(make([]byte, 2)); !errors.Is(err, vfs.ErrClosed) {
		t.Fatalf("Read: error = %v, want vfs.ErrClosed", err)
	}
	if !nodeCacheHas(fs, "retyc://dr1/") {
		t.Error("the listing was dropped by a read the shutdown interrupted")
	}

	// The same on the Seek that downloads the chunk of its target.
	h := open()
	h.file = nil
	if err := fs.tree.Close(); err != nil {
		t.Fatalf("closing the vfs.FS: %v", err)
	}
	if _, err := h.Seek(5, io.SeekStart); !errors.Is(err, vfs.ErrClosed) {
		t.Fatalf("Seek: error = %v, want vfs.ErrClosed", err)
	}
	if got := fake.downloads(); len(got) != 0 {
		t.Errorf("downloads = %v, want none", got)
	}
}
