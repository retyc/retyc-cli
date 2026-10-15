package vfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// testChunkSize is the chunk size of the files read in these tests, unless a
// test says otherwise, and the one their FS assumes.
const testChunkSize = 4

// traceKey is the key of a value a test puts in the context of a read.
type traceKey struct{}

// chunkSource stands in for the API and the decryption: it serves the chunks
// a version was stored in and records what was asked of it.
type chunkSource struct {
	data   []byte
	chunks [][]byte

	mu      sync.Mutex
	calls   map[int]int           // downloads started, per index
	running int                   // downloads that have not returned yet
	gates   map[int]chan struct{} // a gated index waits for its gate or its context
	deaf    map[int]bool          // a deaf gated index ignores its context
	fail    map[int]error
	traces  []any    // the traceKey value of the context of each download
	started chan int // receives the index of every download started
}

// cut returns data in chunks of size bytes, the last one shorter or equal.
func cut(data []byte, size int) [][]byte {
	var chunks [][]byte
	for start := 0; start < len(data); start += size {
		chunks = append(chunks, data[start:min(start+size, len(data))])
	}

	return chunks
}

// newChunkSource serves data stored in chunks of testChunkSize bytes.
func newChunkSource(data []byte) *chunkSource {
	return newChunkSourceOf(cut(data, testChunkSize))
}

// newChunkSourceOf serves a version stored as chunks, uniform or not.
func newChunkSourceOf(chunks [][]byte) *chunkSource {
	return &chunkSource{
		data:    bytes.Join(chunks, nil),
		chunks:  chunks,
		calls:   make(map[int]int),
		gates:   make(map[int]chan struct{}),
		deaf:    make(map[int]bool),
		fail:    make(map[int]error),
		started: make(chan int, 1024),
	}
}

// testData returns size bytes that differ from one offset to the next.
func testData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte('a' + i%26)
	}

	return data
}

func (s *chunkSource) read(ctx context.Context, versionID string, index int) ([]byte, error) {
	s.mu.Lock()
	s.calls[index]++
	s.running++
	s.traces = append(s.traces, ctx.Value(traceKey{}))
	gate, deaf, err := s.gates[index], s.deaf[index], s.fail[index]
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running--
		s.mu.Unlock()
	}()
	select {
	case s.started <- index:
	default: // nobody follows the starts of a test that makes this many
	}

	if versionID != "v1" {
		return nil, fmt.Errorf("unexpected version %q", versionID)
	}
	if gate != nil {
		var done <-chan struct{}
		if !deaf {
			done = ctx.Done()
		}
		select {
		case <-gate:
		case <-done:
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(s.chunks) {
		return nil, fmt.Errorf("downloading chunk %d: %w", index, api.ErrChunkMissing)
	}

	return bytes.Clone(s.chunks[index]), nil
}

// gate makes the downloads of index wait until the returned function is
// called.
func (s *chunkSource) gate(index int) (open func()) {
	ch := make(chan struct{})
	s.mu.Lock()
	s.gates[index] = ch
	s.mu.Unlock()

	return sync.OnceFunc(func() { close(ch) })
}

func (s *chunkSource) setFail(index int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.fail, index)

		return
	}
	s.fail[index] = err
}

// counts returns the downloads started so far, per index.
func (s *chunkSource) counts() map[int]int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return maps.Clone(s.calls)
}

func (s *chunkSource) inFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.running
}

// awaitStart waits for a download of index to start.
func (s *chunkSource) awaitStart(t *testing.T, index int) {
	t.Helper()
	select {
	case got := <-s.started:
		if got != index {
			t.Fatalf("download of chunk %d started, want chunk %d", got, index)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no download of chunk %d started", index)
	}
}

// awaitStartAmong waits for a download of index to start, letting those of
// the chunks in others start before it: downloads started together (a chunk
// and the one fetched ahead of it) reach the source in no given order.
func (s *chunkSource) awaitStartAmong(t *testing.T, index int, others ...int) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-s.started:
			if got == index {
				return
			}
			if !slices.Contains(others, got) {
				t.Fatalf("download of chunk %d started, want chunk %d", got, index)
			}
		case <-timeout:
			t.Fatalf("no download of chunk %d started", index)
		}
	}
}

// openTestFile opens the file src holds, described as it is stored, on an FS
// that assumes chunks of testChunkSize bytes. It is closed with the test.
func openTestFile(t *testing.T, ctx context.Context, src *chunkSource) *file {
	t.Helper()

	return openFileWith(t, ctx, src, Options{ChunkSize: testChunkSize}, len(src.chunks))
}

// openFileWith is openTestFile with the options of the FS (ReadChunk aside)
// and the chunk count the node announces.
func openFileWith(t *testing.T, ctx context.Context, src *chunkSource, opts Options, chunkCount int) *file {
	t.Helper()
	opts.ReadChunk = src.read
	fs := New(nil, opts)
	t.Cleanup(func() { _ = fs.Close() })
	f, err := fs.Open(ctx, "dr1", Node{
		ID: "n1", Type: TypeFile, VersionID: "v1", Size: int64(len(src.data)), ChunkCount: chunkCount,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	return f.(*file)
}

// settle waits for the downloads the window holds, the one started ahead
// included, which no read waits for.
func settle(f *file) {
	f.mu.Lock()
	var held []*chunk
	for _, c := range f.slots {
		if c != nil {
			held = append(held, c)
		}
	}
	f.mu.Unlock()
	for _, c := range held {
		<-c.done
	}
}

// window returns the indexes of the chunks the window holds.
func window(f *file) map[int]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := make(map[int]bool)
	for _, c := range f.slots {
		if c != nil {
			held[c.index] = true
		}
	}

	return held
}

// readAt reads n bytes at off and settles the window.
func readAt(t *testing.T, f *file, off int64, n int, want []byte) {
	t.Helper()
	p := make([]byte, n)
	if _, err := f.ReadAt(p, off); err != nil {
		t.Fatalf("ReadAt(%d bytes at %d): %v", n, off, err)
	}
	if !bytes.Equal(p, want[off:off+int64(n)]) {
		t.Fatalf("ReadAt(%d bytes at %d) = %q, want %q", n, off, p, want[off:off+int64(n)])
	}
	settle(f)
}

func wantCounts(t *testing.T, src *chunkSource, want map[int]int) {
	t.Helper()
	if got := src.counts(); !maps.Equal(got, want) {
		t.Fatalf("downloads per chunk = %v, want %v", got, want)
	}
}

// TestFile_ReadAt reads every range, in and out of bounds, of files that end
// on a chunk boundary or not, and checks the io.ReaderAt contract.
func TestFile_ReadAt(t *testing.T) {
	cases := map[string]int{
		"empty":                    0,
		"one short chunk":          3,
		"one full chunk":           testChunkSize,
		"full chunks":              2 * testChunkSize,
		"short last chunk":         2*testChunkSize + 2,
		"one byte in a last chunk": 3*testChunkSize + 1,
	}
	for name, size := range cases {
		t.Run(name, func(t *testing.T) {
			data := testData(size)
			f := openTestFile(t, context.Background(), newChunkSource(data))

			// Every length at every offset, backwards so that most reads
			// land before the previous one.
			for off := size + 2; off >= 0; off-- {
				for n := 0; n <= size+2; n++ {
					p := make([]byte, n)
					got, err := f.ReadAt(p, int64(off))

					want := 0
					if off < size {
						want = min(n, size-off)
					}
					var wantErr error
					if n > 0 && want < n {
						wantErr = io.EOF
					}
					if got != want || err != wantErr {
						t.Fatalf("ReadAt(%d bytes at %d) = %d, %v; want %d, %v", n, off, got, err, want, wantErr)
					}
					if !bytes.Equal(p[:got], data[min(off, size):min(off, size)+want]) {
						t.Fatalf("ReadAt(%d bytes at %d) read %q", n, off, p[:got])
					}
				}
			}

			if _, err := f.ReadAt(make([]byte, 1), -1); !errors.Is(err, ErrNegativeOffset) {
				t.Errorf("ReadAt at -1: error = %v, want ErrNegativeOffset", err)
			}
			if err := iotest.TestReader(io.NewSectionReader(f, 0, int64(size)), data); err != nil {
				t.Errorf("as an io.SectionReader: %v", err)
			}
		})
	}
}

// An empty file is read without a version and without a download.
func TestFile_EmptyFileDownloadsNothing(t *testing.T) {
	src := newChunkSource(nil)
	fs := New(nil, Options{ReadChunk: src.read, ChunkSize: testChunkSize})
	// With or without a chunk count: there is nothing to read.
	if f, err := fs.Open(context.Background(), "dr1", Node{Type: TypeFile, ChunkCount: 1}); err != nil {
		t.Fatalf("Open: %v", err)
	} else if n, err := f.ReadAt(make([]byte, 8), 0); n != 0 || err != io.EOF {
		t.Errorf("ReadAt = %d, %v; want 0, io.EOF", n, err)
	}
	f, err := fs.Open(context.Background(), "dr1", Node{Type: TypeFile})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	if n, err := f.ReadAt(make([]byte, 8), 0); n != 0 || err != io.EOF {
		t.Errorf("ReadAt = %d, %v; want 0, io.EOF", n, err)
	}
	wantCounts(t, src, map[int]int{})
}

func TestFile_Node(t *testing.T) {
	src := newChunkSource(testData(6))
	f := openTestFile(t, context.Background(), src)
	if got := f.Node(); got.ID != "n1" || got.VersionID != "v1" || got.Size != 6 {
		t.Errorf("Node() = %+v", got)
	}
}

func TestOpen_RefusesWhatHasNoContent(t *testing.T) {
	fs := New(nil, Options{ReadChunk: newChunkSource(nil).read})
	cases := map[string]struct {
		node Node
		want error
	}{
		"folder":               {Node{Type: TypeDir}, ErrIsDir},
		"symlink":              {Node{Type: TypeSymlink, Size: 3, Target: "a/b"}, ErrNotFile},
		"untyped":              {Node{VersionID: "v1", Size: 3}, ErrNotFile},
		"file without version": {Node{Type: TypeFile, Size: 3}, ErrNotFile},
		// What a listing gives for a file whose only version is still being
		// uploaded or copied: the API lists the last complete version, here
		// none, and service reports the node with neither version nor size.
		// It opens as an empty file, which no read downloads anything for.
		"file without version nor size": {Node{Type: TypeFile}, nil},
	}
	for name, tc := range cases {
		if _, err := fs.Open(context.Background(), "dr1", tc.node); !errors.Is(err, tc.want) {
			t.Errorf("%s: Open error = %v, want %v", name, err, tc.want)
		}
	}
}

// A sequential reader downloads every chunk once, and has the next one
// fetched ahead from its second contiguous read on.
func TestFile_SequentialReadFetchesAhead(t *testing.T) {
	data := testData(4*testChunkSize + 2) // chunks 0 to 4, the last one short
	src := newChunkSource(data)
	f := openTestFile(t, context.Background(), src)

	readAt(t, f, 0, 2, data)
	wantCounts(t, src, map[int]int{0: 1}) // one read tells nothing of the next
	readAt(t, f, 2, 1, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1}) // contiguous: chunk 1 is on its way
	readAt(t, f, 3, 1, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1})

	for off := 4; off < len(data); off += 2 {
		readAt(t, f, int64(off), 2, data)
		if held := window(f); len(held) > windowSize {
			t.Fatalf("window holds %v, more than %d chunks", held, windowSize)
		}
	}
	// Each chunk once, and nothing past the end of the file.
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1, 3: 1, 4: 1})
	if held := window(f); !maps.Equal(held, map[int]bool{3: true, 4: true}) {
		t.Errorf("window holds %v, want the last two chunks", held)
	}
}

// prefetchChunkSize is the chunk size of the tests of the fetch ahead: a
// reader of such chunks is sequential after readAheadAfter = 4 bytes.
const prefetchChunkSize = 32

// openPrefetchFile opens a file of chunks whole chunks of prefetchChunkSize
// bytes.
func openPrefetchFile(t *testing.T, chunks int) (*file, *chunkSource, []byte) {
	t.Helper()
	if got := readAheadAfter(prefetchChunkSize); got != 4 {
		t.Fatalf("readAheadAfter(%d) = %d, want 4", prefetchChunkSize, got)
	}
	data := testData(chunks * prefetchChunkSize)
	src := newChunkSourceOf(cut(data, prefetchChunkSize))

	return openFileWith(t, context.Background(), src, Options{ChunkSize: prefetchChunkSize}, chunks), src, data
}

// The threshold is an eighth of a chunk, 1 MiB for the chunks this CLI
// uploads and never more.
func TestReadAheadAfter(t *testing.T) {
	for chunkSize, want := range map[int64]int64{
		1: 1, 4: 1, 32: 4, service.UploadChunkSize: 1 << 20, 16 << 20: 1 << 20, MaxChunkSize: 1 << 20,
	} {
		if got := readAheadAfter(chunkSize); got != want {
			t.Errorf("readAheadAfter(%d) = %d, want %d", chunkSize, got, want)
		}
	}
}

// A short range read in several contiguous calls, as net/http does, costs
// the chunk it is in and nothing ahead; going on past the threshold does
// fetch the next chunk.
func TestFile_ShortRangeFetchesNothingAhead(t *testing.T) {
	f, src, data := openPrefetchFile(t, 4)

	const start = prefetchChunkSize // the start of chunk 1
	readAt(t, f, start, 2, data)
	readAt(t, f, start+2, 1, data)
	readAt(t, f, start+3, 1, data) // 3 contiguous bytes read before this one
	wantCounts(t, src, map[int]int{1: 1})

	readAt(t, f, start+4, 1, data) // 4: the reader is sequential
	wantCounts(t, src, map[int]int{1: 1, 2: 1})
}

// A short range that crosses a chunk boundary downloads both chunks and
// nothing ahead.
func TestFile_ShortReadAcrossChunksFetchesNothingAhead(t *testing.T) {
	f, src, data := openPrefetchFile(t, 4)

	readAt(t, f, prefetchChunkSize-2, 2, data)
	readAt(t, f, prefetchChunkSize, 1, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1})
}

// An established sequential read has two downloads in flight: the chunk it
// enters and the next one, started without waiting for the first. Never
// three.
func TestFile_SequentialReadKeepsTwoDownloadsInFlight(t *testing.T) {
	f, src, data := openPrefetchFile(t, 5)
	open1, open2, open3 := src.gate(1), src.gate(2), src.gate(3)
	defer open3()

	// Establish the read inside chunk 0: chunk 1 starts while chunk 0 is
	// still being read.
	readChunk0 := func(off, n int) {
		t.Helper()
		p := make([]byte, n)
		if _, err := f.ReadAt(p, int64(off)); err != nil || !bytes.Equal(p, data[off:off+n]) {
			t.Fatalf("ReadAt(%d bytes at %d) = %q, %v", n, off, p, err)
		}
	}
	readChunk0(0, 4)
	src.awaitStart(t, 0)
	wantCounts(t, src, map[int]int{0: 1})
	readChunk0(4, prefetchChunkSize-4)
	src.awaitStart(t, 1)

	// The reader enters chunk 1, which has not arrived: chunk 2 starts all
	// the same.
	done := make(chan error, 1)
	go func() {
		p := make([]byte, 2*prefetchChunkSize)
		_, err := f.ReadAt(p, prefetchChunkSize)
		if err == nil && !bytes.Equal(p, data[prefetchChunkSize:3*prefetchChunkSize]) {
			err = errors.New("wrong bytes")
		}
		done <- err
	}()
	src.awaitStart(t, 2)
	if n := src.inFlight(); n != 2 {
		t.Errorf("%d downloads in flight, want 2", n)
	}
	// Chunk 3 waits for the reader to enter chunk 2: the window is two.
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1})
	if held := window(f); !maps.Equal(held, map[int]bool{1: true, 2: true}) {
		t.Errorf("window holds %v, want chunks 1 and 2", held)
	}

	open1()
	src.awaitStart(t, 3) // entering chunk 2
	if n := src.inFlight(); n != 2 {
		t.Errorf("%d downloads in flight, want 2", n)
	}
	open2()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1, 3: 1})
}

// A whole file read in small calls downloads each chunk once, two at a time
// at most.
func TestFile_SequentialReadDownloadsEachChunkOnce(t *testing.T) {
	f, src, data := openPrefetchFile(t, 6)

	got := make([]byte, 0, len(data))
	p := make([]byte, 5)
	for off := 0; off < len(data); {
		n, err := f.ReadAt(p, int64(off))
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt at %d: %v", off, err)
		}
		got = append(got, p[:n]...)
		off += n
		if held := window(f); len(held) > windowSize {
			t.Fatalf("window holds %v, more than %d chunks", held, windowSize)
		}
	}
	if !bytes.Equal(got, data) {
		t.Error("the bytes read are not the file")
	}
	settle(f)
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1})
}

// A jump fetches nothing ahead; reading on from where it landed does.
func TestFile_JumpDisarmsTheFetchAhead(t *testing.T) {
	data := testData(6 * testChunkSize)
	src := newChunkSource(data)
	f := openTestFile(t, context.Background(), src)

	readAt(t, f, 0, 1, data)
	readAt(t, f, 1, 1, data) // sequential: chunk 1 fetched ahead
	wantCounts(t, src, map[int]int{0: 1, 1: 1})

	readAt(t, f, 4*testChunkSize, 1, data) // jump to chunk 4
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 4: 1})

	readAt(t, f, 4*testChunkSize+1, 1, data) // reading on
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 4: 1, 5: 1})

	readAt(t, f, 2*testChunkSize, 1, data) // back, far from both runs
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1, 4: 1, 5: 1})
}

// Reads that arrive out of order are one sequential reader all the same: a
// kernel reading ahead hands consecutive ranges to several goroutines. A
// reader that requires each read to start where the last one ended never
// fetches ahead for them.
func TestFile_ReadsOutOfOrderFetchAhead(t *testing.T) {
	f, src, data := openPrefetchFile(t, 3)

	// 4 bytes each, the pairs swapped: the second read lands before the
	// first, the third one read's length after it.
	readAt(t, f, 4, 4, data)
	wantCounts(t, src, map[int]int{0: 1})
	readAt(t, f, 0, 4, data)
	// The run is [0, 8): a read at its start is not 4 bytes into it.
	wantCounts(t, src, map[int]int{0: 1})
	readAt(t, f, 12, 4, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1})
	for _, off := range []int64{8, 20, 16, 28, 24} {
		readAt(t, f, off, 4, data)
	}
	wantCounts(t, src, map[int]int{0: 1, 1: 1})
	if f.runStart != 0 || f.lastEnd != 32 {
		t.Errorf("run = [%d, %d), want [0, 32)", f.runStart, f.lastEnd)
	}

	// Into chunk 1, still out of order: chunk 2 is fetched ahead.
	readAt(t, f, 36, 4, data)
	readAt(t, f, 32, 4, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1})
}

// Reads that land far from one another are no run, in whatever order: none
// fetches ahead, and each chunk downloaded is one a read entered.
func TestFile_ScatteredReadsFetchNothingAhead(t *testing.T) {
	f, src, data := openPrefetchFile(t, 4)

	// Each more than a read's length, and more than the threshold, from the
	// run the previous one left. The chunks entered are 0, 0, 3, 1, 0, 1, 2,
	// through a window of two.
	for _, off := range []int64{20, 4, 100, 60, 12, 44, 84} {
		readAt(t, f, off, 4, data)
		if f.runStart != off || f.lastEnd != off+4 {
			t.Fatalf("after the read at %d the run is [%d, %d), want the read alone", off, f.runStart, f.lastEnd)
		}
	}
	wantCounts(t, src, map[int]int{0: 2, 1: 1, 2: 1, 3: 1})
}

// Reading backwards costs nothing inside the window, and one download for a
// chunk that left it.
func TestFile_BackwardReads(t *testing.T) {
	data := testData(4 * testChunkSize)
	src := newChunkSource(data)
	f := openTestFile(t, context.Background(), src)

	readAt(t, f, testChunkSize, 1, data) // chunk 1
	readAt(t, f, 0, 1, data)             // chunk 0, a jump
	readAt(t, f, testChunkSize+1, 1, data)
	readAt(t, f, 2, 1, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1}) // both stayed in the window

	readAt(t, f, 3*testChunkSize, 1, data) // chunk 3 takes the place of chunk 1
	readAt(t, f, 2*testChunkSize, 1, data) // chunk 2 takes the place of chunk 0
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1, 3: 1})

	readAt(t, f, 0, 1, data) // chunk 0 left the window: downloaded again
	wantCounts(t, src, map[int]int{0: 2, 1: 1, 2: 1, 3: 1})
}

// A chunk whose fetch ahead failed is not asked for again by every read of
// the chunk before it; the read that needs it asks, and reports the error.
func TestFile_FailedFetchAheadIsNotRepeated(t *testing.T) {
	data := testData(3 * testChunkSize)
	src := newChunkSource(data)
	refused := errors.New("refused")
	src.setFail(1, refused)
	f := openTestFile(t, context.Background(), src)

	readAt(t, f, 0, 1, data)
	readAt(t, f, 1, 1, data) // chunk 1 fetched ahead, refused
	readAt(t, f, 2, 1, data)
	readAt(t, f, 3, 1, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1})

	// The read that needs the chunk asks again, and reports the refusal. It
	// goes on with the run, so chunk 2 is fetched ahead of it.
	if _, err := f.ReadAt(make([]byte, 1), testChunkSize+1); !errors.Is(err, refused) {
		t.Fatalf("ReadAt in the refused chunk: error = %v, want %v", err, refused)
	}
	settle(f)
	wantCounts(t, src, map[int]int{0: 1, 1: 2, 2: 1})

	// A failure is not kept: the chunk is asked for again and served.
	src.setFail(1, nil)
	readAt(t, f, testChunkSize, 1, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 3, 2: 1})
}

// A read that crosses into a chunk that cannot be had returns the bytes it
// read before it, with the error.
func TestFile_PartialReadBeforeAFailedChunk(t *testing.T) {
	data := testData(2 * testChunkSize)
	src := newChunkSource(data)
	src.setFail(1, fmt.Errorf("downloading chunk 1: %w", api.ErrChunkMissing))
	f := openTestFile(t, context.Background(), src)

	p := make([]byte, 6)
	n, err := f.ReadAt(p, 2)
	if n != 2 || !errors.Is(err, api.ErrChunkMissing) {
		t.Fatalf("ReadAt = %d, %v; want 2, ErrChunkMissing", n, err)
	}
	if !bytes.Equal(p[:n], data[2:4]) {
		t.Errorf("read %q, want %q", p[:n], data[2:4])
	}
}

// The errors of the API reach the caller as they are.
func TestFile_ErrorsPassThrough(t *testing.T) {
	rateLimited := &api.HTTPError{Status: http.StatusTooManyRequests}
	cases := map[string]struct {
		err   error
		check func(error) bool
	}{
		"chunk missing": {
			fmt.Errorf("downloading chunk 0: %w", fmt.Errorf("%w: %w", api.ErrChunkMissing, api.ErrNotFound)),
			func(err error) bool { return errors.Is(err, api.ErrChunkMissing) && errors.Is(err, api.ErrNotFound) },
		},
		"rate limited": {
			fmt.Errorf("downloading chunk 0: %w", rateLimited),
			func(err error) bool {
				var httpErr *api.HTTPError

				return errors.Is(err, api.ErrRateLimited) && errors.As(err, &httpErr) && httpErr == rateLimited
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src := newChunkSource(testData(testChunkSize))
			src.setFail(0, tc.err)
			f := openTestFile(t, context.Background(), src)

			n, err := f.ReadAt(make([]byte, 2), 0)
			if n != 0 || !tc.check(err) {
				t.Fatalf("ReadAt = %d, %v", n, err)
			}
			if held := window(f); len(held) != 0 {
				t.Errorf("window holds %v after a failed download", held)
			}
		})
	}
}

// The bug this guards against: 12 bytes stored as [0:8][8:12], read by an FS
// that assumes chunks of 4. Dividing the offset by 4 asks for chunk 1 and
// gets 4 bytes, the very length 4 would give it: "jk" served for "fg".
func TestFile_ChunkSizeIsNotTheDefault(t *testing.T) {
	data := testData(12)
	src := newChunkSourceOf(cut(data, 8))
	f := openFileWith(t, context.Background(), src, Options{ChunkSize: 4}, 2)

	p := make([]byte, 2)
	if _, err := f.ReadAt(p, 5); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(p) != "fg" {
		t.Fatalf("ReadAt(2 bytes at 5) = %q, want %q", p, "fg")
	}
	// 4 does not make 2 chunks of 12 bytes: chunk 0 told the chunk size, and
	// held the bytes.
	wantCounts(t, src, map[int]int{0: 1})
}

// Versions cut at another size than the default one, larger or smaller, with
// or without a chunk count the default also gives: every range reads the
// bytes of the file, whichever chunk the first read enters.
func TestFile_ReadsAnyUniformChunkSize(t *testing.T) {
	cases := map[string]struct {
		size, stored, assumed int
		// countKnown is false for a node that does not tell its chunk count.
		countUnknown bool
	}{
		"larger than the default":                    {size: 12, stored: 8, assumed: 4},
		"larger, last chunk of the default length":   {size: 20, stored: 8, assumed: 4},
		"smaller than the default":                   {size: 12, stored: 4, assumed: 8},
		"smaller, short last chunk":                  {size: 14, stored: 4, assumed: 8},
		"larger, same chunk count as the default":    {size: 8, stored: 5, assumed: 4},
		"smaller, same chunk count as the default":   {size: 6, stored: 3, assumed: 4},
		"close to the default, several chunks":       {size: 58, stored: 20, assumed: 21},
		"close to the default, full last chunk":      {size: 60, stored: 20, assumed: 21},
		"the default":                                {size: 14, stored: 4, assumed: 4},
		"one chunk larger than the default":          {size: 7, stored: 7, assumed: 4},
		"chunk count unknown, the default":           {size: 14, stored: 4, assumed: 4, countUnknown: true},
		"chunk count unknown, larger":                {size: 12, stored: 8, assumed: 4, countUnknown: true},
		"chunk count unknown, smaller":               {size: 14, stored: 4, assumed: 8, countUnknown: true},
		"chunk count unknown, one chunk":             {size: 7, stored: 7, assumed: 4, countUnknown: true},
		"chunk count unknown, one chunk, small file": {size: 3, stored: 8, assumed: 4, countUnknown: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			data := testData(tc.size)
			chunks := cut(data, tc.stored)
			count := len(chunks)
			if tc.countUnknown {
				count = 0
			}
			// A new file for each read: the chunk a File downloads first is
			// the one that settles its chunk size.
			for off := range tc.size {
				for n := 1; n <= tc.size-off; n++ {
					src := newChunkSourceOf(chunks)
					f := openFileWith(t, context.Background(), src, Options{ChunkSize: int64(tc.assumed)}, count)
					p := make([]byte, n)
					if _, err := f.ReadAt(p, int64(off)); err != nil {
						t.Fatalf("ReadAt(%d bytes at %d): %v", n, off, err)
					}
					if !bytes.Equal(p, data[off:off+n]) {
						t.Fatalf("ReadAt(%d bytes at %d) = %q, want %q", n, off, p, data[off:off+n])
					}
					// And the rest of the file on the same handle.
					if err := iotest.TestReader(io.NewSectionReader(f, 0, int64(tc.size)), data); err != nil {
						t.Fatalf("after ReadAt(%d bytes at %d): %v", n, off, err)
					}
					if got, want := f.chunkSize, int64(min(tc.stored, tc.size)); got != want || !f.measured {
						t.Fatalf("chunk size settled at %d (measured %v), want %d", got, f.measured, want)
					}
					_ = f.Close()
				}
			}
		})
	}
}

// A wrong assumption costs no download: the chunk that contradicts it is the
// chunk of its index, kept, and the read goes on from it.
func TestFile_CorrectedAssumptionKeepsTheChunk(t *testing.T) {
	// 58 bytes in chunks of 20 make 3 chunks, as chunks of 21 would.
	data := testData(58)
	src := newChunkSourceOf(cut(data, 20))
	f := openFileWith(t, context.Background(), src, Options{ChunkSize: 21}, 3)

	// Offset 41 is in chunk 1 for chunks of 21, in chunk 2 in the version.
	readAt(t, f, 41, 2, data)
	wantCounts(t, src, map[int]int{1: 1, 2: 1})
	readAt(t, f, 39, 1, data) // chunk 1, still in the window
	wantCounts(t, src, map[int]int{1: 1, 2: 1})

	// The last chunk tells the chunk size as well: 58 - 18 bytes in 2 chunks.
	src = newChunkSourceOf(cut(data, 20))
	f = openFileWith(t, context.Background(), src, Options{ChunkSize: 21}, 3)
	readAt(t, f, 57, 1, data)
	wantCounts(t, src, map[int]int{2: 1})
	if f.chunkSize != 20 {
		t.Errorf("chunk size = %d, want 20", f.chunkSize)
	}
}

// What cannot be read at an offset is refused with ErrChunkLayout, for good,
// and never served.
func TestFile_ChunkLayoutErrors(t *testing.T) {
	long := testData(14)
	data := long[:12]
	cases := map[string]struct {
		chunks [][]byte
		opts   Options
		size   int // the size the node announces, that of the chunks when zero
		count  int
		// off is where the refused read is made; before, when positive, is a
		// read that succeeds first.
		off, before int64
		downloads   map[int]int
	}{
		"more chunks than the chunk size makes": {
			chunks: cut(data, 4), opts: Options{ChunkSize: 5}, count: 2, off: 5,
			downloads: map[int]int{0: 1},
		},
		"chunk count unknown, chunks not uniform": {
			chunks: [][]byte{data[:4], data[4:6], data[6:]}, opts: Options{ChunkSize: 4}, off: 5,
			downloads: map[int]int{0: 1, 1: 1},
		},
		"chunks not uniform, no size makes the count": {
			// Nothing tells the chunk size: 3 is assumed, the smallest that
			// makes 4 chunks of 12 bytes, and chunk 1 holds 2.
			chunks: [][]byte{data[:4], data[4:6], data[6:10], data[10:]}, opts: Options{ChunkSize: 4}, count: 4,
			off: 5, downloads: map[int]int{1: 1},
		},
		"no chunk size makes the count": {
			// 7 chunks of 10 bytes: chunks of 2 make 5, chunks of 1 make 10.
			// Refused without a download.
			chunks: cut(data[:10], 2), opts: Options{ChunkSize: 4}, count: 7, off: 9,
			downloads: map[int]int{},
		},
		"chunks not uniform, after a chunk of the assumed size": {
			chunks: [][]byte{long[:4], long[4:6], long[6:10], long[10:]}, opts: Options{ChunkSize: 4}, count: 4,
			off: 5, before: 1, downloads: map[int]int{0: 1, 1: 1},
		},
		"chunks not uniform under a wrong assumption": {
			// 3 chunks as chunks of 5 would make, but no size shares 12 - 3
			// bytes between the first two.
			chunks: [][]byte{data[:6], data[6:9], data[9:]}, opts: Options{ChunkSize: 5}, count: 3, off: 11,
			downloads: map[int]int{2: 1},
		},
		"last chunk larger than the others": {
			chunks: [][]byte{data[:2], data[2:4], data[4:]}, opts: Options{ChunkSize: 5}, count: 3, off: 11,
			downloads: map[int]int{2: 1},
		},
		"last chunk longer than the size leaves it": {
			chunks: cut(data, 4), opts: Options{ChunkSize: 4}, size: 11, count: 3, off: 9,
			before: 1, downloads: map[int]int{0: 1, 2: 1},
		},
		"file smaller than its chunks": {
			chunks: cut(data, 4), opts: Options{ChunkSize: 4}, size: 3, count: 1, off: 1,
			downloads: map[int]int{0: 1},
		},
		"more chunks than bytes": {
			chunks: cut(data, 4), opts: Options{ChunkSize: 4}, size: 2, count: 3, off: 1,
			downloads: map[int]int{},
		},
		"empty chunk": {
			chunks: [][]byte{{}, data}, opts: Options{ChunkSize: 4}, off: 1,
			downloads: map[int]int{0: 1},
		},
		"one chunk beyond the limit": {
			chunks: cut(data, 12), opts: Options{ChunkSize: 4, MaxChunkSize: 8}, count: 1, off: 1,
			downloads: map[int]int{},
		},
		"chunks that must be beyond the limit": {
			chunks: cut(data, 6), opts: Options{ChunkSize: 4, MaxChunkSize: 5}, count: 2, off: 1,
			downloads: map[int]int{},
		},
		"chunk count unknown, chunk beyond the limit": {
			chunks: cut(data, 6), opts: Options{ChunkSize: 4, MaxChunkSize: 5}, off: 1,
			downloads: map[int]int{0: 1},
		},
		"corrected chunk size beyond the limit": {
			// 12 bytes in 2 chunks: 6 is allowed, the chunks are of 7.
			chunks: cut(data, 7), opts: Options{ChunkSize: 6, MaxChunkSize: 6}, count: 2, off: 1,
			downloads: map[int]int{0: 1},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src := newChunkSourceOf(tc.chunks)
			tc.opts.ReadChunk = src.read
			fs := New(nil, tc.opts)
			size := tc.size
			if size == 0 {
				size = len(src.data)
			}
			f, err := fs.Open(context.Background(), "dr1",
				Node{Type: TypeFile, VersionID: "v1", Size: int64(size), ChunkCount: tc.count})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = f.Close() }()

			if tc.before > 0 {
				p := make([]byte, 1)
				if _, err := f.ReadAt(p, tc.before); err != nil || p[0] != long[tc.before] {
					t.Fatalf("ReadAt at %d = %q, %v; want %q", tc.before, p, err, long[tc.before:tc.before+1])
				}
			}
			n, err := f.ReadAt(make([]byte, 1), tc.off)
			if n != 0 || !errors.Is(err, ErrChunkLayout) {
				t.Fatalf("ReadAt at %d = %d, %v; want 0, ErrChunkLayout", tc.off, n, err)
			}
			wantCounts(t, src, tc.downloads)
			// For good, and at no further cost.
			for off := range int64(size) {
				if _, err := f.ReadAt(make([]byte, 1), off); !errors.Is(err, ErrChunkLayout) {
					t.Fatalf("ReadAt at %d after the refusal: error = %v, want ErrChunkLayout", off, err)
				}
			}
			wantCounts(t, src, tc.downloads)
		})
	}
}

// The limit is 32 MiB unless a test lowers it, and the default chunk size is
// the one this CLI uploads.
func TestOptions_ChunkSizes(t *testing.T) {
	if MaxChunkSize != 32<<20 {
		t.Errorf("MaxChunkSize = %d, want 32 MiB", MaxChunkSize)
	}
	if got := (Options{}).maxChunkSize(); got != MaxChunkSize {
		t.Errorf("maxChunkSize() = %d, want MaxChunkSize", got)
	}
	if got := (Options{}).defaultChunkSize(); got != service.UploadChunkSize {
		t.Errorf("defaultChunkSize() = %d, want service.UploadChunkSize", got)
	}

	// The decision at the real sizes, without a byte allocated: what the
	// node tells is enough to accept or refuse.
	const mib = 1 << 20
	for name, tc := range map[string]struct {
		size      int64
		count     int
		chunkSize int64 // 0: to be learned from chunk 0
		refused   bool
	}{
		"8 MiB chunks":                   {size: 20 * mib, count: 3, chunkSize: 8 * mib},
		"16 MiB chunks":                  {size: 40 * mib, count: 3},
		"one chunk of 32 MiB":            {size: 32 * mib, count: 1, chunkSize: 32 * mib},
		"one chunk beyond 32 MiB":        {size: 32*mib + 1, count: 1, refused: true},
		"two chunks of 32 MiB":           {size: 64 * mib, count: 2},
		"two chunks, one beyond 32 MiB":  {size: 64*mib + 1, count: 2, refused: true},
		"chunk count unknown":            {size: 500 * mib},
		"more chunks than bytes":         {size: 2, count: 3, refused: true},
		"empty file":                     {},
		"empty file with a chunk count":  {count: 1},
		"8 MiB chunks, exact multiple":   {size: 16 * mib, count: 2, chunkSize: 8 * mib},
		"8 MiB file, one chunk":          {size: 8 * mib, count: 1, chunkSize: 8 * mib},
		"small file, one chunk":          {size: 5, count: 1, chunkSize: 5},
		"8 MB chunks, count of 8 MiB":    {size: 20 * 1000 * 1000, count: 3, chunkSize: 8 * mib},
		"8 MB chunks, count beyond that": {size: 200 * 1000 * 1000, count: 25},
	} {
		f := &file{node: Node{Size: tc.size, ChunkCount: tc.count}, maxSize: MaxChunkSize}
		f.assumeLayout(service.UploadChunkSize)
		if refused := errors.Is(f.layoutErr, ErrChunkLayout); refused != tc.refused || f.chunkSize != tc.chunkSize {
			t.Errorf("%s: refused %v (%v), chunk size %d; want refused %v, chunk size %d",
				name, refused, f.layoutErr, f.chunkSize, tc.refused, tc.chunkSize)
		}
	}
}

// A read whose context is already over reads nothing and downloads nothing.
func TestFile_CancelledReadDownloadsNothing(t *testing.T) {
	data := testData(2 * testChunkSize)
	src := newChunkSource(data)
	f := openTestFile(t, context.Background(), src)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := f.ReadAtContext(ctx, make([]byte, 2*testChunkSize), 1); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadAtContext = %d, %v; want 0, context.Canceled", n, err)
	}
	wantCounts(t, src, map[int]int{})
	if held := window(f); len(held) != 0 {
		t.Errorf("window holds %v", held)
	}

	// Nor does it count as a read: the next one is not its continuation.
	readAt(t, f, 1, 1, data)
	wantCounts(t, src, map[int]int{0: 1})

	// A read cancelled while it waits returns what it read, and its context
	// starts nothing afterwards.
	src.gate(1)
	ctx, cancel = context.WithCancel(context.Background())
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := f.ReadAtContext(ctx, make([]byte, 2*testChunkSize), testChunkSize-1)
		done <- result{n, err}
	}()
	src.awaitStart(t, 0) // the download of the first read
	src.awaitStart(t, 1)
	cancel()
	if r := <-done; r.n != 1 || !errors.Is(r.err, context.Canceled) {
		t.Fatalf("ReadAtContext = %d, %v; want 1, context.Canceled", r.n, r.err)
	}
	if n, err := f.ReadAtContext(ctx, make([]byte, 1), 0); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadAtContext = %d, %v; want 0, context.Canceled", n, err)
	}
	wantCounts(t, src, map[int]int{0: 1, 1: 1})
}

// Readers of the same chunk share one download.
//
// The readers are one sequential run as soon as two of them are recorded (a
// chunk of testChunkSize bytes is read ahead after one byte), so the reader
// that pins chunk 0 may start chunk 1 with it: two goroutines, whose first
// calls to the source arrive in either order.
func TestFile_ConcurrentReadersShareOneDownload(t *testing.T) {
	data := testData(2 * testChunkSize)
	src := newChunkSource(data)
	open := src.gate(0)
	f := openTestFile(t, context.Background(), src)

	const readers = 16
	errs := make(chan error, readers)
	for i := range readers {
		go func() {
			p := make([]byte, 2)
			off := int64(i % 3)
			if _, err := f.ReadAt(p, off); err != nil {
				errs <- err

				return
			}
			if !bytes.Equal(p, data[off:off+2]) {
				errs <- fmt.Errorf("read %q at %d", p, off)

				return
			}
			errs <- nil
		}()
	}
	src.awaitStartAmong(t, 0, 1)
	open()
	for range readers {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	settle(f)
	got := src.counts()
	if got[0] != 1 {
		t.Errorf("chunk 0 downloaded %d times, want 1", got[0])
	}
	if got[1] > 1 || len(got) > 2 {
		t.Errorf("downloads = %v, want chunk 0 once and chunk 1 once at most", got)
	}
}

// Readers all over the file, at once, each read what the file holds, and the
// window never exceeds its two chunks.
func TestFile_ConcurrentRandomReads(t *testing.T) {
	data := testData(9*testChunkSize + 1)
	src := newChunkSource(data)
	f := openTestFile(t, context.Background(), src)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g))) //nolint:gosec // G404: test offsets
			off := 0
			for i := range 300 {
				if g%2 == 0 || i%7 == 0 {
					off = rng.Intn(len(data))
				}
				n := 1 + rng.Intn(2*testChunkSize)
				p := make([]byte, n)
				got, err := f.ReadAt(p, int64(off))
				want := data[off:min(off+n, len(data))]
				if (err != nil && err != io.EOF) || !bytes.Equal(p[:got], want) {
					errs <- fmt.Errorf("ReadAt(%d bytes at %d) = %q, %v; want %q", n, off, p[:got], err, want)

					return
				}
				if held := window(f); len(held) > windowSize {
					errs <- fmt.Errorf("window holds %v", held)

					return
				}
				off = (off + got) % len(data)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// waitFor polls cond, which reads state guarded by f.mu.
func waitFor(t *testing.T, f *file, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		ok := cond()
		f.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// With a read waiting on each chunk of the window, a third read waits for a
// slot instead of holding a third chunk, and gives up with its context.
func TestFile_ReadWaitsForASlot(t *testing.T) {
	data := testData(3 * testChunkSize)
	src := newChunkSource(data)
	open0, open1 := src.gate(0), src.gate(1)
	defer open1()
	f := openTestFile(t, context.Background(), src)

	results := make(chan error, 3)
	read := func(ctx context.Context, off int64) {
		p := make([]byte, 1)
		_, err := f.ReadAtContext(ctx, p, off)
		if err == nil && p[0] != data[off] {
			err = fmt.Errorf("read %q at %d", p, off)
		}
		results <- err
	}
	go read(context.Background(), 0)
	src.awaitStart(t, 0)
	go read(context.Background(), testChunkSize)
	src.awaitStart(t, 1)

	// Both slots are pinned: a read of chunk 2 waits, and leaves with its
	// context.
	ctx, cancel := context.WithCancel(context.Background())
	go read(ctx, 2*testChunkSize)
	waitFor(t, f, "the third read to wait for a slot", func() bool { return f.waiting == 1 })
	cancel()
	if err := <-results; !errors.Is(err, context.Canceled) {
		t.Fatalf("read waiting for a slot: error = %v, want context.Canceled", err)
	}
	wantCounts(t, src, map[int]int{0: 1, 1: 1})

	// Another one gets the slot of chunk 0 once its reader is done.
	go read(context.Background(), 2*testChunkSize)
	waitFor(t, f, "the third read to wait for a slot", func() bool { return f.waiting == 1 })
	open0()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	wantCounts(t, src, map[int]int{0: 1, 1: 1, 2: 1})
	if held := window(f); !maps.Equal(held, map[int]bool{1: true, 2: true}) {
		t.Errorf("window holds %v, want chunks 1 and 2", held)
	}
	open1()
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

// Cancelling the context of one read fails that read only: the download goes
// on for the others, and is not made twice.
func TestFile_ReadContextCancelsTheReadNotTheDownload(t *testing.T) {
	data := testData(testChunkSize)
	src := newChunkSource(data)
	open := src.gate(0)
	f := openTestFile(t, context.Background(), src)

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := f.ReadAtContext(ctx, make([]byte, 1), 0)
		first <- err
	}()
	src.awaitStart(t, 0)

	second := make(chan error, 1)
	go func() {
		_, err := f.ReadAtContext(context.Background(), make([]byte, 1), 1)
		second <- err
	}()
	waitFor(t, f, "the second read to join the download", func() bool {
		return f.slots[0] != nil && f.slots[0].pins == 2
	})

	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read: error = %v, want context.Canceled", err)
	}
	open()
	if err := <-second; err != nil {
		t.Fatalf("read sharing the download: %v", err)
	}
	wantCounts(t, src, map[int]int{0: 1})
}

// The context given to Open bounds the opening and nothing after it: the
// File reads and downloads once it is over.
func TestFile_OpenContextDoesNotBoundTheHandle(t *testing.T) {
	data := testData(2 * testChunkSize)
	src := newChunkSource(data)
	ctx, cancel := context.WithCancel(context.Background())
	f := openTestFile(t, ctx, src)
	cancel()

	readAt(t, f, 1, 2, data)
	readAt(t, f, testChunkSize, 2, data)
	wantCounts(t, src, map[int]int{0: 1, 1: 1})
}

// The context of an open reaches the resolution of the session, and an open
// that waits for a resolution already running leaves when its context ends.
// The resolution itself is shared and goes on (service.SessionCache).
func TestOpen_ContextBoundsTheWaitForTheSession(t *testing.T) {
	entered, release := make(chan any, 1), make(chan struct{})
	fs := New(nil, Options{
		ReadChunk: nil,
		Session: func(ctx context.Context, _ string) (*service.DataroomSession, error) {
			entered <- ctx.Value(traceKey{})
			<-release

			return &service.DataroomSession{}, nil
		},
	})
	node := Node{Type: TypeFile, VersionID: "v1", Size: 1, ChunkCount: 1}

	first := make(chan error, 1)
	go func() {
		f, err := fs.Open(context.WithValue(context.Background(), traceKey{}, "open"), "dr1", node)
		if err == nil {
			err = f.Close()
		}
		first <- err
	}()
	if got := <-entered; got != "open" {
		t.Errorf("the resolution ran on a context holding %v, want the value of the open", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fs.Open(ctx, "dr1", node); !errors.Is(err, context.Canceled) {
		t.Errorf("interrupted Open: error = %v, want context.Canceled", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Errorf("first Open: %v", err)
	}
}

// A download belongs to the trace of the read that started it, the one ahead
// included, and to none when ReadAt started it.
func TestFile_DownloadCarriesTheTraceOfItsRead(t *testing.T) {
	data := testData(3 * testChunkSize)
	src := newChunkSource(data)
	f := openTestFile(t, context.Background(), src)

	if _, err := f.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), traceKey{}, "read")
	if _, err := f.ReadAtContext(ctx, make([]byte, 1), 1); err != nil { // fetches chunk 1 ahead
		t.Fatal(err)
	}
	settle(f)
	wantCounts(t, src, map[int]int{0: 1, 1: 1})
	src.mu.Lock()
	defer src.mu.Unlock()
	if len(src.traces) != 2 || src.traces[0] != nil || src.traces[1] != "read" {
		t.Errorf("trace values of the downloads = %v, want [<nil> read]", src.traces)
	}
}

// Closing the FS stops the downloads of the files still open, whose reads
// fail with ErrClosed and start nothing more.
func TestFile_FSCloseStopsDownloads(t *testing.T) {
	src := newChunkSource(testData(2 * testChunkSize))
	src.gate(0)
	fs := New(nil, Options{ReadChunk: src.read, ChunkSize: testChunkSize})
	f, err := fs.Open(context.Background(), "dr1",
		Node{Type: TypeFile, VersionID: "v1", Size: 2 * testChunkSize, ChunkCount: 2})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	done := make(chan error, 2)
	go func() {
		_, err := f.ReadAt(make([]byte, 1), 0)
		done <- err
	}()
	go func() {
		_, err := f.ReadAtContext(context.Background(), make([]byte, 1), 3) // too far to continue the other
		done <- err
	}()
	src.awaitStart(t, 0)
	if err := fs.Close(); err != nil {
		t.Fatalf("FS.Close: %v", err)
	}
	for range 2 {
		if err := <-done; !errors.Is(err, ErrClosed) {
			t.Errorf("read waiting at FS.Close: error = %v, want ErrClosed", err)
		}
	}
	if _, err := f.ReadAt(make([]byte, 1), testChunkSize); !errors.Is(err, ErrClosed) {
		t.Errorf("ReadAt after FS.Close: error = %v, want ErrClosed", err)
	}
	// Close still returns, the download having stopped.
	if err := f.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if n := src.inFlight(); n != 0 {
		t.Errorf("%d downloads still running", n)
	}
	wantCounts(t, src, map[int]int{0: 1})
}

// Close during a download stops it, waits for it, fails the reads waiting
// for it and keeps nothing.
func TestFile_CloseDuringDownload(t *testing.T) {
	data := testData(3 * testChunkSize)
	src := newChunkSource(data)
	f := openTestFile(t, context.Background(), src)

	// A sequential reader, so that a fetch ahead is in flight too.
	readAt(t, f, 0, 1, data)
	src.gate(1)
	src.gate(2)
	if _, err := f.ReadAt(make([]byte, 1), 1); err != nil {
		t.Fatal(err)
	}
	<-src.started // chunk 0
	src.awaitStart(t, 1)

	// A read waiting for a chunk that is not in the window.
	done := make(chan error, 1)
	go func() {
		_, err := f.ReadAt(make([]byte, 1), 2*testChunkSize)
		done <- err
	}()
	src.awaitStart(t, 2)

	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close returned: the downloads have.
	if n := src.inFlight(); n != 0 {
		t.Errorf("%d downloads still running after Close", n)
	}
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Errorf("read waiting at Close: error = %v, want ErrClosed", err)
	}
	if held := window(f); len(held) != 0 {
		t.Errorf("window holds %v after Close", held)
	}
	if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrClosed) {
		t.Errorf("ReadAt after Close: error = %v, want ErrClosed", err)
	}
	if _, err := f.ReadAtContext(context.Background(), nil, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("empty ReadAtContext after Close: error = %v, want ErrClosed", err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// A download that completes although the file was closed is not kept.
func TestFile_CloseDiscardsALateChunk(t *testing.T) {
	src := newChunkSource(testData(testChunkSize))
	open := src.gate(0)
	src.deaf[0] = true
	f := openTestFile(t, context.Background(), src)

	done := make(chan error, 1)
	go func() {
		_, err := f.ReadAt(make([]byte, 1), 0)
		done <- err
	}()
	src.awaitStart(t, 0)
	f.mu.Lock()
	late := f.slots[0]
	f.mu.Unlock()

	closed := make(chan struct{})
	go func() {
		_ = f.Close()
		close(closed)
	}()
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Errorf("read waiting at Close: error = %v, want ErrClosed", err)
	}
	select {
	case <-closed:
		t.Fatal("Close returned before the download did")
	case <-time.After(20 * time.Millisecond):
	}
	open()
	<-closed
	if late.data != nil {
		t.Error("the chunk downloaded after Close is still held")
	}
}

// Open without the test hook reads through the API and the session of the
// dataroom: chunks downloaded by index and decrypted, whatever the size the
// version was cut at.
func TestFile_ReadsThroughTheAPI(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	data := testData(2*testChunkSize + 3) // 11 bytes
	const chunkPath = "/dataroom/node/version/v1/chunk/"
	for name, tc := range map[string]struct {
		stored   int
		requests string
	}{
		// The read covers the last two chunks; the first one is never asked for.
		"cut at the default size": {testChunkSize, chunkPath + "1 " + chunkPath + "2"},
		// 2 chunks where the default size makes 3: chunk 0 tells the size,
		// and holds the first byte read.
		"cut larger":  {6, chunkPath + "0 " + chunkPath + "1"},
		"cut smaller": {3, chunkPath + "0 " + chunkPath + "1 " + chunkPath + "2 " + chunkPath + "3"},
	} {
		t.Run(name, func(t *testing.T) {
			chunks := cut(data, tc.stored)
			var log callLog
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.add(r.URL.Path)
				var index int
				if _, err := fmt.Sscanf(r.URL.Path, chunkPath+"%d", &index); err != nil || index >= len(chunks) {
					http.NotFound(w, r)

					return
				}
				enc, err := crypto.EncryptBinaryForKey(chunks[index], identity.Recipient().String())
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)

					return
				}
				_, _ = w.Write(enc)
			}))
			defer srv.Close()

			fs := New(testClient(srv), Options{
				ChunkSize: testChunkSize,
				Session: func(context.Context, string) (*service.DataroomSession, error) {
					return &service.DataroomSession{Identity: identity}, nil
				},
			})
			f, err := fs.Open(context.Background(), "dr1",
				Node{Type: TypeFile, VersionID: "v1", Size: int64(len(data)), ChunkCount: len(chunks)})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			p := make([]byte, 5)
			if _, err := f.ReadAt(p, 5); err != nil {
				t.Fatalf("ReadAt: %v", err)
			}
			if !bytes.Equal(p, data[5:10]) {
				t.Errorf("read %q, want %q", p, data[5:10])
			}
			if err := f.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if got := strings.Join(log.sorted(), " "); got != tc.requests {
				t.Errorf("requests = %s, want %s", got, tc.requests)
			}
		})
	}
}

// A session that cannot be resolved fails Open, not the first read.
func TestOpen_SessionError(t *testing.T) {
	down := errors.New("no session")
	fs := New(nil, Options{Session: func(context.Context, string) (*service.DataroomSession, error) {
		return nil, down
	}})
	_, err := fs.Open(context.Background(), "dr1", Node{Type: TypeFile, VersionID: "v1", Size: 1})
	if !errors.Is(err, down) {
		t.Errorf("Open error = %v, want %v", err, down)
	}
}
