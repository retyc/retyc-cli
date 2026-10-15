package vfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
)

// Errors of Open and of a File. Open answers ErrIsDir (errors.go) for a folder.
var (
	// ErrNotFile is returned by Open for a node that carries no content: a
	// symbolic link, or a file without a version.
	ErrNotFile = errors.New("vfs: not a regular file")
	// ErrClosed is returned by a read on a closed File, including one that
	// was waiting for a chunk when Close was called, and by a read on a File
	// whose FS was closed.
	ErrClosed = errors.New("vfs: file already closed")
	// ErrNegativeOffset is returned by a read at a negative offset.
	ErrNegativeOffset = errors.New("vfs: negative offset")
	// ErrChunkLayout is returned by a read of a version that cannot be read
	// at an offset: its chunks are not all of one size (bar the last), the
	// number of chunks, the size of the file and the size of the chunks read
	// do not agree, or a chunk is larger than MaxChunkSize. The version may
	// still be read from its start to its end, by concatenating its chunks
	// (service.StreamDownloadChunks). The error is final for the File: every
	// later read returns it, without a download.
	ErrChunkLayout = errors.New("vfs: version not readable at an offset")
)

// MaxChunkSize is the largest plaintext chunk a File reads. A File holds two
// chunks in memory, 64 MiB at this limit, and no larger chunk exists: the API
// is served behind a limit of 32 MiB on the whole request that uploads a
// chunk, encryption and multipart framing included. A version said to be cut
// in larger chunks is answered ErrChunkLayout, before the chunk is downloaded
// whenever its size can be told first (see file), and never held in memory
// (service.ReadDataroomChunkBounded).
const MaxChunkSize = 32 << 20

// readAheadAfterMax bounds readAheadAfter.
const readAheadAfterMax = 1 << 20

// windowSize is the number of decrypted chunks a File holds at most: the one
// being read, and the next one once the read is seen to be sequential.
const windowSize = 2

// ReadChunkFunc returns the decrypted chunk at index of a file version.
type ReadChunkFunc func(ctx context.Context, versionID string, index int) ([]byte, error)

// ChunkSizeFunc returns the number of plaintext bytes of the chunk at index of
// a file version, without downloading it. Its error matches api.ErrNoChunkSize
// when the API cannot tell, api.ErrNotFound when it does not hold the chunk.
type ChunkSizeFunc func(ctx context.Context, versionID string, index int) (int64, error)

// File is a file version open for reading at any offset. A File reads the
// version it was opened on, whatever becomes of the file afterwards: a new
// version uploaded, the file renamed or deleted (a deleted version ends up
// failing the downloads). A version never changes, so neither does what a
// File reads.
//
// It is safe for concurrent use. Reading costs one download per chunk
// entered; a File holds two decrypted chunks at most, of the size the version
// was cut at (see file), nothing of it is shared with another File or written
// to disk, and Close releases it all.
type File interface {
	// ReadAt reads for as long as the File is open: nothing but Close, or the
	// Close of the FS, interrupts it.
	io.ReaderAt
	// ReadAtContext is ReadAt for a caller with a context of its own: ctx
	// bounds how long this read waits, and the trace it carries is the one a
	// download started by this read belongs to. A read whose context is
	// already over starts no download.
	//
	// Cancelling ctx fails this read only. The download it was waiting for
	// goes on, since other reads may share it, and its chunk stays in the
	// window; Close, or the Close of the FS, is what stops a download.
	ReadAtContext(ctx context.Context, p []byte, off int64) (int, error)
	// Close stops the downloads in flight, waits for them to return, and
	// releases the chunks held. Reads waiting on the File fail with
	// ErrClosed. A second Close does nothing.
	io.Closer
	// Node returns the node the File was opened from.
	Node() Node
}

// Open opens the version n.VersionID of the file n of dataroom drID for
// reading. Nothing is downloaded, and nothing asked of the API, before the
// first read: an Open followed by a Close costs no request.
//
// ctx bounds the opening alone, that is the resolution of the dataroom
// session when the FS does not hold it yet: an open that waits for a
// resolution already running leaves when ctx ends. The resolution itself is
// shared by every caller and never interrupted by one of them
// (service.SessionCache), so the open that started it waits for its end. The
// File does not live on ctx: its downloads last until its Close, or the Close
// of the FS, and each carries the trace of the read that started it.
//
// n is trusted as given: a node from an expired listing may name a version
// that no longer exists, which the first read reports. n.ChunkCount and
// n.Size are what the chunk size of the version is worked out from (see
// file); a ChunkCount of zero for a file that is not empty means "not known".
func (fs *FS) Open(ctx context.Context, drID string, n Node) (File, error) {
	switch {
	case n.Type == TypeDir:
		return nil, ErrIsDir
	case n.Type != TypeFile, n.Size < 0, n.Size > 0 && n.VersionID == "":
		return nil, ErrNotFile
	}

	maxSize := fs.opts.maxChunkSize()
	fetch, sizeOf := fs.opts.ReadChunk, fs.opts.ChunkSizeOf
	if fetch == nil {
		sess, err := fs.Session(ctx, drID)
		if err != nil {
			return nil, fmt.Errorf("dataroom session: %w", err)
		}
		fetch = func(ctx context.Context, versionID string, index int) ([]byte, error) {
			return service.ReadDataroomChunkBounded(ctx, fs.client, versionID, index, sess, maxSize)
		}
		if sizeOf == nil {
			sizeOf = func(ctx context.Context, versionID string, index int) (int64, error) {
				return service.DataroomChunkPlainSize(ctx, fs.client, versionID, index, sess)
			}
		}
	}

	fctx, cancel := context.WithCancel(fs.ctx)
	f := &file{
		node:    n,
		fetch:   fetch,
		sizeOf:  sizeOf,
		sizes:   &fs.chunkSizes,
		maxSize: maxSize,
		ctx:     fctx,
		cancel:  cancel,
		lastEnd: -1,
		failed:  -1,
		freed:   make(chan struct{}),
	}
	f.assumeLayout(fs.opts.defaultChunkSize())
	f.recallLayout()

	return f, nil
}

// file is the File of Open.
//
// # Chunk size
//
// A version is a sequence of chunks, each encrypted on its own. All hold the
// same number of plaintext bytes, bar the last, which holds what is left.
// That number is chosen by the client that uploaded the version (8 MiB for
// this CLI, a setting of the web application, the cut of the source for a
// copy) and the listing does not tell it: only the number of chunks (count)
// and the plaintext size of the file (size). A read at an offset needs it, to
// find the chunk that holds the offset. It is settled per File, at the first
// read and not before, by the first of these that applies:
//
//  1. one chunk: it holds the whole file, there is nothing to work out;
//  2. the FS remembers the chunk size of the version (chunkSizes): a version
//     never changes, and every size told by the API or proved by a chunk is
//     recorded;
//  3. several chunks, and the default chunk size gives the right number of
//     them, ceil(size / default) == count: the default is assumed;
//  4. the first read is in chunk 0 whatever the chunk size (offset 0, or an
//     offset below ceil(size / count), the smallest chunk size that fits
//     size in count chunks): chunk 0 is downloaded, its length is the chunk
//     size, and it is the chunk the read needed;
//  5. the API is asked for the size of chunk 0 (sizeOf: one HEAD, nothing
//     downloaded), once per File and, the answer being remembered, once per
//     version;
//  6. the API cannot tell (see below) and count is known:
//     c = ceil(size / count) is assumed. If ceil(size / c) != count, no
//     chunk size makes count chunks of size bytes: the version is refused at
//     once, without a download;
//  7. count is not known either: chunk 0 is downloaded first, as in 4.
//
// A chunk size told by the API (5), or remembered (2), is an assumption like
// any other when count is known, and must give count chunks. When count is
// not known it is taken as the length of chunk 0, which it is, exactly as if
// chunk 0 had been downloaded.
//
// Whatever the way, every chunk downloaded must hold exactly the bytes the
// chunk size gives it, min(chunkSize, size - index*chunkSize). A chunk that
// contradicts an assumption corrects it (settleLocked); one that contradicts
// a chunk size already measured makes the version unreadable at an offset
// (ErrChunkLayout).
//
// Why no read is served from a wrong offset. Take a version cut uniformly at
// c' in count chunks, so ceil(size/c') == count, and let c be the chunk size
// in use, with ceil(size/c) == count as well, wherever c comes from: the
// default, the API, the memo, ceil(size/count). A chunk i < count-1 is not
// the last under either: it holds c' bytes and is expected to hold c. The
// chunk count-1 is the last under both: it holds size - (count-1)*c' bytes
// and is expected to hold size - (count-1)*c. Either check passes only if
// c == c'. No byte is copied out of a chunk before its length was checked, so
// by the time a read copies from chunk i at pos - i*c, c is the real chunk
// size, and that is where the byte at pos is. Without the count the argument
// fails (12 bytes in chunks of 8 read with c = 4: chunk 1 holds the 4 bytes c
// expects), which is why an unknown count is never paired with an assumption:
// the length of chunk 0, downloaded or told by the API, then gives c' itself.
//
// The argument rests on what the reader cannot check without downloading
// every chunk: that the cut is uniform, which every client guarantees, and
// that the count is the one of the version, which the API tells. A version
// that breaks either is refused only when a chunk read shows it, and a cut
// that is not uniform but whose chunks happen to have the lengths a uniform
// one would give them where they are read is not told apart at all.
//
// The API cannot tell (6) when it has no such route. It says so itself with
// a 405 (api.ErrNoChunkSize), which is recorded for the life of the FS: no
// File asks again. Behind some proxies it answers 404 instead, which is also
// what the route answers for a chunk the store does not hold; a 404 carrying
// an error code (CHUNK_NOT_FOUND, VERSION_NOT_FOUND…) is the route's own: the
// route is recorded present and the read fails. Without a code, the two are
// told apart by what follows: the File goes on with 6, and if a chunk of that
// version then downloads, the version exists and the 404 was the route
// (chunkSizes.routeMissed), unless the route was seen to answer before, in
// which case it was the chunk. Until one of the two is established each File
// asks once. Any other failure of the request (429 once the client's own
// retries are spent, 410, 403, a network error) fails the read that needed
// it, and the next read asks again.
//
// # Window
//
// The window is windowSize slots, each holding one chunk, downloaded or on
// its way. A read pins the chunk it needs for the time it waits for it and
// copies from it, one chunk at a time; a chunk that no read pins can be
// evicted, the least recently used first. A read that finds every slot
// pinned waits for one, so the bound holds whatever the number of readers.
// This is no cache: it only spares a sequential reader, which asks for a few
// kilobytes at a time, one download per read.
//
// # Fetch ahead
//
// A reader is sequential once its run covers readAheadAfter bytes. The run is
// the span of the file its recent reads cover, [runStart, lastEnd): a read
// that starts inside it or at its end continues it, and so does one that
// lands within readAheadSlack of either end, the run then growing to hold it.
// Any other read starts a new run. Reads need not arrive in order: a kernel
// reading ahead hands consecutive ranges to several goroutines, which reach
// the File in any order (4, 0, 12, 8, ...), each a read's length away from
// the previous one; requiring each read to start where the last one ended
// would never see that reader as sequential. The price is that a seek back
// into the span already read continues the run too.
//
// From then on, entering a chunk starts the download of the next one at
// once, without waiting for the chunk entered: a sequential reader has two
// downloads in flight, never more, the window being two slots. Below the
// threshold nothing is fetched ahead: a short range, even read in several
// calls (a preview, the probe of a media player), costs the chunks it covers
// and no other.
type file struct {
	node    Node
	fetch   ReadChunkFunc
	maxSize int64
	// sizeOf asks the API for the size of a chunk; nil when there is no such
	// request to make. sizes is the memo of the FS, nil in some tests.
	sizeOf ChunkSizeFunc
	sizes  *chunkSizes

	// ctx ends with the FS or with Close; every download stops with it.
	ctx    context.Context
	cancel context.CancelFunc
	// wg counts the download goroutines, which Close waits for.
	wg sync.WaitGroup

	mu     sync.Mutex
	closed bool

	// count is the number of chunks of the version, 0 while it is not known.
	count int
	// chunkSize is the plaintext size of every chunk but the last, 0 until
	// it is settled (see file).
	chunkSize int64
	// measured is set once chunkSize is more than an assumption: a chunk was
	// checked against it, or it is the length of chunk 0.
	measured bool
	// learn is set once chunk 0 is what will tell the chunk size: every read
	// asks for it while chunkSize is 0.
	learn bool
	// probe is the request for the size of chunk 0 in flight, probed is set
	// once the request was answered, by a size or by a 404, and suspect while
	// that 404 may yet prove to be a missing route (see file).
	probe   *sizeProbe
	probed  bool
	suspect bool
	// layoutErr is the ErrChunkLayout every read returns once set.
	layoutErr error

	slots [windowSize]*chunk
	clock uint64 // source of chunk.used
	// The run of the reader (see file): the offset it starts at and the one
	// it ends at, -1 before the first read.
	lastEnd  int64
	runStart int64
	// failed is the index of the last chunk whose download failed, -1 when
	// none: it is not fetched ahead again, so that a sequential reader does
	// not ask for a chunk the API refuses once per read. A read that needs
	// it still asks, and reports the error.
	failed int
	// freed is closed, and replaced, when a slot may have become available
	// while a read was waiting for one.
	freed   chan struct{}
	waiting int
}

// chunk is one slot of the window: a chunk downloaded, or its download.
type chunk struct {
	index int
	// done is closed once data or err is set.
	done chan struct{}
	data []byte
	err  error
	// cancel stops the download.
	cancel context.CancelFunc

	// The fields below are guarded by file.mu.
	pins    int    // reads waiting for the chunk or copying from it
	used    uint64 // file.clock when last pinned or started
	dropped bool   // evicted, or the file was closed: the result is discarded
}

// sizeProbe is the request for the size of chunk 0, shared by the reads that
// wait for it.
type sizeProbe struct {
	// done is closed once the answer was applied to the file, or err set.
	done chan struct{}
	// err is the failure the reads waiting for this request return.
	err error
}

// chunksOf returns the number of chunks of chunkSize bytes a file of size
// bytes is cut in. Both are positive.
func chunksOf(size, chunkSize int64) int64 {
	return (size-1)/chunkSize + 1
}

// readAheadAfter is the number of contiguous bytes after which a reader of
// chunks of chunkSize bytes is taken to be sequential: an eighth of a chunk,
// 1 MiB at most (the eighth of the usual 8 MiB).
//
// It is weighed against one wasted chunk. Below it sit the requests that end
// early: a media player reading a header or an index, a preview, a client
// probing with a short range, all well under 1 MiB and often read in several
// calls (net/http copies 32 KiB at a time). Above it, the reader has consumed
// an eighth of the chunk it is in, so the download of the next one has the
// other seven eighths to arrive, and at worst one chunk is downloaded for
// nothing, by a read that had already cost one.
func readAheadAfter(chunkSize int64) int64 {
	return max(1, min(chunkSize/8, readAheadAfterMax))
}

// readAheadSlack is how far from the run of the reader a read of n bytes may
// land and still continue it: the length of the read, which is how far apart
// two reads issued in order and served out of order are, and readAheadAfter
// at least. chunkSize is 0 while it is not known.
func readAheadSlack(chunkSize, n int64) int64 {
	return max(n, readAheadAfter(chunkSize))
}

// layoutErrorf records, and returns, the ErrChunkLayout of the file. The
// caller holds mu, or is Open.
func (f *file) layoutErrorf(format string, args ...any) error {
	f.layoutErr = fmt.Errorf("%w: "+format, append([]any{ErrChunkLayout}, args...)...)

	return f.layoutErr
}

// assumeLayout sets what the node alone tells of the chunk size (see file);
// defaultSize is the one assumed when it fits. What it leaves unsettled
// (chunkSize 0) is settled by the first read (decideLocked).
func (f *file) assumeLayout(defaultSize int64) {
	size, count := f.node.Size, int64(f.node.ChunkCount)
	switch {
	case size == 0:
		// Nothing to read, whatever the count.
	case count <= 0:
		// Not known: the length of chunk 0 tells the chunk size, and the
		// count with it.
	case count > size:
		_ = f.layoutErrorf("%d chunks for %d bytes", count, size)
	case chunksOf(size, count) > f.maxSize:
		// chunksOf(size, count) is ceil(size / count), the smallest chunk
		// size that fits size in count chunks.
		_ = f.layoutErrorf("%d bytes in %d chunks: chunks of more than %d bytes", size, count, f.maxSize)
	case count == 1:
		f.count, f.chunkSize, f.measured = 1, size, true
	case chunksOf(size, defaultSize) == count:
		f.count, f.chunkSize = int(count), defaultSize
	default:
		f.count = int(count)
	}
}

// recallLayout applies the chunk size the FS remembers of the version, if
// any, in place of what assumeLayout assumed. The caller is Open.
func (f *file) recallLayout() {
	if f.sizes == nil || f.layoutErr != nil || f.node.Size == 0 || f.node.ChunkCount == 1 {
		return
	}
	if size, ok := f.sizes.get(f.node.VersionID); ok {
		f.chunkSize, f.measured = 0, false
		f.applySizeLocked(size)
	}
}

// rememberLocked records the chunk size, now proved, in the memo of the FS.
// A version the listing gives one chunk has no chunk size to speak of. The
// caller holds mu.
func (f *file) rememberLocked() {
	if f.sizes != nil && f.node.ChunkCount != 1 {
		f.sizes.put(f.node.VersionID, f.chunkSize)
	}
}

// applySizeLocked takes the length of chunk 0 as told without downloading
// it, by the API or by the memo, for the chunk size (see file). It sets the
// chunk size, or the error of a version it shows unreadable at an offset.
// The caller holds mu, or is Open.
func (f *file) applySizeLocked(first int64) {
	size := f.node.Size
	switch {
	case first <= 0 || first > size:
		_ = f.layoutErrorf("chunk 0 holds %d bytes of a file of %d", first, size)
	case first > f.maxSize:
		_ = f.layoutErrorf("chunk 0 holds %d bytes, more than %d", first, f.maxSize)
	case f.count == 0:
		// As if chunk 0 had been downloaded: its length is the chunk size.
		f.count, f.chunkSize, f.measured = int(chunksOf(size, first)), first, true
	case chunksOf(size, first) != int64(f.count):
		_ = f.layoutErrorf("chunks of %d bytes make %d chunks of %d bytes, the version has %d",
			first, chunksOf(size, first), size, f.count)
	default:
		// An assumption, which the count allows: the chunks read check it.
		f.chunkSize = first
	}
}

// decideLocked settles how the chunk size will be known, for a file whose
// node did not tell and whose first read is at pos (see file, 4 to 7). It
// returns the request to wait for when it starts one; otherwise the chunk
// size is set or assumed, chunk 0 is to tell it (learn), or the version is
// refused. The caller holds mu, and has checked that the file is open.
func (f *file) decideLocked(ctx context.Context, pos int64) *sizeProbe {
	size := f.node.Size
	switch {
	case f.count > 0 && pos < chunksOf(size, int64(f.count)), f.count == 0 && pos == 0:
		// Chunk 0 holds pos whatever the chunk size: it is downloaded for
		// the read, and tells.
		f.learn = true
	case f.sizeOf != nil && !f.probed && (f.sizes == nil || !f.sizes.routeAbsent()):
		return f.probeLocked(ctx)
	default:
		f.fallbackLocked()
	}

	return nil
}

// fallbackLocked settles the chunk size without the API telling it: the
// smallest one the count allows, assumed, or chunk 0 when the count is not
// known. The caller holds mu.
func (f *file) fallbackLocked() {
	if f.count == 0 {
		f.learn = true

		return
	}
	size, count := f.node.Size, int64(f.count)
	c := chunksOf(size, count)
	if chunksOf(size, c) != count {
		// c is the smallest chunk size that fits size in count chunks, and
		// already makes fewer: larger ones make fewer still.
		_ = f.layoutErrorf("no chunk size makes %d chunks of %d bytes", count, size)

		return
	}
	f.chunkSize = c
}

// probeLocked asks the API for the size of chunk 0 and returns the request,
// which applies its answer to the file before done is closed. Like a
// download, it carries the values of ctx and not its cancellation, other
// reads waiting for it, and stops with the file. The caller holds mu, and has
// checked that the file is open.
func (f *file) probeLocked(ctx context.Context) *sizeProbe {
	pctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(f.ctx, cancel)

	p := &sizeProbe{done: make(chan struct{})}
	f.probe = p

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		first, err := f.sizeOf(pctx, f.node.VersionID, 0)
		stop()
		cancel()

		f.mu.Lock()
		f.probe = nil
		switch {
		case err == nil:
			f.probed = true
			if f.sizes != nil {
				f.sizes.routeAnswered()
				if first > 0 && first <= f.node.Size && first <= f.maxSize {
					// The length of chunk 0 is the chunk size of the version,
					// whatever the count the node of this file tells.
					f.sizes.put(f.node.VersionID, first)
				}
			}
			f.applySizeLocked(first)
		case errors.Is(err, api.ErrNoChunkSize):
			f.probed = true
			if f.sizes != nil {
				f.sizes.routeRefused()
			}
			f.fallbackLocked()
		case errors.Is(err, api.ErrNotFound) && api.ErrorCode(err) != "":
			// A refusal with a code comes from the route itself: the route
			// exists, the chunk or the version does not. Fails the read like
			// any other failure of the request.
			if f.sizes != nil {
				f.sizes.routeAnswered()
			}
			p.err = err
		case errors.Is(err, api.ErrNotFound) && !errors.Is(err, api.ErrGone):
			// No such route, or no such chunk: a chunk of the version that
			// downloads will tell (see startLocked).
			f.probed, f.suspect = true, true
			f.fallbackLocked()
		default:
			p.err = err
		}
		f.mu.Unlock()
		close(p.done)
	}()

	return p
}

// settleLocked checks the length of the chunk at index, just downloaded,
// against the chunk size, and settles the chunk size when it was unknown or
// assumed. It returns the ErrChunkLayout of a version that cannot be read at
// an offset. The caller holds mu.
func (f *file) settleLocked(index int, got int64) error {
	if f.layoutErr != nil {
		return f.layoutErr
	}
	size := f.node.Size
	switch {
	case got <= 0 || got > size:
		return f.layoutErrorf("chunk %d holds %d bytes of a file of %d", index, got, size)
	case got > f.maxSize:
		return f.layoutErrorf("chunk %d holds %d bytes, more than %d", index, got, f.maxSize)
	}

	if f.chunkSize == 0 {
		// Only chunk 0 is asked for while the chunk size is unknown.
		if index != 0 {
			return f.layoutErrorf("chunk %d downloaded before the chunk size is known", index)
		}
		count := chunksOf(size, got)
		if f.count > 0 && count != int64(f.count) {
			return f.layoutErrorf("chunks of %d bytes make %d chunks of %d bytes, the version has %d",
				got, count, size, f.count)
		}
		f.count, f.chunkSize, f.measured = int(count), got, true
		f.rememberLocked()

		return nil
	}

	want := min(f.chunkSize, size-int64(index)*f.chunkSize)
	if got == want {
		// See file: a chunk of the expected length proves the assumption.
		f.measured = true
		f.rememberLocked()

		return nil
	}
	if f.measured {
		return f.layoutErrorf("chunk %d holds %d bytes, want %d", index, got, want)
	}

	// The assumption is wrong, and this chunk tells the chunk size: its own
	// length, or for the last chunk what the others must share evenly.
	last := f.count - 1
	actual := got
	switch {
	case index > last:
		return f.layoutErrorf("chunk %d of a version of %d chunks", index, f.count)
	case index == last:
		rest := size - got
		actual = rest / int64(last)
		if rest%int64(last) != 0 || got > actual {
			return f.layoutErrorf("last chunk of %d holds %d bytes of %d: no uniform chunk size", f.count, got, size)
		}
	}
	if actual > f.maxSize || chunksOf(size, actual) != int64(f.count) {
		return f.layoutErrorf("chunk %d holds %d bytes: no chunk size makes %d chunks of %d bytes",
			index, got, f.count, size)
	}
	// Nothing in the window needs dropping: a chunk downloaded and kept would
	// have been checked, which settles the chunk size for good, so the window
	// holds downloads in flight only. Each is the chunk of its index whatever
	// the chunk size, and is checked against the corrected one when it
	// arrives. The reads waiting for them locate their offset again (chunkAt).
	f.chunkSize, f.measured = actual, true
	f.rememberLocked()

	return nil
}

func (f *file) Node() Node { return f.node }

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	return f.ReadAtContext(f.ctx, p, off)
}

func (f *file) ReadAtContext(ctx context.Context, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrNegativeOffset
	}

	f.mu.Lock()
	if f.overLocked() {
		f.mu.Unlock()

		return 0, ErrClosed
	}
	if len(p) == 0 {
		f.mu.Unlock()

		return 0, nil
	}
	if off >= f.node.Size {
		f.mu.Unlock()

		return 0, io.EOF
	}
	if err := ctx.Err(); err != nil {
		// Nothing is read, so nothing is recorded either.
		f.mu.Unlock()

		return 0, err
	}
	want := min(int64(len(p)), f.node.Size-off)
	// The read is recorded before it is made, and joins the run of the
	// reader when it lands in it or next to it (see file): the reads of
	// concurrent callers (a kernel reading ahead) are one run whatever the
	// order they arrive in.
	slack := readAheadSlack(f.chunkSize, want)
	if f.lastEnd >= 0 && off <= f.lastEnd+slack && off+want >= f.runStart-slack {
		f.runStart, f.lastEnd = min(f.runStart, off), max(f.lastEnd, off+want)
	} else {
		f.runStart, f.lastEnd = off, off+want
	}
	runStart := f.runStart
	f.mu.Unlock()

	var n int64
	for n < want {
		pos := off + n
		c, start, err := f.chunkAt(ctx, pos, runStart)
		if err != nil {
			return int(n), err
		}
		n += int64(copy(p[n:want], c.data[pos-start:]))
		f.release(c)
	}
	if want < int64(len(p)) {
		return int(n), io.EOF
	}

	return int(n), nil
}

func (f *file) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()

		return nil
	}
	f.closed = true
	for i, c := range f.slots {
		if c != nil {
			f.dropLocked(i)
		}
	}
	f.mu.Unlock()

	f.cancel()
	f.wg.Wait()

	return nil
}

// chunkAt returns the chunk holding the byte at pos, downloaded, checked and
// pinned, with the offset of its first byte; the caller releases it.
// runStart is where the run of contiguous reads pos belongs to started.
//
// The chunk asked for is the one the chunk size places pos in, chunk 0 while
// chunk 0 is to tell it. When the download settles the chunk size otherwise
// (see settleLocked), the chunk is not the right one and pos is located
// again: twice at most, the chunk size being settled once.
func (f *file) chunkAt(ctx context.Context, pos, runStart int64) (*chunk, int64, error) {
	for {
		c, err := f.acquire(ctx, pos, runStart)
		if err != nil {
			return nil, 0, err
		}
		f.mu.Lock()
		size := f.chunkSize
		f.mu.Unlock()
		if start := int64(c.index) * size; size > 0 && pos >= start && pos-start < int64(len(c.data)) {
			return c, start, nil
		}
		f.release(c)
	}
}

// acquire returns the chunk pos is placed in, downloaded and pinned; the
// caller releases it. Readers of the same chunk share one download.
func (f *file) acquire(ctx context.Context, pos, runStart int64) (*chunk, error) {
	c, err := f.pin(ctx, pos, runStart)
	if err != nil {
		return nil, err
	}

	err = nil
	select {
	case <-c.done:
		err = c.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err == nil {
		return c, nil
	}
	f.release(c)
	// Close ends the context ReadAt reads on and fails the download: either
	// way, what the read ran into is the Close.
	f.mu.Lock()
	over := f.overLocked()
	f.mu.Unlock()
	if over {
		return nil, ErrClosed
	}

	return nil, err
}

// pin returns the slot of the chunk pos is placed in, pinned, starting its
// download when the window does not hold it, and that of the next chunk when
// the reader is sequential (see file). It first settles how the chunk size
// is known when nothing did yet, waiting for the API when it is asked
// (decideLocked). It waits for a slot while reads pin them all. A read whose
// context is over starts nothing.
func (f *file) pin(ctx context.Context, pos, runStart int64) (*chunk, error) {
	f.mu.Lock()
	for {
		if f.overLocked() {
			f.mu.Unlock()

			return nil, ErrClosed
		}
		err := f.layoutErr
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			f.mu.Unlock()

			return nil, err
		}

		if f.chunkSize == 0 && !f.learn {
			p := f.probe
			if p == nil {
				p = f.decideLocked(ctx, pos)
			}
			if p != nil {
				f.mu.Unlock()
				select {
				case <-p.done:
				case <-ctx.Done():
				case <-f.ctx.Done():
				}
				f.mu.Lock()
				select {
				case <-p.done:
					if p.err != nil && !f.overLocked() {
						f.mu.Unlock()

						return nil, fmt.Errorf("chunk size: %w", p.err)
					}
				default:
				}
			}
			// The next turn of the loop reads what was settled, or tells
			// what ended the wait.
			continue
		}

		index := 0
		if f.chunkSize > 0 {
			index = int(pos / f.chunkSize)
		}
		c := f.heldLocked(index)
		if c == nil {
			if slot := f.slotLocked(-1); slot >= 0 {
				c = f.startLocked(ctx, slot, index)
			}
		}
		if c != nil {
			c.pins++
			f.clock++
			c.used = f.clock
			if f.chunkSize > 0 && pos-runStart >= readAheadAfter(f.chunkSize) {
				f.prefetchLocked(ctx, index+1)
			}
			f.mu.Unlock()

			return c, nil
		}

		f.waiting++
		freed := f.freed
		f.mu.Unlock()
		select {
		case <-freed:
		case <-ctx.Done():
		case <-f.ctx.Done():
		}
		// The next turn of the loop tells what ended the wait.
		f.mu.Lock()
		f.waiting--
	}
}

// release unpins c.
func (f *file) release(c *chunk) {
	f.mu.Lock()
	c.pins--
	if c.pins == 0 {
		f.freedLocked()
	}
	f.mu.Unlock()
}

// prefetchLocked starts the download of the chunk at index, the one a
// sequential reader needs next, unless the window holds it, the file ends
// before it, its last download failed, or no slot can be had without
// evicting the chunk the reader is on (other reads pin the rest). Nobody
// waits for it: a failure is reported by the read that needs the chunk, which
// asks again. The caller holds mu.
func (f *file) prefetchLocked(ctx context.Context, index int) {
	if int64(index)*f.chunkSize >= f.node.Size || index == f.failed || f.heldLocked(index) != nil {
		return
	}
	if slot := f.slotLocked(index - 1); slot >= 0 {
		f.startLocked(ctx, slot, index)
	}
}

// overLocked reports whether the file was closed, or its FS. The caller holds
// mu.
func (f *file) overLocked() bool {
	return f.closed || f.ctx.Err() != nil
}

// heldLocked returns the slot of the chunk at index, nil when the window does
// not hold it. The caller holds mu.
func (f *file) heldLocked(index int) *chunk {
	for _, c := range f.slots {
		if c != nil && c.index == index {
			return c
		}
	}

	return nil
}

// slotLocked returns a slot to start a download in: an empty one, else the
// least recently used one that no read pins, evicted. The chunk at index
// keep is never evicted. It returns -1 when there is none. The caller holds
// mu.
func (f *file) slotLocked(keep int) int {
	victim := -1
	for i, c := range f.slots {
		if c == nil {
			return i
		}
		if c.pins > 0 || c.index == keep {
			continue
		}
		if victim < 0 || c.used < f.slots[victim].used {
			victim = i
		}
	}
	if victim >= 0 {
		f.dropLocked(victim)
	}

	return victim
}

// dropLocked empties a slot: its download is stopped and its result
// discarded. A read that still pins the chunk keeps what it holds until it
// releases it. The caller holds mu.
func (f *file) dropLocked(slot int) {
	c := f.slots[slot]
	c.dropped = true
	c.cancel()
	f.slots[slot] = nil
	f.freedLocked()
}

// freedLocked wakes the reads waiting for a slot. The caller holds mu.
func (f *file) freedLocked() {
	if f.waiting > 0 {
		close(f.freed)
		f.freed = make(chan struct{})
	}
}

// startLocked starts the download of the chunk at index in an empty slot and
// returns it. The caller holds mu, and has checked that the file is open.
//
// The download carries the values of ctx, so its spans belong to the trace of
// the read that started it, but not its cancellation: other reads may be
// waiting for the same chunk. It stops with the file.
func (f *file) startLocked(ctx context.Context, slot, index int) *chunk {
	fctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(f.ctx, cancel)

	f.clock++
	c := &chunk{index: index, done: make(chan struct{}), cancel: cancel, used: f.clock}
	f.slots[slot] = c

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		data, err := f.fetch(fctx, f.node.VersionID, index)
		stop()
		cancel()

		f.mu.Lock()
		if err == nil && f.suspect {
			// The version exists, so the 404 that answered the request for
			// its chunk size was about the route (see file).
			f.suspect = false
			if f.sizes != nil {
				f.sizes.routeMissed()
			}
		}
		if c.dropped {
			// Evicted or closed meanwhile: neither kept, nor checked, nor
			// counted as a failure of the chunk. A read still waiting for
			// it fails.
			if err == nil {
				err = context.Canceled
			}
		} else {
			switch {
			case err == nil:
				err = f.settleLocked(index, int64(len(data)))
			case errors.Is(err, api.ErrChunkTooLarge):
				// Refused before it was held: the version is cut in chunks
				// this reader does not take.
				err = f.layoutErrorf("chunk %d holds more than %d bytes", index, f.maxSize)
			}
			if err != nil {
				// A failed download is not kept: the next read asks again.
				f.failed = index
				for i := range f.slots {
					if f.slots[i] == c {
						f.slots[i] = nil
					}
				}
				f.freedLocked()
			} else {
				c.data = data
				if f.failed == index {
					f.failed = -1
				}
			}
		}
		c.err = err
		f.mu.Unlock()
		close(c.done)
	}()

	return c
}
