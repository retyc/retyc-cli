package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/ui"
	"go.opentelemetry.io/otel/trace"
)

const (
	// UploadChunkSize is the plaintext size of each chunk this CLI uploads,
	// before encryption. It says nothing of the versions it downloads: the
	// chunk size is chosen by the client that uploaded a version (the web
	// application has its own setting, a copy keeps the cut of its source).
	UploadChunkSize = 8 * 1024 * 1024 // 8 MB

	// SmallUploadMaxSize is the largest plaintext a file may hold to be sent
	// through the single-request route (POST /dataroom/{id}/node/file, see
	// UploadSmallFile): one chunk, whose request the proxy bounds like the
	// chunk upload route (32 MiB for the whole body, the encrypted chunk plus
	// the multipart envelope). A larger file goes through a version and its
	// chunks. A proxy that still refuses it (413) gets it through the chunks
	// (uploadSmallFileChunked).
	SmallUploadMaxSize = UploadChunkSize
)

// ChunkCount is the number of chunks UploadChunks sends for fileSize bytes (none
// for an empty file). A dataroom version announces it when it is created
// (chunk_count_expected), before a single byte is read.
func ChunkCount(fileSize int64) int {
	if fileSize <= 0 {
		return 0
	}

	// Ceiling without the usual "+ size - 1", which would overflow for a size
	// near MaxInt64 — reachable from a client-supplied WebDAV Content-Length.
	return int((fileSize-1)/UploadChunkSize + 1)
}

// UploadChunks reads r in UploadChunkSize chunks, encrypts each with sessionPubKey,
// and calls uploadFn for each encrypted chunk using up to api.concurrency.upload
// concurrent goroutines (see SetConcurrency). An internal context is cancelled as soon as the first error is detected,
// stopping all in-flight workers promptly. progress is called (if non-nil) after each
// chunk is successfully uploaded.
//
// r must yield exactly fileSize bytes, so that exactly ChunkCount(fileSize) chunks
// are sent: the dataroom API rejects a chunk index beyond the count announced at
// version creation, and a chunk it already stored cannot be sent again. A source
// that grows past fileSize (a local file appended to mid-upload) fails before
// the extra chunk is sent; one that ends early fails once the last chunk is in.
func UploadChunks(
	ctx context.Context,
	r io.Reader,
	fileSize int64,
	displayName string,
	sessionPubKey string,
	progress ProgressFn,
	uploadFn func(ctx context.Context, chunkID int, data []byte) error,
) error {
	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, Concurrency().Upload)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)

	setErr := func(e error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = e
			cancel() // stop all in-flight workers
		}
		mu.Unlock()
	}
	hasErr := func() bool {
		mu.Lock()
		defer mu.Unlock()

		return firstErr != nil
	}

	buf := make([]byte, UploadChunkSize)
	var total int64
readLoop:
	for chunkID := 0; ; chunkID++ {
		if hasErr() {
			break
		}

		n, readErr := io.ReadFull(r, buf)
		total += int64(n)
		if total > fileSize {
			setErr(fmt.Errorf("source is larger than its declared %d bytes", fileSize))

			break
		}
		if n > 0 {
			encrypted, encErr := encryptChunk(ctx, chunkID, buf[:n], sessionPubKey)
			if encErr != nil {
				setErr(fmt.Errorf("encrypting chunk %d: %w", chunkID, encErr))

				break
			}

			select {
			case sem <- struct{}{}:
			case <-innerCtx.Done():
				setErr(innerCtx.Err())

				break readLoop // a bare break would only exit the select
			}
			if hasErr() {
				break
			}

			id, enc, sz := chunkID, encrypted, n
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if err := uploadFn(innerCtx, id, enc); err != nil {
					setErr(fmt.Errorf("uploading chunk %d: %w", id, err))

					return
				}
				if progress != nil {
					progress(displayName, sz, fileSize)
				}
			}()
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			setErr(fmt.Errorf("reading file: %w", readErr))

			break
		}
	}

	wg.Wait()
	if firstErr == nil && total < fileSize {
		return fmt.Errorf("source ended after %d of its declared %d bytes", total, fileSize)
	}

	return firstErr
}

// encryptChunk encrypts one chunk for the session key, under a short
// crypto.encrypt span of the caller's span: index and size only, never the
// file name.
func encryptChunk(ctx context.Context, chunkID int, plain []byte, sessionPubKey string) ([]byte, error) {
	_, span := telemetry.Tracer().Start(ctx, "crypto.encrypt", trace.WithAttributes(
		telemetry.AttrChunkIndex.Int(chunkID), telemetry.AttrChunkPlaintextBytes.Int(len(plain))))
	start := time.Now()
	encrypted, err := crypto.EncryptBinaryForKey(plain, sessionPubKey)
	metrics.CryptoDuration.WithLabelValues("encrypt").Observe(time.Since(start).Seconds())
	telemetry.RecordError(span, err)
	span.End()

	return encrypted, err
}

// decryptChunk decrypts one chunk with identity, under a short crypto.decrypt
// span of the caller's span: index and encrypted size only, never the file
// name.
func decryptChunk(ctx context.Context, chunkID int, encrypted []byte, identity *age.HybridIdentity) ([]byte, error) {
	_, span := telemetry.Tracer().Start(ctx, "crypto.decrypt", trace.WithAttributes(
		telemetry.AttrChunkIndex.Int(chunkID), telemetry.AttrChunkCiphertextBytes.Int(len(encrypted))))
	start := time.Now()
	plaintext, err := crypto.DecryptBinary(encrypted, identity)
	metrics.CryptoDuration.WithLabelValues("decrypt").Observe(time.Since(start).Seconds())
	telemetry.RecordError(span, err)
	span.End()

	return plaintext, err
}

// ReadDataroomChunk downloads the chunk at index of a dataroom file version
// and returns it decrypted: as many bytes as the client that uploaded the
// version put in a chunk (UploadChunkSize for this CLI, not for every
// client), fewer for the last chunk of the file. The caller works out which
// index holds an offset (see vfs.File). It is the positioned counterpart of
// StreamDownloadChunks, with the
// same crypto.decrypt span and metric per chunk, and the download behind it
// waits for a chunk the store does not hold yet the same way
// (api.ErrChunkMissing once the retries are spent). Errors wrap their cause,
// so api.ErrChunkMissing, api.ErrRateLimited and a cancellation stay matchable
// with errors.Is. Nothing is kept: a caller that reads the same chunk twice
// downloads it twice.
func ReadDataroomChunk(
	ctx context.Context, client *api.Client, versionID string, index int, identity *age.HybridIdentity,
) ([]byte, error) {
	return readDataroomChunk(ctx, client, versionID, index, identity, 0)
}

// ReadDataroomChunkBounded is ReadDataroomChunk for a caller that holds
// chunks in memory and refuses those of more than maxPlain plaintext bytes:
// the download is bounded by what such a chunk makes once encrypted for the
// session, so a larger one fails with api.ErrChunkTooLarge before its body is
// read (or, when the API announces no length, once the bound is passed),
// neither held nor decrypted.
func ReadDataroomChunkBounded(
	ctx context.Context, client *api.Client, versionID string, index int, sess *DataroomSession, maxPlain int64,
) ([]byte, error) {
	envelope, err := sess.chunkEnvelope()
	if err != nil {
		// No measure of the header: allow a generous one rather than refuse
		// every chunk. The decryption that follows needs the same key.
		envelope = unmeasuredEnvelopeMax
	}

	return readDataroomChunk(ctx, client, versionID, index, sess.Identity, encryptedChunkSize(maxPlain, envelope))
}

func readDataroomChunk(
	ctx context.Context, client *api.Client, versionID string, index int, identity *age.HybridIdentity, limit int64,
) ([]byte, error) {
	encrypted, err := client.DownloadDataroomChunkLimit(ctx, versionID, index, limit)
	if err != nil {
		return nil, fmt.Errorf("downloading chunk %d: %w", index, err)
	}
	plaintext, err := decryptChunk(ctx, index, encrypted, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting chunk %d: %w", index, err)
	}

	return plaintext, nil
}

// The AGE payload format (STREAM): after the header and a 16-byte nonce, the
// plaintext goes in segments of 64 KiB, each followed by a 16-byte tag. The
// last segment may be short, and is empty only when the plaintext is: an
// empty plaintext still makes one segment, its tag alone.
const (
	ageStreamNonce   = 16
	ageStreamSegment = 64 << 10
	ageStreamTag     = 16
)

// unmeasuredEnvelopeMax stands in for an envelope that could not be measured
// where only an upper bound is needed.
const unmeasuredEnvelopeMax = 64 << 10

// chunkEnvelope is the number of bytes a chunk encrypted for a session holds
// before its segments: the AGE header and the nonce. The header depends on
// the recipient alone (one stanza of fixed length for the hybrid
// post-quantum key of a session, 1627 bytes when this was written), so it is
// measured, once per session, by encrypting nothing — never written down.
type chunkEnvelope struct {
	once sync.Once
	size int64
	err  error
}

// chunkEnvelope measures, on first use, the envelope of the chunks encrypted
// for the session key.
func (s *dataroomSession) chunkEnvelope() (int64, error) {
	e := &s.envelope
	e.once.Do(func() {
		publicKey := s.PublicKey
		if s.Identity != nil {
			publicKey = s.Identity.Recipient().String()
		}
		empty, err := crypto.EncryptBinaryForKey(nil, publicKey)
		if err != nil {
			e.err = fmt.Errorf("measuring the AGE header of a chunk: %w", err)

			return
		}
		// An empty plaintext is the envelope and one tag.
		e.size = int64(len(empty)) - ageStreamTag
	})

	return e.size, e.err
}

// encryptedChunkSize returns the size of a chunk of plain plaintext bytes
// once encrypted under an envelope of envelope bytes.
func encryptedChunkSize(plain, envelope int64) int64 {
	segments := max(1, (plain+ageStreamSegment-1)/ageStreamSegment)

	return envelope + plain + segments*ageStreamTag
}

// plainChunkSize is the inverse of encryptedChunkSize: the number of
// plaintext bytes of a chunk of encrypted bytes, false when no plaintext
// encrypts to that size under this envelope.
func plainChunkSize(encrypted, envelope int64) (int64, bool) {
	payload := encrypted - envelope
	if payload < ageStreamTag {
		return 0, false
	}
	// Every segment is full bar the last, so the payload tells their number.
	segments := (payload + ageStreamSegment + ageStreamTag - 1) / (ageStreamSegment + ageStreamTag)
	plain := payload - segments*ageStreamTag
	if encryptedChunkSize(plain, envelope) != encrypted {
		return 0, false
	}

	return plain, true
}

// DataroomChunkPlainSize returns the number of plaintext bytes of the chunk at
// index of a dataroom file version without downloading it: the API tells the
// size of the chunk as stored (api.Client.DataroomChunkEncryptedSize, one
// HEAD), and what encryption for the session adds is known (chunkEnvelope,
// the AGE segments). For chunk 0 of a version of several chunks that is the
// chunk size the version was cut at.
//
// The call costs the API a request to its object store: callers keep the
// answer, a version never changes. Errors are those of the API, wrapped; the
// error matches api.ErrNoChunkSize when the API has no such route, or answers
// a size no chunk encrypted for this session has (another recipient, a proxy
// rewriting the length): the caller then works the size out otherwise.
func DataroomChunkPlainSize(
	ctx context.Context, client *api.Client, versionID string, index int, sess *DataroomSession,
) (int64, error) {
	envelope, err := sess.chunkEnvelope()
	if err != nil {
		return 0, fmt.Errorf("%w: %w", api.ErrNoChunkSize, err)
	}
	encrypted, err := client.DataroomChunkEncryptedSize(ctx, versionID, index)
	if err != nil {
		return 0, fmt.Errorf("size of chunk %d: %w", index, err)
	}
	plain, ok := plainChunkSize(encrypted, envelope)
	if !ok {
		return 0, fmt.Errorf("%w: chunk %d is stored in %d bytes, which no chunk encrypted for this dataroom makes",
			api.ErrNoChunkSize, index, encrypted)
	}

	return plain, nil
}

// StreamDownloadChunks downloads chunkCount chunks concurrently via downloadFn,
// decrypts each with identity, and writes them in order to w. No output directory
// or file naming is required — suitable for streaming to an io.Writer.
// progress is called (if non-nil) after each chunk is written.
func StreamDownloadChunks(
	ctx context.Context,
	w io.Writer,
	originalSize int64,
	chunkCount int,
	identity *age.HybridIdentity,
	progress ProgressFn,
	downloadFn func(ctx context.Context, chunkID int) ([]byte, error),
) error {
	type chunkResult struct {
		id   int
		data []byte
		err  error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	concurrency := min(Concurrency().Download, chunkCount)
	if concurrency < 1 {
		// Nothing to download (empty file, or a malformed negative chunkCount).
		return nil
	}

	// slots bounds how many chunks may be in flight or buffered for reordering at
	// once. Without it, a slow low-index chunk lets the workers race ahead and
	// accumulate the whole (decrypted) file in the reorder map — unacceptable for a
	// long-running streaming server. A slot is taken at dispatch and released once
	// the chunk has been written in order, so peak memory is bounded to `window`
	// decrypted chunks regardless of file size.
	window := concurrency * 2

	jobs := make(chan int, concurrency)
	results := make(chan chunkResult, concurrency*2)
	slots := make(chan struct{}, window)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				encrypted, err := downloadFn(ctx, id)
				if err != nil {
					results <- chunkResult{id: id, err: fmt.Errorf("downloading chunk %d: %w", id, err)}

					return
				}
				// One short span per chunk under the caller's span (workers share
				// ctx).
				plaintext, err := decryptChunk(ctx, id, encrypted, identity)
				if err != nil {
					results <- chunkResult{id: id, err: fmt.Errorf("decrypting chunk %d: %w", id, err)}

					return
				}
				results <- chunkResult{id: id, data: plaintext}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := 0; i < chunkCount; i++ {
			// Acquire a window slot before dispatching so production cannot run
			// arbitrarily far ahead of the in-order writer. The slot at index
			// nextWrite is always already dispatched, so this never deadlocks.
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	reorder := make(map[int][]byte)
	nextWrite := 0

	for r := range results {
		if r.err != nil {
			cancel()
			for range results {
			}

			return r.err
		}
		reorder[r.id] = r.data

		for {
			data, ok := reorder[nextWrite]
			if !ok {
				break
			}
			if _, err := w.Write(data); err != nil {
				cancel()
				for range results {
				}

				return fmt.Errorf("writing chunk %d: %w", nextWrite, err)
			}
			if progress != nil {
				progress("", len(data), originalSize)
			}
			delete(reorder, nextWrite)
			nextWrite++
			<-slots // release the slot now that this chunk is written
		}
	}

	return nil
}

// ErrFileExists is returned by DownloadChunks when the destination file is
// already present: nothing is overwritten.
var ErrFileExists = errors.New("file already exists")

// localFileName is the on-disk name of a downloaded file: the base of its
// decrypted name, with control and format characters replaced so a name
// chosen by the sender cannot plant escape sequences in a directory listing,
// and never a name that designates the directory itself. It is idempotent,
// so DownloadChunks can apply it again to a name its caller already mapped.
func localFileName(name string) string {
	base := ui.FileName(filepath.Base(name))
	switch base {
	case ".", "..", string(filepath.Separator):
		return "_"
	}

	return base
}

// localFileNames maps the decrypted names of files downloaded into the same
// directory to distinct on-disk names. localFileName is many-to-one ("a_"
// and "a\x1b" both give "a_", and a transfer may hold two "report.pdf"): a
// collision would otherwise stop the download halfway on ErrFileExists. The
// later duplicates are suffixed ("a_ (2)") the way the admin export does.
func localFileNames(names []string) []string {
	taken := make(map[string]bool, len(names))
	local := make([]string, len(names))
	for i, name := range names {
		local[i] = uniqueSiblingName(taken, "", localFileName(name))
	}

	return local
}

// DownloadChunks downloads chunkCount chunks concurrently via downloadFn, decrypts each
// with identity, and writes them in order to outputDir/name. A .part suffix is used
// during the download; on success the file is atomically renamed to its final name. On
// any error the .part file is removed, so retries always start from a clean state.
// progress is called (if non-nil) after each chunk is written to disk.
func DownloadChunks(
	ctx context.Context,
	outputDir string,
	name string,
	originalSize int64,
	chunkCount int,
	identity *age.HybridIdentity,
	progress ProgressFn,
	downloadFn func(ctx context.Context, chunkID int) ([]byte, error),
) (retErr error) {
	dest := filepath.Join(outputDir, localFileName(name))
	partDest := dest + ".part"

	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%w: %s", ErrFileExists, dest)
	}

	//nolint:gosec // G304: dest is validated outputDir + sanitised base filename
	out, err := os.OpenFile(partDest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	// On any error: close and remove the partial file.
	// On success: close then atomically rename to final dest.
	defer func() {
		_ = out.Close()
		if retErr != nil {
			_ = os.Remove(partDest)

			return
		}
		if renameErr := os.Rename(partDest, dest); renameErr != nil {
			retErr = fmt.Errorf("finalizing download: %w", renameErr)
			_ = os.Remove(partDest)
		}
	}()

	// Delegate the concurrency logic to StreamDownloadChunks, writing to the .part file.
	streamProgress := progress
	if progress != nil {
		streamProgress = func(_ string, n int, total int64) {
			progress(name, n, total)
		}
	}

	return StreamDownloadChunks(ctx, out, originalSize, chunkCount, identity, streamProgress, downloadFn)
}
