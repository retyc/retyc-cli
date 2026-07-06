package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/crypto"
)

const (
	// UploadChunkSize is the plaintext size of each upload chunk before encryption.
	UploadChunkSize = 8 * 1024 * 1024 // 8 MB

	// UploadConcurrency is the number of chunks uploaded simultaneously per file.
	UploadConcurrency = 4

	// DownloadConcurrency is the number of chunks downloaded simultaneously per file.
	DownloadConcurrency = 4
)

// UploadChunks reads r in UploadChunkSize chunks, encrypts each with sessionPubKey,
// and calls uploadFn for each encrypted chunk using up to UploadConcurrency concurrent
// goroutines. An internal context is cancelled as soon as the first error is detected,
// stopping all in-flight workers promptly. progress is called (if non-nil) after each
// chunk is successfully uploaded.
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

	sem := make(chan struct{}, UploadConcurrency)
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
readLoop:
	for chunkID := 0; ; chunkID++ {
		if hasErr() {
			break
		}

		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			encrypted, encErr := crypto.EncryptBinaryForKey(buf[:n], sessionPubKey)
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

	return firstErr
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

	concurrency := DownloadConcurrency
	if chunkCount < concurrency {
		concurrency = chunkCount
	}
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
	window := DownloadConcurrency * 2

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
				plaintext, err := crypto.DecryptBinary(encrypted, identity)
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
	dest := filepath.Join(outputDir, filepath.Base(name))
	partDest := dest + ".part"

	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("file already exists: %s", dest)
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
