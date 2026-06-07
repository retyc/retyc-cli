package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/crypto"
)

// TestUploadChunks_ProgressConcurrency verifies that the progress callback is invoked
// correctly under concurrent uploads. Run with -race to detect data races.
func TestUploadChunks_ProgressConcurrency(t *testing.T) {
	data := make([]byte, UploadChunkSize*3+1024) // 3 full + 1 partial = 4 chunks
	f := writeTempFile(t, data)
	defer f.Close() //nolint:errcheck

	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	var progressCalls atomic.Int64
	progress := func(_ string, _ int, _ int64) {
		progressCalls.Add(1)
	}

	uploadFn := func(_ context.Context, _ int, _ []byte) error { return nil }

	err = UploadChunks(
		context.Background(), f, int64(len(data)), "test.bin", identity.Recipient().String(), progress, uploadFn,
	)
	if err != nil {
		t.Fatalf("UploadChunks: %v", err)
	}

	if got := progressCalls.Load(); got != 4 {
		t.Errorf("progress calls = %d, want 4", got)
	}
}

// TestUploadChunks_ErrorCancelsWorkers verifies that a worker error stops the upload.
func TestUploadChunks_ErrorCancelsWorkers(t *testing.T) {
	data := make([]byte, UploadChunkSize*4)
	f := writeTempFile(t, data)
	defer f.Close() //nolint:errcheck

	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	var uploaded atomic.Int64
	uploadFn := func(_ context.Context, chunkID int, _ []byte) error {
		if chunkID == 1 {
			return fmt.Errorf("simulated network error")
		}
		uploaded.Add(1)

		return nil
	}

	if err := UploadChunks(
		context.Background(), f, int64(len(data)), "test.bin", identity.Recipient().String(), nil, uploadFn,
	); err == nil {
		t.Fatal("expected error, got nil")
	}

	if n := uploaded.Load(); n >= 4 {
		t.Errorf("uploaded %d chunks, want fewer than 4 after error on chunk 1", n)
	}
}

// TestDownloadChunks_PartialFileCleanup verifies that no file remains after a failed download.
func TestDownloadChunks_PartialFileCleanup(t *testing.T) {
	dir := t.TempDir()
	name := "output.bin"

	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	downloadFn := func(_ context.Context, _ int) ([]byte, error) {
		return nil, fmt.Errorf("simulated download error")
	}

	if err := DownloadChunks(context.Background(), dir, name, 1024, 2, identity, nil, downloadFn); err == nil {
		t.Fatal("expected error, got nil")
	}

	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Errorf("final file should not exist after failed download")
	}
	if _, err := os.Stat(filepath.Join(dir, name+".part")); !os.IsNotExist(err) {
		t.Errorf(".part file should have been cleaned up after failure")
	}
}

// TestDownloadChunks_RetryAfterFailure verifies that a second attempt succeeds even
// after the first one failed (no stale .part file blocking).
func TestDownloadChunks_RetryAfterFailure(t *testing.T) {
	dir := t.TempDir()
	name := "output.bin"

	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	// First attempt always fails.
	failFn := func(_ context.Context, _ int) ([]byte, error) {
		return nil, fmt.Errorf("first attempt fails")
	}
	_ = DownloadChunks(context.Background(), dir, name, 16, 1, identity, nil, failFn)

	// Second attempt returns valid encrypted data.
	plain := make([]byte, 16)
	enc, err := crypto.EncryptBinaryForKey(plain, identity.Recipient().String())
	if err != nil {
		t.Fatalf("encrypting test chunk: %v", err)
	}
	successFn := func(_ context.Context, _ int) ([]byte, error) { return enc, nil }

	if err := DownloadChunks(context.Background(), dir, name, int64(len(plain)), 1, identity, nil, successFn); err != nil {
		t.Fatalf("second attempt failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Errorf("output file missing after successful retry: %v", err)
	}
}

// TestUploadChunks_ReaderInterface verifies that 2 full + 1 partial chunk
// are uploaded and that the concatenated plaintext matches the original data.
func TestUploadChunks_ReaderInterface(t *testing.T) {
	data := make([]byte, UploadChunkSize*2+1024)
	for i := range data {
		data[i] = byte(i % 251)
	}

	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	var mu sync.Mutex
	received := make(map[int][]byte)

	uploadFn := func(_ context.Context, chunkID int, encData []byte) error {
		plain, decErr := crypto.DecryptBinary(encData, identity)
		if decErr != nil {
			return decErr
		}
		mu.Lock()
		received[chunkID] = plain
		mu.Unlock()

		return nil
	}

	err = UploadChunks(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)), "test.bin",
		identity.Recipient().String(),
		nil,
		uploadFn,
	)
	if err != nil {
		t.Fatalf("UploadChunks: %v", err)
	}
	if len(received) != 3 {
		t.Fatalf("got %d chunks, want 3", len(received))
	}
	var got []byte
	for i := 0; i < 3; i++ {
		got = append(got, received[i]...)
	}
	if !bytes.Equal(got, data) {
		t.Error("reassembled data does not match original")
	}
}

// TestUploadChunks_ReaderErrorPropagation verifies that an uploadFn error is returned.
func TestUploadChunks_ReaderErrorPropagation(t *testing.T) {
	data := make([]byte, UploadChunkSize*3)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	uploadFn := func(_ context.Context, chunkID int, _ []byte) error {
		if chunkID == 1 {
			return fmt.Errorf("simulated error on chunk 1")
		}

		return nil
	}

	if err := UploadChunks(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)), "test.bin",
		identity.Recipient().String(),
		nil,
		uploadFn,
	); err == nil {
		t.Fatal("expected error from uploadFn, got nil")
	}
}

// TestStreamDownloadChunks_InOrder verifies that chunks are decrypted and written
// in order even when the download function returns them out of order.
func TestStreamDownloadChunks_InOrder(t *testing.T) {
	// 3 chunks of 16 bytes each
	const chunkCount = 3
	plain := [][]byte{
		bytes.Repeat([]byte{1}, 16),
		bytes.Repeat([]byte{2}, 16),
		bytes.Repeat([]byte{3}, 16),
	}
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	encrypted := make([][]byte, chunkCount)
	for i, p := range plain {
		enc, err := crypto.EncryptBinaryForKey(p, identity.Recipient().String())
		if err != nil {
			t.Fatalf("encrypting chunk %d: %v", i, err)
		}
		encrypted[i] = enc
	}

	downloadFn := func(_ context.Context, chunkID int) ([]byte, error) {
		return encrypted[chunkID], nil
	}

	var buf bytes.Buffer
	if err := StreamDownloadChunks(context.Background(), &buf, 48, chunkCount, identity, nil, downloadFn); err != nil {
		t.Fatalf("StreamDownloadChunks: %v", err)
	}

	want := append(append(plain[0], plain[1]...), plain[2]...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Error("output data does not match expected order")
	}
}

// TestStreamDownloadChunks_ErrorPropagation verifies that a downloadFn error is returned.
func TestStreamDownloadChunks_ErrorPropagation(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	downloadFn := func(_ context.Context, _ int) ([]byte, error) {
		return nil, fmt.Errorf("simulated download error")
	}
	var buf bytes.Buffer
	if err := StreamDownloadChunks(context.Background(), &buf, 16, 1, identity, nil, downloadFn); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestStreamDownloadChunks_EmptyFile verifies that a zero-chunk download writes
// nothing and returns nil (no panic on the concurrency clamp).
func TestStreamDownloadChunks_EmptyFile(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	called := false
	downloadFn := func(_ context.Context, _ int) ([]byte, error) {
		called = true

		return nil, fmt.Errorf("should not be called for 0 chunks")
	}
	var buf bytes.Buffer
	if err := StreamDownloadChunks(context.Background(), &buf, 0, 0, identity, nil, downloadFn); err != nil {
		t.Fatalf("StreamDownloadChunks(0 chunks): %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("output = %d bytes, want 0", buf.Len())
	}
	if called {
		t.Error("downloadFn was called for a 0-chunk file")
	}
}

// TestStreamDownloadChunks_ManyChunksInOrder exercises the bounded reorder window:
// many chunks delivered with the lowest index returning last must still be written
// in order without deadlocking.
func TestStreamDownloadChunks_ManyChunksInOrder(t *testing.T) {
	const chunkCount = 40
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}
	encrypted := make([][]byte, chunkCount)
	for i := 0; i < chunkCount; i++ {
		enc, encErr := crypto.EncryptBinaryForKey([]byte{byte(i)}, identity.Recipient().String())
		if encErr != nil {
			t.Fatalf("encrypting chunk %d: %v", i, encErr)
		}
		encrypted[i] = enc
	}

	// Delay chunk 0 so workers race ahead and must buffer under the window cap.
	downloadFn := func(_ context.Context, chunkID int) ([]byte, error) {
		if chunkID == 0 {
			time.Sleep(50 * time.Millisecond)
		}

		return encrypted[chunkID], nil
	}

	var buf bytes.Buffer
	if err := StreamDownloadChunks(
		context.Background(), &buf, chunkCount, chunkCount, identity, nil, downloadFn,
	); err != nil {
		t.Fatalf("StreamDownloadChunks: %v", err)
	}
	got := buf.Bytes()
	if len(got) != chunkCount {
		t.Fatalf("output = %d bytes, want %d", len(got), chunkCount)
	}
	for i := 0; i < chunkCount; i++ {
		if got[i] != byte(i) {
			t.Fatalf("byte %d = %d, want %d (out of order)", i, got[i], i)
		}
	}
}

func writeTempFile(t *testing.T, content []byte) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "chunk-test-*")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seeking: %v", err)
	}

	return f
}
