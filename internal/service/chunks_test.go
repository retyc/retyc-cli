package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

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
