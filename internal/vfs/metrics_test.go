package vfs

import (
	"bytes"
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/retyc/retyc-cli/internal/metrics"
)

// retyc_cli_vfs_spool_bytes follows what the spool files hold: nothing for a
// version not brought in yet, the size of the file once it is, nothing once
// the spool is closed.
func TestSpoolBytesGauge(t *testing.T) {
	base := testutil.ToFloat64(metrics.VFSSpoolBytes)
	held := func() float64 { return testutil.ToFloat64(metrics.VFSSpoolBytes) - base }

	// A new file: what was written, then what a truncation leaves.
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, testData(100), 0)
	if got := held(); got != 100 {
		t.Errorf("after a write of 100 bytes: %v", got)
	}
	if err := s.Truncate(40); err != nil {
		t.Fatal(err)
	}
	if got := held(); got != 40 {
		t.Errorf("after a truncation to 40 bytes: %v", got)
	}

	// An existing file: nothing until its version is copied in.
	_, lazy, _, _ := existingSpool(t, 18, false)
	if got := held(); got != 40 {
		t.Errorf("with a second spool opened and not read: %v, want 40", got)
	}
	_ = spoolContent(t, lazy)
	if got := held(); got != 58 {
		t.Errorf("once the version of 18 bytes is in: %v, want 58", got)
	}

	if err := lazy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := held(); got != 0 {
		t.Errorf("with every spool closed: %v, want 0", got)
	}
}

// retyc_cli_vfs_uploads_total counts each upload once, a Flush like a Create,
// by its outcome; a Flush with nothing to send is not one.
func TestUploadsCounter(t *testing.T) {
	ok := testutil.ToFloat64(metrics.VFSUploads.WithLabelValues("ok"))
	failed := testutil.ToFloat64(metrics.VFSUploads.WithLabelValues("error"))

	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, testData(10), 0)
	mustFlush(t, s)
	mustFlush(t, s) // clean: nothing sent
	if _, err := fs.Create(context.Background(), "dr1", "/other.txt", 0, s.ModTime(), bytes.NewReader(nil)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := testutil.ToFloat64(metrics.VFSUploads.WithLabelValues("ok")) - ok; got != 2 {
		t.Errorf("uploads ok moved by %v, want 2", got)
	}

	// The dataroom root is not a file.
	if _, err := fs.Create(context.Background(), "dr1", "/", 0, s.ModTime(), bytes.NewReader(nil)); err == nil {
		t.Fatal("Create at the root succeeded")
	}
	if got := testutil.ToFloat64(metrics.VFSUploads.WithLabelValues("error")) - failed; got != 1 {
		t.Errorf("uploads error moved by %v, want 1", got)
	}
}
