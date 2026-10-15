//go:build linux

package retycfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/retyc/retyc-cli/internal/metrics"
)

// lockingMount mounts the sample tree with Options.MirrorLocks.
func lockingMount(t *testing.T, mirror bool) (*mounted, *fakeDataroom) {
	t.Helper()
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	opts := single("dr1")
	opts.driver.MirrorLocks = mirror

	return mountFS(t, a, opts), dr
}

// An existing file opened for writing is locked at the API for as long as a
// handle opened for writing is open on it: one lock for the inode, whatever
// the number of handles, released with the last of them, after its flush.
func TestMirrorLocks_OneLockPerInode(t *testing.T) {
	m, dr := lockingMount(t, true)
	path := filepath.Join(m.dir, "hello.txt")
	held := testutil.ToFloat64(metrics.LocksHeld)

	first, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if n, locks := m.api.count("lock"), m.tree.Locks().Held(); n != 1 || locks != 1 {
		t.Fatalf("after the first open: %d lock requests, %d held; want 1 and 1", n, locks)
	}
	if got := testutil.ToFloat64(metrics.LocksHeld) - held; got != 1 {
		t.Errorf("retycfs_locks_held moved by %v, want 1", got)
	}

	// A second handle for writing shares the lock; one for reading takes none.
	second, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	reader, err := os.Open(path) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if n := m.api.count("lock"); n != 1 {
		t.Errorf("%d lock requests with three handles open, want 1", n)
	}

	if _, err := first.WriteAt([]byte("J"), 0); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The release of a handle comes after its close(2): give it the time it
	// would take to release the lock by mistake.
	time.Sleep(200 * time.Millisecond)
	if n, locks := m.api.count("unlock"), m.api.locksHeld(); n != 0 || locks != 1 {
		t.Fatalf("with one writer left: %d unlock requests, %d locks at the API; want 0 and 1", n, locks)
	}

	if err := second.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	eventually(t, "the lock to be released", func() bool { return m.api.locksHeld() == 0 })
	if n, locks := m.api.count("unlock"), m.tree.Locks().Held(); n != 1 || locks != 0 {
		t.Errorf("after the last close: %d unlock requests, %d held; want 1 and 0", n, locks)
	}
	if got := testutil.ToFloat64(metrics.LocksHeld) - held; got != 0 {
		t.Errorf("retycfs_locks_held is off by %v once released", got)
	}
	m.wantFile(t, dr, "", "hello.txt", []byte("Jello"))

	// The next open for writing takes a new lock.
	writeFile(t, path, []byte("again"))
	m.settle(t)
	eventually(t, "the second lock to be released", func() bool { return m.api.locksHeld() == 0 })
	if n := m.api.count("lock"); n != 2 {
		t.Errorf("%d lock requests after a second open, want 2", n)
	}
}

// A file another client holds answers EBUSY to open(2), before anything is
// truncated; a read is not concerned.
func TestMirrorLocks_LockedElsewhere(t *testing.T) {
	m, dr := lockingMount(t, true)
	path := filepath.Join(m.dir, "hello.txt")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	m.api.mu.Lock()
	m.api.lockedElsewhere[m.api.datarooms["dr1"].children[""]["hello.txt"].id] = true
	m.api.mu.Unlock()

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // G304: a file of the test's mount
	if err == nil {
		_ = f.Close()
	}
	if !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("open for writing = %v, want EBUSY", err)
	}
	m.settle(t)
	if locks := m.tree.Locks().Held(); locks != 0 {
		t.Errorf("%d locks held after a refusal", locks)
	}
	if got, err := readFile(path); err != nil || string(got) != "hello" {
		t.Errorf("read of a file locked elsewhere = %q, %v; want its content", got, err)
	}
	if got := stored(t, m.api, dr, "", "hello.txt"); string(got) != "hello" {
		t.Errorf("the API holds %q after a refused O_TRUNC, want the file untouched", got)
	}

	// Unlocked there, it opens.
	m.api.mu.Lock()
	clear(m.api.lockedElsewhere)
	m.api.mu.Unlock()
	writeFile(t, path, []byte("mine"))
	m.wantFile(t, dr, "", "hello.txt", []byte("mine"))
}

// A file created through the mount has no node to lock; without the option
// nothing is ever locked.
func TestMirrorLocks_PendingAndDisabled(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		m, dr := lockingMount(t, true)
		writeFile(t, filepath.Join(m.dir, "new.txt"), []byte("new"))
		m.wantFile(t, dr, "", "new.txt", []byte("new"))
		if n := m.api.count("lock"); n != 0 {
			t.Errorf("%d lock requests for a file created here, want none", n)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		m, dr := lockingMount(t, false)
		writeFile(t, filepath.Join(m.dir, "hello.txt"), []byte("bye"))
		m.wantFile(t, dr, "", "hello.txt", []byte("bye"))
		if n := m.api.count("lock"); n != 0 {
			t.Errorf("%d lock requests without MirrorLocks, want none", n)
		}
		if m.srv.locksDone != nil {
			t.Error("the lock renewal runs without MirrorLocks")
		}
	})
}

// The locks still held when the filesystem is unmounted (a handle the kernel
// never released) are released by the mount before Unmount returns. The lock
// is taken here as the open of such a handle takes it: the mount point must
// not be busy for the test to unmount it.
func TestMirrorLocks_ReleasedAtUnmount(t *testing.T) {
	m, _ := lockingMount(t, true)
	if _, err := os.Stat(filepath.Join(m.dir, "hello.txt")); err != nil {
		t.Fatal(err)
	}
	m.api.mu.Lock()
	nodeID := m.api.datarooms["dr1"].children[""]["hello.txt"].id
	m.api.mu.Unlock()
	if err := m.tree.Locks().Take(context.Background(), "fuse:left", nodeID, "node "+nodeID, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if locks := m.api.locksHeld(); locks != 1 {
		t.Fatalf("%d locks at the API, want 1", locks)
	}

	if err := m.srv.Unmount(); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	if held, locks := m.tree.Locks().Held(), m.api.locksHeld(); held != 0 || locks != 0 {
		t.Errorf("after the unmount: %d held, %d at the API; want none", held, locks)
	}
}

// The operations feed retycfs_*: one count per operation and result,
// the bytes read and written, the handles open by kind.
func TestMetrics_FuseOperations(t *testing.T) {
	m, _ := lockingMount(t, false)
	path := filepath.Join(m.dir, "hello.txt")
	opens := testutil.ToFloat64(metrics.Ops.WithLabelValues("open", "ok"))
	missing := testutil.ToFloat64(metrics.Ops.WithLabelValues("lookup", "ENOENT"))
	read := testutil.ToFloat64(metrics.Bytes.WithLabelValues("read"))
	written := testutil.ToFloat64(metrics.Bytes.WithLabelValues("write"))
	readers := testutil.ToFloat64(metrics.OpenHandles.WithLabelValues("read"))
	writers := testutil.ToFloat64(metrics.OpenHandles.WithLabelValues("write"))

	if _, err := os.Stat(filepath.Join(m.dir, "nothing-here")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat of a missing name = %v", err)
	}
	if got := testutil.ToFloat64(metrics.Ops.WithLabelValues("lookup", "ENOENT")) - missing; got < 1 {
		t.Errorf("lookup/ENOENT moved by %v, want at least 1", got)
	}

	r, err := os.Open(path) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, _ := r.Read(buf); n != 5 {
		t.Fatalf("read %d bytes, want 5", n)
	}
	if got := testutil.ToFloat64(metrics.OpenHandles.WithLabelValues("read")) - readers; got != 1 {
		t.Errorf("open read handles moved by %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.Bytes.WithLabelValues("read")) - read; got != 5 {
		t.Errorf("bytes read moved by %v, want 5", got)
	}
	_ = r.Close()

	w, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("seven b")); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.OpenHandles.WithLabelValues("write")) - writers; got != 1 {
		t.Errorf("open write handles moved by %v, want 1", got)
	}
	_ = w.Close()
	m.settle(t)

	if got := testutil.ToFloat64(metrics.Bytes.WithLabelValues("write")) - written; got != 7 {
		t.Errorf("bytes written moved by %v, want 7", got)
	}
	if got := testutil.ToFloat64(metrics.Ops.WithLabelValues("open", "ok")) - opens; got != 2 {
		t.Errorf("open/ok moved by %v, want 2", got)
	}
	eventually(t, "the handles to be released", func() bool {
		return testutil.ToFloat64(metrics.OpenHandles.WithLabelValues("read")) == readers &&
			testutil.ToFloat64(metrics.OpenHandles.WithLabelValues("write")) == writers
	})
	if n := testutil.CollectAndCount(metrics.OpDuration); n == 0 {
		t.Error("no operation duration observed")
	}
}

// An errno the driver has no name for does not grow the label set.
func TestResultLabel(t *testing.T) {
	for errno, want := range map[syscall.Errno]string{0: "ok", syscall.ENOENT: "ENOENT", syscall.EMLINK: "other"} {
		if got := resultLabel(errno); got != want {
			t.Errorf("resultLabel(%d) = %q, want %q", errno, got, want)
		}
	}
}
