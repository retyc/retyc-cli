//go:build linux

package retycfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// wrapSpools puts wrap between the driver and the spools opened from now on,
// the way a test gets between the driver and vfs at a chosen instant.
func (m *mounted) wrapSpools(wrap func(vfs.Spool) vfs.Spool) {
	m.srv.drv.wrapSpool.Store(&wrap)
}

// calledFrom reports whether a function whose name ends with suffix is on the
// stack of the caller.
func calledFrom(suffix string) bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, suffix) {
			return true
		}
		if !more {
			return false
		}
	}
}

// crossedSpool is a spool whose first flush runs to its end right after an
// unlink has read that the API holds nothing of the file: the answer the
// unlink got is stale by the time it has it.
type crossedSpool struct {
	vfs.Spool
	// sp is the spool of the driver, set once the file is created: the
	// wrapper does nothing before.
	sp      atomic.Pointer[openSpool]
	crossed atomic.Bool
	// flushed receives what that flush returned.
	flushed chan error
}

func (c *crossedSpool) Node() (vfs.Node, bool) {
	node, exists := c.Spool.Node()
	sp := c.sp.Load()
	if sp != nil && !exists && calledFrom("(*dirNode).Unlink") && c.crossed.CompareAndSwap(false, true) {
		c.flushed <- sp.flush(context.Background())
	}

	return node, exists
}

// An unlink that finds a file pending while its first flush ends removes the
// node that flush created: answering 0 on what it first read would leave the
// file at the API.
func TestUnlink_PendingFileStoredMeanwhile(t *testing.T) {
	m, dr, _ := writable(t)
	crossed := &crossedSpool{flushed: make(chan error, 1)}
	m.wrapSpools(func(s vfs.Spool) vfs.Spool {
		crossed.Spool = s

		return crossed
	})
	path := filepath.Join(m.dir, "born.txt")
	f, err := create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("born"); err != nil {
		t.Fatal(err)
	}
	crossed.sp.Store(m.srv.drv.spools.open()[0])

	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}
	select {
	case err := <-crossed.flushed:
		if err != nil {
			t.Fatalf("the flush that crosses the unlink: %v", err)
		}
	default:
		t.Fatal("no flush crossed the unlink")
	}
	if m.api.node(dr, "", "born.txt") != nil {
		t.Error("rm answered 0 and the API still holds the file")
	}
	if _, err := os.Stat(path); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("stat after rm = %v, want ENOENT", err)
	}
	// What is written after the unlink is sent nowhere.
	if _, err := f.WriteString(" again"); err != nil {
		t.Errorf("write after the unlink: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	m.settle(t)
	if m.api.node(dr, "", "born.txt") != nil {
		t.Error("the file came back at the API")
	}
}

// heldSpool is a spool whose SetModTime waits to be let through.
type heldSpool struct {
	vfs.Spool
	entered chan struct{}
	through chan struct{}
	once    sync.Once
}

func (h *heldSpool) SetModTime(ctx context.Context, at time.Time) error {
	h.once.Do(func() { close(h.entered) })
	<-h.through

	return h.Spool.SetModTime(ctx, at)
}

// utimensat by path on a file whose last handle is released meanwhile (the
// release follows close(2)) dates the file: the spool it found stays open
// until it is done. It used to be closed under it, EIO.
func TestSetattr_KeepsTheSpoolItDates(t *testing.T) {
	m, dr, _ := writable(t)
	drv := m.srv.drv
	held := &heldSpool{entered: make(chan struct{}), through: make(chan struct{})}
	m.wrapSpools(func(s vfs.Spool) vfs.Spool {
		held.Spool = s

		return held
	})
	path := filepath.Join(m.dir, "dated.txt")
	f, err := create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("dated"); err != nil {
		t.Fatal(err)
	}
	sp := drv.spools.open()[0]

	want := time.Unix(1_700_000_000, 0)
	dated := make(chan error, 1)
	go func() { dated <- os.Chtimes(path, want, want) }()
	select {
	case <-held.entered:
	case err := <-dated:
		t.Fatalf("utimensat ended before it reached the spool: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("utimensat never reached the spool")
	}

	// The writer closes: its release ends while the date is being set.
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	eventually(t, "the release of the writer", func() bool {
		sp.st.mu.Lock()
		writers, refs := sp.writers, sp.refs
		sp.st.mu.Unlock()

		return writers == 0 && (refs > 0 || len(drv.spools.open()) == 0)
	})
	close(held.through)
	if err := <-dated; err != nil {
		t.Fatalf("utimensat = %v", err)
	}
	m.settle(t)
	if _, mtime, ok := m.api.content(dr, "", "dated.txt"); !ok || !mtime.Equal(want) {
		t.Errorf("the API dates the file %v (stored: %v), want %v", mtime, ok, want)
	}
}

// Once the shutdown has closed the spools, a mount still used (detached
// while busy) opens nothing for writing: the spool would be neither sent nor
// reported. Reading goes on.
func TestShutdown_NoSpoolOnceTheyAreClosed(t *testing.T) {
	m, dr, _ := writable(t)
	drv := m.srv.drv
	m.warm(t)
	hello := filepath.Join(m.dir, "hello.txt")
	if _, err := os.Stat(hello); err != nil {
		t.Fatal(err)
	}

	// What Server.finish does to the spools: closed, then sealed by abort.
	drv.closeSpools()
	drv.spools.seal()

	if f, err := openFile(hello, os.O_WRONLY); !errors.Is(err, syscall.ENOTCONN) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("open for writing = %v, want ENOTCONN", err)
	}
	if f, err := openFile(hello, os.O_RDONLY|os.O_TRUNC); !errors.Is(err, syscall.ENOTCONN) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("open with O_TRUNC = %v, want ENOTCONN", err)
	}
	if err := os.Truncate(hello, 1); !errors.Is(err, syscall.ENOTCONN) {
		t.Errorf("truncate = %v, want ENOTCONN", err)
	}
	if f, err := create(filepath.Join(m.dir, "late.txt")); !errors.Is(err, syscall.ENOTCONN) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("create = %v, want ENOTCONN", err)
	}
	if open := drv.spools.open(); len(open) != 0 {
		t.Errorf("%d spools opened after the shutdown closed them", len(open))
	}
	if got, err := readFile(hello); err != nil || string(got) != "hello" {
		t.Errorf("read = %q, %v; want the file", got, err)
	}
	if got := stored(t, m.api, dr, "", "hello.txt"); string(got) != "hello" {
		t.Errorf("the API holds %q, want the file untouched", got)
	}
	if m.api.node(dr, "", "late.txt") != nil {
		t.Error("the API holds a file created after the shutdown")
	}
}

// The end of the drain seals the registry, whatever ends it.
func TestAbort_SealsTheSpools(t *testing.T) {
	d := newDriver(nil, Options{})
	sp := d.newOpenSpool(&inodeState{}, 2, "dr1", nil)
	if !d.spools.add(sp, location{}) || d.spools.isSealed() {
		t.Fatal("a new driver takes no spool")
	}
	d.abort(nil)
	if !d.spools.isSealed() || d.spools.add(d.newOpenSpool(&inodeState{}, 3, "dr1", nil), location{}) {
		t.Error("spools are still taken after the drain ended")
	}
	if open := d.spools.seal(); len(open) != 1 || open[0] != sp {
		t.Errorf("seal = %v, want the spool open before it", open)
	}
}

// A /proc that hides processes (hidepid=2) answers ENOENT for a caller that
// is alive: it must not be taken for gone, or any harmless signal would
// cancel its operations.
func TestCallerDying_HiddenProcess(t *testing.T) {
	root := t.TempDir()
	hides, shows := func() bool { return false }, func() bool { return true }
	read := func(showsAll func() bool) procStatusReader {
		return func(pid uint32) ([]byte, error) { return procStatusIn(root, pid, showsAll) }
	}

	if _, err := procStatusIn(root, 43, hides); !errors.Is(err, errProcUnusable) {
		t.Errorf("status of a process /proc may hide = %v, want errProcUnusable", err)
	}
	if callerDying(43, read(hides)) {
		t.Error("a caller /proc may hide is reported dying")
	}
	// The same answer from a /proc that hides nothing: the caller is gone.
	if !callerDying(43, read(shows)) {
		t.Error("a caller missing from a /proc that shows every process is not reported dying")
	}

	// A caller that is there is read whatever /proc hides.
	if err := os.Mkdir(filepath.Join(root, "43"), 0o700); err != nil {
		t.Fatal(err)
	}
	killed := status("0000000000000100", "0000000000000000")
	if err := os.WriteFile(filepath.Join(root, "43", "status"), killed, 0o600); err != nil {
		t.Fatal(err)
	}
	if !callerDying(43, read(hides)) {
		t.Error("a visible caller with SIGKILL pending is not reported dying")
	}
}

// Whether /proc shows every process is read from the processes of other
// users it lists: this process seeing itself says nothing.
func TestProcListsOthers(t *testing.T) {
	root := t.TempDir()
	me := uint32(os.Geteuid()) //nolint:gosec // G115: IDs are 32 bits on Linux
	for _, name := range []string{"self", "sys", "17", "4242"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if procListsOthers(root, me) {
		t.Error("a /proc that lists this user's processes only is said to show every process")
	}
	// Read as another user, the same entries are those of somebody else.
	if !procListsOthers(root, me+1) {
		t.Error("a /proc that lists the processes of another user is said to hide them")
	}
	if procListsOthers(filepath.Join(root, "missing"), me) {
		t.Error("a missing /proc is said to show every process")
	}
}

// A reader blocked on the access log of an idle mount leaves as soon as the
// kernel interrupts its request, whatever /proc says of it: here a caller the
// driver cannot see (no PID), which no other operation is interrupted for.
func TestAccessLog_ReadEndsWithItsRequest(t *testing.T) {
	d := newDriver(nil, Options{procStatus: func(uint32) ([]byte, error) { return nil, errProcUnusable }})
	defer d.abort(nil)
	n := &accessLogNode{drv: d}
	fh, _, errno := n.Open(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		t.Fatalf("Open = %v", errno)
	}

	ctx, interrupt := context.WithCancel(context.Background())
	done := make(chan syscall.Errno, 1)
	go func() {
		_, errno := n.Read(ctx, fh, make([]byte, 64), 0)
		done <- errno
	}()
	select {
	case errno := <-done:
		t.Fatalf("a read of an idle log returned %v", errno)
	case <-time.After(50 * time.Millisecond):
	}
	interrupt()
	select {
	case errno := <-done:
		if errno != syscall.EINTR {
			t.Errorf("interrupted read = %v, want EINTR", errno)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked read of the access log ignored the interruption of its request")
	}

	// Nothing was consumed: the next read gets the next record.
	d.log.record(accessRecord{op: "open", ino: 7})
	res, errno := n.Read(context.Background(), fh, make([]byte, 256), 0)
	if errno != 0 {
		t.Fatalf("read after the interruption = %v", errno)
	}
	if line, _ := res.Bytes(nil); !strings.Contains(string(line), "open ino=7") {
		t.Errorf("read after the interruption = %q", line)
	}
}

// A lock the API neither renewed nor gave again is asked for by the next open
// for writing, although handles opened under the lost lock are still there.
func TestMirrorLocks_RetakenAfterItIsLost(t *testing.T) {
	m, _ := lockingMount(t, true)
	path := filepath.Join(m.dir, "hello.txt")
	first, err := openFile(path, os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if held := m.api.locksHeld(); held != 1 {
		t.Fatalf("%d locks at the API after the open, want 1", held)
	}

	// The lease ended and another client took the file: the renewal finds
	// no lock and is refused a new one.
	m.api.mu.Lock()
	node := m.api.datarooms["dr1"].children[""]["hello.txt"].id
	clear(m.api.locks)
	m.api.lockedElsewhere[node] = true
	m.api.mu.Unlock()
	m.tree.Locks().RefreshAll(context.Background())
	if held := m.tree.Locks().Held(); held != 0 {
		t.Fatalf("%d locks held after a renewal that lost it, want 0", held)
	}

	// Still locked elsewhere: a new writer is refused, the first goes on.
	if f, err := openFile(path, os.O_WRONLY); !errors.Is(err, syscall.EBUSY) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("open for writing of a file locked elsewhere = %v, want EBUSY", err)
	}
	if _, err := first.WriteString("mine"); err != nil {
		t.Errorf("write through the handle that lost its lock: %v", err)
	}

	// Free again: the next open for writing takes the lock anew.
	m.api.mu.Lock()
	clear(m.api.lockedElsewhere)
	m.api.mu.Unlock()
	second, err := openFile(path, os.O_WRONLY)
	if err != nil {
		t.Fatalf("open for writing: %v", err)
	}
	if api, held := m.api.locksHeld(), m.tree.Locks().Held(); api != 1 || held != 1 {
		t.Errorf("%d locks at the API, %d held, after the open that follows the loss; want 1 and 1", api, held)
	}
	if err := second.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	m.settle(t)
	eventually(t, "the lock to be released", func() bool { return m.api.locksHeld() == 0 && m.tree.Locks().Held() == 0 })
}
