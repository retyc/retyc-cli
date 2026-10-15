//go:build linux

package retycfs

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/service"
)

// A mount point that cannot be detached is the error of the shutdown, and the
// rest of it runs all the same: the file still open is sent, the mount is
// over for its callers.
func TestShutdown_DetachFailureStillFinishes(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	refused := errors.New("detach refused")
	var refuse atomic.Bool
	refuse.Store(true)
	opts := single("dr1")
	opts.driver.UnmountGrace = 200 * time.Millisecond
	opts.driver.detach = func(mountpoint string) error {
		if refuse.Load() {
			return refused
		}

		return detach(mountpoint)
	}
	m := mountFS(t, a, opts)

	// A file open, with changes nothing sent: the mount point is busy.
	f, err := create(filepath.Join(m.dir, "held.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("held"); err != nil {
		t.Fatal(err)
	}

	err = m.srv.Unmount()
	if !errors.Is(err, refused) {
		t.Errorf("Unmount = %v, want the error of the detach", err)
	}
	select {
	case <-m.srv.Done():
	default:
		t.Error("the mount is not over: what served it was not released")
	}
	if got := stored(t, a, dr, "", "held.txt"); string(got) != "held" {
		t.Errorf("the API holds %q: the file still open was not sent", got)
	}
	if open := m.srv.drv.spools.open(); len(open) != 0 {
		t.Errorf("%d spools still open", len(open))
	}

	// The kernel still holds the mount: let go of it for the cleanup.
	_ = f.Close()
	refuse.Store(false)
	if err := m.srv.srv.Unmount(); err != nil {
		t.Errorf("unmounting for the cleanup: %v", err)
	}
	m.logs.forget()
}

// An upload cancelled by the end of the drain removes what it had sent from
// the API before it returns. An API that no longer answers holds it there for
// longer than the shutdown waits: the file is reported lost, and counted in
// the error, before Shutdown returns all the same.
func TestShutdown_ReportsLossesBeforeAHungCleanup(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	opts := single("dr1")
	opts.driver.DrainTimeout = 300 * time.Millisecond
	opts.driver.UnmountGrace = 100 * time.Millisecond
	m := mountFS(t, a, opts)

	// The API stops answering once the first chunk is on its way: neither
	// the chunks nor the removal of the version they belong to are answered.
	gate, arrived := make(chan struct{}), make(chan struct{})
	var first, open sync.Once
	var cleanups atomic.Int32
	release := func() { open.Do(func() { close(gate) }) }
	t.Cleanup(release)
	a.mu.Lock()
	a.before = func(r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/chunk/"):
			first.Do(func() { close(arrived) })
			<-gate
		case r.Method == http.MethodDelete:
			cleanups.Add(1)
			<-gate
		}
	}
	a.mu.Unlock()

	// Larger than a chunk: streamed, so a failure has something to remove.
	closed := make(chan error, 1)
	go func() {
		closed <- writeMode(filepath.Join(m.dir, "big.bin"), make([]byte, service.UploadChunkSize+1), 0o644)
	}()
	select {
	case <-arrived:
	case err := <-closed:
		t.Fatalf("the write ended before its upload reached the API: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the upload never reached the API")
	}

	start := time.Now()
	err := m.srv.Shutdown(context.Background())
	took := time.Since(start)
	logs := m.logs.text()

	var lost *LostWritesError
	if !errors.As(err, &lost) || lost.Files != 1 {
		t.Errorf("Shutdown = %v, want one file lost", err)
	}
	if strings.Contains(err.Error(), "big.bin") {
		t.Errorf("the error names the file: %v", err)
	}
	if strings.Count(logs, "its changes are lost") != 1 || strings.Contains(logs, "big.bin") {
		t.Errorf("no report of the loss when Shutdown returned: %q", logs)
	}
	if cleanups.Load() == 0 {
		t.Error("the cleanup never reached the API: the test did not hold it")
	}
	if took >= abortGrace {
		t.Errorf("the shutdown took %v: it waited for the cleanup", took)
	}
	select {
	case <-m.srv.Done():
	default:
		t.Error("the mount is not over when Shutdown returned")
	}

	release()
	if err := <-closed; err == nil {
		t.Error("close(2) reported the file sent")
	}
	// The mount point was busy, which is the point of this test.
	m.logs.forget()
}

// A shutdown that lost nothing is no error, one that lost files says how many
// once: the next call, of a mount already gone, has nothing to report.
func TestShutdown_LossesAreReturnedOnce(t *testing.T) {
	m, _, _ := writable(t)
	f, err := create(filepath.Join(m.dir, "held.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("held"); err != nil {
		t.Fatal(err)
	}
	m.api.refuseUploads(true)
	err = m.srv.Shutdown(context.Background())
	m.api.refuseUploads(false)
	_ = f.Close()

	var lost *LostWritesError
	if !errors.As(err, &lost) || lost.Files != 1 {
		t.Fatalf("Shutdown = %v, want one file lost", err)
	}
	if !strings.Contains(err.Error(), "1 file") || strings.Contains(err.Error(), "held.txt") {
		t.Errorf("the error = %q, want the count and no name", err)
	}
	if err := m.srv.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown = %v", err)
	}
	m.logs.forget()
}

// The filesystem still in use through another mount of it (a bind mount in a
// pod's namespace): the kernel lets the mount point go, but go-fuse's Unmount
// then waits for the connection to close, for as long as a file is open
// through that mount. The shutdown does not wait with it: the file still
// open is reported lost, and counted, before the drain is over.
func TestShutdown_MountedElsewhereStillFinishes(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	opts := single("dr1")
	opts.driver.DrainTimeout = 2 * time.Second
	held := make(chan struct{})
	t.Cleanup(func() { close(held) })
	var m *mounted
	// What go-fuse does then: the mount point leaves this namespace, and
	// Unmount returns only once the connection is closed.
	opts.driver.unmount = func() error {
		if err := detach(m.srv.mountpoint); err != nil {
			return err
		}
		<-held

		return nil
	}
	m = mountFS(t, a, opts)

	f, err := create(filepath.Join(m.dir, "held.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.WriteString("held"); err != nil {
		t.Fatal(err)
	}
	a.refuseUploads(true)

	start := time.Now()
	err = m.srv.Shutdown(context.Background())
	took := time.Since(start)

	var lost *LostWritesError
	if !errors.As(err, &lost) || lost.Files != 1 {
		t.Errorf("Shutdown = %v, want one file lost", err)
	}
	if took >= opts.driver.DrainTimeout {
		t.Errorf("the shutdown took %v: it waited for the drain or the connection", took)
	}
	select {
	case <-m.srv.Done():
	default:
		t.Error("the mount is not over")
	}
	if !strings.Contains(m.logs.text(), "its FUSE connection is still open") {
		t.Errorf("no report of the other mount: %q", m.logs.text())
	}
	m.logs.forget()
}

// No drain at all: the end of the drain comes before go-fuse could answer the
// unmount, which is still a clean one.
func TestShutdown_NoDrainUnmountsCleanly(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	opts := single("dr1")
	opts.driver.DrainTimeout = -1
	m := mountFS(t, a, opts)

	if err := m.srv.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown = %v, want a clean unmount", err)
	}
	if logs := m.logs.text(); strings.Contains(logs, "detaching") || strings.Contains(logs, "still open") {
		t.Errorf("a clean unmount was taken for a busy one: %q", logs)
	}
}
