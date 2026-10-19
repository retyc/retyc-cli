//go:build linux

package retycfs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/service"
)

// The owner and the default modes are those the mount is given; a mode the
// API stores is presented as it is.
func TestMount_PresentsTheOwnerAndModesAsked(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	a.dir(dr, "", "plain")
	uid, gid := uint32(4242), uint32(4343)
	// Modes the user running the test can still read through, whoever owns.
	opts := single("dr1")
	opts.driver.UID, opts.driver.GID = &uid, &gid
	opts.driver.FileMode, opts.driver.DirMode = 0o444, 0o555
	m := mountFS(t, a, opts)

	for name, want := range map[string]os.FileMode{
		"":          os.ModeDir | 0o555,
		"plain":     os.ModeDir | 0o555,
		"empty.txt": 0o444,
		"hello.txt": 0o640,
	} {
		info, err := os.Lstat(filepath.Join(m.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != want {
			t.Errorf("%q: mode %v, want %v", name, info.Mode(), want)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uid || st.Gid != gid {
			t.Errorf("%q: owner %d:%d, want %d:%d", name, st.Uid, st.Gid, uid, gid)
		}
	}
}

// Without options the owner is the process, and the modes 0644 / 0755.
func TestNewDriver_Defaults(t *testing.T) {
	d := newDriver(nil, Options{})
	defer d.abort(nil)
	if d.attrs.uid != uint32(os.Getuid()) || d.attrs.gid != uint32(os.Getgid()) { //nolint:gosec // G115: 32-bit IDs
		t.Errorf("owner %d:%d, want the process", d.attrs.uid, d.attrs.gid)
	}
	if d.attrs.fileMode != 0o644 || d.attrs.dirMode != 0o755 {
		t.Errorf("modes %o / %o, want 644 / 755", d.attrs.fileMode, d.attrs.dirMode)
	}
	// Owner 0 is an owner, not "unset".
	root := uint32(0)
	d = newDriver(nil, Options{UID: &root, GID: &root, FileMode: 0o600, DirMode: 0o700})
	defer d.abort(nil)
	if d.attrs.uid != 0 || d.attrs.gid != 0 || d.attrs.fileMode != 0o600 || d.attrs.dirMode != 0o700 {
		t.Errorf("attrs = %+v", d.attrs)
	}
}

func TestOptions_DrainTimeout(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0:               DefaultDrainTimeout,
		-1:              0,
		5 * time.Second: 5 * time.Second,
	} {
		if got := (Options{DrainTimeout: in}).drainTimeout(); got != want {
			t.Errorf("drainTimeout(%v) = %v, want %v", in, got, want)
		}
	}
}

// isUpload matches the request that stores a small file.
func isUpload(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/node/file")
}

// writeHeld writes a file whose upload the API holds back, and returns once
// the request is held: the close(2) of the writer is then waiting for it.
// closed receives what that close returned.
func writeHeld(t *testing.T, m *mounted, name string) (closed <-chan error, release func()) {
	t.Helper()
	arrived, release := m.api.holdRequests(isUpload)
	// Whatever the test does, the API answers before its server is closed.
	t.Cleanup(release)
	done := make(chan error, 1)
	go func() { done <- writeMode(filepath.Join(m.dir, name), []byte("held"), 0o644) }()
	select {
	case <-arrived:
	case err := <-done:
		t.Fatalf("the write ended before its upload reached the API: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the upload never reached the API")
	}

	return done, release
}

// A flush in progress when the mount is stopped reaches the API before the
// filesystem is unmounted: the shutdown waits for it.
func TestShutdown_WaitsForAFlushInProgress(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	opts := single("dr1")
	opts.driver.DrainTimeout = 30 * time.Second
	opts.driver.UnmountGrace = 10 * time.Second
	m := mountFS(t, a, opts)
	closed, release := writeHeld(t, m, "slow.txt")

	stopped := make(chan error, 1)
	go func() { stopped <- m.srv.Shutdown(context.Background()) }()
	select {
	case err := <-stopped:
		t.Fatalf("the shutdown did not wait for the upload: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if still, err := isMounted(m.srv.mountpoint); err != nil || !still {
		t.Errorf("unmounted under an upload in progress (err %v)", err)
	}

	release()
	if err := <-closed; err != nil {
		t.Errorf("close(2) of the file being sent: %v", err)
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the shutdown did not end once the upload had")
	}
	if got := stored(t, a, dr, "", "slow.txt"); string(got) != "held" {
		t.Errorf("the API holds %q", got)
	}
	if logs := m.logs.text(); strings.Contains(logs, "lost") || strings.Contains(logs, "cancelled") ||
		!strings.Contains(logs, "stopping: 1 file still to send to the API, waiting for them up to 30s") ||
		!strings.Contains(logs, "everything was sent") {
		t.Errorf("logs = %q", logs)
	}
}

// Past the drain timeout, or when the shutdown is forced, the upload still in
// progress is cancelled: the file is reported lost, by IDs, and the
// filesystem is unmounted all the same.
func TestShutdown_DrainCutShort(t *testing.T) {
	for name, tc := range map[string]struct {
		drain  time.Duration
		forced bool
		why    string
	}{
		"timeout":       {drain: 300 * time.Millisecond, why: "the drain timeout is over"},
		"second signal": {drain: time.Minute, forced: true, why: "the shutdown was forced"},
	} {
		t.Run(name, func(t *testing.T) {
			a := newFakeAPI(t)
			dr, _ := sampleTree(a)
			opts := single("dr1")
			opts.driver.DrainTimeout = tc.drain
			opts.driver.UnmountGrace = 100 * time.Millisecond
			m := mountFS(t, a, opts)
			closed, _ := writeHeld(t, m, "slow.txt")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.forced {
				time.AfterFunc(300*time.Millisecond, cancel)
			}
			start := time.Now()
			// The file lost is the error of the shutdown, by its count.
			err := m.srv.Shutdown(ctx)
			var lost *LostWritesError
			if !errors.As(err, &lost) || lost.Files != 1 || strings.Contains(err.Error(), "slow.txt") {
				t.Fatalf("Shutdown = %v, want one file lost", err)
			}
			if took := time.Since(start); took > 10*time.Second {
				t.Errorf("the shutdown took %v", took)
			}
			if still, err := isMounted(m.srv.mountpoint); err != nil || still {
				t.Errorf("still mounted after the drain (err %v)", err)
			}
			if err := <-closed; err == nil {
				t.Error("close(2) reported the file sent")
			}
			if a.node(dr, "", "slow.txt") != nil {
				t.Error("the API holds the file")
			}
			logs := m.logs.text()
			if !strings.Contains(logs, tc.why) ||
				strings.Count(logs, "its changes are lost") != 1 ||
				!strings.Contains(logs, "not sent before the end of the shutdown drain") ||
				!strings.Contains(logs, "stopping: 1 file still to send to the API") ||
				!strings.Contains(logs, ": 1 file not sent") ||
				strings.Contains(logs, "slow.txt") {
				t.Errorf("logs = %q", logs)
			}
			// The mount point was busy, which is the point of this test:
			// mountFS takes a detached mount for a test that leaked a file.
			m.logs.forget()
		})
	}
}

// isChunkUpload matches the request that stores one chunk of a file too large
// for the single request (see isUpload).
func isChunkUpload(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/node/version/")
}

// A file sent chunk by chunk whose upload the drain cuts short leaves a node
// behind, which the tree (vfs) removes and reports: neither that report nor
// the one of the loss names the file or its folder. Both tell it by
// identifiers, the loss by the folder the file was created in, since it never
// had a node, and by the size of what is lost.
func TestShutdown_DrainCutShort_ChunkedUploadNamesNothing(t *testing.T) {
	const folder, name = "confidential-folder", "payroll-2026-secret.bin"
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	parent := a.dir(dr, "", folder)
	opts := single("dr1")
	opts.driver.DrainTimeout = 300 * time.Millisecond
	opts.driver.UnmountGrace = 100 * time.Millisecond
	m := mountFS(t, a, opts)

	// Past the size of the single request (service.SmallUploadMaxSize).
	data := testData(service.SmallUploadMaxSize+17, 1)
	arrived, release := a.holdRequests(isChunkUpload)
	t.Cleanup(release)
	closed := make(chan error, 1)
	go func() { closed <- writeMode(filepath.Join(m.dir, folder, name), data, 0o644) }()
	select {
	case <-arrived:
	case err := <-closed:
		t.Fatalf("the write ended before a chunk reached the API: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no chunk ever reached the API")
	}

	err := m.srv.Shutdown(context.Background())
	var lost *LostWritesError
	if !errors.As(err, &lost) || lost.Files != 1 || strings.Contains(err.Error(), name) {
		t.Fatalf("Shutdown = %v, want one file lost", err)
	}
	if err := <-closed; err == nil {
		t.Error("close(2) reported the file sent")
	}
	if a.node(dr, parent, name) != nil {
		t.Error("the API holds the file")
	}

	logs := m.logs.text()
	// What vfs reports is recorded too: the node the upload created is gone.
	if !strings.Contains(logs, "cleaned up orphaned node: dataroom dr1, node ") {
		t.Errorf("logs = %q, want the cleanup of the node reported by the tree", logs)
	}
	want := fmt.Sprintf("its changes are lost: dataroom dr1, no node (never stored), parent %s, inode ", parent)
	if strings.Count(logs, "its changes are lost") != 1 || !strings.Contains(logs, want) ||
		!strings.Contains(logs, fmt.Sprintf(", %d bytes: not sent before the end of the shutdown drain", len(data))) {
		t.Errorf("logs = %q, want one loss with %q and the size", logs, want)
	}
	for _, secret := range []string{name, folder, `node ""`} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs hold %q:\n%s", secret, logs)
		}
	}
	// The mount point was busy, which is the point of this test (see
	// TestShutdown_DrainCutShort).
	m.logs.forget()
}

// A shutdown with nothing in progress costs nothing of its drain.
func TestShutdown_NothingToDrain(t *testing.T) {
	m, dr, _ := writable(t)
	writeFile(t, filepath.Join(m.dir, "done.txt"), []byte("done"))
	start := time.Now()
	if err := m.srv.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the shutdown took %v", took)
	}
	if got := stored(t, m.api, dr, "", "done.txt"); string(got) != "done" {
		t.Errorf("the API holds %q", got)
	}
	if logs := m.logs.text(); strings.Contains(logs, "lost") {
		t.Errorf("logs = %q", logs)
	}
}
