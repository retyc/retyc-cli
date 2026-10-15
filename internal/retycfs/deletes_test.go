//go:build linux

package retycfs

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// laterMount mounts the sample tree with Options.BackgroundDelete, its
// listings in cache and no request counted.
func laterMount(t *testing.T, change func(*mountOptions)) (*mounted, *fakeDataroom) {
	t.Helper()
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	opts := single("dr1")
	opts.driver.BackgroundDelete = true
	if change != nil {
		change(&opts)
	}
	m := mountFS(t, a, opts)
	walk(t, m.dir)
	a.resetCounts()

	return m, dr
}

// heldDeletes is the deletes of nodes the fake API holds back.
type heldDeletes struct {
	// arrived counts the deletes that reached the API.
	arrived atomic.Int32
	gate    chan struct{}
	open    sync.Once

	mu sync.Mutex
	// order is what reached the handlers of the API, in order: "delete" for
	// the delete of a node once it is let through, "write" for anything
	// else that writes.
	order []string
}

// holdDeletes makes the API hold every delete of a node until release, which
// the end of the test calls too.
func (m *mounted) holdDeletes(t *testing.T) *heldDeletes {
	t.Helper()
	h := &heldDeletes{gate: make(chan struct{})}
	t.Cleanup(h.release)
	m.api.mu.Lock()
	m.api.before = func(r *http.Request) {
		what := "write"
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/dataroom/node/") {
			what = "delete"
			h.arrived.Add(1)
			<-h.gate
		}
		h.mu.Lock()
		h.order = append(h.order, what)
		h.mu.Unlock()
	}
	m.api.mu.Unlock()

	return h
}

func (h *heldDeletes) release() { h.open.Do(func() { close(h.gate) }) }

func (h *heldDeletes) sequence() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.order)
}

// pending returns the number of deletes the mount has not seen the end of.
func (m *mounted) pendingDeletes() int {
	q := m.srv.drv.deletes
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.jobs)
}

func missing(path string) bool {
	_, err := os.Lstat(path)

	return errors.Is(err, syscall.ENOENT)
}

// Without the option an unlink asks the API before it answers.
func TestBackgroundDelete_Off(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	if m.srv.drv.deletes != nil {
		t.Fatal("a mount without the option has a delete queue")
	}
	if err := os.Remove(filepath.Join(m.dir, "hello.txt")); err != nil {
		t.Fatal(err)
	}
	// Read as unlink returns: nothing is waited for.
	if n := m.api.count("delete"); n != 1 || m.api.node(dr, "", "hello.txt") != nil {
		t.Errorf("unlink returned after %d delete, the API holds the file: %v", n, m.api.node(dr, "", "hello.txt") != nil)
	}
}

// With the option unlink answers while the API holds the delete back: the
// name is gone from the mount at once, and stays gone when the listing of the
// folder, fetched again, still names the node. Once the API answers, the node
// is gone there too.
func TestBackgroundDelete_AnswersBeforeTheAPI(t *testing.T) {
	m, dr := laterMount(t, nil)
	held := m.holdDeletes(t)
	before := testutil.ToFloat64(metrics.BackgroundDeletes.WithLabelValues("ok"))

	for _, name := range []string{"hello.txt", "link"} {
		if err := os.Remove(filepath.Join(m.dir, name)); err != nil {
			t.Fatalf("unlink %s while the API holds the deletes: %v", name, err)
		}
	}
	absent := func(when string) {
		t.Helper()
		for _, name := range []string{"hello.txt", "link"} {
			if !missing(filepath.Join(m.dir, name)) {
				t.Errorf("%s: %s is still there", when, name)
			}
		}
		if names := walk(t, m.dir); slices.Contains(names, "hello.txt") || slices.Contains(names, "link") {
			t.Errorf("%s: listed: %v", when, names)
		}
	}
	absent("right after unlink")
	eventually(t, "the deletes to reach the API", func() bool { return held.arrived.Load() == 2 })
	if m.api.node(dr, "", "hello.txt") == nil || m.api.node(dr, "", "link") == nil {
		t.Fatal("the API deleted the nodes while their deletes are held")
	}

	// A listing fetched now still names both nodes.
	m.api.resetCounts()
	m.tree.InvalidateListing("dr1", "/")
	absent("after the listing was fetched again")
	if m.api.count("listing") == 0 {
		t.Errorf("the listing was not fetched again (%s): the test proves nothing", m.api.summary())
	}
	// So does a lookup by name, which the kernel spares the mount here (it
	// holds the name as missing): asked of the tree.
	_, asked, err := m.tree.LookupRemote(context.Background(), "dr1", "/", "hello.txt")
	if !asked || !errors.Is(err, os.ErrNotExist) || m.api.count("lookup") == 0 {
		t.Errorf("lookup by name of a node being deleted = asked %v, %v (%s), want not found",
			asked, err, m.api.summary())
	}
	// Still there: the big file, which nothing removed.
	if missing(filepath.Join(m.dir, "big.bin")) {
		t.Error("big.bin is gone")
	}

	held.release()
	eventually(t, "the nodes to be deleted at the API", func() bool {
		return m.api.node(dr, "", "hello.txt") == nil && m.api.node(dr, "", "link") == nil && m.pendingDeletes() == 0
	})
	absent("once deleted")
	if got := testutil.ToFloat64(metrics.BackgroundDeletes.WithLabelValues("ok")) - before; got != 2 {
		t.Errorf("deletes counted ok = %v, want 2", got)
	}
	if logs := m.logs.text(); logs != "" {
		t.Errorf("reported: %s", logs)
	}
}

// A file created under a name whose delete is on its way is sent after that
// delete, and stored.
func TestBackgroundDelete_NameReusedAfterTheDelete(t *testing.T) {
	m, dr := laterMount(t, nil)
	old := m.api.node(dr, "", "hello.txt")
	held := m.holdDeletes(t)

	if err := os.Remove(filepath.Join(m.dir, "hello.txt")); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { written <- writeMode(filepath.Join(m.dir, "hello.txt"), []byte("again"), 0o644) }()
	select {
	case err := <-written:
		t.Fatalf("the file was sent while the delete of its name is held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if seq := held.sequence(); len(seq) != 0 {
		t.Fatalf("requests let through before the delete: %v", seq)
	}

	held.release()
	if err := <-written; err != nil {
		t.Fatalf("write after the delete: %v", err)
	}
	m.settle(t)
	if seq := held.sequence(); len(seq) < 2 || seq[0] != "delete" {
		t.Errorf("order at the API = %v, want the delete first", seq)
	}
	m.wantFile(t, dr, "", "hello.txt", []byte("again"))
	if now := m.api.node(dr, "", "hello.txt"); now == nil || now.id == old.id {
		t.Errorf("the name holds %+v, want a new node", now)
	}

	// mkdir and symlink wait the same way.
	m.api.before = nil
	late := m.holdDeletes(t)
	if err := os.Remove(filepath.Join(m.dir, "empty.txt")); err != nil {
		t.Fatal(err)
	}
	made := make(chan error, 1)
	go func() { made <- mkdir(filepath.Join(m.dir, "empty.txt")) }()
	select {
	case err := <-made:
		t.Fatalf("mkdir answered while the delete of its name is held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	late.release()
	if err := <-made; err != nil {
		t.Fatalf("mkdir after the delete: %v", err)
	}
	if seq := late.sequence(); len(seq) < 2 || seq[0] != "delete" {
		t.Errorf("order at the API = %v, want the delete first", seq)
	}
}

// rmdir waits for the deletes of what was removed from the folder.
func TestBackgroundDelete_Rmdir(t *testing.T) {
	m, dr := laterMount(t, nil)
	held := m.holdDeletes(t)
	deep := filepath.Join(m.dir, "docs", "deep")

	if err := os.Remove(filepath.Join(deep, "b.txt")); err != nil {
		t.Fatal(err)
	}
	removed := make(chan error, 1)
	go func() { removed <- os.Remove(deep) }()
	select {
	case err := <-removed:
		t.Fatalf("rmdir answered while the delete of a child is held: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	held.release()
	if err := <-removed; err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	if !missing(deep) {
		t.Error("the folder is still there")
	}
	docs := m.api.node(dr, "", "docs")
	if m.api.node(dr, docs.id, "deep") != nil {
		t.Error("the API still holds the folder")
	}
}

// A delete the API refuses is reported by identifiers, counted, and the file
// is back in the mount.
func TestBackgroundDelete_Failure(t *testing.T) {
	m, dr := laterMount(t, nil)
	node := m.api.node(dr, "", "hello.txt")
	m.api.mu.Lock()
	m.api.undeletable = map[string]bool{node.id: true}
	m.api.mu.Unlock()
	before := testutil.ToFloat64(metrics.BackgroundDeletes.WithLabelValues("error"))

	path := filepath.Join(m.dir, "hello.txt")
	if err := os.Remove(path); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	eventually(t, "the failure to be reported", func() bool {
		return strings.Contains(m.logs.text(), "a background delete failed")
	})
	logs := m.logs.text()
	want := "a background delete failed, the file is still in the dataroom: dataroom dr1, node " + node.id + ": EACCES"
	if logs != want {
		t.Errorf("log = %q, want %q", logs, want)
	}
	if strings.Contains(logs, "hello") {
		t.Errorf("the log names the file: %q", logs)
	}
	eventually(t, "the file to be back", func() bool { return !missing(path) })
	wantContent(t, path, "hello")
	if !slices.Contains(walk(t, m.dir), "hello.txt") {
		t.Error("the file is not listed again")
	}
	if got := testutil.ToFloat64(metrics.BackgroundDeletes.WithLabelValues("error")) - before; got != 1 {
		t.Errorf("deletes counted error = %v, want 1", got)
	}
}

// A shutdown waits for the queue while its drain lasts.
func TestBackgroundDelete_ShutdownDrains(t *testing.T) {
	m, dr := laterMount(t, nil)
	held := m.holdDeletes(t)
	for _, name := range []string{"hello.txt", "empty.txt"} {
		if err := os.Remove(filepath.Join(m.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	time.AfterFunc(300*time.Millisecond, held.release)
	if err := m.srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if m.api.node(dr, "", "hello.txt") != nil || m.api.node(dr, "", "empty.txt") != nil {
		t.Error("Shutdown returned before the deletes reached the API")
	}
	if logs := m.logs.text(); !strings.Contains(logs, "stopping: 2 deletes still to send to the API") ||
		!strings.Contains(logs, "everything was sent") || strings.Contains(logs, "lost") {
		t.Errorf("reported: %s", logs)
	}
}

// A drain that is cut reports each delete it did not see the end of, the one
// at the API and the one still queued, and Shutdown counts them in its error.
func TestBackgroundDelete_ShutdownCut(t *testing.T) {
	m, dr := laterMount(t, func(o *mountOptions) {
		o.driver.DrainTimeout = 300 * time.Millisecond
		o.driver.UnmountGrace = 100 * time.Millisecond
		o.driver.DeleteConcurrency = 1
	})
	ids := []string{m.api.node(dr, "", "hello.txt").id, m.api.node(dr, "", "empty.txt").id}
	held := m.holdDeletes(t)
	for _, name := range []string{"hello.txt", "empty.txt"} {
		if err := os.Remove(filepath.Join(m.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "one delete to reach the API", func() bool { return held.arrived.Load() == 1 })

	err := m.srv.Shutdown(context.Background())
	logs := m.logs.text()
	var lost *LostWritesError
	if !errors.As(err, &lost) || lost.Deletes != 2 || lost.Files != 0 {
		t.Fatalf("Shutdown = %v, want two deletes lost", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "2 files removed") || strings.Contains(msg, "being written") ||
		strings.Contains(msg, "hello") || strings.Contains(msg, "empty") {
		t.Errorf("the error = %q, want the count of deletes and no name", msg)
	}
	const report = "a background delete did not end before the end of the shutdown drain"
	if strings.Count(logs, report) != 2 || strings.Contains(logs, "hello") || strings.Contains(logs, "empty.txt") {
		t.Errorf("reports = %q, want one per node and no name", logs)
	}
	for _, id := range ids {
		if !strings.Contains(logs, "dataroom dr1, node "+id) {
			t.Errorf("no report for node %s: %q", id, logs)
		}
	}
	if err := m.srv.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown = %v", err)
	}
	held.release()
}

// The message of the error keeps its form without deletes, and never names a
// file with them.
func TestLostWritesError_Deletes(t *testing.T) {
	for want, e := range map[string]*LostWritesError{
		"1 file being written was not sent before the filesystem was unmounted: its changes are lost": {Files: 1},
		"3 files being written were not sent before the filesystem was unmounted: " +
			"their changes are lost": {Files: 3},
		"1 file removed was not deleted before the filesystem was unmounted: it may still be in the dataroom": {Deletes: 1},
		"1 file being written was not sent before the filesystem was unmounted: its changes are lost; " +
			"2 files removed were not deleted before the filesystem was unmounted: " +
			"they may still be in the dataroom": {Files: 1, Deletes: 2},
	} {
		if got := e.Error(); got != want {
			t.Errorf("%+v = %q, want %q", *e, got, want)
		}
	}
}

// What is refused without asking the API is still the error of unlink.
func TestBackgroundDelete_ReadOnly(t *testing.T) {
	m, dr := laterMount(t, func(o *mountOptions) { o.driver.ReadOnly = true })
	wantErrno(t, "unlink on a read-only mount", os.Remove(filepath.Join(m.dir, "hello.txt")), syscall.EROFS)
	if m.srv.drv.deletes != nil {
		t.Error("a read-only mount has a delete queue")
	}

	viewer, _ := laterMount(t, func(o *mountOptions) {
		o.driver.Access = func(context.Context, string) (vfs.Access, error) {
			return vfs.Access{Role: "viewer", Writable: true, ReadOnly: true}, nil
		}
	})
	wantErrno(t, "unlink in a dataroom the user cannot write to",
		os.Remove(filepath.Join(viewer.dir, "hello.txt")), syscall.EROFS)
	if n := viewer.pendingDeletes(); n != 0 || viewer.api.count("delete") != 0 {
		t.Errorf("%d deletes queued for a viewer", n)
	}
	if m.api.node(dr, "", "hello.txt") == nil {
		t.Error("the file is gone from the API")
	}
}

// A file removed while it is open stays readable and writable through its
// handles, and what was written to it is never sent.
func TestBackgroundDelete_OpenFile(t *testing.T) {
	m, dr := laterMount(t, nil)
	held := m.holdDeletes(t)

	reader, err := os.Open(filepath.Join(m.dir, "docs", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	writer, err := openFile(filepath.Join(m.dir, "hello.txt"), os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	if _, err := writer.WriteAt([]byte("J"), 0); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"docs/a.txt", "hello.txt"} {
		if err := os.Remove(filepath.Join(m.dir, rel)); err != nil {
			t.Fatalf("unlink %s: %v", rel, err)
		}
	}
	buf := make([]byte, 16)
	if n, _ := reader.ReadAt(buf, 0); string(buf[:n]) != "alpha" {
		t.Errorf("read through the handle of a removed file = %q, want alpha", buf[:n])
	}
	if n, _ := writer.ReadAt(buf, 0); string(buf[:n]) != "Jello" {
		t.Errorf("read through the handle that writes a removed file = %q, want Jello", buf[:n])
	}
	if info, err := writer.Stat(); err != nil || info.Size() != 5 {
		t.Errorf("fstat of the removed file = %v, %v", info, err)
	}
	if err := writer.Close(); err != nil {
		t.Errorf("close of the removed file: %v", err)
	}
	_ = reader.Close()
	m.settle(t)

	held.release()
	docs := m.api.node(dr, "", "docs")
	eventually(t, "both nodes to be deleted", func() bool {
		return m.api.node(dr, "", "hello.txt") == nil && m.api.node(dr, docs.id, "a.txt") == nil
	})
	if seq := held.sequence(); slices.Contains(seq, "write") {
		t.Errorf("the removed file was sent: %v", seq)
	}
	if logs := m.logs.text(); logs != "" {
		t.Errorf("reported: %s", logs)
	}
}
