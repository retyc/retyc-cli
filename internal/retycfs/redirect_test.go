//go:build linux

package retycfs

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// redirect does what a shell does for `echo text > path`: it opens the file
// (created or truncated), duplicates the descriptor, closes the first one,
// writes through the copy and closes it. The first close reaches the driver
// as a flush of a file nothing was written to yet. An empty text is `: >`.
func redirect(t *testing.T, path, text string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatalf("dup: %v", err)
	}
	// No descriptor is left open on a failure: the mount would be busy.
	first := unix.Close(fd)
	var written error
	if text != "" && first == nil {
		_, written = unix.Write(dup, []byte(text))
	}
	last := unix.Close(dup)
	if first != nil || written != nil || last != nil {
		t.Fatalf("close of the first descriptor: %v, write: %v, close: %v", first, written, last)
	}
}

// A shell redirection closes a duplicate of the descriptor before it writes:
// that close sends nothing, the file gets one version, not an empty one first.
func TestWrite_RedirectionSendsOneVersion(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	// echo 123 > new
	redirect(t, filepath.Join(m.dir, "new.txt"), "123\n")
	m.cost(t, "echo > new", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "new.txt", []byte("123\n"))
	first := m.api.node(dr, "", "new.txt")

	// echo 456 > existing: one new version of the same node.
	m.api.resetCounts()
	redirect(t, filepath.Join(m.dir, "new.txt"), "456\n")
	m.cost(t, "echo > existing", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "new.txt", []byte("456\n"))
	if again := m.api.node(dr, "", "new.txt"); again.id != first.id || again.version == first.version {
		t.Errorf("overwritten: node %s version %s, was node %s version %s", again.id, again.version, first.id, first.version)
	}

	// : > new: never written, the empty file is created by the release, and
	// is there for stat as soon as it is opened.
	m.api.resetCounts()
	fd, err := unix.Open(filepath.Join(m.dir, "blank.txt"), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if _, info := stat(t, filepath.Join(m.dir, "blank.txt")); info.Size != 0 {
		t.Errorf("the file created has %d bytes", info.Size)
	}
	if m.api.node(dr, "", "blank.txt") != nil {
		t.Error("the close of a duplicate sent a file nothing was written to")
	}
	if err := unix.Close(dup); err != nil {
		t.Fatal(err)
	}
	m.cost(t, ": > new", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "blank.txt", nil)

	// : > existing: one empty version.
	m.api.resetCounts()
	redirect(t, filepath.Join(m.dir, "new.txt"), "")
	m.cost(t, ": > existing", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "new.txt", nil)

	// ftruncate and fsync are sent by the close and by the call, as before.
	m.api.resetCounts()
	f, err := create(filepath.Join(m.dir, "sized.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if m.api.node(dr, "", "sized.txt") == nil {
		t.Error("fsync did not send the file created")
	}
	if err := f.Truncate(3); err != nil {
		t.Fatalf("ftruncate: %v", err)
	}
	m.api.refuseUploads(true)
	if err := f.Close(); err == nil {
		t.Error("the close after a ftruncate did not report the upload refused")
	}
	m.settle(t)
	m.api.refuseUploads(false)
}

// The upload of a file created and never written fails at its release: close
// answered already, the loss is reported, without the name.
func TestWrite_RedirectionLossIsReported(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	m.api.refuseUploads(true)
	redirect(t, filepath.Join(m.dir, "refused.txt"), "")
	m.settle(t)
	m.api.refuseUploads(false)
	if m.api.node(dr, "", "refused.txt") != nil {
		t.Fatal("the API holds the file it refused")
	}
	logs := m.logs.text()
	if strings.Count(logs, "its changes are lost") != 1 || strings.Contains(logs, "refused.txt") {
		t.Errorf("logs = %q, want the loss reported once and no name", logs)
	}
}

// opened creates a file and closes a duplicate of its descriptor, as a shell
// does before it writes: the file is left open, its flush not sent.
func opened(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	dup, err := unix.Dup(fd)
	if err == nil {
		err = unix.Close(dup)
	}
	if err != nil {
		_ = unix.Close(fd)
		t.Fatalf("dup and close: %v", err)
	}

	return fd
}

// A file created, not written, and still open when the filesystem goes away
// is sent by the shutdown like any other, or reported lost.
func TestCloseSpools_FileCreatedAndNotWritten(t *testing.T) {
	m, dr, _ := writable(t)
	drv := m.srv.drv

	fd := opened(t, filepath.Join(m.dir, "held.txt"))
	defer func() { _ = unix.Close(fd) }()
	if m.api.node(dr, "", "held.txt") != nil {
		t.Fatal("the API holds the file before any flush")
	}
	drv.closeSpools()
	if got := stored(t, m.api, dr, "", "held.txt"); len(got) != 0 {
		t.Errorf("the API holds %q", got)
	}
	logs := m.logs.text()
	if strings.Count(logs, "sent as it was at shutdown, the file was still open") != 1 ||
		strings.Contains(logs, "held.txt") || strings.Contains(logs, "lost") {
		t.Errorf("logs = %q", logs)
	}
}

func TestCloseSpools_FileCreatedAndNotWrittenIsReportedLost(t *testing.T) {
	m, dr, _ := writable(t)

	fd := opened(t, filepath.Join(m.dir, "held.txt"))
	defer func() { _ = unix.Close(fd) }()
	m.api.refuseUploads(true)
	m.srv.drv.closeSpools()
	m.api.refuseUploads(false)
	if m.api.node(dr, "", "held.txt") != nil {
		t.Fatal("the API holds the file it refused")
	}
	logs := m.logs.text()
	if strings.Count(logs, "its changes are lost") != 1 || strings.Contains(logs, "held.txt") {
		t.Errorf("logs = %q, want the loss reported once and no name", logs)
	}
}

// The unlink and the rename of a file whose first close sent nothing are
// those of any file not stored yet.
func TestWrite_RedirectionUnlinkAndRename(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	gone := filepath.Join(m.dir, "gone.txt")
	fd := opened(t, gone)
	err := unix.Unlink(gone)
	closed := unix.Close(fd)
	if err != nil || closed != nil {
		t.Fatalf("unlink: %v, close: %v", err, closed)
	}
	m.cost(t, "a file created and unlinked", map[string]int{})
	if m.api.node(dr, "", "gone.txt") != nil {
		t.Error("the API holds a file unlinked before it was sent")
	}

	from, to := filepath.Join(m.dir, "from.txt"), filepath.Join(m.dir, "to.txt")
	fd = opened(t, from)
	err = unix.Rename(from, to)
	var written error
	if err == nil {
		_, written = unix.Write(fd, []byte("moved"))
	}
	closed = unix.Close(fd)
	if err != nil || written != nil || closed != nil {
		t.Fatalf("rename: %v, write: %v, close: %v", err, written, closed)
	}
	m.cost(t, "a file created, renamed and written", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "to.txt", []byte("moved"))
	if m.api.node(dr, "", "from.txt") != nil {
		t.Error("the API holds the file under the name it was created with")
	}
	if logs := m.logs.text(); strings.Contains(logs, "lost") {
		t.Errorf("logs = %q", logs)
	}
}
