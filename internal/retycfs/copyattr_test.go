//go:build linux

package retycfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/retyc/retyc-cli/internal/api"
)

// copySource is the file the copies of these tests are made from: a mode and
// a modification time (with microseconds) no default would give.
const (
	copySourceName = "tool.sh"
	copySourceMode = 0o755
)

var copySourceTime = time.Date(2026, 9, 1, 8, 30, 0, 123456000, time.UTC)

// copyMount mounts the sample tree with the source of the copies, warmed.
func copyMount(t *testing.T) (*mounted, *fakeDataroom, []byte) {
	t.Helper()
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	data := testData(2*testChunkSize+77, 3)
	a.put(dr, "", copySourceName, fakeNode{
		kind: api.NodeTypeFile, data: data, mode: "0755", mime: "text/plain", mtime: copySourceTime,
	})
	m := mountFS(t, a, single("dr1"))
	m.warm(t)

	return m, dr, data
}

// copyOpen does the first half of cp(1): it opens the source, creates the
// destination with O_EXCL and the mode given, and copies the whole file with
// copy_file_range. It returns the descriptor of the destination, still open,
// and what fstat said of the source.
func copyOpen(t *testing.T, m *mounted, dst string, mode uint32, size int) (int, unix.Stat_t) {
	t.Helper()
	in, err := unix.Open(filepath.Join(m.dir, copySourceName), unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open of the source: %v", err)
	}
	defer func() { _ = unix.Close(in) }()
	var src unix.Stat_t
	if err := unix.Fstat(in, &src); err != nil {
		t.Fatalf("fstat of the source: %v", err)
	}
	out, err := unix.Open(dst, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, mode)
	if err != nil {
		t.Fatalf("open of the destination: %v", err)
	}
	if n, err := unix.CopyFileRange(in, nil, out, nil, 1<<30, 0); err != nil || n != size {
		_ = unix.Close(out)
		t.Fatalf("copy_file_range = %d, %v, want %d", n, err, size)
	}

	return out, src
}

func permOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, _ := stat(t, path)

	return info.Mode().Perm()
}

// cp -a creates its destination with a restrictive mode, copies, then gives
// it the mode and the modification time of the source. The server-side copy
// has both already: nothing but the copy is asked of the API.
func TestCopy_ArchiveCostsTheCopyOnly(t *testing.T) {
	m, dr, data := copyMount(t)
	dst := filepath.Join(m.dir, "archived.sh")

	out, src := copyOpen(t, m, dst, 0o600, len(data))
	closed := false
	defer func() {
		if !closed {
			_ = unix.Close(out)
		}
	}()
	// The mode the program asked for is the one it sees, before any request.
	if got := permOf(t, dst); got != 0o600 {
		t.Errorf("mode after the copy = %04o, want the mode of the creation 0600", got)
	}
	if err := unix.Fchmod(out, src.Mode&0o777); err != nil {
		t.Fatalf("fchmod: %v", err)
	}
	if got := permOf(t, dst); got != copySourceMode {
		t.Errorf("mode after fchmod = %04o, want %04o", got, copySourceMode)
	}
	times := []unix.Timespec{{Sec: time.Now().Unix()}, src.Mtim}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, dst, times, 0); err != nil {
		t.Fatalf("utimensat: %v", err)
	}
	closed = true
	if err := unix.Close(out); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The lookup is the one of O_EXCL (see dirNode.create).
	m.cost(t, "cp -a", map[string]int{"copy": 1, "lookup": 1})
	m.wantFile(t, dr, "", "archived.sh", data)
	n := m.api.node(dr, "", "archived.sh")
	if n.mode != "0755" || !n.mtime.Equal(copySourceTime) {
		t.Errorf("the copy has mode %q and time %v at the API, want 0755 and %v", n.mode, n.mtime, copySourceTime)
	}
	info, _ := stat(t, dst)
	if info.Mode().Perm() != copySourceMode || !info.ModTime().Equal(copySourceTime) {
		t.Errorf("stat of the copy: mode %04o, time %v", info.Mode().Perm(), info.ModTime())
	}
}

// The same when the source has no mode stored: its copy has none either,
// which is 0644 for everyone, and cp -a asking for 0644 stores nothing.
func TestCopy_ArchiveOfAFileWithoutAMode(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	data := testData(testChunkSize+5, 4)
	a.put(dr, "", copySourceName, fakeNode{
		kind: api.NodeTypeFile, data: data, mime: "text/plain", mtime: copySourceTime,
	})
	m := mountFS(t, a, single("dr1"))
	m.warm(t)
	dst := filepath.Join(m.dir, "plain-copy.txt")

	out, src := copyOpen(t, m, dst, 0o600, len(data))
	if src.Mode&0o777 != 0o644 {
		_ = unix.Close(out)
		t.Fatalf("mode shown for the source = %04o, want 0644", src.Mode&0o777)
	}
	err := unix.Fchmod(out, src.Mode&0o777)
	if err == nil {
		err = unix.UtimesNanoAt(unix.AT_FDCWD, dst, []unix.Timespec{{Sec: time.Now().Unix()}, src.Mtim}, 0)
	}
	if cerr := unix.Close(out); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}

	m.cost(t, "cp -a", map[string]int{"copy": 1, "lookup": 1})
	if n := m.api.node(dr, "", "plain-copy.txt"); n.mode != "" {
		t.Errorf("the API stored the mode %q for the copy of a file without one", n.mode)
	}
	if got := permOf(t, dst); got != 0o644 {
		t.Errorf("mode of the copy = %04o, want 0644", got)
	}
}

// cp without -a gives its destination a mode of its own and never changes
// it: that mode is sent once, when the file is closed, and is the one of the
// file from its creation on.
func TestCopy_ModeOfTheCreationIsSentAtClose(t *testing.T) {
	m, dr, data := copyMount(t)
	dst := filepath.Join(m.dir, "plain.sh")

	out, _ := copyOpen(t, m, dst, 0o644, len(data))
	if got := permOf(t, dst); got != 0o644 {
		t.Errorf("mode before the close = %04o, want 0644", got)
	}
	m.cost2(t, "cp, before the close", map[string]int{"copy": 1, "lookup": 1})
	if err := unix.Close(out); err != nil {
		t.Fatalf("close: %v", err)
	}
	m.cost(t, "cp, the close", map[string]int{"update": 1})
	if n := m.api.node(dr, "", "plain.sh"); n.mode != "0644" {
		t.Errorf("the copy has mode %q at the API, want 0644", n.mode)
	}
	if got := permOf(t, dst); got != 0o644 {
		t.Errorf("mode once closed = %04o, want 0644", got)
	}
	m.wantFile(t, dr, "", "plain.sh", data)
	if logs := m.logs.text(); logs != "" {
		t.Errorf("logs = %q", logs)
	}
}

// A chmod of a copy still open is sent when it is asked, once, and settles
// what the creation owed: the close sends nothing more. The copy written
// after that keeps the mode.
func TestCopy_ChmodBeforeTheClose(t *testing.T) {
	m, dr, data := copyMount(t)
	dst := filepath.Join(m.dir, "changed.sh")

	out, _ := copyOpen(t, m, dst, 0o600, len(data))
	m.cost2(t, "the copy", map[string]int{"copy": 1, "lookup": 1})
	if err := unix.Fchmod(out, 0o640); err != nil {
		_ = unix.Close(out)
		t.Fatalf("fchmod: %v", err)
	}
	if got := permOf(t, dst); got != 0o640 {
		t.Errorf("mode after fchmod = %04o, want 0640", got)
	}
	m.cost2(t, "fchmod to a third mode", map[string]int{"update": 1})
	if err := unix.Close(out); err != nil {
		t.Fatalf("close: %v", err)
	}
	m.cost(t, "the close", map[string]int{})
	if n := m.api.node(dr, "", "changed.sh"); n.mode != "0640" {
		t.Errorf("the copy has mode %q at the API, want 0640", n.mode)
	}

	// A mode owed outlives a version written before the close.
	dst = filepath.Join(m.dir, "written.sh")
	out, _ = copyOpen(t, m, dst, 0o600, len(data))
	if _, err := unix.Pwrite(out, []byte("patched"), 0); err != nil {
		_ = unix.Close(out)
		t.Fatalf("write: %v", err)
	}
	if err := unix.Fsync(out); err != nil {
		_ = unix.Close(out)
		t.Fatalf("fsync: %v", err)
	}
	if got := permOf(t, dst); got != 0o600 {
		t.Errorf("mode after a version was written = %04o, want 0600", got)
	}
	if err := unix.Close(out); err != nil {
		t.Fatalf("close: %v", err)
	}
	m.settle(t)
	if n, got := m.api.node(dr, "", "written.sh"), m.api.count("update"); n.mode != "0600" || got != 1 {
		t.Errorf("the copy written has mode %q at the API after %d updates, want 0600 and 1", n.mode, got)
	}
}

// utimensat and chmod ask the API only for what its node does not carry: a
// modification time is compared at the microsecond, which is what is stored.
func TestSetattr_SameValueCostsNothing(t *testing.T) {
	m, dr, _ := copyMount(t)
	path := filepath.Join(m.dir, "hello.txt")
	set := func(mtime time.Time, atime unix.Timespec) {
		t.Helper()
		times := []unix.Timespec{atime, unix.NsecToTimespec(mtime.UnixNano())}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, times, 0); err != nil {
			t.Fatalf("utimensat: %v", err)
		}
	}
	omit := unix.Timespec{Nsec: unix.UTIME_OMIT}
	other := time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.UTC)

	set(other, omit)
	m.cost(t, "another time", map[string]int{"patch": 1})
	set(other, omit)
	m.cost(t, "the same time", map[string]int{})
	// The access time is not stored, whatever it is.
	set(other, unix.NsecToTimespec(time.Now().UnixNano()))
	m.cost(t, "the same time and an access time", map[string]int{})
	set(other.Add(999*time.Nanosecond), omit)
	m.cost(t, "the same microsecond", map[string]int{})
	set(other.Add(time.Microsecond), omit)
	m.cost(t, "the next microsecond", map[string]int{"patch": 1})
	if n := m.api.node(dr, "", "hello.txt"); !n.mtime.Equal(other.Add(time.Microsecond)) {
		t.Errorf("the API holds the time %v", n.mtime)
	}

	// UTIME_NOW is a time like another, never the one held.
	before := time.Now().Add(-time.Second)
	now := []unix.Timespec{omit, {Nsec: unix.UTIME_NOW}}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, now, 0); err != nil {
		t.Fatalf("utimensat(UTIME_NOW): %v", err)
	}
	m.cost(t, "UTIME_NOW", map[string]int{"patch": 1})
	if n := m.api.node(dr, "", "hello.txt"); n.mtime.Before(before) {
		t.Errorf("UTIME_NOW left the time %v", n.mtime)
	}

	// The mode the node carries, then another.
	if err := chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	m.cost(t, "chmod to the mode held", map[string]int{})
	if err := chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	m.cost(t, "chmod to another mode", map[string]int{"update": 1})
}

// A file with no mode stored is 0644 for the API and for every client: a
// chmod to 0644 writes nothing, another mode is stored.
func TestSetattr_ChmodToTheDefaultOfAnUnsetMode(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	a.put(dr, "", "plain.txt", fakeNode{kind: api.NodeTypeFile, data: []byte("x"), mime: "text/plain"})
	m := mountFS(t, a, single("dr1"))
	m.warm(t)
	path := filepath.Join(m.dir, "plain.txt")
	if got := permOf(t, path); got != 0o644 {
		t.Fatalf("mode shown for a file without one = %04o, want 0644", got)
	}
	m.cost2(t, "the stat", map[string]int{})

	if err := unix.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	m.cost(t, "chmod to the default", map[string]int{})
	if n := m.api.node(dr, "", "plain.txt"); n.mode != "" {
		t.Errorf("the API stored the mode %q", n.mode)
	}
	if err := unix.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	m.cost(t, "chmod to another mode", map[string]int{"update": 1})
	if n := m.api.node(dr, "", "plain.txt"); n.mode != "0600" {
		t.Errorf("the API holds the mode %q, want 0600", n.mode)
	}
}

// A mount that goes away under a copy still open sends the mode it owes with
// the rest; one the API refuses is told to the operator, by identifiers.
func TestCopy_ShutdownSettlesTheMode(t *testing.T) {
	m, dr, data := copyMount(t)

	out, _ := copyOpen(t, m, filepath.Join(m.dir, "kept.sh"), 0o600, len(data))
	defer func() { _ = unix.Close(out) }()
	// Deleted elsewhere: its mode can be stored nowhere.
	gone, _ := copyOpen(t, m, filepath.Join(m.dir, "gone.sh"), 0o600, len(data))
	defer func() { _ = unix.Close(gone) }()
	id := m.api.node(dr, "", "gone.sh").id
	m.api.drop(dr, "", "gone.sh")
	m.api.resetCounts()

	// What Server.finish does to the spools.
	<-m.srv.drv.closeSpools()

	if n := m.api.node(dr, "", "kept.sh"); n.mode != "0600" {
		t.Errorf("the copy still open has mode %q at the API after the shutdown, want 0600", n.mode)
	}
	if got := m.api.count("update"); got != 2 {
		t.Errorf("%d updates during the shutdown, want one per file", got)
	}
	logs := m.logs.text()
	if strings.Count(logs, "the mode of a file could not be stored") != 1 ||
		!strings.Contains(logs, "node "+id) || !strings.Contains(logs, "ENOENT") {
		t.Errorf("logs = %q, want the mode refused reported once, by node", logs)
	}
	if strings.Contains(logs, "gone.sh") || strings.Contains(logs, "kept.sh") {
		t.Errorf("logs name a file: %q", logs)
	}
}
