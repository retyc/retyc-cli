//go:build linux

package retycfs

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// editorFiles are the patterns `retyc fs mount` keeps local by default
// (config.DefaultMountLocalFiles).
var editorFiles = []string{".*.swp", ".*.swx", "*~", "4913"}

// localMount mounts the sample tree read-write with the local files of an
// editor, its listings in cache and no request counted.
func localMount(t *testing.T) (*mounted, *fakeDataroom) {
	t.Helper()
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	opts := single("dr1")
	opts.driver.LocalFiles = editorFiles
	m := mountFS(t, a, opts)
	walk(t, m.dir)
	a.resetCounts()

	return m, dr
}

// sent waits until every file that is sent has been: the local files stay.
func (m *mounted) sent(t *testing.T) {
	t.Helper()
	eventually(t, "every spool that is sent to be closed", func() bool {
		for _, sp := range m.srv.drv.spools.open() {
			if !sp.local.Load() {
				return false
			}
		}

		return true
	})
}

// locals returns the number of local files the mount holds.
func (m *mounted) locals() int {
	count := 0
	for _, sp := range m.srv.drv.spools.open() {
		if sp.local.Load() {
			count++
		}
	}

	return count
}

// asked fails unless the requests counted since the last reset are want,
// then forgets them.
func (m *mounted) asked(t *testing.T, what string, want map[string]int) {
	t.Helper()
	m.sent(t)
	m.api.mu.Lock()
	got := maps.Clone(m.api.counts)
	m.api.mu.Unlock()
	if !maps.Equal(got, want) {
		t.Errorf("%s: requests = %s, want %v", what, m.api.summary(), want)
	}
	m.api.resetCounts()
}

func wantErrno(t *testing.T, what string, err error, want syscall.Errno) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s = %v, want %v", what, err, want)
	}
}

func wantContent(t *testing.T, path, want string) {
	t.Helper()
	if got, err := readFile(path); err != nil || string(got) != want {
		t.Errorf("%s reads %q, %v, want %q", filepath.Base(path), got, err, want)
	}
}

// exclusive creates path as an editor does, and closes it.
func exclusive(path string, extra int) (*os.File, error) {
	return openFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|extra)
}

// What vim does in the folder of a file it edits, call by call: every answer
// is the one of a local disk, and the API hears nothing of it.
func TestLocal_VimSequence(t *testing.T) {
	m, dr := localMount(t)
	swp := filepath.Join(m.dir, ".hello.txt.swp")
	swx := filepath.Join(m.dir, ".hello.txt.swx")

	// The probe of the swap file names.
	for _, path := range []string{swp, swx} {
		_, err := openFile(path, os.O_RDONLY)
		wantErrno(t, "open of a missing swap file", err, syscall.ENOENT)
		f, err := exclusive(path, 0)
		if err != nil {
			t.Fatalf("exclusive creation: %v", err)
		}
		_ = f.Close()
	}
	for _, path := range []string{swx, swp} {
		if err := os.Remove(path); err != nil {
			t.Errorf("unlink: %v", err)
		}
	}
	for range 3 {
		_, err := os.Lstat(swp)
		wantErrno(t, "stat of the removed swap file", err, syscall.ENOENT)
	}

	// The swap file itself, written and synced for as long as the edit lasts.
	f, err := exclusive(swp, syscall.O_NOFOLLOW)
	if err != nil {
		t.Fatalf("creation of the swap file: %v", err)
	}
	if err := f.Chmod(0o600); err != nil {
		t.Errorf("chmod: %v", err)
	}
	for _, block := range []string{"b0VIM ", "swap"} {
		if _, err := f.WriteString(block); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := f.Sync(); err != nil {
			t.Errorf("fsync: %v", err)
		}
	}
	_, err = exclusive(swp, 0)
	wantErrno(t, "exclusive creation over the swap file", err, syscall.EEXIST)
	if info, err := os.Stat(swp); err != nil || info.Size() != 10 || info.Mode().Perm() != 0o600 {
		t.Errorf("stat of the swap file = %v, %v, want 10 bytes and 0600", info, err)
	}
	wantContent(t, swp, "b0VIM swap")
	if !slices.Contains(walk(t, m.dir), ".hello.txt.swp") {
		t.Error("the swap file is not listed in its folder")
	}

	// Saving: the probe file and the backup, created then removed.
	probe, backup := filepath.Join(m.dir, "4913"), filepath.Join(m.dir, "hello.txt~")
	for _, path := range []string{probe, backup} {
		g, err := exclusive(path, 0)
		if err != nil {
			t.Fatalf("creation of %s: %v", filepath.Base(path), err)
		}
		_, _ = g.WriteString("hello")
		_ = g.Chmod(0o640)
		_ = g.Close()
		wantContent(t, path, "hello")
		if err := os.Remove(path); err != nil {
			t.Errorf("unlink: %v", err)
		}
		_, err = os.Lstat(path)
		wantErrno(t, "stat after the unlink", err, syscall.ENOENT)
	}

	// The file outlives its last handle, as it was left.
	if err := f.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	wantContent(t, swp, "b0VIM swap")
	if err := os.Truncate(swp, 5); err != nil {
		t.Errorf("truncate: %v", err)
	}
	if err := os.Chtimes(swp, m.srv.drv.attrs.epoch, m.srv.drv.attrs.epoch); err != nil {
		t.Errorf("utimens: %v", err)
	}
	wantContent(t, swp, "b0VIM")
	if err := appendTo(swp); err != nil {
		t.Errorf("a second open for writing: %v", err)
	}
	if n := m.locals(); n != 1 {
		t.Errorf("%d local files held, want the swap file alone", n)
	}

	// Leaving.
	if err := os.Remove(swp); err != nil {
		t.Errorf("unlink of the swap file: %v", err)
	}
	_, err = os.Lstat(swp)
	wantErrno(t, "stat after the last unlink", err, syscall.ENOENT)
	eventually(t, "the local files to be dropped", func() bool { return len(m.srv.drv.spools.open()) == 0 })

	m.asked(t, "the whole sequence", map[string]int{})
	for _, name := range []string{".hello.txt.swp", ".hello.txt.swx", "4913", "hello.txt~"} {
		if m.api.node(dr, "", name) != nil {
			t.Errorf("the API holds a node for a local file")
		}
	}
	// Neither the driver nor the access log names a file.
	if text := m.logs.text() + m.journal(4096); strings.Contains(text, "swp") || strings.Contains(text, "hello") {
		t.Errorf("a name reached the logs:\n%s", text)
	}
}

// With no listing in cache, a name that may be local costs the listing of its
// folder, and never a lookup by name.
func TestLocal_LookupReadsTheListing(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	opts := single("dr1")
	opts.driver.LocalFiles = editorFiles
	m := mountFS(t, a, opts)
	a.resetCounts()

	path := filepath.Join(m.dir, "docs", ".a.txt.swp")
	_, err := os.Lstat(path)
	wantErrno(t, "stat", err, syscall.ENOENT)
	f, err := exclusive(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if a.count("listing") == 0 {
		t.Error("the folder was never listed")
	}
	for kind, count := range map[string]int{
		"create_file": a.count("create_file"), "create_node": a.count("create_node"),
		"version": a.count("version"), "upload": a.count("upload"), "other": a.count("other"),
	} {
		if count != 0 {
			t.Errorf("%d %s requests", count, kind)
		}
	}
	// The one lookup by name is the one of the folder, a name like any other.
	if got := a.count("lookup"); got > 1 {
		t.Errorf("%d lookups by name, want at most the one of the folder (%s)", got, a.summary())
	}
}

// A node the dataroom holds under a name that matches is a file like any
// other: read, written and removed through the API.
func TestLocal_ExistingNodeIsNotLocal(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	a.file(dr, "", "notes~", []byte("remote"))
	opts := single("dr1")
	opts.driver.LocalFiles = editorFiles
	m := mountFS(t, a, opts)
	path := filepath.Join(m.dir, "notes~")
	id := a.node(dr, "", "notes~").id

	wantContent(t, path, "remote")
	_, err := exclusive(path, 0)
	wantErrno(t, "exclusive creation over a node", err, syscall.EEXIST)
	writeFile(t, path, []byte("rewritten"))
	m.sent(t)
	if got := stored(t, a, dr, "", "notes~"); string(got) != "rewritten" {
		t.Errorf("the API holds %q", got)
	}
	if node := a.node(dr, "", "notes~"); node == nil || node.id != id {
		t.Error("the node was replaced instead of given a version")
	}
	if n := m.locals(); n != 0 {
		t.Errorf("%d local files, want none", n)
	}
	a.resetCounts()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if a.count("delete") != 1 || a.node(dr, "", "notes~") != nil {
		t.Errorf("the node was not removed at the API (%s)", a.summary())
	}
}

// A local file renamed to a name that matches no pattern becomes a file of
// the dataroom: sent by the rename when no handle writes it, whose error is
// then the one of the upload.
func TestLocal_RenameToAnOrdinaryName(t *testing.T) {
	m, dr := localMount(t)
	draft, final := filepath.Join(m.dir, "draft~"), filepath.Join(m.dir, "draft.txt")
	writeFile(t, draft, []byte("v1"))
	m.asked(t, "a local file written and closed", map[string]int{})

	m.api.refuseUploads(true)
	err := os.Rename(draft, final)
	m.api.refuseUploads(false)
	wantErrno(t, "rename while the API refuses the upload", err, syscall.ENOSPC)
	wantContent(t, draft, "v1")
	if _, err := os.Lstat(final); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("the new name exists after a rename that failed: %v", err)
	}
	if m.locals() != 1 || m.api.node(dr, "", "draft.txt") != nil {
		t.Error("the file is not local any more after a rename that failed")
	}
	m.api.resetCounts()

	if err := os.Rename(draft, final); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := stored(t, m.api, dr, "", "draft.txt"); string(got) != "v1" {
		t.Errorf("the API holds %q once rename returned", got)
	}
	m.wantFile(t, dr, "", "draft.txt", []byte("v1"))
	_, err = os.Lstat(draft)
	wantErrno(t, "the old name", err, syscall.ENOENT)

	// With a handle that writes it, the close of that handle sends it.
	open, moved := filepath.Join(m.dir, "open~"), filepath.Join(m.dir, "open.txt")
	f, err := create(open)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("one ")
	if err := os.Rename(open, moved); err != nil {
		t.Fatalf("rename of an open local file: %v", err)
	}
	_, _ = f.WriteString("two")
	if err := f.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	m.wantFile(t, dr, "", "open.txt", []byte("one two"))

	// Over a node: a new version of that node.
	id := m.api.node(dr, "", "hello.txt").id
	over := filepath.Join(m.dir, "hello.txt~")
	writeFile(t, over, []byte("replaced"))
	if err := os.Rename(over, filepath.Join(m.dir, "hello.txt")); err != nil {
		t.Fatalf("rename over a node: %v", err)
	}
	m.wantFile(t, dr, "", "hello.txt", []byte("replaced"))
	if node := m.api.node(dr, "", "hello.txt"); node == nil || node.id != id {
		t.Error("the node replaced did not keep its ID")
	}
	if n := m.locals(); n != 0 {
		t.Errorf("%d local files left, want none", n)
	}
}

// Between two names that match, a local file stays local, replaces another,
// and asks nothing.
func TestLocal_RenameBetweenLocalNames(t *testing.T) {
	m, dr := localMount(t)
	a, b, c := filepath.Join(m.dir, "a~"), filepath.Join(m.dir, "docs", "b~"), filepath.Join(m.dir, "docs", "c~")
	writeFile(t, a, []byte("alpha"))
	writeFile(t, c, []byte("charlie"))

	if err := os.Rename(a, b); err != nil {
		t.Fatalf("rename: %v", err)
	}
	_, err := os.Lstat(a)
	wantErrno(t, "the old name", err, syscall.ENOENT)
	wantContent(t, b, "alpha")
	if err := os.Rename(b, c); err != nil {
		t.Fatalf("rename over a local file: %v", err)
	}
	wantContent(t, c, "alpha")
	eventually(t, "the replaced file to be dropped", func() bool { return m.locals() == 1 })
	m.asked(t, "renames between local names", map[string]int{})
	if m.api.node(dr, "", "a~") != nil || len(m.srv.drv.spools.open()) != 1 {
		t.Error("the renames left something at the API or in the registry")
	}
}

// A file of the dataroom renamed to a name that matches stays a node: one
// rename at the API, which replaces a local file under that name.
func TestLocal_RenameOfANodeToALocalName(t *testing.T) {
	m, dr := localMount(t)
	backup := filepath.Join(m.dir, "hello.txt~")
	if err := os.Rename(filepath.Join(m.dir, "hello.txt"), backup); err != nil {
		t.Fatalf("rename: %v", err)
	}
	m.asked(t, "a node renamed to a name that matches", map[string]int{"update": 1})
	if m.api.node(dr, "", "hello.txt~") == nil || m.locals() != 0 {
		t.Error("the node was not renamed at the API")
	}
	wantContent(t, backup, "hello")
	m.api.resetCounts()

	// Over a local file.
	held := filepath.Join(m.dir, "docs", "a.txt~")
	writeFile(t, held, []byte("local"))
	if err := os.Rename(filepath.Join(m.dir, "docs", "a.txt"), held); err != nil {
		t.Fatalf("rename over a local file: %v", err)
	}
	eventually(t, "the local file to be dropped", func() bool { return m.locals() == 0 })
	wantContent(t, held, "alpha")
	if m.api.count("update") != 1 || m.api.count("delete") != 0 {
		t.Errorf("requests = %s, want one rename", m.api.summary())
	}

	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	if m.api.count("delete") != 1 || m.api.node(dr, "", "hello.txt~") != nil {
		t.Errorf("the node was not removed at the API (%s)", m.api.summary())
	}
}

// A folder that holds local files only is not empty.
func TestLocal_RmdirOfAFolderOfLocalFiles(t *testing.T) {
	m, dr := localMount(t)
	dir := filepath.Join(m.dir, "work")
	if err := mkdir(dir); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ".x.swp"), []byte("x"))
	m.sent(t)
	m.api.resetCounts()

	wantErrno(t, "rmdir", os.Remove(dir), syscall.ENOTEMPTY)
	m.asked(t, "the rmdir refused", map[string]int{})
	if m.api.node(dr, "", "work") == nil {
		t.Fatal("the folder is gone from the API")
	}
	if err := os.Remove(filepath.Join(dir, ".x.swp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Errorf("rmdir once the local file is removed: %v", err)
	}
	if m.api.node(dr, "", "work") != nil {
		t.Error("the folder is still at the API")
	}
}

// A local file removed while open is written and read through its handle,
// and goes with it.
func TestLocal_UnlinkWhileOpen(t *testing.T) {
	m, _ := localMount(t)
	path := filepath.Join(m.dir, "held~")
	f, err := create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("still here"); err != nil {
		t.Errorf("write after the unlink: %v", err)
	}
	buf := make([]byte, 16)
	if n, _ := f.ReadAt(buf, 0); string(buf[:n]) != "still here" {
		t.Errorf("read after the unlink = %q", buf[:n])
	}
	if err := f.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	eventually(t, "the file to be dropped", func() bool { return len(m.srv.drv.spools.open()) == 0 })
	m.asked(t, "a local file unlinked while open", map[string]int{})
}

// The local files go with the mount, open or not: no loss is reported.
func TestLocal_ShutdownDropsThemSilently(t *testing.T) {
	m, dr := localMount(t)
	writeFile(t, filepath.Join(m.dir, "closed~"), []byte("closed"))
	f, err := create(filepath.Join(m.dir, ".open.swp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("open"); err != nil {
		t.Fatal(err)
	}
	// Nothing could be sent anyway: a flush would fail, and be a loss.
	m.api.refuseUploads(true)
	err = m.srv.Shutdown(context.Background())
	m.api.refuseUploads(false)
	_ = f.Close()

	if err != nil {
		t.Errorf("Shutdown = %v, want no error", err)
	}
	logs := m.logs.text()
	if strings.Contains(logs, "lost") || strings.Contains(logs, "sent as it was") {
		t.Errorf("the local files were reported:\n%s", logs)
	}
	if n := len(m.srv.drv.spools.open()); n != 0 {
		t.Errorf("%d spools left open", n)
	}
	m.asked(t, "the shutdown", map[string]int{})
	if m.api.node(dr, "", "closed~") != nil || m.api.node(dr, "", ".open.swp") != nil {
		t.Error("a local file reached the API at shutdown")
	}
	// The mount point was busy: a file was open.
	m.logs.forget()
}

// With closed local files only, the mount point is not busy.
func TestLocal_UnmountWithClosedFiles(t *testing.T) {
	m, _ := localMount(t)
	writeFile(t, filepath.Join(m.dir, "docs", "kept~"), []byte("kept"))
	if n := m.locals(); n != 1 {
		t.Fatalf("%d local files, want 1", n)
	}
	if err := m.srv.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown = %v", err)
	}
	if logs := m.logs.text(); logs != "" {
		t.Errorf("the shutdown reported:\n%s", logs)
	}
}

// No local file where nothing may be written.
func TestLocal_ReadOnly(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	opts := single("dr1")
	opts.driver.LocalFiles = editorFiles
	opts.driver.ReadOnly = true
	m := mountFS(t, a, opts)
	_, err := exclusive(filepath.Join(m.dir, ".hello.txt.swp"), 0)
	wantErrno(t, "a local file on a read-only mount", err, syscall.EROFS)
	if n := len(m.srv.drv.spools.open()); n != 0 {
		t.Errorf("%d spools open", n)
	}

	// A dataroom the user may only read, on a mount that is read-write.
	b := newFakeAPI(t)
	sampleTree(b)
	opts = single("dr1")
	opts.driver.LocalFiles = editorFiles
	opts.driver.Access = func(context.Context, string) (vfs.Access, error) {
		return vfs.Access{Role: "viewer", Writable: true, ReadOnly: true}, nil
	}
	viewer := mountFS(t, b, opts)
	_, err = exclusive(filepath.Join(viewer.dir, ".hello.txt.swp"), 0)
	wantErrno(t, "a local file in a dataroom the user cannot write to", err, syscall.EROFS)
	_, err = os.Lstat(filepath.Join(viewer.dir, ".hello.txt.swp"))
	wantErrno(t, "its name", err, syscall.ENOENT)
}

// Without patterns such a name is a file like any other: looked up by name,
// sent when it is closed.
func TestLocal_NoPatternNoLocalFile(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	f, err := exclusive(filepath.Join(m.dir, ".hello.txt.swp"), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("swap")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	m.wantFile(t, dr, "", ".hello.txt.swp", []byte("swap"))
	if m.api.count("lookup") != 1 || m.api.count("create_file") != 1 {
		t.Errorf("requests = %s, want the lookup of an exclusive creation and the upload", m.api.summary())
	}
}

func TestLocal_MalformedPattern(t *testing.T) {
	_, err := Mount(context.Background(), nil, t.TempDir(), Options{DataroomID: "dr1", LocalFiles: []string{"*~", "[a"}})
	if err == nil || !strings.Contains(err.Error(), `"[a"`) {
		t.Errorf("Mount with a malformed pattern = %v, want an error that quotes it", err)
	}
}

func TestLocal_Names(t *testing.T) {
	d := &driver{opts: Options{LocalFiles: editorFiles}}
	for name, want := range map[string]bool{
		".a.txt.swp": true, ".a.txt.swx": true, "a.txt~": true, "4913": true, "~": true,
		"a.swp": false, ".swp": false, "a.txt": false, "49130": false, ".~lock.a.odt#": false,
	} {
		if got := d.localName(name); got != want {
			t.Errorf("localName(%q) = %v, want %v", name, got, want)
		}
	}
	if (&driver{}).localName("a~") {
		t.Error("a name is local without patterns")
	}
}

// A local file whose folder the kernel forgot and was given a new inode for
// is found under the new one; a file that is sent never is.
func TestLocal_FoundUnderANewInodeOfItsFolder(t *testing.T) {
	// Two inodes of one number: the zero one.
	gone, live := &fs.Inode{}, &fs.Inode{}
	r := newSpoolRegistry()
	local, sending := &openSpool{}, &openSpool{}
	local.local.Store(true)
	r.add(local, location{parent: gone, name: "a~"})
	r.add(sending, location{parent: gone, name: "b.txt"})

	if got := r.find(location{parent: live, name: "a~"}); got != local {
		t.Fatal("the local file is not found under the new inode of its folder")
	}
	if _, stale := r.byAt[location{parent: gone, name: "a~"}]; stale || local.at.parent != live {
		t.Error("the local file was not moved to the place it was found at")
	}
	if r.find(location{parent: live, name: "b.txt"}) != nil {
		t.Error("a file being sent was found under another inode")
	}
	if r.find(location{parent: live, name: "c~"}) != nil {
		t.Error("a name nothing holds was found")
	}
}
