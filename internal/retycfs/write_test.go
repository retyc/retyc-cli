//go:build linux

package retycfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/sys/unix"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// The tests create their files with the default mode: under another umask
// each creation would cost the request that stores the mode.
func init() { syscall.Umask(0o022) }

// writable mounts the sample tree read-write.
func writable(t *testing.T) (*mounted, *fakeDataroom, []byte) {
	t.Helper()
	a := newFakeAPI(t)
	dr, big := sampleTree(a)

	return mountFS(t, a, single("dr1")), dr, big
}

// settle waits until no file is being written any more: the release of a
// handle comes after its close(2) has returned.
func (m *mounted) settle(t *testing.T) {
	t.Helper()
	eventually(t, "every spool to be closed", func() bool { return len(m.srv.drv.spools.open()) == 0 })
}

// warm lists the tree and writes one file, so that the listings and the MIME
// table are in cache, then forgets the requests counted.
func (m *mounted) warm(t *testing.T) {
	t.Helper()
	walk(t, m.dir)
	writeFile(t, filepath.Join(m.dir, "warm.txt"), []byte("warm"))
	m.settle(t)
	m.api.resetCounts()
}

// cost fails unless the requests counted since the last reset are want, then
// forgets them.
func (m *mounted) cost(t *testing.T, what string, want map[string]int) {
	t.Helper()
	m.settle(t)
	m.api.mu.Lock()
	got := maps.Clone(m.api.counts)
	m.api.mu.Unlock()
	if !maps.Equal(got, want) {
		t.Errorf("%s: requests = %s, want %v", what, m.api.summary(), want)
	}
	m.api.resetCounts()
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := writeMode(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", filepath.Base(path), err)
	}
}

// The files and the folders of these tests get the modes a user's would
// have, not the ones a program should give its own.

func writeMode(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func openFile(path string, flag int) (*os.File, error) {
	mode := os.FileMode(0o644)

	return os.OpenFile(path, flag, mode) //nolint:gosec // G304: a file of the test's mount
}

func create(path string) (*os.File, error) {
	return openFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
}

func mkdir(path string) error {
	mode := os.FileMode(0o755)

	return os.Mkdir(path, mode)
}

func chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// stored returns the content of a file as the API holds it.
func stored(t *testing.T, a *fakeAPI, dr *fakeDataroom, parent, name string) []byte {
	t.Helper()
	data, _, ok := a.content(dr, parent, name)
	if !ok {
		t.Fatalf("the API holds no file %s", name)
	}

	return data
}

// wantFile checks a file both ways: what the API holds, and what the mount
// reads back once the file is closed (through the chunks, like any reader).
func (m *mounted) wantFile(t *testing.T, dr *fakeDataroom, parent, rel string, want []byte) {
	t.Helper()
	m.settle(t)
	if got := stored(t, m.api, dr, parent, filepath.Base(rel)); !bytes.Equal(got, want) {
		t.Errorf("%s at the API: %d bytes, want %d", rel, len(got), len(want))
	}
	got, err := readFile(filepath.Join(m.dir, rel))
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("%s read back: %d bytes, %v, want %d", rel, len(got), err, len(want))
	}
	if info, err := os.Stat(filepath.Join(m.dir, rel)); err != nil || info.Size() != int64(len(want)) {
		t.Errorf("stat %s = %v, %v, want %d bytes", rel, info, err, len(want))
	}
}

func TestWrite_CreateAndReadBack(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	// echo > f: nothing at open, one request at close.
	small := []byte("hello, dataroom\n")
	writeFile(t, filepath.Join(m.dir, "new.txt"), small)
	m.cost(t, "a small file", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "new.txt", small)

	// Larger than one request takes: node, version, then its two chunks.
	large := testData(service.SmallUploadMaxSize+123, 7)
	m.api.resetCounts()
	writeFile(t, filepath.Join(m.dir, "large.bin"), large)
	m.cost(t, "a large file", map[string]int{"create_node": 1, "version": 1, "upload": 2})
	m.wantFile(t, dr, "", "large.bin", large)

	// Written again: a version of the same node.
	node := m.api.node(dr, "", "large.bin")
	larger := testData(service.SmallUploadMaxSize+4<<10, 9)
	m.api.resetCounts()
	writeFile(t, filepath.Join(m.dir, "large.bin"), larger)
	m.cost(t, "a large file overwritten", map[string]int{"version": 1, "upload": 2})
	m.wantFile(t, dr, "", "large.bin", larger)
	if again := m.api.node(dr, "", "large.bin"); again.id != node.id || again.version == node.version {
		t.Errorf("overwritten: node %s version %s, was node %s version %s", again.id, again.version, node.id, node.version)
	}

	if got := walk(t, m.dir); !slices.Contains(got, "new.txt") || !slices.Contains(got, "large.bin") {
		t.Errorf("tree = %v", got)
	}
	if s := m.api.count("other"); s != 0 {
		t.Errorf("%d unexpected requests", s)
	}
}

// for i in 1..10; do echo 1 > f$i; done in a folder nobody listed: the kernel
// looks each name up before creating it. The second lookup starts the listing
// of the folder, and once it is cached a creation costs its one request: no
// lookup by name, no other listing, although every creation changed the
// folder while or after it was listed.
func TestWrite_LoopInAFolderNeverListed(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	opts := single("dr1")
	opts.listAhead = true
	m := mountFS(t, a, opts)
	deep := m.api.node(dr, m.api.node(dr, "", "docs").id, "deep").id
	dir := filepath.Join(m.dir, "docs", "deep")
	m.api.resetCounts()

	for i := 1; i <= 2; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("f%d.txt", i)), []byte("1\n"))
	}
	m.settle(t)
	// docs, deep, f1.txt, f2.txt: one lookup by name each, and no more.
	if got := m.api.count("lookup"); got > 4 {
		t.Errorf("%d lookups by name for the first two files, want 4 (%s)", got, m.api.summary())
	}
	// Cached once a name nobody looked up is answered without the API.
	probe := 0
	eventually(t, "the listing of the folder to be cached", func() bool {
		before := m.api.count("lookup")
		probe++
		_, err := os.Lstat(filepath.Join(dir, fmt.Sprintf("probe%d", probe)))
		wantErrno(t, "stat", err, syscall.ENOENT)

		return m.api.count("lookup") == before
	})
	// The listing of the folder, and the one of the root when the desktop
	// session probed a name there (see desktopProbe): with docs, that is two.
	if got := m.api.count("listing"); got < 1 || got > 2 {
		t.Errorf("%d listings, want the one of the folder (%s)", got, m.api.summary())
	}
	m.api.resetCounts()

	for i := 3; i <= 10; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("f%d.txt", i)), []byte("1\n"))
	}
	m.cost(t, "eight more files", map[string]int{"create_file": 8})
	for i := 1; i <= 10; i++ {
		m.wantFile(t, dr, deep, fmt.Sprintf("docs/deep/f%d.txt", i), []byte("1\n"))
	}
	if s := m.api.count("other"); s != 0 {
		t.Errorf("%d unexpected requests", s)
	}
}

func TestWrite_ExistingFiles(t *testing.T) {
	m, dr, big := writable(t)
	docs := m.api.node(dr, "", "docs").id
	m.warm(t)

	// O_TRUNC: nothing of the version is downloaded.
	writeFile(t, filepath.Join(m.dir, "hello.txt"), []byte("bye"))
	m.cost(t, "O_TRUNC", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "hello.txt", []byte("bye"))

	// O_APPEND: the version comes in first.
	m.api.resetCounts()
	f, err := os.OpenFile(filepath.Join(m.dir, "docs", "a.txt"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{" and", " omega"} {
		if _, err := f.WriteString(part); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.cost(t, "O_APPEND", map[string]int{"chunk": 1, "create_file": 1})
	m.wantFile(t, dr, docs, "docs/a.txt", []byte("alpha and omega"))

	// truncate(1) to a size that is not zero: what is kept is downloaded,
	// then sent.
	keep := testChunkSize + 10
	m.api.resetCounts()
	if err := os.Truncate(filepath.Join(m.dir, "big.bin"), int64(keep)); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if info, err := os.Stat(filepath.Join(m.dir, "big.bin")); err != nil || info.Size() != int64(keep) {
		t.Errorf("stat after truncate = %v, %v", info, err)
	}
	m.settle(t)
	if n := m.api.count("create_file"); n != 1 {
		t.Errorf("truncate: %s, want one upload", m.api.summary())
	}
	m.wantFile(t, dr, "", "big.bin", big[:keep])

	// truncate to 0: one request, no download.
	m.api.resetCounts()
	if err := os.Truncate(filepath.Join(m.dir, "big.bin"), 0); err != nil {
		t.Fatalf("Truncate(0): %v", err)
	}
	m.cost(t, "truncate to 0", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "big.bin", nil)
}

func TestWrite_TouchTimesAndMode(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	// touch of a new name: an empty file, flushed.
	f, err := openFile(filepath.Join(m.dir, "touched"), os.O_WRONLY|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.cost(t, "touch", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "touched", nil)

	// utimens of a file that is not open: declared for its version.
	when := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	m.api.resetCounts()
	if err := os.Chtimes(filepath.Join(m.dir, "hello.txt"), when, when); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	m.cost(t, "utimens", map[string]int{"patch": 1})
	if _, mtime, _ := m.api.content(dr, "", "hello.txt"); !mtime.Equal(when) {
		t.Errorf("mtime at the API = %v, want %v", mtime, when)
	}
	if info, err := os.Stat(filepath.Join(m.dir, "hello.txt")); err != nil || !info.ModTime().Equal(when) {
		t.Errorf("stat after utimens = %v, %v", info, err)
	}

	// utimens of a file being written: sent with its content.
	f, err = create(filepath.Join(m.dir, "dated.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("dated"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f.Name(), when, when); err != nil {
		t.Fatalf("Chtimes of an open file: %v", err)
	}
	if info, err := f.Stat(); err != nil || !info.ModTime().Equal(when) || info.Size() != 5 {
		t.Errorf("fstat = %v, %v", info, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.cost(t, "a dated file", map[string]int{"create_file": 1})
	if _, mtime, _ := m.api.content(dr, "", "dated.txt"); !mtime.Equal(when) {
		t.Errorf("mtime of the file created = %v, want %v", mtime, when)
	}

	// chmod is stored; chown is accepted and ignored.
	if err := chmod(filepath.Join(m.dir, "hello.txt"), 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	m.cost(t, "chmod", map[string]int{"update": 1})
	if n := m.api.node(dr, "", "hello.txt"); n.mode != "0755" {
		t.Errorf("mode at the API = %q", n.mode)
	}
	if info, err := os.Stat(filepath.Join(m.dir, "hello.txt")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("stat after chmod = %v, %v", info, err)
	}
	if err := os.Chown(filepath.Join(m.dir, "hello.txt"), os.Getuid(), os.Getgid()); err != nil {
		t.Errorf("Chown: %v", err)
	}
	if err := chmod(filepath.Join(m.dir, "docs"), 0o700); err != nil {
		t.Errorf("Chmod of a folder: %v", err)
	}
	m.cost(t, "chown and a folder's mode", map[string]int{})

	// A file created with another mode than the default gets it,
	// with the request that creates it, single or not, and no other.
	if err := writeMode(filepath.Join(m.dir, "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m.cost(t, "an executable", map[string]int{"create_file": 1})
	if n := m.api.node(dr, "", "run.sh"); n.mode != "0755" {
		t.Errorf("mode of the file created = %q", n.mode)
	}
	if info, err := os.Stat(filepath.Join(m.dir, "run.sh")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("stat of the file created = %v, %v", info, err)
	}
	large := testData(service.SmallUploadMaxSize+1, 3)
	if err := writeMode(filepath.Join(m.dir, "tool.bin"), large, 0o750); err != nil {
		t.Fatal(err)
	}
	m.cost(t, "a large executable", map[string]int{"create_node": 1, "version": 1, "upload": 2})
	if n := m.api.node(dr, "", "tool.bin"); n.mode != "0750" {
		t.Errorf("mode of the large file created = %q", n.mode)
	}
	if info, err := os.Stat(filepath.Join(m.dir, "tool.bin")); err != nil || info.Mode().Perm() != 0o750 {
		t.Errorf("stat of the large file created = %v, %v", info, err)
	}

	// A mode given between the creation and the first flush travels with it.
	f, err = create(filepath.Join(m.dir, "late.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Chmod(0o700); err != nil {
		t.Fatalf("fchmod of a file not flushed yet: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.cost(t, "fchmod before the first flush", map[string]int{"create_file": 1})
	if n := m.api.node(dr, "", "late.sh"); n.mode != "0700" {
		t.Errorf("mode given before the first flush = %q", n.mode)
	}

	// A mode of 0 is a mode: stored as "0000" and presented as it is, never
	// as the default of a file that has none.
	if err := chmod(filepath.Join(m.dir, "hello.txt"), 0); err != nil {
		t.Fatalf("chmod 000: %v", err)
	}
	m.cost(t, "chmod 000", map[string]int{"update": 1})
	if n := m.api.node(dr, "", "hello.txt"); n.mode != "0000" {
		t.Errorf("mode at the API after chmod 000 = %q", n.mode)
	}
	if info, err := os.Stat(filepath.Join(m.dir, "hello.txt")); err != nil || info.Mode() != 0 {
		t.Errorf("stat after chmod 000 = %v, %v", info, err)
	}
	if err := writeMode(filepath.Join(m.dir, "none.bin"), []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	m.cost(t, "a file created with mode 0", map[string]int{"create_file": 1})
	if n := m.api.node(dr, "", "none.bin"); n.mode != "0000" {
		t.Errorf("mode of the file created with mode 0 = %q", n.mode)
	}
	if info, err := os.Stat(filepath.Join(m.dir, "none.bin")); err != nil || info.Mode() != 0 {
		t.Errorf("stat of the file created with mode 0 = %v, %v", info, err)
	}
}

func TestWrite_Folders(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	dir := filepath.Join(m.dir, "made")

	if err := mkdir(dir); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	m.cost(t, "mkdir", map[string]int{"create_node": 1})
	if err := mkdir(dir); !errors.Is(err, syscall.EEXIST) {
		t.Errorf("Mkdir again = %v, want EEXIST", err)
	}
	made := m.api.node(dr, "", "made")
	if made == nil {
		t.Fatal("the API holds no folder")
	}

	writeFile(t, filepath.Join(dir, "in.txt"), []byte("inside"))
	m.wantFile(t, dr, made.id, "made/in.txt", []byte("inside"))
	m.api.resetCounts()
	if err := os.Remove(dir); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Errorf("rmdir of a folder that holds a file = %v, want ENOTEMPTY", err)
	}
	m.cost(t, "rmdir refused", map[string]int{"listing": 1})

	if err := os.Remove(filepath.Join(dir, "in.txt")); err != nil {
		t.Fatalf("rm: %v", err)
	}
	m.cost(t, "rm", map[string]int{"delete": 1})
	if _, err := os.Stat(filepath.Join(dir, "in.txt")); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("stat after rm = %v", err)
	}

	// A file created and not flushed yet makes the folder not empty too.
	f, err := create(filepath.Join(dir, "pending"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Errorf("rmdir of a folder that holds a file being created = %v, want ENOTEMPTY", err)
	}
	if err := os.Remove(f.Name()); err != nil {
		t.Fatalf("rm of a file being created: %v", err)
	}
	_ = f.Close()
	m.cost(t, "a file created and removed", map[string]int{})

	if err := os.Remove(dir); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	m.cost(t, "rmdir", map[string]int{"listing": 1, "delete": 1})
	if m.api.node(dr, "", "made") != nil {
		t.Error("the folder is still at the API")
	}
	if got := walk(t, m.dir); slices.Contains(got, "made") {
		t.Errorf("tree = %v", got)
	}
}

func TestWrite_Rename(t *testing.T) {
	m, dr, _ := writable(t)
	docs := m.api.node(dr, "", "docs").id
	m.warm(t)
	at := func(rel string) string { return filepath.Join(m.dir, rel) }

	// mv, same folder.
	if err := os.Rename(at("hello.txt"), at("hi.txt")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	m.cost(t, "mv", map[string]int{"update": 1})
	m.wantFile(t, dr, "", "hi.txt", []byte("hello"))
	if _, err := os.Stat(at("hello.txt")); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("the old name: %v", err)
	}

	// mv over a file, from another folder: it replaces it.
	m.api.resetCounts()
	if err := os.Rename(at("docs/a.txt"), at("hi.txt")); err != nil {
		t.Fatalf("rename over a file: %v", err)
	}
	m.cost(t, "mv over a file", map[string]int{"update": 1})
	m.wantFile(t, dr, "", "hi.txt", []byte("alpha"))
	if m.api.node(dr, docs, "a.txt") != nil {
		t.Error("the source is still at the API")
	}

	// RENAME_NOREPLACE and RENAME_EXCHANGE.
	err := unix.Renameat2(unix.AT_FDCWD, at("hi.txt"), unix.AT_FDCWD, at("empty.txt"), unix.RENAME_NOREPLACE)
	if !errors.Is(err, syscall.EEXIST) {
		t.Errorf("RENAME_NOREPLACE over a file = %v, want EEXIST", err)
	}
	err = unix.Renameat2(unix.AT_FDCWD, at("hi.txt"), unix.AT_FDCWD, at("empty.txt"), unix.RENAME_EXCHANGE)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("RENAME_EXCHANGE = %v, want EINVAL", err)
	}
	if err := os.Rename(at("hi.txt"), at("docs")); err == nil {
		t.Error("a file renamed over a folder")
	}

	// What an editor does: write a temporary file, fsync, rename it over
	// the file.
	m.api.resetCounts()
	tmp, err := create(at(".hi.txt.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString("edited"); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if got := stored(t, m.api, dr, "", ".hi.txt.tmp"); string(got) != "edited" {
		t.Errorf("after fsync the API holds %q", got)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Rename(at(".hi.txt.tmp"), at("hi.txt")); err != nil {
		t.Fatalf("rename of the temporary file: %v", err)
	}
	m.cost(t, "the editor pattern", map[string]int{"create_file": 1, "update": 1})
	m.wantFile(t, dr, "", "hi.txt", []byte("edited"))
	if m.api.node(dr, "", ".hi.txt.tmp") != nil {
		t.Error("the temporary file is still at the API")
	}

	// A file that was never flushed is renamed at no request, and sent under
	// its new name.
	m.api.resetCounts()
	f, err := create(at("draft"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("draft"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(at("draft"), at("docs/final")); err != nil {
		t.Fatalf("rename of a file being created: %v", err)
	}
	m.cost2(t, "a pending file renamed", map[string]int{})
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.cost(t, "then closed", map[string]int{"create_file": 1})
	m.wantFile(t, dr, docs, "docs/final", []byte("draft"))
	if m.api.node(dr, "", "draft") != nil {
		t.Error("the file was sent under its old name")
	}

	// A folder: what is being written below it follows.
	g, err := create(at("docs/deep/late"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.WriteString("late"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(at("docs"), at("papers")); err != nil {
		t.Fatalf("rename of a folder: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close below a renamed folder: %v", err)
	}
	deep := m.api.node(dr, docs, "deep").id
	m.wantFile(t, dr, deep, "papers/deep/late", []byte("late"))
	if got, err := readFile(at("papers/deep/b.txt")); err != nil || string(got) != "bravo" {
		t.Errorf("below the renamed folder: %q, %v", got, err)
	}
}

// cost2 is cost without waiting for the spools to close: for a file still
// open.
func (m *mounted) cost2(t *testing.T, what string, want map[string]int) {
	t.Helper()
	m.api.mu.Lock()
	got := maps.Clone(m.api.counts)
	m.api.mu.Unlock()
	if !maps.Equal(got, want) {
		t.Errorf("%s: requests = %s, want %v", what, m.api.summary(), want)
	}
	m.api.resetCounts()
}

func TestWrite_SharedSpool(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	path := filepath.Join(m.dir, "hello.txt")

	// A reader opened before the file is written keeps its version.
	before, err := os.Open(path) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = before.Close() }()

	w1, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	w2, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w1.WriteAt([]byte("AA"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := w2.WriteAt([]byte("BB"), 2); err != nil {
		t.Fatal(err)
	}

	// Every handle of the inode sees one content: the other writer, stat, a
	// reader opened since. The one opened before keeps its version.
	got := make([]byte, 16)
	if n, _ := w2.ReadAt(got, 0); string(got[:n]) != "AABBo" {
		t.Errorf("the other writer reads %q", got[:n])
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 5 {
		t.Errorf("stat = %v, %v", info, err)
	}
	if n, _ := before.ReadAt(got, 0); string(got[:n]) != "hello" {
		t.Errorf("the reader opened before reads %q, want its version", got[:n])
	}
	if data := stored(t, m.api, dr, "", "hello.txt"); string(data) != "hello" {
		t.Errorf("the API holds %q before any close", data)
	}
	m.api.resetCounts()
	since, err := os.Open(path) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := since.ReadAt(got, 0); string(got[:n]) != "AABBo" {
		t.Errorf("a reader opened since reads %q", got[:n])
	}
	m.cost2(t, "a reader of a file being written", map[string]int{})
	// The close(2) and the fsync(2) of a reader send nothing: the file is
	// still being written, and what it holds now is no version of it.
	if err := since.Sync(); err != nil {
		t.Fatalf("Sync of the reader: %v", err)
	}
	if err := since.Close(); err != nil {
		t.Fatalf("Close of the reader: %v", err)
	}
	// Its release comes after its close has returned.
	eventually(t, "the reader to be released", func() bool {
		sp := m.srv.drv.spools.open()
		if len(sp) != 1 {
			return false
		}
		sp[0].st.mu.Lock()
		defer sp[0].st.mu.Unlock()

		return sp[0].refs == 2
	})
	m.cost2(t, "a reader of a file being written, closed", map[string]int{})
	if data := stored(t, m.api, dr, "", "hello.txt"); string(data) != "hello" {
		t.Errorf("the API holds %q after the close of a reader", data)
	}

	// One version for all the writers: the first close sends it, the other
	// finds the spool clean.
	if err := w1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.cost(t, "two writers closed", map[string]int{"create_file": 1})
	m.wantFile(t, dr, "", "hello.txt", []byte("AABBo"))
}

func TestWrite_PendingFileIsListed(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	path := filepath.Join(m.dir, "pending.txt")

	f, err := create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("12345"); err != nil {
		t.Fatal(err)
	}
	if m.api.node(dr, "", "pending.txt") != nil {
		t.Fatal("the API holds the file before any flush")
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Name() != "pending.txt" {
			continue
		}
		found = true
		if info, err := e.Info(); err != nil || info.Size() != 5 || time.Since(info.ModTime()) > time.Minute {
			t.Errorf("the entry of the file being created = %v, %v", info, err)
		}
	}
	if !found {
		t.Errorf("ls does not show the file being created: %v", entries)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 5 {
		t.Errorf("stat = %v, %v", info, err)
	}
	m.cost2(t, "a file being created", map[string]int{})
	if data, err := readFile(path); err != nil || string(data) != "12345" {
		t.Errorf("read = %q, %v", data, err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.wantFile(t, dr, "", "pending.txt", []byte("12345"))
	// The inode is the same before and after the file got a node.
	_, st := stat(t, path)
	if ino := m.srv.drv.inodes.ino(m.api.node(dr, "", "pending.txt").id); ino != st.Ino {
		t.Errorf("inode %d after the flush, the node has %d", st.Ino, ino)
	}
}

// The numbers of files created, looked at and removed do not pile up: once
// the kernel has forgotten them and the grace is over, the table lets them
// go, and a file looked up again gets a new number.
func TestWrite_ChurnDoesNotGrowTheInodeTable(t *testing.T) {
	m, _, _ := writable(t)
	m.warm(t)
	table := m.srv.drv.inodes
	before, _ := table.size()

	const files = 200
	for i := range files {
		path := filepath.Join(m.dir, fmt.Sprintf("churn-%d.txt", i))
		writeFile(t, path, []byte("x"))
		stat(t, path)
	}
	m.settle(t)
	kept := filepath.Join(m.dir, "hello.txt")
	_, first := stat(t, kept)
	if grown, _ := table.size(); grown < before+files {
		t.Fatalf("%d numbers after %d files created, want at least %d", grown, files, before+files)
	}
	for i := range files {
		if err := os.Remove(filepath.Join(m.dir, fmt.Sprintf("churn-%d.txt", i))); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	}
	walk(t, m.dir)

	// The kernel forgets a removed file as soon as nothing uses it; past the
	// grace, the sweep drops its number.
	table.advance(handoutGrace + time.Second)
	eventually(t, "the numbers of the removed files to go", func() bool {
		table.sweep()
		ids, _ := table.size()

		return ids <= before
	})
	// A file the kernel still holds keeps its number.
	if _, again := stat(t, kept); again.Ino != first.Ino {
		t.Errorf("hello.txt: inode %d then %d while the kernel holds it", first.Ino, again.Ino)
	}
}

// The kernel's FORGETs alone release the records and the objects they hold:
// nothing is assigned afterwards, the table does not grow, the sweep the
// FORGETs scheduled does it.
func TestWrite_ForgetsReleaseTheInodeTable(t *testing.T) {
	m, _, _ := writable(t)
	m.warm(t)
	table := m.srv.drv.inodes
	table.mu.Lock()
	scheduled := table.manualSweeps()
	table.mu.Unlock()
	sweeps := func() []func() {
		table.mu.Lock()
		defer table.mu.Unlock()

		return scheduled()
	}
	before, _ := table.records()

	const files = 200
	for i := range files {
		path := filepath.Join(m.dir, fmt.Sprintf("forgotten-%d.txt", i))
		writeFile(t, path, []byte("x"))
		stat(t, path)
	}
	m.settle(t)
	if recs, objects := table.records(); recs < before+files || objects < before+files {
		t.Fatalf("%d records holding %d objects after %d files, want at least %d", recs, objects, files, before+files)
	}
	for i := range files {
		if err := os.Remove(filepath.Join(m.dir, fmt.Sprintf("forgotten-%d.txt", i))); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	}
	m.settle(t)

	// Each FORGET of the kernel is one for the table; the sweep they
	// scheduled runs past the grace and is followed by another while
	// FORGETs keep coming.
	table.advance(forgetSweepDelay)
	eventually(t, "the records of the forgotten files to go", func() bool {
		for _, sweep := range sweeps() {
			sweep()
		}
		recs, objects := table.records()

		return recs <= before && objects <= before
	})
}

func TestWrite_UnlinkOfAnOpenFile(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	// Flushed, then removed while open: nothing is created again.
	path := filepath.Join(m.dir, "gone.txt")
	f, err := create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("first"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if _, err := f.WriteString(" second"); err != nil {
		t.Errorf("write after the unlink: %v", err)
	}
	got := make([]byte, 32)
	if n, _ := f.ReadAt(got, 0); string(got[:n]) != "first second" {
		t.Errorf("read after the unlink = %q", got[:n])
	}
	if info, err := f.Stat(); err != nil || info.Size() != 12 {
		t.Errorf("fstat after the unlink = %v, %v", info, err)
	}
	m.api.resetCounts()
	if err := f.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	m.cost(t, "closing a file removed", map[string]int{})
	if m.api.node(dr, "", "gone.txt") != nil {
		t.Error("the file came back at the API")
	}
	if _, err := os.Stat(path); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("stat = %v", err)
	}

	// A file read while it is removed keeps being read.
	r, err := os.Open(filepath.Join(m.dir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := os.Remove(r.Name()); err != nil {
		t.Fatalf("rm of a file open for reading: %v", err)
	}
	if n, err := r.ReadAt(got, int64(testChunkSize)); err != nil || n != len(got) {
		t.Errorf("read after the unlink = %d, %v", n, err)
	}
	if s := m.api.count("other"); s != 0 {
		t.Errorf("%d unexpected requests", s)
	}
}

func TestWrite_QuotaIsReportedAtClose(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	m.api.refuseUploads(true)

	for name, data := range map[string][]byte{"small.txt": []byte("x"), "large.bin": testData(1<<20, 3)} {
		path := filepath.Join(m.dir, name)
		f, err := create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		if err := f.Close(); !errors.Is(err, syscall.ENOSPC) {
			t.Errorf("%s: Close = %v, want ENOSPC", name, err)
		}
		m.settle(t)
		if n := m.api.node(dr, "", name); n != nil && n.version != "" {
			t.Errorf("%s: the API holds a version", name)
		}
		// Never stored: the name goes with its last handle.
		eventually(t, name+" to be gone", func() bool {
			_, err := os.Stat(path)

			return errors.Is(err, syscall.ENOENT)
		})
	}
	if logs := m.logs.text(); !strings.Contains(logs, "last flush of a file failed") || !strings.Contains(logs, "ENOSPC") {
		t.Errorf("the operator was not told of the lost changes:\n%s", logs)
	}

	// An existing file keeps its content, and the next close succeeds.
	path := filepath.Join(m.dir, "hello.txt")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("kept in the spool"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("fsync = %v, want ENOSPC", err)
	}
	m.api.refuseUploads(false)
	if err := f.Close(); err != nil {
		t.Errorf("Close once there is room = %v", err)
	}
	m.wantFile(t, dr, "", "hello.txt", []byte("kept in the spool"))
}

// The kernel asks for a creation when it believes a name is free; the name
// may have been taken elsewhere since it last asked.
func TestWrite_CreateOverAFileCreatedElsewhere(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	opts := single("dr1")
	opts.driver.NegativeTimeout = time.Minute
	m := mountFS(t, a, opts)
	path := filepath.Join(m.dir, "race.txt")

	if _, err := os.Stat(path); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("stat = %v", err)
	}
	a.file(dr, "", "race.txt", []byte("theirs"))
	node := a.node(dr, "", "race.txt")
	time.Sleep(1100 * time.Millisecond) // vfs.DefaultNegativeTTL

	if f, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL); !errors.Is(err, syscall.EEXIST) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("O_EXCL over a file created elsewhere = %v, want EEXIST", err)
	}
	f, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND)
	if err != nil {
		t.Fatalf("O_CREAT over a file created elsewhere: %v", err)
	}
	if _, err := f.WriteString(" and ours"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.wantFile(t, dr, "", "race.txt", []byte("theirs and ours"))
	if again := a.node(dr, "", "race.txt"); again.id != node.id {
		t.Errorf("the file was replaced by node %s, was %s", again.id, node.id)
	}
}

func TestWrite_AllDataroomsAndCrossDataroom(t *testing.T) {
	a := newFakeAPI(t)
	one := a.dataroom("dr1", "One")
	two := a.dataroom("dr2", "Two")
	a.file(one, "", "a.txt", []byte("alpha"))
	var asked atomic.Int32
	access := func(_ context.Context, id string) (vfs.Access, error) {
		asked.Add(1)
		if id == "dr2" {
			return vfs.Access{Role: api.RoleViewer, Writable: true, ReadOnly: true}, nil
		}

		return vfs.Access{Role: "editor", Writable: true}, nil
	}
	m := mountFS(t, a, mountOptions{driver: Options{All: true, Access: access}})

	writeFile(t, filepath.Join(m.dir, "One", "b.txt"), []byte("bravo"))
	m.wantFile(t, one, "", "One/b.txt", []byte("bravo"))

	// A dataroom the user may only read.
	if err := writeMode(filepath.Join(m.dir, "Two", "c.txt"), []byte("x"), 0o644); !errors.Is(err, syscall.EROFS) {
		t.Errorf("a write in a read-only dataroom = %v, want EROFS", err)
	}
	if err := mkdir(filepath.Join(m.dir, "Two", "d")); !errors.Is(err, syscall.EROFS) {
		t.Errorf("mkdir in a read-only dataroom = %v, want EROFS", err)
	}
	// Between two datarooms: mv copies and deletes.
	err := os.Rename(filepath.Join(m.dir, "One", "a.txt"), filepath.Join(m.dir, "Two", "a.txt"))
	if !errors.Is(err, syscall.EXDEV) {
		t.Errorf("rename between two datarooms = %v, want EXDEV", err)
	}
	if err := writeMode(filepath.Join(m.dir, "new.txt"), nil, 0o644); !errors.Is(err, syscall.EPERM) {
		t.Errorf("a file where datarooms are listed = %v, want EPERM", err)
	}
	if n := len(two.children[""]); n != 0 {
		t.Errorf("%d nodes in the read-only dataroom", n)
	}
	// Asked when a dataroom is first entered, and remembered.
	walk(t, m.dir)
	if n := asked.Load(); n != 2 {
		t.Errorf("Access asked %d times, want once per dataroom", n)
	}
	if logs := m.logs.text(); !strings.Contains(logs, "dataroom dr2 is read-only: you are a viewer") {
		t.Errorf("the operator is not told why dr2 is read-only:\n%s", logs)
	}
}

// While Access cannot answer for a dataroom, it is read and not written; the
// operator is told once, and the next access asks again.
func TestWrite_AccessUnknown(t *testing.T) {
	a := newFakeAPI(t)
	one := a.dataroom("dr1", "One")
	a.file(one, "", "a.txt", []byte("alpha"))
	var down atomic.Bool
	down.Store(true)
	access := func(context.Context, string) (vfs.Access, error) {
		if down.Load() {
			return vfs.Access{}, &api.HTTPError{Status: 503}
		}

		return vfs.Access{Writable: true}, nil
	}
	m := mountFS(t, a, mountOptions{driver: Options{All: true, Access: access}})

	if got, err := os.ReadFile(filepath.Join(m.dir, "One", "a.txt")); err != nil || string(got) != "alpha" {
		t.Errorf("read while Access fails = %q, %v", got, err)
	}
	for range 2 {
		if err := writeMode(filepath.Join(m.dir, "One", "b.txt"), []byte("x"), 0o644); !errors.Is(err, syscall.EROFS) {
			t.Errorf("a write while Access fails = %v, want EROFS", err)
		}
		if _, err := os.ReadDir(filepath.Join(m.dir, "One")); err != nil {
			t.Errorf("ReadDir while Access fails: %v", err)
		}
	}
	if n := strings.Count(m.logs.text(), "cannot tell whether it is writable"); n != 1 {
		t.Errorf("the failure is reported %d times, want once:\n%s", n, m.logs.text())
	}

	down.Store(false)
	if _, err := os.ReadDir(filepath.Join(m.dir, "One")); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	writeFile(t, filepath.Join(m.dir, "One", "b.txt"), []byte("bravo"))
	m.wantFile(t, one, "", "One/b.txt", []byte("bravo"))
}

// ln -s: the link is there at once, whatever its target names, and is
// removed and renamed like a file.
func TestWrite_Symlink(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	for name, target := range map[string]string{
		"rel": "docs/a.txt", "dangling": "nowhere/at all", "abs": "/etc/hostname",
	} {
		path := filepath.Join(m.dir, name)
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("Symlink(%s): %v", name, err)
		}
		m.cost(t, "ln -s "+name, map[string]int{"symlink": 1})
		if got, err := os.Readlink(path); err != nil || got != target {
			t.Errorf("readlink %s = %q, %v, want %q", name, got, err, target)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 || info.Size() != int64(len(target)) {
			t.Errorf("lstat %s = %v, %v", name, info, err)
		}
		if n := m.api.node(dr, "", name); n == nil || n.kind != api.NodeTypeSymlink || n.target != target {
			t.Errorf("the API holds %+v for %s", n, name)
		}
	}
	m.cost(t, "readlink and lstat of links just made", map[string]int{})
	if got, err := os.ReadFile(filepath.Join(m.dir, "rel")); err != nil || string(got) != "alpha" {
		t.Errorf("read through the link = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "dangling")); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("stat through a dangling link = %v, want ENOENT", err)
	}
	if !slices.Contains(walk(t, m.dir), "dangling") {
		t.Error("the link is not listed")
	}
	if err := os.Symlink("x", filepath.Join(m.dir, "rel")); !errors.Is(err, syscall.EEXIST) {
		t.Errorf("a link over a name that is taken = %v, want EEXIST", err)
	}
	m.api.resetCounts()

	// mv, then rm.
	if err := os.Rename(filepath.Join(m.dir, "abs"), filepath.Join(m.dir, "docs", "moved")); err != nil {
		t.Fatalf("Rename of a link: %v", err)
	}
	m.cost(t, "mv of a link", map[string]int{"update": 1})
	if got, err := os.Readlink(filepath.Join(m.dir, "docs", "moved")); err != nil || got != "/etc/hostname" {
		t.Errorf("readlink after mv = %q, %v", got, err)
	}
	if err := os.Remove(filepath.Join(m.dir, "dangling")); err != nil {
		t.Fatalf("Remove of a link: %v", err)
	}
	m.cost(t, "rm of a link", map[string]int{"delete": 1})
	if _, err := os.Lstat(filepath.Join(m.dir, "dangling")); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("lstat after rm = %v, want ENOENT", err)
	}
	if m.api.node(dr, "", "dangling") != nil || m.api.node(dr, "", "abs") != nil {
		t.Error("the API still holds a link removed or moved")
	}

	// Hard links and device nodes stay refused.
	if err := os.Link(filepath.Join(m.dir, "hello.txt"), filepath.Join(m.dir, "hard")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("link = %v, want EPERM", err)
	}
	if err := unix.Mknod(filepath.Join(m.dir, "fifo"), unix.S_IFIFO|0o600, 0); !errors.Is(err, syscall.EPERM) {
		t.Errorf("mknod = %v, want EPERM", err)
	}
}

// cp runs cp(1), which copies with copy_file_range (coreutils 9 and later).
func cp(t *testing.T, src, dst string) {
	t.Helper()
	cmd := exec.Command("cp", src, dst) //nolint:gosec // G204: files of the test's mount
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cp to %s: %v: %s", filepath.Base(dst), err, out)
	}
}

// cp of a whole file into a new one is a server-side copy: one request, no
// chunk downloaded or sent, the same content.
func TestWrite_CopyIsServerSide(t *testing.T) {
	m, dr, big := writable(t)
	m.warm(t)

	src, dst := filepath.Join(m.dir, "big.bin"), filepath.Join(m.dir, "docs", "copy.bin")
	cp(t, src, dst)
	// cp creates its destination with O_EXCL: the lookup that checks the
	// name with the API (see dirNode.create).
	m.cost(t, "cp of a file of several chunks", map[string]int{"copy": 1, "lookup": 1})
	if info, err := os.Stat(dst); err != nil || info.Size() != int64(len(big)) {
		t.Errorf("stat of the copy = %v, %v", info, err)
	}
	docs := m.api.node(dr, "", "docs").id
	m.wantFile(t, dr, docs, "docs/copy.bin", big)
	if a, b := m.api.node(dr, "", "big.bin"), m.api.node(dr, docs, "copy.bin"); a.id == b.id || a.version == b.version {
		t.Errorf("the copy is not a node of its own: %+v and %+v", a, b)
	}
	m.api.resetCounts()

	// The copy is a file like another: written, it gets a new version.
	f, err := os.OpenFile(dst, os.O_WRONLY, 0) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("patched"), 3); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	patched := slices.Clone(big)
	copy(patched[3:], "patched")
	m.wantFile(t, dr, docs, "docs/copy.bin", patched)
	m.wantFile(t, dr, "", "big.bin", big)
	m.api.resetCounts()

	// Anything but a whole file into a new one is copied by the kernel,
	// through reads and writes: a file that exists (it keeps its node and
	// gets a version), a part of a file.
	before := m.api.node(dr, "", "hello.txt").id
	cp(t, src, filepath.Join(m.dir, "hello.txt"))
	m.settle(t)
	if n := m.api.count("copy"); n != 0 {
		t.Errorf("%d server-side copies over a file that exists, want none", n)
	}
	if after := m.api.node(dr, "", "hello.txt").id; after != before {
		t.Errorf("the file copied over is node %s, was %s", after, before)
	}
	m.wantFile(t, dr, "", "hello.txt", big)

	in, err := os.Open(src) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	// The system call itself, for a whole file: one request again.
	whole, err := create(filepath.Join(m.dir, "whole.bin"))
	if err != nil {
		t.Fatal(err)
	}
	m.api.resetCounts()
	fdSrc, fdWhole := int(in.Fd()), int(whole.Fd()) //nolint:gosec // G115: file descriptors
	if n, err := unix.CopyFileRange(fdSrc, nil, fdWhole, nil, 1<<30, 0); err != nil || n != len(big) {
		t.Fatalf("copy_file_range of the whole file = %d, %v, want %d", n, err, len(big))
	}
	if err := whole.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.cost(t, "copy_file_range of a whole file", map[string]int{"copy": 1})
	m.wantFile(t, dr, "", "whole.bin", big)
	m.api.resetCounts()

	part, err := create(filepath.Join(m.dir, "part.bin"))
	if err != nil {
		t.Fatal(err)
	}
	from := int64(testChunkSize - 10)
	fdIn, fdOut := int(in.Fd()), int(part.Fd()) //nolint:gosec // G115: file descriptors
	if n, err := unix.CopyFileRange(fdIn, &from, fdOut, nil, 100, 0); err != nil || n != 100 {
		t.Fatalf("copy_file_range of a part = %d, %v", n, err)
	}
	if err := part.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.settle(t)
	if n := m.api.count("copy"); n != 0 {
		t.Errorf("%d server-side copies of a part of a file, want none", n)
	}
	m.wantFile(t, dr, "", "part.bin", big[testChunkSize-10:testChunkSize+90])
}

// The errors of a write, as close(2), write(2) and rename(2) report them.
func TestToErrno_Writes(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want syscall.Errno
	}{
		"no room in the dataroom": {vfs.ErrStorageExceeded, syscall.ENOSPC},
		"no room for the spool":   {fmt.Errorf("write: %w", vfs.ErrSpoolFull), syscall.ENOSPC},
		"refused":                 {vfs.ErrForbidden, syscall.EACCES},
		"dataroom read-only":      {errors.Join(vfs.ErrReadOnly, vfs.ErrForbidden), syscall.EROFS},
		"401":                     {&api.HTTPError{Status: 401}, syscall.EACCES},
		"rate limit":              {fmt.Errorf("upload: %w", api.ErrRateLimited), syscall.EIO},
		"name being deleted":      {fmt.Errorf("create: %w", vfs.ErrNameBeingDeleted), syscall.EBUSY},
		"locked elsewhere":        {api.ErrLocked, syscall.EBUSY},
		"folder not empty":        {vfs.ErrNotEmpty, syscall.ENOTEMPTY},
		"name taken":              {vfs.ErrExist, syscall.EEXIST},
		"spool closed":            {vfs.ErrClosed, syscall.EIO},
		"an API without symlinks": {fmt.Errorf("symlink: %w", vfs.ErrSymlinkUnsupported), syscall.EPERM},
	} {
		if got := toErrno(tc.err); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// A dataroom the API reports read-only (403 DATAROOM_READ_ONLY: the role
// allows the write, the owner's plan does not) answers EROFS, not EACCES.
func TestWrite_ReadOnlyDataroomIsEROFS(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	m := mountFS(t, a, single("dr1"))
	walk(t, m.dir)
	a.mu.Lock()
	a.readOnly = true
	a.mu.Unlock()

	wantErrno(t, "mkdir", os.Mkdir(filepath.Join(m.dir, "new"), 0o750), syscall.EROFS)
	wantErrno(t, "chmod", os.Chmod(filepath.Join(m.dir, "hello.txt"), 0o600), syscall.EROFS)
	wantErrno(t, "symlink", os.Symlink("hello.txt", filepath.Join(m.dir, "ln")), syscall.EROFS)
	wantErrno(t, "rename", os.Rename(filepath.Join(m.dir, "hello.txt"), filepath.Join(m.dir, "hi.txt")), syscall.EROFS)
	wantErrno(t, "unlink", os.Remove(filepath.Join(m.dir, "empty.txt")), syscall.EROFS)
	wantErrno(t, "utimes", os.Chtimes(filepath.Join(m.dir, "hello.txt"), time.Now(), time.Now()), syscall.EROFS)

	// The upload of a written file is refused at its close.
	f, err := create(filepath.Join(m.dir, "written.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("refused"); err != nil {
		t.Fatal(err)
	}
	wantErrno(t, "close", f.Close(), syscall.EROFS)
	m.settle(t) // the release closes the spool: its loss is logged there, not at the unmount
}

// A mount that goes away under a file still open (detached while busy) sends
// what the file holds: nothing else will.
func TestCloseSpools_SendsWhatIsStillOpen(t *testing.T) {
	m, dr, _ := writable(t)
	drv := m.srv.drv

	f, err := create(filepath.Join(m.dir, "held.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("held"); err != nil {
		t.Fatal(err)
	}
	if m.api.node(dr, "", "held.txt") != nil {
		t.Fatal("the API holds the file before any flush")
	}
	drv.closeSpools()
	if got := stored(t, m.api, dr, "", "held.txt"); string(got) != "held" {
		t.Errorf("the API holds %q", got)
	}
	if open := drv.spools.open(); len(open) != 0 {
		t.Errorf("%d spools still open", len(open))
	}
	// The operator is told, by IDs: the version is whatever the writer had
	// written so far.
	logs := m.logs.text()
	if strings.Count(logs, "sent as it was at shutdown, the file was still open") != 1 ||
		strings.Contains(logs, "held.txt") || strings.Contains(logs, "lost") {
		t.Errorf("logs = %q", logs)
	}
	// The handle outlived its spool: its close has nothing left to send.
	_ = f.Close()
}

// A file still open at shutdown whose flush fails is reported lost, once.
func TestCloseSpools_ReportsWhatCouldNotBeSent(t *testing.T) {
	m, dr, _ := writable(t)
	drv := m.srv.drv

	f, err := create(filepath.Join(m.dir, "held.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("held"); err != nil {
		t.Fatal(err)
	}
	m.api.refuseUploads(true)
	drv.closeSpools()
	m.api.refuseUploads(false)
	if m.api.node(dr, "", "held.txt") != nil {
		t.Error("the API holds the file")
	}
	logs := m.logs.text()
	if strings.Count(logs, "its changes are lost") != 1 || strings.Contains(logs, "held.txt") ||
		strings.Contains(logs, "sent as it was") {
		t.Errorf("logs = %q", logs)
	}
	_ = f.Close()
}

// ops returns the number of operations op the access log holds: an operation
// is recorded once its handler has returned.
func (m *mounted) ops(op string) (n int) {
	l := m.srv.drv.log
	l.mu.Lock()
	defer l.mu.Unlock()
	for seq := l.oldestLocked(); seq < l.next; seq++ {
		if l.ring[seq%uint64(len(l.ring))].op == op {
			n++
		}
	}

	return n
}

// holdRequests makes the API hold back the first request match accepts, until
// the function returned is called. arrived tells that it is held.
func (a *fakeAPI) holdRequests(match func(r *http.Request) bool) (arrived <-chan struct{}, release func()) {
	here, gate := make(chan struct{}), make(chan struct{})
	var first, open sync.Once
	a.mu.Lock()
	a.before = func(r *http.Request) {
		if match(r) {
			first.Do(func() {
				close(here)
				<-gate
			})
		}
	}
	a.mu.Unlock()

	return here, func() { open.Do(func() { close(gate) }) }
}

// A spool the registry dropped is closed: a rename that ends after the last
// release must not put it back under its new name, where it would answer for
// the file for good.
func TestSpoolRegistry_MoveOfADroppedSpool(t *testing.T) {
	r := newSpoolRegistry()
	dir := new(fs.Inode)
	from, to := location{parent: dir, name: "tmp"}, location{parent: dir, name: "f"}

	sp := &openSpool{}
	r.add(sp, from)
	r.move(sp, to)
	if r.find(to) != sp || r.find(from) != nil {
		t.Fatal("an open spool did not move")
	}
	r.drop(sp)
	r.move(sp, from)
	r.unname(sp)
	if len(r.named()) != 0 || len(r.open()) != 0 {
		t.Errorf("a dropped spool is registered again: %d named, %d open", len(r.named()), len(r.open()))
	}
}

// An operation that holds a spool keeps it open across the release of its
// last handle, and closes it when it lets go.
func TestOpenSpool_HoldOutlivesTheLastRelease(t *testing.T) {
	m, dr, _ := writable(t)
	drv := m.srv.drv

	f, err := create(filepath.Join(m.dir, "held.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("held"); err != nil {
		t.Fatal(err)
	}
	sp := drv.spools.open()[0]
	if sp.hold() != sp {
		t.Fatal("hold refused the spool of an open file")
	}
	releases := m.ops("release")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the release of the handle", func() bool { return m.ops("release") > releases })
	if open := drv.spools.open(); len(open) != 1 || drv.spools.find(sp.st.where()) != sp {
		t.Fatalf("the spool was closed while held: %d open", len(open))
	}
	sp.letGo(context.Background())
	if len(drv.spools.open()) != 0 || len(drv.spools.named()) != 0 {
		t.Error("the spool outlived its last reference")
	}
	if sp.hold() != nil {
		t.Error("hold took a closed spool")
	}
	if got := stored(t, m.api, dr, "", "held.txt"); string(got) != "held" {
		t.Errorf("the API holds %q", got)
	}
}

// close(2) returns before the release of the handle reaches the driver, so a
// program that writes a temporary file, closes it and renames it has its
// rename cross the release that closes the spool. The spool must not come
// back under the new name.
func TestWrite_RenameAcrossTheLastRelease(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	drv := m.srv.drv
	dir := filepath.Join(m.dir, "work")
	if err := mkdir(dir); err != nil {
		t.Fatal(err)
	}
	f, err := create(filepath.Join(dir, "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("content"); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}

	// The file is closed while the API holds the rename back, and the rename
	// answered once the spool is gone, or after a moment when the driver
	// keeps it (which it does: the rename holds it).
	closed := make(chan error, 1)
	arrived, release := m.api.holdRequests(func(r *http.Request) bool { return r.Method == http.MethodPut })
	defer release()
	go func() {
		<-arrived
		go func() { closed <- f.Close() }()
		for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); {
			if len(drv.spools.open()) == 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		release()
	}()
	if err := os.Rename(filepath.Join(dir, "tmp"), filepath.Join(dir, "f")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.settle(t)

	if named := drv.spools.named(); len(named) != 0 {
		t.Fatalf("%d closed spools still hold a name", len(named))
	}
	work := m.api.node(dr, "", "work").id
	m.wantFile(t, dr, work, "work/f", []byte("content"))
	if g, err := openFile(filepath.Join(dir, "f"), os.O_WRONLY|os.O_CREATE|os.O_EXCL); !errors.Is(err, syscall.EEXIST) {
		if err == nil {
			_ = g.Close()
		}
		t.Errorf("O_EXCL over the renamed file = %v, want EEXIST", err)
	}
	if err := os.Remove(filepath.Join(dir, "f")); err != nil {
		t.Errorf("rm: %v", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Errorf("rmdir of the folder the file was renamed in: %v", err)
	}
}

// A file created here and renamed while its first flush is on its way ends at
// its new name: the rename waits for the flush, then asks the API, which
// holds the file by then.
func TestWrite_RenameDuringTheFirstFlush(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)
	from, to := filepath.Join(m.dir, "f.txt"), filepath.Join(m.dir, "g.txt")

	f, err := create(from)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("first"); err != nil {
		t.Fatal(err)
	}
	arrived, release := m.api.holdRequests(func(r *http.Request) bool {
		return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/node/file")
	})
	defer release()
	closed, renamed := make(chan error, 1), make(chan error, 1)
	go func() { closed <- f.Close() }()
	<-arrived
	go func() { renamed <- os.Rename(from, to) }()
	select {
	case err := <-renamed:
		t.Fatalf("rename returned (%v) while the first flush was in flight", err)
	case <-time.After(150 * time.Millisecond):
	}
	release()
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-renamed; err != nil {
		t.Fatalf("rename: %v", err)
	}
	m.settle(t)

	if m.api.node(dr, "", "f.txt") != nil {
		t.Error("the API holds the file under its old name")
	}
	if n := m.api.count("update"); n != 1 {
		t.Errorf("%d renames sent, want 1", n)
	}
	m.wantFile(t, dr, "", "g.txt", []byte("first"))
	if _, err := os.Stat(from); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("the old name: %v", err)
	}
}

// A flush that failed is not a loss when a later one succeeded; changes that
// no flush sent are reported once, when the spool closes.
func TestWrite_LossIsReportedOnceAtClose(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	f, err := create(filepath.Join(m.dir, "kept.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("kept"); err != nil {
		t.Fatal(err)
	}
	m.api.refuseUploads(true)
	if err := f.Sync(); err == nil {
		t.Fatal("fsync succeeded without storage")
	}
	m.api.refuseUploads(false)
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.wantFile(t, dr, "", "kept.txt", []byte("kept"))
	if logs := m.logs.text(); strings.Contains(logs, "lost") {
		t.Errorf("a loss was reported for a file that was sent:\n%s", logs)
	}

	g, err := create(filepath.Join(m.dir, "lost.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.WriteString("lost"); err != nil {
		t.Fatal(err)
	}
	m.api.refuseUploads(true)
	if err := g.Sync(); err == nil {
		t.Fatal("fsync succeeded without storage")
	}
	if err := g.Close(); err == nil {
		t.Fatal("Close succeeded without storage")
	}
	m.settle(t)
	m.api.refuseUploads(false)
	logs := m.logs.text()
	if strings.Count(logs, "its changes are lost") != 1 || strings.Contains(logs, "lost.txt") {
		t.Errorf("logs = %q, want the loss reported once and no name", logs)
	}
}

// O_EXCL asks the API for the name: a file created elsewhere that the cached
// listing does not show yet is not given a new version. One lookup by name
// hash per exclusive creation, which a plain creation does not make.
func TestWrite_ExclusiveCreateAsksTheAPI(t *testing.T) {
	m, dr, _ := writable(t)
	m.warm(t)

	// A free name, in a folder whose listing is cached: the lookup, and
	// nothing else before the flush.
	f, err := openFile(filepath.Join(m.dir, "free.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatalf("O_EXCL on a free name: %v", err)
	}
	if got := m.api.summary(); got != "lookup=1" {
		t.Errorf("requests of an exclusive creation = %s, want lookup=1", got)
	}
	if _, err := f.WriteString("ours"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	m.wantFile(t, dr, "", "free.txt", []byte("ours"))

	path := filepath.Join(m.dir, "taken.txt")
	if _, err := os.Stat(path); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("stat = %v", err)
	}
	m.api.file(dr, "", "taken.txt", []byte("theirs"))
	m.api.resetCounts()
	if f, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL); !errors.Is(err, syscall.EEXIST) {
		if err == nil {
			_, _ = f.WriteString("ours")
			_ = f.Close()
		}
		t.Errorf("O_EXCL over a file the listing does not show = %v, want EEXIST", err)
	}
	if got := m.api.summary(); got != "lookup=1" {
		t.Errorf("requests of a refused exclusive creation = %s, want lookup=1", got)
	}
	m.wantFile(t, dr, "", "taken.txt", []byte("theirs"))
}
