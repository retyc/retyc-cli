//go:build linux

package retycfs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/retyc/retyc-cli/internal/api"
)

// sampleTree fills a dataroom with:
//
//	/empty.txt             0 byte
//	/hello.txt             "hello" (mode 0640)
//	/big.bin               5 chunks and a tail
//	/link -> docs/a.txt    symbolic link
//	/docs/a.txt            "alpha"
//	/docs/deep/b.txt       "bravo"
func sampleTree(a *fakeAPI) (dr *fakeDataroom, big []byte) {
	dr = a.dataroom("dr1", "Projects")
	big = testData(5*testChunkSize+1234, 0)
	a.file(dr, "", "empty.txt", nil)
	a.put(dr, "", "hello.txt", fakeNode{kind: api.NodeTypeFile, data: []byte("hello"), mode: "0640", mime: "text/plain"})
	a.file(dr, "", "big.bin", big)
	a.put(dr, "", "link", fakeNode{kind: api.NodeTypeSymlink, target: "docs/a.txt"})
	docs := a.dir(dr, "", "docs")
	a.file(dr, docs, "a.txt", []byte("alpha"))
	deep := a.dir(dr, docs, "deep")
	a.file(dr, deep, "b.txt", []byte("bravo"))

	return dr, big
}

func single(id string) mountOptions {
	return mountOptions{driver: Options{DataroomID: id}}
}

// walk returns every path below dir, relative to it, sorted.
func walk(t *testing.T, dir string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			rel, _ := filepath.Rel(dir, p)
			paths = append(paths, rel)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	slices.Sort(paths)

	return paths
}

func stat(t *testing.T, path string) (os.FileInfo, *syscall.Stat_t) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}

	return info, info.Sys().(*syscall.Stat_t)
}

func TestMount_TreeAttributesAndContent(t *testing.T) {
	testTreeAttributesAndContent(t, single("dr1"))
}

// With READDIRPLUS the attributes come with the listing, not from a lookup
// per entry: they are the same.
func TestMount_TreeAttributesAndContentReadDirPlus(t *testing.T) {
	opts := single("dr1")
	opts.driver.ReadDirPlus = true
	testTreeAttributesAndContent(t, opts)
}

func testTreeAttributesAndContent(t *testing.T, opts mountOptions) {
	t.Helper()
	a := newFakeAPI(t)
	_, big := sampleTree(a)
	m := mountFS(t, a, opts)

	want := []string{"big.bin", "docs", "docs/a.txt", "docs/deep", "docs/deep/b.txt", "empty.txt", "hello.txt", "link"}
	if got := walk(t, m.dir); !slices.Equal(got, want) {
		t.Fatalf("tree = %v, want %v", got, want)
	}

	t.Run("file", func(t *testing.T) {
		info, sys := stat(t, filepath.Join(m.dir, "hello.txt"))
		if info.Size() != 5 || info.Mode() != 0o640 {
			t.Errorf("size %d mode %v, want 5 and 0640", info.Size(), info.Mode())
		}
		if want := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC); !info.ModTime().Equal(want) {
			t.Errorf("mtime = %v, want %v", info.ModTime(), want)
		}
		if int(sys.Uid) != os.Getuid() || int(sys.Gid) != os.Getgid() {
			t.Errorf("owner %d:%d, want the process's", sys.Uid, sys.Gid)
		}
		if sys.Nlink != 1 || sys.Blocks != 1 {
			t.Errorf("nlink %d blocks %d, want 1 and 1", sys.Nlink, sys.Blocks)
		}
		got, err := readFile(filepath.Join(m.dir, "hello.txt"))
		if err != nil || string(got) != "hello" {
			t.Errorf("content = %q, %v", got, err)
		}
	})

	t.Run("default modes", func(t *testing.T) {
		info, _ := stat(t, filepath.Join(m.dir, "docs/a.txt"))
		if info.Mode() != 0o644 {
			t.Errorf("file mode = %v, want 0644", info.Mode())
		}
		info, sys := stat(t, filepath.Join(m.dir, "docs"))
		if info.Mode() != fs.ModeDir|0o755 || sys.Nlink != 2 {
			t.Errorf("folder mode %v nlink %d, want drwxr-xr-x and 2", info.Mode(), sys.Nlink)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		info, _ := stat(t, filepath.Join(m.dir, "empty.txt"))
		if info.Size() != 0 {
			t.Errorf("size = %d", info.Size())
		}
		got, err := readFile(filepath.Join(m.dir, "empty.txt"))
		if err != nil || len(got) != 0 {
			t.Errorf("content = %q, %v", got, err)
		}
	})

	t.Run("nested", func(t *testing.T) {
		got, err := readFile(filepath.Join(m.dir, "docs/deep/b.txt"))
		if err != nil || string(got) != "bravo" {
			t.Errorf("content = %q, %v", got, err)
		}
	})

	t.Run("several chunks", func(t *testing.T) {
		got, err := readFile(filepath.Join(m.dir, "big.bin"))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.Equal(got, big) {
			t.Errorf("content differs (%d bytes read, %d expected)", len(got), len(big))
		}
	})

	t.Run("inode numbers", func(t *testing.T) {
		seen := map[uint64]string{}
		for _, p := range append([]string{"."}, want...) {
			_, sys := stat(t, filepath.Join(m.dir, p))
			if other, dup := seen[sys.Ino]; dup {
				t.Errorf("%s and %s share inode %d", p, other, sys.Ino)
			}
			seen[sys.Ino] = p
			_, again := stat(t, filepath.Join(m.dir, p))
			if again.Ino != sys.Ino {
				t.Errorf("%s: inode %d then %d", p, sys.Ino, again.Ino)
			}
		}
		if _, sys := stat(t, m.dir); sys.Ino != rootIno {
			t.Errorf("root inode = %d, want %d", sys.Ino, rootIno)
		}
	})

	t.Run("mount", func(t *testing.T) {
		info, err := readFile("/proc/self/mountinfo")
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(info), "\n") {
			if !strings.Contains(line, " "+m.srv.mountpoint+" ") {
				continue
			}
			if !strings.Contains(line, " rw,") || !strings.Contains(line, "fuse."+FSType+" retyc://dr1 ") ||
				!strings.Contains(line, "default_permissions") {
				t.Errorf("mountinfo = %s", line)
			}

			return
		}
		t.Error("the mount is not in /proc/self/mountinfo")
	})
}

func TestMount_PositionedReads(t *testing.T) {
	a := newFakeAPI(t)
	_, big := sampleTree(a)
	m := mountFS(t, a, single("dr1"))

	f, err := os.Open(filepath.Join(m.dir, "big.bin"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	size := len(big)
	for _, r := range []struct{ off, n int }{
		{0, 1},
		{testChunkSize - 1, 2},                // across the first boundary
		{3*testChunkSize + 17, testChunkSize}, // a whole chunk's worth, unaligned
		{size - 10, 10},                       // the tail
		{size - 5, 100},                       // past the end
		{2 * testChunkSize, 4096},             // backwards
		{100, 3 * testChunkSize},              // long, over several chunks
	} {
		buf := make([]byte, r.n)
		n, err := f.ReadAt(buf, int64(r.off))
		want := big[r.off:min(r.off+r.n, size)]
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(%d, %d): %v", r.off, r.n, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Errorf("ReadAt(%d, %d) read %d bytes that differ from the %d expected", r.off, r.n, n, len(want))
		}
	}
	if n, err := f.ReadAt(make([]byte, 10), int64(size)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt at the end = %d, %v; want 0, EOF", n, err)
	}
}

// A whole file costs one download per chunk, and nothing the second time: the
// kernel keeps the pages of a version, which never changes.
func TestMount_ReadCost(t *testing.T) {
	a := newFakeAPI(t)
	_, big := sampleTree(a)
	m := mountFS(t, a, single("dr1"))
	path := filepath.Join(m.dir, "big.bin")
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}

	a.resetCounts()
	got, err := readFile(path)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("first read: %d bytes, %v", len(got), err)
	}
	if chunks := a.count("chunk"); chunks != 6 {
		t.Errorf("first read: %d chunk downloads, want 6 (%s)", chunks, a.summary())
	}
	if n := a.count("listing") + a.count("lookup"); n != 0 {
		t.Errorf("first read: %d listing or lookup requests, want 0 (%s)", n, a.summary())
	}

	a.resetCounts()
	got, err = readFile(path)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("second read: %d bytes, %v", len(got), err)
	}
	if s := a.summary(); s != "" {
		t.Errorf("second read reached the API: %s", s)
	}
}

func TestMount_MissingName(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	m := mountFS(t, a, single("dr1"))

	a.resetCounts()
	for range 20 {
		if _, err := os.Lstat(filepath.Join(m.dir, "docs", "nope.swp")); !errors.Is(err, syscall.ENOENT) {
			t.Fatalf("Lstat = %v, want ENOENT", err)
		}
	}
	// One lookup for the folder, one for the name: the other nineteen probes
	// are answered by the kernel, or by the negative entry of vfs.
	if n := a.count("lookup"); n != 2 {
		t.Errorf("%d lookups for 20 probes of one missing name, want 2 (%s)", n, a.summary())
	}
	if n := a.count("listing"); n != 0 {
		t.Errorf("%d listings, want 0", n)
	}
}

func TestMount_Symlink(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	m := mountFS(t, a, single("dr1"))

	info, sys := stat(t, filepath.Join(m.dir, "link"))
	if info.Mode() != fs.ModeSymlink|0o777 {
		t.Errorf("mode = %v, want Lrwxrwxrwx", info.Mode())
	}
	if info.Size() != int64(len("docs/a.txt")) || sys.Nlink != 1 {
		t.Errorf("size %d nlink %d, want %d and 1", info.Size(), sys.Nlink, len("docs/a.txt"))
	}
	target, err := os.Readlink(filepath.Join(m.dir, "link"))
	if err != nil || target != "docs/a.txt" {
		t.Errorf("Readlink = %q, %v", target, err)
	}
	// The kernel follows the link; the driver never does.
	got, err := readFile(filepath.Join(m.dir, "link"))
	if err != nil || string(got) != "alpha" {
		t.Errorf("content through the link = %q, %v", got, err)
	}
}

func getxattr(t *testing.T, path, name string) (string, error) {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, name, buf)
	if err != nil {
		return "", err
	}

	return string(buf[:n]), nil
}

func TestMount_Xattr(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	m := mountFS(t, a, single("dr1"))
	node := dr.children[""]["hello.txt"]
	path := filepath.Join(m.dir, "hello.txt")

	for name, want := range map[string]string{
		xattrNodeID:     node.id,
		xattrVersionID:  node.version,
		xattrDataroomID: "dr1",
		xattrMIME:       "text/plain",
	} {
		if got, err := getxattr(t, path, name); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := getxattr(t, path, "user.retyc.nope"); !errors.Is(err, unix.ENODATA) {
		t.Errorf("unknown attribute: %v, want ENODATA", err)
	}

	buf := make([]byte, 512)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		t.Fatalf("Llistxattr: %v", err)
	}
	names := strings.Split(strings.TrimRight(string(buf[:n]), "\x00"), "\x00")
	slices.Sort(names)
	if want := []string{xattrDataroomID, xattrMIME, xattrNodeID, xattrVersionID}; !slices.Equal(names, want) {
		t.Errorf("attributes = %v, want %v", names, want)
	}

	// A folder has neither version nor MIME type, the root no node either.
	if _, err := getxattr(t, filepath.Join(m.dir, "docs"), xattrVersionID); !errors.Is(err, unix.ENODATA) {
		t.Errorf("version of a folder: %v, want ENODATA", err)
	}
	if got, err := getxattr(t, m.dir, xattrDataroomID); err != nil || got != "dr1" {
		t.Errorf("dataroom of the root = %q, %v", got, err)
	}
	if _, err := getxattr(t, m.dir, xattrNodeID); !errors.Is(err, unix.ENODATA) {
		t.Errorf("node of the root: %v, want ENODATA", err)
	}

	// Read only: the kernel says EROFS on a read-only mount, the driver
	// ENOTSUP if it were asked.
	err = unix.Lsetxattr(path, "user.test", []byte("x"), 0)
	if !errors.Is(err, unix.EROFS) && !errors.Is(err, unix.ENOTSUP) {
		t.Errorf("Lsetxattr: %v, want EROFS or ENOTSUP", err)
	}
}

func TestMount_Statfs(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	bare := a.dataroom("dr2", "No counters")
	bare.hasQuota = false

	t.Run("quota", func(t *testing.T) {
		m := mountFS(t, a, single("dr1"))
		var st unix.Statfs_t
		if err := unix.Statfs(filepath.Join(m.dir, "docs"), &st); err != nil {
			t.Fatalf("Statfs: %v", err)
		}
		if st.Bsize != blockSize || st.Namelen != maxNameLen {
			t.Errorf("bsize %d namelen %d", st.Bsize, st.Namelen)
		}
		if want := uint64(dr.used+dr.free) / blockSize; st.Blocks != want { //nolint:gosec // G115: test values
			t.Errorf("blocks = %d, want %d", st.Blocks, want)
		}
		if want := uint64(dr.free) / blockSize; st.Bfree != want || st.Bavail != want { //nolint:gosec // G115
			t.Errorf("bfree %d bavail %d, want %d", st.Bfree, st.Bavail, want)
		}
		// Cached by vfs for the TTL.
		for range 5 {
			_ = unix.Statfs(m.dir, &st)
		}
		if n := a.count("stats"); n != 1 {
			t.Errorf("%d stats requests, want 1", n)
		}
	})

	t.Run("no counters", func(t *testing.T) {
		m := mountFS(t, a, single("dr2"))
		var st unix.Statfs_t
		if err := unix.Statfs(m.dir, &st); err != nil {
			t.Fatalf("Statfs: %v", err)
		}
		if want := uint64(unboundedBytes / blockSize); st.Blocks != want || st.Bfree != want {
			t.Errorf("blocks %d bfree %d, want %d", st.Blocks, st.Bfree, want)
		}
	})
}

func TestMount_AllDatarooms(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	// Two datarooms of one title, and one whose title is no file name.
	twin := a.dataroom("dr2", "Projects")
	a.file(twin, "", "twin.txt", []byte("twin"))
	odd := a.dataroom("dr3", "Q3/Q4 review")
	a.file(odd, "", "odd.txt", []byte("odd"))
	m := mountFS(t, a, mountOptions{driver: Options{All: true}})

	entries, err := os.ReadDir(m.dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	byContent := map[string]string{}
	for _, e := range entries {
		if !e.IsDir() {
			t.Errorf("%s is not a folder", e.Name())
		}
		for _, probe := range []string{"hello.txt", "twin.txt", "odd.txt"} {
			if got, err := readFile(filepath.Join(m.dir, e.Name(), probe)); err == nil {
				byContent[string(got)] = e.Name()
			}
		}
	}
	if len(entries) != 3 {
		t.Fatalf("root holds %d entries, want 3", len(entries))
	}
	if byContent["hello"] == "" || byContent["twin"] == "" || byContent["hello"] == byContent["twin"] {
		t.Errorf("datarooms sharing a title: %v", byContent)
	}
	if got := byContent["odd"]; got != "Q3_Q4 review" {
		t.Errorf("title with a slash presented as %q, want %q", got, "Q3_Q4 review")
	}

	// The same tree as when mounted alone, one level down.
	got, err := readFile(filepath.Join(m.dir, byContent["hello"], "docs/deep/b.txt"))
	if err != nil || string(got) != "bravo" {
		t.Errorf("nested file = %q, %v", got, err)
	}
	if got, err := getxattr(t, filepath.Join(m.dir, byContent["twin"]), xattrDataroomID); err != nil || got != "dr2" {
		t.Errorf("dataroom of a dataroom folder = %q, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(m.dir, "No such dataroom")); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("missing dataroom: %v, want ENOENT", err)
	}

	// No quota is summed at the root: a constant, and no request.
	a.resetCounts()
	var st unix.Statfs_t
	if err := unix.Statfs(m.dir, &st); err != nil {
		t.Fatalf("Statfs: %v", err)
	}
	if want := uint64(unboundedBytes / blockSize); st.Blocks != want || a.count("stats") != 0 {
		t.Errorf("root: blocks %d (want %d), %d stats requests (want 0)", st.Blocks, want, a.count("stats"))
	}

	if err := os.Mkdir(filepath.Join(m.dir, "new"), 0o750); !errors.Is(err, syscall.EPERM) {
		t.Errorf("mkdir at the root: %v, want EPERM", err)
	}
}

// ls -l of a folder of 200 entries is one listing: the kernel bridge asks for
// the attributes of each entry, and each is answered from the listing the
// folder handle holds.
func TestMount_ListingCost(t *testing.T) {
	a := newFakeAPI(t)
	dr := a.dataroom("dr1", "Projects")
	folder := a.dir(dr, "", "many")
	for i := range 200 {
		a.file(dr, folder, "file-"+strconv.Itoa(i)+".txt", []byte("x"))
	}
	m := mountFS(t, a, single("dr1"))
	dir := filepath.Join(m.dir, "many")

	check := func(t *testing.T, list func() int) {
		t.Helper()
		a.resetCounts()
		if n := list(); n != 200 {
			t.Fatalf("%d entries listed, want 200", n)
		}
	}

	t.Run("cold", func(t *testing.T) {
		check(t, func() int {
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			for _, e := range entries {
				if _, err := e.Info(); err != nil {
					t.Fatalf("Info: %v", err)
				}
			}

			return len(entries)
		})
		// One lookup: the folder itself, by name. None for its entries.
		if a.count("listing") != 1 || a.count("lookup") != 1 {
			t.Errorf("requests: %s; want 1 listing and 1 lookup", a.summary())
		}
	})

	t.Run("ls -l", func(t *testing.T) {
		ls, err := exec.LookPath("ls")
		if err != nil {
			t.Skip("no ls")
		}
		check(t, func() int {
			out, err := exec.Command(ls, "-l", dir).Output() //nolint:gosec // G204: ls, on the test's mount
			if err != nil {
				t.Fatalf("ls -l: %v", err)
			}

			return strings.Count(string(out), "\n") - 1 // the "total" line
		})
		if s := a.summary(); s != "" {
			t.Errorf("ls -l of a folder just listed reached the API: %s", s)
		}
	})
}

// find walks a tree with one listing per folder and no lookup.
func TestMount_WalkCost(t *testing.T) {
	a := newFakeAPI(t)
	dr := a.dataroom("dr1", "Projects")
	folders := 1 // the root
	for _, top := range []string{"a", "b", "c"} {
		topID := a.dir(dr, "", top)
		folders++
		for _, mid := range []string{"x", "y"} {
			midID := a.dir(dr, topID, mid)
			folders++
			for _, leaf := range []string{"1.txt", "2.txt", "3.txt"} {
				a.file(dr, midID, leaf, []byte(leaf))
			}
		}
	}
	m := mountFS(t, a, single("dr1"))

	a.resetCounts()
	if got := len(walk(t, m.dir)); got != 3+6+18 {
		t.Fatalf("%d paths walked, want 27", got)
	}
	if a.count("listing") != folders || a.count("lookup") != 0 {
		t.Errorf("requests: %s; want %d listings and no lookup", a.summary(), folders)
	}
}

// A walk that reads no attribute gives an object to the folders it walks
// into, not to the files it lists, unless READDIRPLUS is on: then every entry
// listed has one, as long as the kernel keeps it.
func TestMount_ReadDirPlusMakesAnObjectPerEntry(t *testing.T) {
	const folders, files = 9, 18
	for _, plus := range []bool{false, true} {
		t.Run(map[bool]string{false: "readdir", true: "readdirplus"}[plus], func(t *testing.T) {
			a := newFakeAPI(t)
			dr := a.dataroom("dr1", "Projects")
			for _, top := range []string{"a", "b", "c"} {
				topID := a.dir(dr, "", top)
				for _, mid := range []string{"x", "y"} {
					midID := a.dir(dr, topID, mid)
					for _, leaf := range []string{"1.txt", "2.txt", "3.txt"} {
						a.file(dr, midID, leaf, []byte(leaf))
					}
				}
			}
			opts := single("dr1")
			opts.driver.ReadDirPlus = plus
			m := mountFS(t, a, opts)
			table := m.srv.drv.inodes
			_, before := table.records()

			if got := len(walk(t, m.dir)); got != folders+files {
				t.Fatalf("%d paths walked, want %d", got, folders+files)
			}
			_, after := table.records()
			made := after - before
			switch {
			case plus && made < folders+files:
				t.Errorf("%d objects made by the walk, want one per entry (%d)", made, folders+files)
			case !plus && (made < folders || made >= folders+files):
				t.Errorf("%d objects made by the walk, want the %d folders only", made, folders)
			}
		})
	}
}

// eventually polls cond for a few seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A file replaced elsewhere is read in its new version once the cache has
// expired, even when neither its size nor its modification time moved: the
// kernel's pages are those of a version, and are dropped with it.
func TestMount_RemoteVersionChange(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	const ttl = 150 * time.Millisecond
	m := mountFS(t, a, mountOptions{ttl: ttl, driver: Options{DataroomID: "dr1", EntryTimeout: ttl, AttrTimeout: ttl}})
	path := filepath.Join(m.dir, "docs", "a.txt")

	if got, err := readFile(path); err != nil || string(got) != "alpha" {
		t.Fatalf("first read = %q, %v", got, err)
	}
	_, before := stat(t, path)

	docs := dr.children[""]["docs"].id
	a.rewrite(dr, docs, "a.txt", []byte("omega"), time.Time{}) // same size, same mtime
	eventually(t, "the new version", func() bool {
		got, err := readFile(path)

		return err == nil && string(got) == "omega"
	})
	if _, after := stat(t, path); after.Ino != before.Ino {
		t.Errorf("inode %d became %d with the new version", before.Ino, after.Ino)
	}

	a.rewrite(dr, docs, "a.txt", []byte("a longer third version"), time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	eventually(t, "the third version", func() bool {
		got, err := readFile(path)

		return err == nil && string(got) == "a longer third version"
	})
	info, _ := stat(t, path)
	if info.Size() != int64(len("a longer third version")) || info.ModTime().Day() != 3 {
		t.Errorf("attributes not updated: size %d, mtime %v", info.Size(), info.ModTime())
	}
}

// A handle keeps reading the version it opened; an open that follows the
// change reads the new one.
func TestMount_OpenHandleKeepsItsVersion(t *testing.T) {
	a := newFakeAPI(t)
	dr, big := sampleTree(a)
	const ttl = 150 * time.Millisecond
	m := mountFS(t, a, mountOptions{ttl: ttl, driver: Options{DataroomID: "dr1", EntryTimeout: ttl, AttrTimeout: ttl}})
	path := filepath.Join(m.dir, "big.bin")

	old, err := os.Open(path) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = old.Close() }()

	replaced := testData(len(big), 0x5a)
	a.rewrite(dr, "", "big.bin", replaced, time.Time{})
	time.Sleep(2 * ttl)

	// Nothing told the driver yet, and no page is cached: the old handle
	// reads what it opened.
	buf := make([]byte, 4096)
	off := int64(2 * testChunkSize)
	if _, err := old.ReadAt(buf, off); err != nil {
		t.Fatalf("ReadAt on the old handle: %v", err)
	}
	if !bytes.Equal(buf, big[off:off+4096]) {
		t.Error("the old handle did not read the version it opened")
	}
	// Let the read-ahead that read started through the old handle land: what
	// arrives after the next open would be pages of the old version again.
	time.Sleep(100 * time.Millisecond)

	// A new open revalidates, and must not be served the pages the old
	// handle just brought in.
	got, err := readFile(path)
	if err != nil || !bytes.Equal(got, replaced) {
		t.Fatalf("a new open read %d bytes of the old version (err %v)", len(got), err)
	}

	// Once the old handle is gone the pages it filled are dropped too.
	_ = old.Close()
	eventually(t, "the new version after the old handle closed", func() bool {
		got, err := readFile(path)

		return err == nil && bytes.Equal(got, replaced)
	})
}

// Two handles on two versions of one file share one page cache. The handle
// opened on the new version must not be served what the old one, still
// reading, brings into it.
func TestMount_NewHandleReadsAroundAnOldOne(t *testing.T) {
	a := newFakeAPI(t)
	dr, big := sampleTree(a)
	const ttl = 150 * time.Millisecond
	m := mountFS(t, a, mountOptions{ttl: ttl, driver: Options{DataroomID: "dr1", EntryTimeout: ttl, AttrTimeout: ttl}})
	path := filepath.Join(m.dir, "big.bin")

	old, err := os.Open(path) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = old.Close() }()

	replaced := testData(len(big), 0x5a)
	a.rewrite(dr, "", "big.bin", replaced, time.Time{})
	time.Sleep(2 * ttl)
	fresh, err := os.Open(path) //nolint:gosec // G304: a file of the test's mount
	if err != nil {
		t.Fatalf("Open after the new version: %v", err)
	}
	defer func() { _ = fresh.Close() }()

	// The old handle reads first, each time: what it read is in the page
	// cache when the new handle asks for the same bytes.
	buf := make([]byte, 8192)
	for _, off := range []int64{0, testChunkSize - 100, 3 * testChunkSize, int64(len(big)) - 8192} {
		if _, err := old.ReadAt(buf, off); err != nil {
			t.Fatalf("ReadAt %d on the old handle: %v", off, err)
		}
		if !bytes.Equal(buf, big[off:off+8192]) {
			t.Errorf("offset %d: the old handle did not read the version it opened", off)
		}
		if _, err := fresh.ReadAt(buf, off); err != nil {
			t.Fatalf("ReadAt %d on the new handle: %v", off, err)
		}
		if !bytes.Equal(buf, replaced[off:off+8192]) {
			t.Errorf("offset %d: the new handle was served the old version", off)
		}
	}
}

// An open that finds a new version reads all of it at once, although the
// kernel still holds the size of the old one for a minute: it is told before
// the open is answered.
func TestMount_OpenSeesTheNewSize(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	const ttl = 100 * time.Millisecond
	m := mountFS(t, a, mountOptions{ttl: ttl, driver: Options{DataroomID: "dr1"}})
	docs := dr.children[""]["docs"].id
	path := filepath.Join(m.dir, "docs", "a.txt")
	if info, _ := stat(t, path); info.Size() != int64(len("alpha")) {
		t.Fatalf("size = %d", info.Size())
	}

	// Never opened, then open: both ways the kernel knows the old size.
	for _, content := range []string{"a second version, longer", "a third version, longer than the second"} {
		a.rewrite(dr, docs, "a.txt", []byte(content), time.Time{})
		time.Sleep(2 * ttl)
		if got, err := readFile(path); err != nil || string(got) != content {
			t.Fatalf("first open after the change read %q (err %v), want %q", got, err, content)
		}
	}
}

// A node moved elsewhere, then looked up at its old place while the listing of
// that folder, older than the move, is still served: the old place is the last
// one a lookup found it at. What is reached through the new place must still
// be read once the old listing is gone.
func TestMount_MovedNodeLookedUpAtItsOldPlace(t *testing.T) {
	a := newFakeAPI(t)
	dr := a.dataroom("dr1", "Projects")
	from, to := a.dir(dr, "", "a"), a.dir(dr, "", "b")
	folder := a.dir(dr, from, "F")
	a.file(dr, folder, "x.txt", []byte("in the folder"))
	a.file(dr, from, "y.txt", []byte("a file"))
	m := mountFS(t, a, single("dr1"))
	ctx := context.Background()

	// The cache holds the listing of /a; the kernel knows nothing of it.
	if _, err := m.tree.ReadDir(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	a.move(dr, from, "F", to)
	a.move(dr, from, "y.txt", to)

	// The new place first, then the old one, which the old listing answers.
	for _, name := range []string{"b/F", "b/y.txt", "a/F", "a/y.txt"} {
		if _, err := os.Lstat(filepath.Join(m.dir, name)); err != nil {
			t.Fatalf("Lstat %s: %v", name, err)
		}
	}
	// A folder held open is not looked up again by the kernel.
	held, err := os.Open(filepath.Join(m.dir, "b", "F"))
	if err != nil {
		t.Fatalf("Open b/F: %v", err)
	}
	defer func() { _ = held.Close() }()
	if _, err := os.Lstat(filepath.Join(m.dir, "a", "F")); err != nil {
		t.Fatalf("Lstat a/F: %v", err)
	}

	// The old listing expires.
	m.tree.InvalidateListing("dr1", "/a")

	if got, err := readFile(filepath.Join(m.dir, "b", "y.txt")); err != nil || string(got) != "a file" {
		t.Errorf("the moved file read %q, %v", got, err)
	}
	fd, err := syscall.Openat(int(held.Fd()), "x.txt", syscall.O_RDONLY, 0) //nolint:gosec // G115: a descriptor
	if err != nil {
		t.Errorf("open of a file of the moved folder, from the folder held open: %v", err)
	} else {
		_ = syscall.Close(fd)
	}
	entries, err := os.ReadDir(filepath.Join(m.dir, "b", "F"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "x.txt" {
		t.Errorf("listing of the moved folder = %v, %v", entries, err)
	}
	if got, err := readFile(filepath.Join(m.dir, "b", "F", "x.txt")); err != nil || string(got) != "in the folder" {
		t.Errorf("a file of the moved folder read %q, %v", got, err)
	}
	// And the old names are gone.
	for _, name := range []string{"a/F", "a/y.txt"} {
		if _, err := os.Lstat(filepath.Join(m.dir, name)); !errors.Is(err, syscall.ENOENT) {
			t.Errorf("Lstat %s after the listing expired: %v, want ENOENT", name, err)
		}
	}
}

// A name removed elsewhere is dropped from the kernel when a listing shows it
// gone, without waiting for the entry timeout.
func TestMount_RemoteRemovalNotifiesTheKernel(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	// The kernel would keep the entry for a minute; the listings for 100 ms.
	m := mountFS(t, a, mountOptions{ttl: 100 * time.Millisecond, driver: Options{DataroomID: "dr1"}})
	path := filepath.Join(m.dir, "docs", "a.txt")
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}

	a.drop(dr, dr.children[""]["docs"].id, "a.txt")
	eventually(t, "the removal", func() bool {
		// The listing is what shows the driver the name is gone.
		if _, err := os.ReadDir(filepath.Join(m.dir, "docs")); err != nil {
			return false
		}
		_, err := os.Lstat(path)

		return errors.Is(err, syscall.ENOENT)
	})

	// The same for a name that now holds another node: deleted and created
	// again elsewhere. The kernel still knows the old inode under that name.
	hello := filepath.Join(m.dir, "hello.txt")
	_, before := stat(t, hello)
	a.drop(dr, "", "hello.txt")
	a.file(dr, "", "hello.txt", []byte("another file"))
	eventually(t, "the replacement", func() bool {
		if _, err := os.ReadDir(m.dir); err != nil {
			return false
		}
		info, err := os.Lstat(hello)

		return err == nil && info.Size() == int64(len("another file"))
	})
	if _, after := stat(t, hello); after.Ino == before.Ino {
		t.Errorf("another node kept inode %d", after.Ino)
	}
}

// Close-to-open: an open reads the version that is current when it is made,
// not the one the kernel remembers. Here the kernel would keep names and
// attributes for a minute, and nothing lists the folder: the open alone finds
// out, once the listing cache (100 ms) has expired.
func TestMount_OpenRevalidates(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	const ttl = 100 * time.Millisecond
	m := mountFS(t, a, mountOptions{ttl: ttl, driver: Options{DataroomID: "dr1"}})
	docs := dr.children[""]["docs"].id
	path := filepath.Join(m.dir, "docs", "a.txt")
	read := func() string {
		t.Helper()
		got, err := readFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}

		return string(got)
	}
	if got := read(); got != "alpha" {
		t.Fatalf("first read = %q", got)
	}

	// A new version of the same node.
	a.rewrite(dr, docs, "a.txt", []byte("omega"), time.Time{})
	time.Sleep(2 * ttl)
	if got := read(); got != "omega" {
		t.Errorf("after a new version: %q, want the new one at the first open", got)
	}

	// Another node under the same name: the open answers ESTALE and the
	// kernel resolves the path again, which the reader never sees.
	a.drop(dr, docs, "a.txt")
	a.file(dr, docs, "a.txt", []byte("a different node"))
	time.Sleep(2 * ttl)
	if got := read(); got != "a different node" {
		t.Errorf("after a replacement: %q", got)
	}

	// Gone.
	a.drop(dr, docs, "a.txt")
	time.Sleep(2 * ttl)
	if _, err := readFile(path); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("after the removal: %v, want ENOENT", err)
	}
}

// A mount made read only (`retyc fs mount --read-only`) refuses every change,
// and no request reaches the API.
func TestMount_ReadOnlyRefusesWrites(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	opts := single("dr1")
	opts.driver.ReadOnly = true
	m := mountFS(t, a, opts)
	file := filepath.Join(m.dir, "hello.txt")

	for what, err := range map[string]error{
		"create":   os.WriteFile(filepath.Join(m.dir, "new.txt"), []byte("x"), 0o600),
		"write":    os.WriteFile(file, []byte("x"), 0o600),
		"append":   appendTo(file),
		"mkdir":    os.Mkdir(filepath.Join(m.dir, "newdir"), 0o750),
		"remove":   os.Remove(file),
		"rmdir":    os.Remove(filepath.Join(m.dir, "docs", "deep")),
		"rename":   os.Rename(file, filepath.Join(m.dir, "renamed.txt")),
		"chmod":    os.Chmod(file, 0o600),
		"truncate": os.Truncate(file, 0),
		"utimens":  os.Chtimes(file, time.Now(), time.Now()),
		"symlink":  os.Symlink("hello.txt", filepath.Join(m.dir, "link2")),
		"link":     os.Link(file, filepath.Join(m.dir, "hard")),
	} {
		if !errors.Is(err, syscall.EROFS) {
			t.Errorf("%s: %v, want EROFS", what, err)
		}
	}
	if got, err := readFile(file); err != nil || string(got) != "hello" {
		t.Errorf("the file changed: %q, %v", got, err)
	}
	for _, kind := range []string{
		"other", "create_file", "create_node", "version", "upload", "update", "patch", "delete", "delete_version",
	} {
		if s := a.count(kind); s != 0 {
			t.Errorf("%d %s requests reached the API", s, kind)
		}
	}
}

// appendTo opens path for appending and returns the error.
func appendTo(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: a file of the test's mount
	if err == nil {
		_ = f.Close()
	}

	return err
}

// readFile reads a file of the test's mount.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: a file of the test's mount
}

// The handlers of a read-only mount answer for themselves too, should the
// kernel ever let a write through: EROFS in a dataroom, EPERM where datarooms
// are listed.
func TestHandlers_RefuseWrites(t *testing.T) {
	ctx := context.Background()
	drv := &driver{opts: Options{ReadOnly: true}, inodes: newInodeTable(), log: newAccessLog(0)}
	defer drv.log.close()
	dir, root := &dirNode{base: base{ident: ident{drv: drv}}}, &allRoot{}
	file := &fileNode{base: base{ident: ident{drv: drv}}}
	if _, _, errno := file.Open(ctx, syscall.O_WRONLY); errno != syscall.EROFS {
		t.Errorf("open for writing: %v, want EROFS", errno)
	}
	if _, errno := file.CopyFileRange(ctx, nil, 0, nil, nil, 0, 0, 0); errno != syscall.EXDEV {
		t.Errorf("copy_file_range: %v, want EXDEV", errno)
	}

	_, mkdir := dir.Mkdir(ctx, "x", 0o755, nil)
	_, _, _, create := dir.Create(ctx, "x", 0, 0o644, nil)
	_, symlink := dir.Symlink(ctx, "t", "x", nil)
	_, link := dir.Link(ctx, nil, "x", nil)
	_, mknod := dir.Mknod(ctx, "x", 0, 0, nil)
	for what, errno := range map[string]syscall.Errno{
		"mkdir": mkdir, "create": create, "symlink": symlink, "link": link, "mknod": mknod,
		"rmdir": dir.Rmdir(ctx, "x"), "unlink": dir.Unlink(ctx, "x"), "rename": dir.Rename(ctx, "x", nil, "y", 0),
		"setattr": dir.Setattr(ctx, nil, nil, nil),
	} {
		if errno != syscall.EROFS {
			t.Errorf("%s in a dataroom: %v, want EROFS", what, errno)
		}
	}
	if errno := dir.Setxattr(ctx, "user.x", nil, 0); errno != syscall.ENOTSUP {
		t.Errorf("setxattr: %v, want ENOTSUP", errno)
	}
	if errno := dir.Removexattr(ctx, "user.x"); errno != syscall.ENOTSUP {
		t.Errorf("removexattr: %v, want ENOTSUP", errno)
	}

	_, mkdir = root.Mkdir(ctx, "x", 0o755, nil)
	for what, errno := range map[string]syscall.Errno{
		"mkdir": mkdir, "rmdir": root.Rmdir(ctx, "x"), "rename": root.Rename(ctx, "x", nil, "y", 0),
	} {
		if errno != syscall.EPERM {
			t.Errorf("%s where datarooms are listed: %v, want EPERM", what, errno)
		}
	}
}

var accessLine = regexp.MustCompile(
	`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z [a-z]+ ino=\d+( off=\d+ len=\d+)? \S+ (ok|E[A-Z]+)$`)

func TestMount_AccessLog(t *testing.T) {
	a := newFakeAPI(t)
	dr := a.dataroom("dr1", "Projects")
	secret := a.dir(dr, "", "secret-folder-name")
	a.file(dr, secret, "secret-file-name.txt", testData(2*testChunkSize, 0))
	m := mountFS(t, a, single("dr1"))

	// Absent from the listing, reached by name.
	wantTree := []string{"secret-folder-name", "secret-folder-name/secret-file-name.txt"}
	if got := walk(t, m.dir); !slices.Equal(got, wantTree) {
		t.Errorf("tree = %v", got)
	}
	info, err := os.Stat(filepath.Join(m.dir, controlDirName))
	if err != nil || !info.IsDir() {
		t.Fatalf("Stat(%s) = %v, %v", controlDirName, info, err)
	}
	if entries, err := os.ReadDir(filepath.Join(m.dir, controlDirName)); err != nil ||
		len(entries) != 1 || entries[0].Name() != accessLogName {
		t.Errorf("control folder = %v, %v", entries, err)
	}

	logFile, err := os.Open(filepath.Join(m.dir, controlDirName, accessLogName))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	lines := make(chan string, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = logFile.Close() }()
		sc := bufio.NewScanner(logFile)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	target := filepath.Join(m.dir, "secret-folder-name", "secret-file-name.txt")
	_, sys := stat(t, target)
	if _, err := readFile(target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(m.dir, "missing")); !errors.Is(err, syscall.ENOENT) {
		t.Fatal(err)
	}

	// The reader follows the log: the read of the file shows up while it is
	// still blocked on it.
	ino := " ino=" + itoa(sys.Ino) + " "
	var seen []string
	sawRead, sawMissing := false, false
	timeout := time.After(5 * time.Second)
	for !sawRead || !sawMissing {
		select {
		case line := <-lines:
			seen = append(seen, line)
			if !accessLine.MatchString(line) {
				t.Errorf("malformed line: %q", line)
			}
			if strings.Contains(line, "secret") {
				t.Errorf("a name in the access log: %q", line)
			}
			sawRead = sawRead || (strings.Contains(line, " read"+ino) && strings.Contains(line, " off=0 len=") &&
				strings.HasSuffix(line, " ok"))
			sawMissing = sawMissing || (strings.Contains(line, " lookup ino=1 ") && strings.HasSuffix(line, " ENOENT"))
		case <-timeout:
			t.Fatalf("read %v, missing %v after 5 s; log:\n%s", sawRead, sawMissing, strings.Join(seen, "\n"))
		}
	}

	// Unmounting wakes the reader with the end of the file; left blocked, it
	// would hold the mount busy.
	if err := m.srv.Unmount(); err != nil {
		t.Fatalf("Unmount with a reader blocked on the access log: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader of the access log was not woken by the unmount")
	}
	if logs := m.logs.text(); strings.Contains(logs, "detaching") {
		t.Errorf("the mount had to be detached:\n%s", logs)
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func TestMount_ExternalUnmount(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	m := mountFS(t, a, single("dr1"))
	if _, err := os.ReadDir(m.dir); err != nil {
		t.Fatal(err)
	}

	if os.Geteuid() == 0 {
		if err := unix.Unmount(m.dir, 0); err != nil {
			t.Fatalf("umount: %v", err)
		}
	} else if out, err := unmountHelper(m.dir); err != nil {
		t.Fatalf("fusermount3 -u: %v: %s", err, out)
	}

	select {
	case <-m.srv.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed after an external unmount")
	}
	m.srv.Wait()
	if err := m.srv.Unmount(); err != nil {
		t.Errorf("Unmount after an external unmount: %v", err)
	}
	if entries, _ := os.ReadDir(m.dir); len(entries) != 0 {
		t.Errorf("the mount point still holds %d entries", len(entries))
	}
}

// unmountHelper unmounts dir as a user would from another terminal.
func unmountHelper(dir string) ([]byte, error) {
	helper := "fusermount3"
	if _, err := exec.LookPath(helper); err != nil {
		helper = "fusermount"
	}

	return exec.Command(helper, "-u", dir).CombinedOutput() //nolint:gosec // G204: the test's mount
}

// A mount point that stays busy is detached after the grace period, so that
// the process can leave.
func TestMount_BusyMountIsDetached(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	m := mountFS(t, a, mountOptions{driver: Options{DataroomID: "dr1", UnmountGrace: 200 * time.Millisecond}})

	f, err := os.Open(filepath.Join(m.dir, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.srv.Unmount(); err != nil {
		t.Fatalf("Unmount of a busy mount: %v", err)
	}
	if !strings.Contains(m.logs.text(), "detaching") {
		t.Errorf("no report of the detach: %q", m.logs.text())
	}
	if still, _ := isMounted(m.srv.mountpoint); still {
		t.Error("still mounted")
	}
	_ = f.Close()
	// The cleanup of mountFS checks for a detach it did not expect.
	m.logs.mu.Lock()
	m.logs.lines = nil
	m.logs.mu.Unlock()
}

// A dataroom the caller refuses answers ENOTSUP, and is reported once.
func TestMount_RefusedDataroom(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	m := mountFS(t, a, mountOptions{driver: Options{
		DataroomID:    "dr1",
		CheckDataroom: func(context.Context, string) error { return ErrLegacyAPI },
	}})

	for range 3 {
		if _, err := os.ReadDir(m.dir); !errors.Is(err, syscall.ENOTSUP) {
			t.Fatalf("ReadDir = %v, want ENOTSUP", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(m.dir, "hello.txt")); !errors.Is(err, syscall.ENOTSUP) {
		t.Errorf("Lstat = %v, want ENOTSUP", err)
	}
	if n := strings.Count(m.logs.text(), "is not served"); n != 1 {
		t.Errorf("refusal reported %d times, want 1:\n%s", n, m.logs.text())
	}
	if s := a.summary(); s != "" {
		t.Errorf("a refused dataroom reached the API: %s", s)
	}
}

// A handler that panics answers EIO and leaves the mount up.
func TestMount_PanicIsAnError(t *testing.T) {
	a := newFakeAPI(t)
	sampleTree(a)
	var panicking atomic.Bool
	panicking.Store(true)
	m := mountFS(t, a, mountOptions{driver: Options{
		DataroomID: "dr1",
		CheckDataroom: func(context.Context, string) error {
			if panicking.Load() {
				panic("boom")
			}

			return nil
		},
	}})

	if _, err := os.Lstat(filepath.Join(m.dir, "hello.txt")); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Lstat = %v, want EIO", err)
	}
	logs := m.logs.text()
	if !strings.Contains(logs, "panic in the lookup handler: boom") || !strings.Contains(logs, "goroutine") {
		t.Errorf("no stack reported:\n%s", logs)
	}

	panicking.Store(false)
	if got, err := readFile(filepath.Join(m.dir, "hello.txt")); err != nil || string(got) != "hello" {
		t.Errorf("after the panic: %q, %v", got, err)
	}
}

// A read held back by the API rate limit waits and returns the right bytes:
// the client retries, the reader sees a slow read, not an error.
func TestMount_RateLimitedReadWaits(t *testing.T) {
	a := newFakeAPI(t)
	_, big := sampleTree(a)
	m := mountFS(t, a, single("dr1"))

	a.mu.Lock()
	a.throttle = 2
	a.mu.Unlock()
	got, err := readFile(filepath.Join(m.dir, "big.bin"))
	if err != nil {
		t.Fatalf("ReadFile during a rate limit episode: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Error("content differs")
	}
	if n := a.count("chunk"); n < 8 {
		t.Errorf("%d chunk requests, want the 6 chunks and the 2 refused", n)
	}
}

func TestMount_Refusals(t *testing.T) {
	requireFUSE(t)
	a := newFakeAPI(t)
	sampleTree(a)
	m := mountFS(t, a, single("dr1"))

	if _, err := Mount(context.Background(), m.tree, t.TempDir(), Options{}); err == nil {
		t.Error("Mount without a dataroom nor All succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Mount(ctx, m.tree, t.TempDir(), Options{All: true}); !errors.Is(err, context.Canceled) {
		t.Errorf("Mount with a cancelled context: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := Mount(context.Background(), m.tree, missing, Options{All: true}); err == nil {
		t.Error("Mount on a missing folder succeeded")
	}
}

// A mode the API stores as "0000" is a mode, not an absence: it is shown as
// it is, and only a node that stores none gets file_mode / dir_mode.
func TestMount_ExplicitZeroModeFromTheAPI(t *testing.T) {
	a := newFakeAPI(t)
	dr := a.dataroom("dr1", "Projects")
	a.put(dr, "", "locked.txt", fakeNode{kind: api.NodeTypeFile, data: []byte("x"), mode: "0000", mime: "text/plain"})
	a.put(dr, "", "closed", fakeNode{kind: api.NodeTypeFolder, mode: "0000"})
	a.file(dr, "", "plain.txt", []byte("y"))
	a.dir(dr, "", "open")
	m := mountFS(t, a, single("dr1"))

	for name, want := range map[string]fs.FileMode{
		"locked.txt": 0, "closed": fs.ModeDir, "plain.txt": 0o644, "open": fs.ModeDir | 0o755,
	} {
		fi, err := os.Lstat(filepath.Join(m.dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := fi.Mode() & (fs.ModeDir | fs.ModePerm); got != want {
			t.Errorf("%s: mode = %v, want %v", name, got, want)
		}
	}
}
