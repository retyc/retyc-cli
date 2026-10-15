//go:build linux

package retycfs

import (
	"context"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// dirHandle is an open folder: the listing read when it was opened, and a
// position in it.
//
// It answers READDIRPLUS on its own. For every entry of a listing the kernel
// bridge asks for the attributes, 1,000 times for a folder of 1,000, cached
// or not: with FileLookuper on the handle those questions come here and are
// answered from the listing in hand, instead of going to the folder's Lookup
// and from there, for each of them, to the cache or the API.
type dirHandle struct {
	drv *driver
	// dir is the inode of the folder listed.
	dir *fs.Inode
	// list reads the listing (see dirNode.list, allRoot.list).
	list func(ctx context.Context) ([]dirEntry, syscall.Errno)

	mu      sync.Mutex
	entries []dirEntry
	pos     int
}

var (
	_ fs.FileReaddirenter = (*dirHandle)(nil)
	_ fs.FileLookuper     = (*dirHandle)(nil)
	_ fs.FileSeekdirer    = (*dirHandle)(nil)
)

// load reads the listing and rewinds the handle.
func (h *dirHandle) load(ctx context.Context) syscall.Errno {
	entries, errno := h.list(ctx)
	if errno != 0 {
		return errno
	}
	h.mu.Lock()
	h.entries, h.pos = entries, 0
	h.mu.Unlock()

	return 0
}

// Readdirent returns the next entry, nil at the end. The offset of an entry
// is its rank in the listing, counted from 1: where Seekdir resumes.
func (h *dirHandle) Readdirent(context.Context) (*fuse.DirEntry, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pos >= len(h.entries) {
		return nil, 0
	}
	e := h.entries[h.pos]
	h.pos++
	off := uint64(h.pos) //nolint:gosec // G115: a rank in a listing

	return &fuse.DirEntry{Name: e.node.Name, Ino: e.ino, Mode: typeBits(e.node.Type), Off: off}, 0
}

// Lookup answers for an entry of the listing, from the listing. The bridge
// calls it with the name Readdirent just returned, which is looked at first.
func (h *dirHandle) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	h.mu.Lock()
	e, ok := h.findLocked(name)
	h.mu.Unlock()
	if !ok {
		return nil, syscall.ENOENT
	}

	return h.drv.child(ctx, h.dir, e, out), 0
}

// findLocked returns the entry called name. The caller holds mu.
func (h *dirHandle) findLocked(name string) (dirEntry, bool) {
	if last := h.pos - 1; last >= 0 && last < len(h.entries) && h.entries[last].node.Name == name {
		return h.entries[last], true
	}
	for _, e := range h.entries {
		if e.node.Name == name {
			return e, true
		}
	}

	return dirEntry{}, false
}

// Seekdir moves to the entry after the one of offset off. Offset 0 is
// rewinddir, which reads the folder again, as POSIX wants; a listing that
// cannot be read then leaves the handle on the one it has.
func (h *dirHandle) Seekdir(ctx context.Context, off uint64) syscall.Errno {
	if off == 0 {
		ctx, release := h.drv.guard(ctx)
		defer release()
		if h.load(ctx) != 0 {
			h.mu.Lock()
			h.pos = 0
			h.mu.Unlock()
		}

		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if off > uint64(len(h.entries)) {
		return syscall.EINVAL
	}
	h.pos = int(off) //nolint:gosec // G115: bounded by the length of the listing

	return 0
}
