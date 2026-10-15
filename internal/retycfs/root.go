//go:build linux

package retycfs

import (
	"context"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// allRoot is the root of the "all datarooms" mode: one folder per dataroom
// the user can reach, named by vfs.FS.Datarooms (the title, with a suffix
// that tells apart the datarooms sharing one).
type allRoot struct {
	base
}

var (
	_ fs.NodeLookuper       = (*allRoot)(nil)
	_ fs.NodeOpendirHandler = (*allRoot)(nil)
	_ fs.NodeOnAdder        = (*allRoot)(nil)
	_ fs.NodeMkdirer        = (*allRoot)(nil)
	_ fs.NodeRmdirer        = (*allRoot)(nil)
	_ fs.NodeUnlinker       = (*allRoot)(nil)
	_ fs.NodeRenamer        = (*allRoot)(nil)
	_ fs.NodeCreater        = (*allRoot)(nil)
	_ fs.NodeSymlinker      = (*allRoot)(nil)
	_ fs.NodeLinker         = (*allRoot)(nil)
	_ fs.NodeMknoder        = (*allRoot)(nil)
)

// OnAdd hangs the control folder from the root.
func (n *allRoot) OnAdd(ctx context.Context) {
	n.drv.addControl(ctx, n.EmbeddedInode())
}

// folderName returns the name the folder of a dataroom is presented under. A
// title is free text and a file name is not: a slash or a NUL becomes an
// underscore.
func folderName(displayName string) string {
	return strings.NewReplacer("/", "_", "\x00", "_").Replace(displayName)
}

// list returns one entry per dataroom, from the list vfs caches. A dataroom
// whose name cannot be presented (".", "..", too long), or is taken by an
// earlier one once slashes are replaced, or by the control folder, is left
// out.
func (n *allRoot) list(ctx context.Context) ([]dirEntry, syscall.Errno) {
	ctx, span := startSpan(ctx, "readdir", "", "")
	stamp := n.drv.stamp()
	datarooms, err := n.drv.tree.Datarooms(ctx)
	span.End(err)
	if err != nil {
		return nil, toErrno(err)
	}

	entries := make([]dirEntry, 0, len(datarooms))
	seen := make(map[string]bool, len(datarooms))
	for _, dr := range datarooms {
		name := folderName(dr.DisplayName)
		if !presentable(name) || name == controlDirName || seen[name] {
			continue
		}
		seen[name] = true
		entries = append(entries, dirEntry{
			node:         vfs.Node{Name: name, Type: vfs.TypeDir},
			ino:          n.drv.inodes.ino(dataroomKey(dr.ID)),
			dataroomID:   dr.ID,
			seen:         stamp,
			dataroomRoot: true,
		})
	}
	n.drv.reconcile(n.EmbeddedInode(), entries)

	return entries, 0
}

// Lookup finds a dataroom by the name of its folder.
func (n *allRoot) Lookup(
	ctx context.Context, name string, out *fuse.EntryOut,
) (child *fs.Inode, errno syscall.Errno) {
	c := n.drv.begin("lookup", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	if name == controlDirName {
		return n.drv.lookupControl(n.EmbeddedInode(), out)
	}
	entries, errno := n.list(ctx)
	if errno != 0 {
		return nil, errno
	}
	for _, e := range entries {
		if e.node.Name == name {
			return n.drv.child(ctx, n.EmbeddedInode(), e, out), 0
		}
	}

	return nil, syscall.ENOENT
}

// OpendirHandle lists the datarooms.
func (n *allRoot) OpendirHandle(
	ctx context.Context, _ uint32,
) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	c := n.drv.begin("opendir", n.ino)
	defer c.end(&errno)
	ctx = c.guard(ctx)

	h := &dirHandle{drv: n.drv, dir: n.EmbeddedInode(), list: n.list}
	if errno := h.load(ctx); errno != 0 {
		return nil, 0, errno
	}

	return h, 0, 0
}

// Creating or removing a dataroom is no file operation: it takes a key
// exchange with its members. mkdir and rmdir at this level are refused for
// good, EPERM, whatever the mount allows below.

func (n *allRoot) Mkdir(context.Context, string, uint32, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}

func (n *allRoot) Rmdir(context.Context, string) syscall.Errno { return syscall.EPERM }

func (n *allRoot) Unlink(context.Context, string) syscall.Errno { return syscall.EPERM }

func (n *allRoot) Rename(context.Context, string, fs.InodeEmbedder, string, uint32) syscall.Errno {
	return syscall.EPERM
}

func (n *allRoot) Create(
	context.Context, string, uint32, uint32, *fuse.EntryOut,
) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	return nil, nil, 0, syscall.EPERM
}

func (n *allRoot) Symlink(context.Context, string, string, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}

func (n *allRoot) Link(context.Context, fs.InodeEmbedder, string, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}

func (n *allRoot) Mknod(context.Context, string, uint32, uint32, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EPERM
}
