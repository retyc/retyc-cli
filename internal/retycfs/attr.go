//go:build linux

package retycfs

import (
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// The modes presented when the API stores none for a node, unless the mount
// is given others (Options.FileMode, Options.DirMode).
const (
	defaultFileMode uint32 = 0o644
	defaultDirMode  uint32 = 0o755
	symlinkMode     uint32 = 0o777
)

// blockSize is the preferred I/O size reported for every inode, and the unit
// of Statfs.
const blockSize = 4096

// attrSource is what the attributes of every inode share: the owner
// presented, and the time given to what carries none.
type attrSource struct {
	uid, gid uint32
	// fileMode and dirMode are the permissions of a node the API stores no
	// mode for.
	fileMode, dirMode uint32
	// epoch stands for a modification time the API does not know: the root, a
	// dataroom folder, a node it reports no time for.
	epoch time.Time
}

// typeBits returns the file type bits of a node.
func typeBits(t vfs.NodeType) uint32 {
	switch t {
	case vfs.TypeDir:
		return syscall.S_IFDIR
	case vfs.TypeSymlink:
		return syscall.S_IFLNK
	default:
		return syscall.S_IFREG
	}
}

// fill writes the attributes of node, which holds inode number ino, to out.
//
//   - size: the plaintext size of the current version; the length of the
//     target for a symbolic link; 0 for a folder.
//   - mtime, ctime and atime: Node.ModTime (the declared modification time of
//     the version, else its creation; a folder's creation).
//   - mode: the access mode the API stores, without setuid, setgid and sticky;
//     fileMode / dirMode (0644 / 0755 unless configured) when it stores none,
//     an explicit 0 being one (Node.HasMode); 0777 for a symbolic link, as
//     lstat reports one.
//   - nlink: 1, 2 for a folder (sub-folders are not counted: find works with
//     that, as on every FUSE filesystem).
//   - blocks: the size in 512-byte units, rounded up.
func (a attrSource) fill(node vfs.Node, ino uint64, out *fuse.Attr) {
	out.Ino = ino
	out.Uid, out.Gid = a.uid, a.gid
	out.Blksize = blockSize
	out.Nlink = 1
	out.Size = 0

	perm := uint32(node.Mode.Perm())
	switch node.Type {
	case vfs.TypeDir:
		if !node.HasMode() {
			perm = a.dirMode
		}
		out.Nlink = 2
	case vfs.TypeSymlink:
		perm = symlinkMode
		out.Size = uint64(len(node.Target))
	default:
		if !node.HasMode() {
			perm = a.fileMode
		}
		if node.Size > 0 {
			out.Size = uint64(node.Size)
		}
	}
	out.Mode = typeBits(node.Type) | perm
	out.Blocks = (out.Size + 511) / 512

	mtime := node.ModTime
	if mtime.IsZero() {
		mtime = a.epoch
	}
	out.SetTimes(&mtime, &mtime, &mtime)
}
