//go:build linux

package retycfs

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// The control folder sits at the root of the mount and is left out of its
// listing: it is reached by name only. The name is not ".retyc", which a
// dataroom may well hold.
const (
	controlDirName = ".retycfs"
	accessLogName  = "accesslog"
)

// addControl hangs the control folder and its files from the root of the
// mount. They are persistent inodes: they exist whether or not the kernel
// knows them.
func (d *driver) addControl(ctx context.Context, root *fs.Inode) {
	dir := root.NewPersistentInode(ctx, &controlDir{drv: d},
		fs.StableAttr{Mode: syscall.S_IFDIR, Ino: controlIno})
	file := dir.NewPersistentInode(ctx, &accessLogNode{drv: d},
		fs.StableAttr{Mode: syscall.S_IFREG, Ino: accessLogIno})
	dir.AddChild(accessLogName, file, true)
	root.AddChild(controlDirName, dir, true)
}

// lookupControl answers the lookup of the control folder in the root.
func (d *driver) lookupControl(root *fs.Inode, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	dir := root.GetChild(controlDirName)
	if dir == nil {
		return nil, syscall.ENOENT
	}
	d.controlAttr(controlIno, syscall.S_IFDIR|0o555, &out.Attr)

	return dir, 0
}

// controlAttr writes the attributes of a control inode.
func (d *driver) controlAttr(ino uint64, mode uint32, out *fuse.Attr) {
	out.Ino = ino
	out.Mode = mode
	out.Nlink = 1
	if mode&syscall.S_IFDIR != 0 {
		out.Nlink = 2
	}
	out.Uid, out.Gid = d.attrs.uid, d.attrs.gid
	out.Blksize = blockSize
	out.SetTimes(&d.attrs.epoch, &d.attrs.epoch, &d.attrs.epoch)
}

// controlDir is the control folder. It has no Lookup nor Readdir of its own:
// go-fuse serves both from its children.
type controlDir struct {
	fs.Inode
	drv *driver
}

var _ fs.NodeGetattrer = (*controlDir)(nil)

func (n *controlDir) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.drv.controlAttr(controlIno, syscall.S_IFDIR|0o555, &out.Attr)

	return 0
}

// accessLogNode is .retycfs/accesslog: the operations of the mount as they
// happen, one line each (see accessRecord). `cat` follows it until the
// filesystem is unmounted.
//
// It is a stream, not a file with a size: it is opened with direct I/O (no
// page cache, a read returns what there is) and without seeking. `tail -f`
// seeks to the end of what it takes for a regular file and shows nothing;
// `cat` and `tail -n +1 -f` work.
//
// Its own reads are not logged: they would feed it.
type accessLogNode struct {
	fs.Inode
	drv *driver
}

var (
	_ fs.NodeGetattrer = (*accessLogNode)(nil)
	_ fs.NodeOpener    = (*accessLogNode)(nil)
	_ fs.NodeReader    = (*accessLogNode)(nil)
)

func (n *accessLogNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.drv.controlAttr(accessLogIno, syscall.S_IFREG|0o444, &out.Attr)

	return 0
}

func (n *accessLogNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		return nil, 0, syscall.EROFS
	}

	return n.drv.log.reader(), fuse.FOPEN_DIRECT_IO | fuse.FOPEN_NONSEEKABLE, 0
}

// Read waits for the next operations. It returns the end of the file once
// the mount is going away, which is what lets the unmount through: a reader
// left blocked would hold the mount busy.
//
// The wait ends with EINTR as soon as the kernel interrupts the request, on
// the context go-fuse ends, not on the one of driver.guard: unlike any other
// operation this one may last for ever on an idle mount, and guard only
// honours the interruption of a caller /proc shows being killed. A reader of
// another PID namespace (PID 0), or one /proc hides, could then never be
// killed. The price is that a signal the reader handles ends its read(2)
// with EINTR, as on any slow device: nothing is lost (no record is consumed
// by a read that returns none), and cat, tail and the runtimes that read
// for a program read again.
func (n *accessLogNode) Read(
	ctx context.Context, fh fs.FileHandle, dest []byte, _ int64,
) (fuse.ReadResult, syscall.Errno) {
	r, ok := fh.(*accessReader)
	if !ok {
		return nil, syscall.EBADF
	}
	read, err := r.read(ctx, dest)
	if err != nil {
		return nil, syscall.EINTR
	}

	return fuse.ReadResultData(dest[:read]), 0
}
