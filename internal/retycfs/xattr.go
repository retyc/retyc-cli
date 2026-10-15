//go:build linux

package retycfs

import (
	"context"
	"syscall"

	"github.com/retyc/retyc-cli/internal/vfs"
)

// The extended attributes every inode of a dataroom carries, read only. They
// give the identifiers the API, the web application and a trace know the node
// by, which no name in the tree shows.
const (
	xattrNodeID     = "user.retyc.node_id"
	xattrVersionID  = "user.retyc.version_id"
	xattrDataroomID = "user.retyc.dataroom_id"
	xattrMIME       = "user.retyc.mime"
)

// xattr is one extended attribute.
type xattr struct {
	name, value string
}

// xattrs returns the attributes of node in the dataroom: those that have a
// value. A folder has no version nor MIME type, the root of a dataroom no
// node ID.
func xattrs(dataroomID string, node vfs.Node) []xattr {
	var out []xattr
	add := func(name, value string) {
		if value != "" {
			out = append(out, xattr{name, value})
		}
	}
	add(xattrDataroomID, dataroomID)
	add(xattrNodeID, node.ID)
	if node.Type == vfs.TypeFile {
		add(xattrVersionID, node.VersionID)
		add(xattrMIME, node.MIMEType)
	}

	return out
}

// fit copies value to dest and returns its length; with a dest too short it
// returns the length needed and ERANGE, which is also how the size is asked
// for (an empty dest).
func fit(dest []byte, value string) (uint32, syscall.Errno) {
	size := uint32(len(value)) //nolint:gosec // G115: a few identifiers
	if len(dest) < len(value) {
		return size, syscall.ERANGE
	}
	copy(dest, value)

	return size, 0
}

func (b *base) Getxattr(_ context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	for _, x := range xattrs(b.dataroomID, b.state().current()) {
		if x.name == attr {
			return fit(dest, x.value)
		}
	}

	return 0, syscall.ENODATA
}

func (b *base) Listxattr(_ context.Context, dest []byte) (uint32, syscall.Errno) {
	var list []byte
	for _, x := range xattrs(b.dataroomID, b.state().current()) {
		list = append(list, x.name...)
		list = append(list, 0)
	}

	return fit(dest, string(list))
}

// Setxattr and Removexattr answer ENOTSUP: without them go-fuse answers
// ENODATA, which says the attribute does not exist rather than that it cannot
// be written.

func (b *base) Setxattr(context.Context, string, []byte, uint32) syscall.Errno {
	return syscall.ENOTSUP
}

func (b *base) Removexattr(context.Context, string) syscall.Errno {
	return syscall.ENOTSUP
}
