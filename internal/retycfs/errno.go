//go:build linux

package retycfs

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// ErrLegacyAPI is what Options.CheckDataroom returns for a dataroom served by
// an API that predates the lookup by name: the driver does not serve it.
var ErrLegacyAPI = errors.New("the API of this dataroom is too old for a FUSE mount")

// errGoingAway refuses what would start a new spool once the shutdown has
// stopped sending them (see spoolRegistry.seal): ENOTCONN, which is what the
// kernel answers for the mount as soon as the process serving it is gone.
var errGoingAway = errors.New("the filesystem is being unmounted")

// The HTTP statuses read from an *api.HTTPError; net/http is not needed here.
const (
	statusUnauthorized = 401
	statusForbidden    = 403
)

// toErrno maps an error of internal/vfs, or one of the API that crossed it,
// to the errno a system call returns. It is the only place that does.
//
// The order matters where an error matches several sentinels:
//
//   - a request the API rate limit defeated is EIO. The client has already
//     waited and retried for the whole budget (api.retry.*): the operation
//     blocked for that long, like a hard NFS mount, and EAGAIN would be taken
//     as an error, or looped on, by a program reading a blocking descriptor;
//   - a missing chunk matches api.ErrNotFound too, and is EIO, not ENOENT: the
//     file exists, its content cannot be read;
//   - a cancelled request is EINTR, which is what the kernel expects of an
//     interrupted one. The context of a handler only ends when its caller is
//     being killed or the mount is going away (see driver.guard), so no
//     program reads that errno: a signal it handles interrupts nothing;
//   - a name the API still holds for a node being deleted (410 on a creation)
//     is EBUSY, not the ENOENT of any other 410;
//   - a spool with no room left is ENOSPC like a dataroom with none: both are
//     what write(2) and close(2) report for a file that cannot be stored;
//   - a dataroom the API reports read-only (DATAROOM_READ_ONLY, its owner's
//     plan exceeded) is EROFS, not the EACCES of the 403 it also is;
//   - an API without symbolic links is EPERM, which is what symlink(2)
//     documents for a filesystem that cannot create one;
//   - a file that cannot be opened for writing any more because the mount is
//     going away (errGoingAway) is ENOTCONN, like everything on that mount a
//     moment later.
//
// No write ever answers ENOSYS, which the kernel takes for "never ask again".
//
// An errno wrapped in the error is never passed on: it would be the one of
// the HTTP client (ECONNREFUSED, ETIMEDOUT), which says nothing true of the
// file. Whatever is not recognised is EIO.
func toErrno(err error) syscall.Errno {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errGoingAway):
		return syscall.ENOTCONN
	case errors.Is(err, api.ErrRateLimited):
		return syscall.EIO
	case errors.Is(err, context.Canceled):
		return syscall.EINTR
	case errors.Is(err, api.ErrChunkMissing), errors.Is(err, vfs.ErrChunkLayout), errors.Is(err, vfs.ErrClosed):
		return syscall.EIO
	case errors.Is(err, vfs.ErrNotEmpty):
		return syscall.ENOTEMPTY
	case errors.Is(err, vfs.ErrIsDir):
		return syscall.EISDIR
	case errors.Is(err, vfs.ErrNotDir), errors.Is(err, os.ErrInvalid):
		// os.ErrInvalid is how vfs.FS.FolderID reports a path component that
		// is not a folder.
		return syscall.ENOTDIR
	case errors.Is(err, vfs.ErrNotFile), errors.Is(err, vfs.ErrNegativeOffset):
		return syscall.EINVAL
	case errors.Is(err, vfs.ErrStorageExceeded), errors.Is(err, vfs.ErrSpoolFull):
		return syscall.ENOSPC
	case errors.Is(err, vfs.ErrNameBeingDeleted), errors.Is(err, api.ErrLocked):
		return syscall.EBUSY
	case errors.Is(err, vfs.ErrSameNode):
		return syscall.EINVAL
	case errors.Is(err, vfs.ErrReplaceUnsupported), errors.Is(err, ErrLegacyAPI):
		return syscall.ENOTSUP
	case errors.Is(err, vfs.ErrSymlinkUnsupported):
		return syscall.EPERM
	case errors.Is(err, vfs.ErrReadOnly):
		// Matches vfs.ErrForbidden too: the role allows the write, the
		// owner's plan does not.
		return syscall.EROFS
	case errors.Is(err, vfs.ErrForbidden), errors.Is(err, vfs.ErrUnauthenticated),
		errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
		return syscall.EACCES
	case errors.Is(err, vfs.ErrNotExist), errors.Is(err, api.ErrNotFound), errors.Is(err, api.ErrGone):
		return syscall.ENOENT
	case errors.Is(err, vfs.ErrExist), errors.Is(err, api.ErrConflict):
		return syscall.EEXIST
	}

	// Path resolution returns the API's refusals as they are, without a vfs
	// sentinel (see vfs.classify): their status is read here.
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) && (httpErr.Status == statusUnauthorized || httpErr.Status == statusForbidden) {
		return syscall.EACCES
	}

	return syscall.EIO
}
