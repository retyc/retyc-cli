package vfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
)

// DefaultFileMode is the mode of a file whose node stores none.
const DefaultFileMode os.FileMode = 0644

// WithExecutable returns mode with its execute bits set for whoever may read
// the file (what chmod +x gives under the usual umask), or cleared. A node
// without a stored mode starts from DefaultFileMode.
func WithExecutable(mode os.FileMode, executable bool) os.FileMode {
	if mode.Perm() == 0 {
		mode |= DefaultFileMode
	}

	return withExecutable(mode, executable)
}

// withExecutable is WithExecutable for a stored mode, 0 included.
func withExecutable(mode os.FileMode, executable bool) os.FileMode {
	if !executable {
		return mode &^ 0111
	}

	return mode | 0100 | (mode&0444)>>2
}

// Chmod stores mode as the POSIX mode of the file at path (PUT
// /dataroom/node/{id}, no new version). See SetExecutable for its errors.
func (fs *FS) Chmod(ctx context.Context, dataroomID, path string, mode os.FileMode) error {
	return fs.chmod(ctx, dataroomID, path, func(os.FileMode, bool) os.FileMode { return mode })
}

// SetExecutable sets or clears the execute bits of the stored mode of the
// file at path (see WithExecutable), the only part of a mode some front ends
// carry. A mode that does not change costs no request.
//
// ErrNotExist when the path names nothing, or a node deleted elsewhere since
// it was listed; ErrIsDir for a folder: only files carry a mode the API
// honours; ErrForbidden when the API refuses (403); api.ErrLocked when
// another client holds the file.
func (fs *FS) SetExecutable(ctx context.Context, dataroomID, path string, executable bool) error {
	return fs.chmod(ctx, dataroomID, path, func(mode os.FileMode, stored bool) os.FileMode {
		if stored {
			return withExecutable(mode, executable)
		}

		return WithExecutable(mode, executable)
	})
}

// fileAt returns the file at path, with the path of its folder.
func (fs *FS) fileAt(ctx context.Context, dataroomID, path string) (node Node, parentPath string, err error) {
	parentPath, name := SplitPath(path)
	node, err = fs.Lookup(ctx, dataroomID, parentPath, name)
	switch {
	case err != nil:
		return Node{}, "", err
	case node.Type == TypeDir:
		return Node{}, "", ErrIsDir
	case node.Type != TypeFile:
		return Node{}, "", fmt.Errorf("not a regular file: %w", os.ErrInvalid)
	}

	return node, parentPath, nil
}

// apiFileMode is the mode of a file that has none stored, for the API and for
// every client of the dataroom.
const apiFileMode os.FileMode = 0o644

// unsetFileMode reports whether giving mode to the file stored would change
// nothing for anyone: the file has none, mode is the one
// the API means by that, and the front end presents such a file with it too
// (Options.FileMode). Storing it would be a request to write the default.
func (fs *FS) unsetFileMode(stored Node, mode os.FileMode) bool {
	shown := fs.opts.FileMode.Perm()
	if shown == 0 {
		shown = apiFileMode
	}

	return !stored.HasMode() && mode.Perm() == apiFileMode && shown == apiFileMode
}

// chmod gives the file at path the mode newMode derives from its stored one
// (stored false: none), and updates its cached listing in place. A mode the
// node stores already costs no request; an explicit 0 given to a node that
// stores none is sent.
func (fs *FS) chmod(
	ctx context.Context, dataroomID, path string, newMode func(mode os.FileMode, stored bool) os.FileMode,
) error {
	node, parentPath, err := fs.fileAt(ctx, dataroomID, path)
	if err != nil {
		return err
	}
	mode := newMode(node.Mode, node.HasMode())
	if (node.HasMode() && mode == node.Mode) || fs.unsetFileMode(node, mode) {
		return nil
	}
	err = fs.client.SetDataroomNodeAccessMode(ctx, node.ID, api.FormatAccessMode(mode))
	if errors.Is(err, api.ErrNotFound) {
		// The listing named a node deleted elsewhere.
		fs.InvalidateListing(dataroomID, parentPath)

		return as(ErrNotExist, err)
	}
	if err != nil {
		return classify(err)
	}
	node.Mode, node.ModeSet = mode, true
	fs.upsert(dataroomID, parentPath, node)

	return nil
}

// SetModTime declares t as the modification time of the file at path: the
// client_mtime of its current version (PATCH /dataroom/node/version/{id}), no
// new version. The cached listing is updated in place. A time the version
// already carries, at the precision the API keeps (see sameModTime), costs no
// request: cp -a and rsync date a server-side copy with the time it kept.
//
// ErrNotExist when the path names nothing, or a version deleted elsewhere
// since it was listed; ErrIsDir for a folder, whose time is its creation's;
// ErrForbidden when the API refuses (403).
func (fs *FS) SetModTime(ctx context.Context, dataroomID, path string, t time.Time) error {
	node, parentPath, err := fs.fileAt(ctx, dataroomID, path)
	if err != nil {
		return err
	}
	if node.VersionID == "" {
		return fmt.Errorf("the file has no version to date: %w", os.ErrInvalid)
	}
	if sameModTime(node.ModTime, t) {
		return nil
	}
	err = fs.client.SetDataroomVersionClientMtime(ctx, node.VersionID, t)
	if errors.Is(err, api.ErrNotFound) {
		fs.InvalidateListing(dataroomID, parentPath)

		return as(ErrNotExist, err)
	}
	if err != nil {
		return classify(err)
	}
	node.ModTime = t
	fs.upsert(dataroomID, parentPath, node)

	return nil
}

// modTimePrecision is what the API keeps of a client_mtime: it is sent with
// nanoseconds (RFC 3339) and stored as a timestamp of microseconds.
const modTimePrecision = time.Microsecond

// sameModTime reports whether declaring t for a version dated held would
// change nothing at the API. A version without a date is never the same.
func sameModTime(held, t time.Time) bool {
	return !held.IsZero() && held.Truncate(modTimePrecision).Equal(t.Truncate(modTimePrecision))
}
