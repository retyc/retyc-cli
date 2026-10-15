package vfs

import (
	"errors"
	"os"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/service"
)

// The sentinel errors of the package. A front end maps them with errors.Is to
// its own vocabulary (an HTTP status, an errno) instead of reading the API's
// answers itself.
//
// An error of a mutation that carries one of them still carries the error it
// was made from (see kindError): errors.Is keeps matching the sentinels of
// internal/api, internal/service and internal/auth, and errors.As still finds
// the *api.HTTPError. Its message is the one of the original error.
//
// api.ErrRateLimited is never given a sentinel of this package: a request the
// API rate limit defeated crosses vfs as it is.
//
// ErrNotExist and ErrExist are the errors of the standard library, so a bare
// one still satisfies os.IsNotExist and os.IsExist, which do not unwrap.
var (
	// ErrNotExist: the path names nothing, or the API answered 404 or 410 for
	// the node its listing named.
	ErrNotExist = os.ErrNotExist
	// ErrExist: the name is already taken (409), or the destination exists
	// and the caller did not ask to replace it.
	ErrExist = os.ErrExist
	// ErrNotEmpty: a folder removed without recursive has children.
	ErrNotEmpty = errors.New("directory not empty")
	// ErrIsDir: the operation applies to files and the path names a folder.
	ErrIsDir = errors.New("is a directory")
	// ErrNotDir: a path component that must be a folder is not one.
	ErrNotDir = errors.New("not a directory")
	// ErrSameNode: the source and the destination of a copy resolve to the
	// same node.
	ErrSameNode = errors.New("source and destination are the same node")
	// ErrStorageExceeded: the API refused a write for lack of storage.
	ErrStorageExceeded = errors.New("storage exceeded")
	// ErrForbidden: the API refused the operation to this user (403).
	ErrForbidden = errors.New("forbidden")
	// ErrReadOnly: the role allows the write but the dataroom is read-only,
	// its owner's plan being exceeded (403 DATAROOM_READ_ONLY). It is given
	// in addition to ErrForbidden, never in its place.
	ErrReadOnly = errors.New("dataroom is read-only")
	// ErrUnauthenticated: the API answered 401, or there is no token left to
	// call it with.
	ErrUnauthenticated = errors.New("not authenticated")
	// ErrReplaceUnsupported: a rename asked to replace its destination on an
	// API that cannot do it in one request (see Rename).
	ErrReplaceUnsupported = errors.New("replacing the destination of a rename is not supported by the API")
	// ErrSymlinkUnsupported: the API has no symbolic links (see Symlink). It
	// is service.ErrSymlinkUnsupported, so an error of the service layer
	// carries it as it is.
	ErrSymlinkUnsupported = service.ErrSymlinkUnsupported
)

// The HTTP statuses read from an *api.HTTPError; net/http is not imported
// here (see the dependency rule of the package).
const (
	statusUnauthorized = 401
	statusForbidden    = 403
)

// replaceFolderDetail is the detail of the 409 an API without error codes
// answers to a rename asked to replace a folder.
const replaceFolderDetail = "Cannot replace a folder"

// isReplaceFolder reports the 409 of a replace whose destination is a folder:
// the code REPLACE_TARGET_IS_FOLDER, or, without a code, the former detail.
func isReplaceFolder(err error) bool {
	if !errors.Is(err, api.ErrConflict) {
		return false
	}
	if code := api.ErrorCode(err); code != "" {
		return code == api.CodeReplaceTargetIsFolder
	}

	return api.ErrorDetail(err) == replaceFolderDetail
}

// isConcurrentUpdate reports the 409 the API answers when a concurrent
// request changed the same rows: worth one more try. Only a code tells it.
func isConcurrentUpdate(err error) bool {
	return errors.Is(err, api.ErrConflict) && api.ErrorCode(err) == api.CodeConcurrentUpdate
}

// kindError gives err a sentinel of this package without changing its
// message: both are found by errors.Is and errors.As.
type kindError struct {
	kind error
	err  error
}

func (e *kindError) Error() string   { return e.err.Error() }
func (e *kindError) Unwrap() []error { return []error{e.kind, e.err} }

// as returns err carrying the sentinel kind.
func as(kind, err error) error { return &kindError{kind: kind, err: err} }

// httpStatus returns the status of the API refusal in err's chain, 0 when
// there is none.
func httpStatus(err error) int {
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Status
	}

	return 0
}

// classify gives the error of an API mutation the sentinel of its status: 401
// or a missing token is ErrUnauthenticated, 403 is ErrForbidden, and also
// ErrReadOnly when its code is DATAROOM_READ_ONLY. Everything else, a rate
// limit included, is returned as it is.
//
// It is applied to the mutation itself, not to the resolution of its paths: an
// error met while listing a folder reaches the caller unchanged.
func classify(err error) error {
	if err == nil || errors.Is(err, api.ErrRateLimited) {
		return err
	}
	switch status := httpStatus(err); {
	case status == statusUnauthorized,
		errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
		return as(ErrUnauthenticated, err)
	case status == statusForbidden && api.ErrorCode(err) == api.CodeDataroomReadOnly:
		return as(ErrReadOnly, as(ErrForbidden, err))
	case status == statusForbidden:
		return as(ErrForbidden, err)
	}

	return err
}

// isStorageExceeded reports a write the API refused for lack of storage: a
// 400 whose detail says so, on the single-request upload, the creation of a
// version (for the size announced), the upload of a chunk (checked again for
// each, so an upload can pass the first and fail at the Nth) and the
// server-side copy. Other 400s (the version limit, the MIME table limit, a
// dataroom without name salt) are not.
func isStorageExceeded(err error) bool {
	return api.IsStorageExceeded(err)
}
