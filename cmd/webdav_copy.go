package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// — COPY ————————————————————————————————————————————————————————————————————————

// handleCopy serves a WebDAV COPY of a file through the API's server-side
// copy: the storage duplicates the chunks, nothing is downloaded or
// re-encrypted. x/net/webdav's own COPY would open the source for reading
// and the destination for writing, moving every byte through the server;
// the mux routes the method here instead.
//
// Folders are not copied (501, as before): the API copies files only, and a
// recursive copy of a tree would fall back to the byte-moving path.
// Semantics follow RFC 4918 §9.8: a destination held by a file is replaced
// unless Overwrite: F (412), by deleting it first, since the API only copies
// into a new node: its versions go with it, and it is not restored when the
// copy then fails; a missing destination folder is a 409; the
// response is 201 for a new resource, 204 for a replaced one. The copy is
// sealed by the server before the response is sent, so the client can read
// the copy at once.
//
// The copy itself is vfs.FS.Copy; what stays here is HTTP: the Destination,
// Overwrite and If headers, the WebDAV locks, the statuses.
func (fs *webdavFS) handleCopy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, err := fs.copyNode(ctx, r)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		if errors.Is(err, api.ErrRateLimited) {
			writeRateLimited(w, err)

			return
		}
		http.Error(w, "COPY: "+ui.EscapeLines(err.Error()), status)

		return
	}
	w.WriteHeader(status)
}

// copyReplaceRetry and copyReplaceWait pace the copy onto a destination this
// server just deleted: how often it is tried again while the API still holds
// the name, and for how long before the 409 is reported. newWebdavFS hands
// them to the tree, which runs the wait (vfs.FS.Copy).
var (
	copyReplaceRetry = vfs.DefaultCopyReplaceRetry
	copyReplaceWait  = vfs.DefaultCopyReplaceWait
)

// copyNode performs the copy of r and returns the status to answer.
func (fs *webdavFS) copyNode(ctx context.Context, r *http.Request) (int, error) {
	dst, status, err := copyDestination(r)
	if err != nil {
		return status, err
	}
	srcKind, srcDR, srcSub := parseWebdavPath(r.URL.Path)
	dstKind, dstDR, dstSub := parseWebdavPath(dst)
	if srcKind != pathDataroomNode || dstKind != pathDataroomNode || srcSub == "/" || dstSub == "/" {
		return http.StatusForbidden, errors.New("only files inside a dataroom can be copied")
	}
	srcID, err := fs.tree.DataroomByName(ctx, srcDR)
	if err != nil {
		return http.StatusNotFound, err
	}
	dstID, err := fs.tree.DataroomByName(ctx, dstDR)
	if err != nil {
		return http.StatusConflict, err
	}
	if srcID != dstID {
		return http.StatusBadGateway, errors.New("copying between datarooms is not supported")
	}

	// The destination is checked against the WebDAV locks as the handler
	// would have: a file another client locked is not replaced.
	release, status, err := fs.confirmCopyLocks(r, path.Clean(dst))
	if err != nil {
		return status, err
	}
	defer release()

	_, replaced, err := fs.tree.Copy(ctx, srcID, srcSub, dstSub, r.Header.Get("Overwrite") != "F")
	if err != nil {
		return copyStatus(err)
	}
	if replaced {
		return http.StatusNoContent, nil
	}

	return http.StatusCreated, nil
}

// copyStatus maps a failed vfs.FS.Copy to the status RFC 4918 §9.8.5 gives it
// and the error to report. The status depends on which resource failed, hence
// the step: a source that cannot be resolved is a 404 where a missing
// destination folder is a 409.
func copyStatus(err error) (int, error) {
	var failed *vfs.CopyError
	if !errors.As(err, &failed) {
		// A rate limit, which crosses the tree as it is: handleCopy answers
		// it 429 whatever the status.
		return http.StatusInternalServerError, err
	}
	switch failed.Step {
	case vfs.CopySource:
		if errors.Is(err, vfs.ErrIsDir) {
			return http.StatusNotImplemented, errors.New("copying a folder is not supported: copy its files")
		}

		return http.StatusNotFound, failed.Err
	case vfs.CopyDestinationFolder:
		// RFC 4918 §9.8.5: a missing intermediate collection is a 409.
		return http.StatusConflict, fmt.Errorf("destination folder: %w", failed.Err)
	case vfs.CopySession:
		return http.StatusInternalServerError, fmt.Errorf("dataroom session: %w", failed.Err)
	case vfs.CopyDestination:
		switch {
		case errors.Is(err, vfs.ErrSameNode):
			// Two spellings of one path (the Destination header is not
			// normalized): replacing it would delete the source.
			return http.StatusForbidden, errors.New("destination equals source")
		case errors.Is(err, vfs.ErrExist):
			return http.StatusPreconditionFailed, errors.New("destination exists and Overwrite is F")
		case errors.Is(err, vfs.ErrIsDir):
			return http.StatusConflict, errors.New("destination is a folder")
		default:
			// The destination could not be looked up: nothing was copied.
			return http.StatusInternalServerError, fmt.Errorf("destination: %w", failed.Err)
		}
	case vfs.CopyReplace:
		return http.StatusInternalServerError, fmt.Errorf("replacing destination: %w", failed.Err)
	case vfs.CopyTransfer:
	}

	return copyErrorStatus(failed.Err), failed.Err
}

// copyDestination parses the Destination header into a path on this server.
func copyDestination(r *http.Request) (string, int, error) {
	hdr := r.Header.Get("Destination")
	if hdr == "" {
		return "", http.StatusBadRequest, errors.New("missing Destination header")
	}
	u, err := url.Parse(hdr)
	if err != nil {
		return "", http.StatusBadRequest, errors.New("invalid Destination header")
	}
	if u.Host != "" && u.Host != r.Host {
		return "", http.StatusBadGateway, errors.New("the Destination header names another host")
	}
	if u.Path == "" {
		return "", http.StatusBadGateway, errors.New("invalid Destination header")
	}
	if u.Path == r.URL.Path {
		return "", http.StatusForbidden, errors.New("destination equals source")
	}

	return u.Path, 0, nil
}

// confirmCopyLocks checks the destination of a COPY against the WebDAV locks,
// as x/net/webdav does for the methods it serves itself (its confirmLocks is
// not exported). Without an If header the destination must not be locked: a
// temporary lock is taken on it, which another client's lock refuses (423).
// With one, a list of the header must name a lock covering the destination
// (412 otherwise). The returned release ends the hold.
func (fs *webdavFS) confirmCopyLocks(r *http.Request, dst string) (release func(), status int, err error) {
	if fs.locks == nil {
		return func() {}, 0, nil
	}
	now := time.Now()
	hdr := r.Header.Get("If")
	if hdr == "" {
		token, err := fs.locks.Create(now, webdav.LockDetails{Root: dst, Duration: -1, ZeroDepth: true})
		switch {
		case errors.Is(err, webdav.ErrLocked):
			return nil, webdav.StatusLocked, errors.New("the destination is locked")
		case err != nil:
			return nil, http.StatusInternalServerError, err
		}

		return func() { _ = fs.locks.Unlock(now, token) }, 0, nil
	}
	lists, ok := parseIfHeader(hdr)
	if !ok {
		return nil, http.StatusBadRequest, errors.New("invalid If header")
	}
	for _, l := range lists {
		target := dst
		if l.resourceTag != "" {
			u, err := url.Parse(l.resourceTag)
			if err != nil {
				continue
			}
			target = path.Clean(u.Path)
		}
		release, err := fs.locks.Confirm(now, target, "", l.conditions...)
		switch {
		case errors.Is(err, webdav.ErrConfirmationFailed):
			continue
		case err != nil:
			return nil, http.StatusInternalServerError, err
		}

		return release, 0, nil
	}

	return nil, http.StatusPreconditionFailed, errors.New("the If header names no lock on the destination")
}

// ifList is one parenthesized list of an If header, with the resource it is
// tagged with ("" for the request's own).
type ifList struct {
	resourceTag string
	conditions  []webdav.Condition
}

// parseIfHeader parses an If header (RFC 4918 §10.4): lists of state tokens
// and entity tags, each optionally negated, optionally tagged with a resource.
func parseIfHeader(hdr string) ([]ifList, bool) {
	var lists []ifList
	var tag string
	for s := strings.TrimSpace(hdr); s != ""; s = strings.TrimSpace(s) {
		switch s[0] {
		case '<':
			end := strings.IndexByte(s, '>')
			if end < 0 {
				return nil, false
			}
			tag, s = s[1:end], s[end+1:]
		case '(':
			end := strings.IndexByte(s, ')')
			if end < 0 {
				return nil, false
			}
			conditions, ok := parseIfConditions(s[1:end])
			if !ok {
				return nil, false
			}
			lists = append(lists, ifList{resourceTag: tag, conditions: conditions})
			s = s[end+1:]
		default:
			return nil, false
		}
	}

	return lists, len(lists) > 0
}

// parseIfConditions parses the inside of one list of an If header.
func parseIfConditions(s string) ([]webdav.Condition, bool) {
	var conditions []webdav.Condition
	var c webdav.Condition
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		closing := byte('>')
		switch {
		case strings.HasPrefix(s, "Not") && !c.Not:
			c.Not, s = true, s[len("Not"):]

			continue
		case s[0] == '[':
			closing = ']'
		case s[0] != '<':
			return nil, false
		}
		end := strings.IndexByte(s, closing)
		if end < 0 {
			return nil, false
		}
		if closing == '>' {
			c.Token = s[1:end]
		} else {
			c.ETag = s[1:end]
		}
		conditions = append(conditions, c)
		c, s = webdav.Condition{}, s[end+1:]
	}

	return conditions, len(conditions) > 0 && !c.Not
}

// copyErrorStatus maps a failed server-side copy to an HTTP status.
func copyErrorStatus(err error) int {
	var httpErr *api.HTTPError
	switch {
	case errors.Is(err, api.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, api.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, service.ErrCopyDiscarded), errors.Is(err, service.ErrCopyTargetDeleted):
		return http.StatusInternalServerError
	case errors.Is(err, vfs.ErrStorageExceeded):
		// The copy exceeds the storage (a 400 of the API).
		return http.StatusInsufficientStorage
	case errors.Is(err, vfs.ErrForbidden):
		return http.StatusForbidden
	case errors.As(err, &httpErr):
		switch httpErr.Status {
		case http.StatusServiceUnavailable:
			return httpErr.Status
		case http.StatusUnprocessableEntity:
			return http.StatusNotImplemented
		}
	}

	return http.StatusInternalServerError
}

// — Quota (RFC 4331) ————————————————————————————————————————————————————————————
//
// The counters come from vfs.FS.Quota, cached there per dataroom.

// quotaFunc is what a folder handle calls to report its dataroom's quota.
type quotaFunc func() (used, free int64, ok bool)

// quotaProps renders the RFC 4331 properties for DeadProps.
func quotaProps(used, free int64) map[string]string {
	return map[string]string{
		"quota-used-bytes":      strconv.FormatInt(used, 10),
		"quota-available-bytes": strconv.FormatInt(free, 10),
	}
}

// quotaOnce memoizes a folder handle's quota lookup for the life of the
// handle: PROPFIND opens the handle once per listed resource.
func quotaOnce(fn quotaFunc) quotaFunc {
	var once sync.Once
	var used, free int64
	var ok bool

	return func() (int64, int64, bool) {
		once.Do(func() { used, free, ok = fn() })

		return used, free, ok
	}
}
