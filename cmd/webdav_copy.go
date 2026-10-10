package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/ui"
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
func (fs *webdavFS) handleCopy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, err := fs.copyNode(ctx, r)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		http.Error(w, "COPY: "+ui.EscapeLines(err.Error()), status)

		return
	}
	w.WriteHeader(status)
}

// copyReplaceRetry and copyReplaceWait pace the copy onto a destination this
// server just deleted: how often it is tried again while the API still holds
// the name, and for how long before the 409 is reported.
var (
	copyReplaceRetry = 500 * time.Millisecond
	copyReplaceWait  = 15 * time.Second
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
	srcID, err := fs.cache.idForName(ctx, srcDR)
	if err != nil {
		return http.StatusNotFound, err
	}
	dstID, err := fs.cache.idForName(ctx, dstDR)
	if err != nil {
		return http.StatusConflict, err
	}
	if srcID != dstID {
		return http.StatusBadGateway, errors.New("copying between datarooms is not supported")
	}

	srcParent, srcName := splitWebdavPath(srcSub)
	src, err := fs.findListedNode(ctx, srcID, srcParent, srcName)
	if err != nil {
		return http.StatusNotFound, err
	}
	if src.Type == "dir" {
		return http.StatusNotImplemented, errors.New("copying a folder is not supported: copy its files")
	}
	dstParent, dstName := splitWebdavPath(dstSub)
	dstParentID, err := fs.parentNodeID(ctx, dstID, dstParent)
	if err != nil {
		// RFC 4918 §9.8.5: a missing intermediate collection is a 409.
		return http.StatusConflict, fmt.Errorf("destination folder: %w", err)
	}

	status = http.StatusCreated
	if existing, err := fs.findListedNode(ctx, dstID, dstParent, dstName); err == nil {
		if r.Header.Get("Overwrite") == "F" {
			return http.StatusPreconditionFailed, errors.New("destination exists and Overwrite is F")
		}
		if existing.Type == "dir" {
			return http.StatusConflict, errors.New("destination is a folder")
		}
		if err := fs.client.DeleteDataroomNode(ctx, existing.ID); err != nil && !errors.Is(err, api.ErrNotFound) {
			return http.StatusInternalServerError, fmt.Errorf("replacing destination: %w", err)
		}
		fs.removeFromNodeCache(dataroomURI(dstID, dstParent), dstName)
		status = http.StatusNoContent
	}

	sess, err := fs.getSession(ctx, dstID)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("dataroom session: %w", err)
	}
	node, err := service.CopyDataroomNodeByID(ctx, fs.client, src.ID, dstParentID, dstName, sess)
	// The API keeps the name of the file just deleted until its purge has run
	// (seconds with the workers keeping up) and answers 409 meanwhile.
	for waited := time.Duration(0); status == http.StatusNoContent && errors.Is(err, api.ErrConflict) &&
		waited < copyReplaceWait; waited += copyReplaceRetry {
		select {
		case <-ctx.Done():
			return http.StatusInternalServerError, ctx.Err()
		case <-time.After(copyReplaceRetry):
		}
		node, err = service.CopyDataroomNodeByID(ctx, fs.client, src.ID, dstParentID, dstName, sess)
	}
	if err != nil {
		return copyErrorStatus(err), err
	}
	fs.upsertNodeCache(dataroomURI(dstID, dstParent), node)

	return status, nil
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
	case errors.As(err, &httpErr):
		switch httpErr.Status {
		case http.StatusBadRequest:
			// The copy exceeds the storage.
			return http.StatusInsufficientStorage
		case http.StatusForbidden, http.StatusServiceUnavailable:
			return httpErr.Status
		case http.StatusUnprocessableEntity:
			return http.StatusNotImplemented
		}
	}

	return http.StatusInternalServerError
}

// — Quota (RFC 4331) ————————————————————————————————————————————————————————————

// quotaCacheEntry is a dataroom's storage counters as last fetched.
type quotaCacheEntry struct {
	used, free int64
	fetchedAt  time.Time
}

// dataroomQuota returns the storage used by the dataroom and the room left
// (its reserved capacity, or its owner's plan remainder), from
// GET /dataroom/{id}/stats, cached for the listing TTL: a PROPFIND asks the
// quota of every collection it lists. ok is false when the counters are
// unavailable (an older API, or a failed fetch), in which case no quota
// property is reported.
func (fs *webdavFS) dataroomQuota(ctx context.Context, drID string) (used, free int64, ok bool) {
	fs.quotaMu.Lock()
	entry, cached := fs.quotaCache[drID]
	fs.quotaMu.Unlock()
	if cached && time.Since(entry.fetchedAt) < fs.nodeTTL() {
		return entry.used, entry.free, true
	}
	stats, err := fs.client.GetDataroomStats(ctx, drID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webdav: dataroom quota: %s\n", ui.EscapeLines(err.Error()))

		return 0, 0, false
	}
	if stats.StorageUsed == nil {
		// An API without storage counters.
		return 0, 0, false
	}
	fs.quotaMu.Lock()
	if fs.quotaCache == nil {
		fs.quotaCache = make(map[string]quotaCacheEntry)
	}
	fs.quotaCache[drID] = quotaCacheEntry{used: *stats.StorageUsed, free: stats.StorageFree, fetchedAt: time.Now()}
	fs.quotaMu.Unlock()

	return *stats.StorageUsed, stats.StorageFree, true
}

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
