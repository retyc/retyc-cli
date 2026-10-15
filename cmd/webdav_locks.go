package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// lockMirror mirrors the WebDAV locks clients take on files onto the API's
// advisory node locks, so that another cooperating RETYC client (a second
// mount; the web app ignores locks) sees the file as locked, and so that a
// file another client locked answers 423 to a LOCK here.
//
// x/net/webdav keeps its own in-memory lock system (the one doing the WebDAV
// bookkeeping: lock-null resources, folders, If-header checks). The mirror
// does not replace it: it watches the LOCK and UNLOCK requests, and when the
// locked path is a listed file, has the matching server lock taken, refreshed
// and released. A LOCK the server refuses (423) is undone locally and refused
// to the client. The temporary locks x/net/webdav takes around every write
// without an If header never reach the server: a request per write would be
// too dear for an advisory lock.
//
// The server locks themselves are held by the tree (vfs.LockManager), keyed by
// WebDAV lock token: it renews them while their WebDAV lock stands (server
// leases are bounded, 5 min at most, while WebDAV clients ask for hours or
// infinity), releases the lapsed ones and all of them on shutdown. What stays
// here is HTTP: the LOCK and UNLOCK requests, their headers, the timeout of
// the response, the local lock system.
type lockMirror struct {
	fs *webdavFS
	ls webdav.LockSystem
}

// locks returns the manager of the server locks. It is read from the file
// system at each use rather than kept: tests swap the tree under it.
func (m *lockMirror) locks() *vfs.LockManager { return m.fs.tree.Locks() }

// lockTimeoutRE matches the timeout x/net/webdav grants in a LOCK response.
var lockTimeoutRE = regexp.MustCompile(`<D:timeout>Second-(\d+)</D:timeout>`)

// lockExpiry reads from a LOCK response when the lock it grants lapses, the
// zero time for one without timeout.
func lockExpiry(body []byte, now time.Time) time.Time {
	m := lockTimeoutRE.FindSubmatch(body)
	if m == nil {
		return time.Time{}
	}
	seconds, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		return time.Time{}
	}

	return now.Add(time.Duration(seconds) * time.Second)
}

func newLockMirror(fs *webdavFS, ls webdav.LockSystem) *lockMirror {
	return &lockMirror{fs: fs, ls: ls}
}

// middleware wraps the WebDAV handler to mirror LOCK and UNLOCK.
func (m *lockMirror) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "LOCK":
			m.handleLock(w, r, next)
		case "UNLOCK":
			m.handleUnlock(w, r, next)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// handleLock lets the WebDAV handler answer the LOCK into a buffer, then
// mirrors a granted lock on a listed file before releasing the buffer.
func (m *lockMirror) handleLock(w http.ResponseWriter, r *http.Request, next http.Handler) {
	buf := newBufferedResponse()
	next.ServeHTTP(buf, r)
	// A new lock carries its token in the Lock-Token response header; a
	// refresh names the token it renews in the If request header.
	refresh := r.Header.Get("If") != ""
	token := strings.Trim(buf.Header().Get("Lock-Token"), "<>")
	if refresh {
		token = ifHeaderToken(r.Header.Get("If"))
	}
	if (buf.status != http.StatusOK && buf.status != http.StatusCreated) || token == "" {
		buf.flush(w)

		return
	}
	nodeID, ok := m.lockedFile(r.Context(), r.URL.Path)
	if !ok {
		buf.flush(w)

		return
	}
	expires := lockExpiry(buf.body.Bytes(), time.Now())
	if refresh {
		// The WebDAV lock already stands; the server lock may too.
		m.locks().Refresh(r.Context(), token, nodeID, r.URL.Path, expires)
		buf.flush(w)

		return
	}
	// Take first releases the server locks still held for this file: the one
	// of a WebDAV lock that lapsed locally (MemLS forgets an expired lock in
	// silence) would answer 423 to its own successor.
	err := m.locks().Take(r.Context(), token, nodeID, r.URL.Path, expires)
	switch {
	case errors.Is(err, api.ErrLocked):
		// Another client holds the file: undo the local lock and refuse.
		_ = m.ls.Unlock(time.Now(), token)
		http.Error(w, "LOCK: the file is locked by another client", webdav.StatusLocked)

		return
	case err != nil:
		// The server lock is a courtesy to other clients; the WebDAV lock
		// stands on its own.
		fmt.Fprintf(os.Stderr, "webdav: LOCK %s: server lock not taken: %s\n",
			ui.Escape(r.URL.Path), ui.EscapeLines(err.Error()))
	}
	buf.flush(w)
}

// handleUnlock releases the server lock once the WebDAV handler released
// the local one.
func (m *lockMirror) handleUnlock(w http.ResponseWriter, r *http.Request, next http.Handler) {
	buf := newBufferedResponse()
	next.ServeHTTP(buf, r)
	if buf.status == http.StatusNoContent {
		token := strings.Trim(r.Header.Get("Lock-Token"), "<>")
		m.locks().Release(r.Context(), token)
	}
	buf.flush(w)
}

// ifHeaderToken returns the first lock token named in an If header,
// "(<urn:...>)" or "<url> (<urn:...>)", or "" when it names none.
func ifHeaderToken(hdr string) string {
	// A resource tag may precede the list; the state token is inside it.
	list := hdr[strings.Index(hdr, "(")+1:]
	start := strings.Index(list, "<")
	if start < 0 {
		return ""
	}
	end := strings.Index(list[start:], ">")
	if end < 0 {
		return ""
	}

	return list[start+1 : start+end]
}

// lockedFile resolves a WebDAV path to a listed file's node ID.
func (m *lockMirror) lockedFile(ctx context.Context, urlPath string) (string, bool) {
	kind, drName, sub := parseWebdavPath(urlPath)
	if kind != pathDataroomNode || sub == "/" {
		return "", false
	}
	drID, err := m.fs.tree.DataroomByName(ctx, drName)
	if err != nil {
		return "", false
	}
	parent, name := splitWebdavPath(sub)
	n, err := m.fs.tree.Lookup(ctx, drID, parent, name)
	if err != nil || n.Type != vfs.TypeFile {
		return "", false
	}

	return n.ID, true
}

// run renews the mirrored locks until ctx ends, then releases them all (see
// vfs.LockManager.Run).
func (m *lockMirror) run(ctx context.Context) { m.locks().Run(ctx) }

// refreshAll renews every mirrored lock and releases those whose WebDAV lock
// lapsed (see vfs.LockManager.RefreshAll).
func (m *lockMirror) refreshAll(ctx context.Context) { m.locks().RefreshAll(ctx) }

// held returns the number of mirrored locks (tests, metrics).
func (m *lockMirror) held() int { return m.locks().Held() }

// bufferedResponse captures a handler's response so that a decision can be
// taken on it before it reaches the client.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) { b.status = status }

func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// flush replays the captured response onto w.
func (b *bufferedResponse) flush(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}
