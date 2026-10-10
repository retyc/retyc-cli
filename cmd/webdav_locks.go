package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/ui"
)

// lockRefreshEvery paces the renewal of the server-side locks: well inside
// the lease taken (api.LockTimeoutMax), so a slow round trip does not let one
// lapse.
const lockRefreshEvery = 2 * time.Minute

// lockMirror mirrors the WebDAV locks clients take on files onto the API's
// advisory node locks, so that another cooperating RETYC client (a second
// mount; the web app ignores locks) sees the file as locked, and so that a
// file another client locked answers 423 to a LOCK here.
//
// x/net/webdav keeps its own in-memory lock system (the one doing the WebDAV
// bookkeeping: lock-null resources, folders, If-header checks). The mirror
// does not replace it: it watches the LOCK and UNLOCK requests, and when the
// locked path is a listed file, takes, refreshes and releases the matching
// server lock. A LOCK the server refuses (423) is undone locally and refused
// to the client. The temporary locks x/net/webdav takes around every write
// without an If header never reach the server: a request per write would be
// too dear for an advisory lock.
//
// Server leases are bounded (5 min at most) while WebDAV clients ask for
// hours or infinity: a background loop renews every mirrored lock while its
// WebDAV lock stands.
type lockMirror struct {
	fs *webdavFS
	ls webdav.LockSystem

	mu    sync.Mutex
	locks map[string]*mirroredLock // by WebDAV lock token
}

// mirroredLock is a server lock taken for a WebDAV lock.
type mirroredLock struct {
	lockID   string
	apiToken string
	nodeID   string
	path     string
}

func newLockMirror(fs *webdavFS, ls webdav.LockSystem) *lockMirror {
	return &lockMirror{fs: fs, ls: ls, locks: make(map[string]*mirroredLock)}
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
	if refresh {
		// The WebDAV lock already stands; the server lock may too.
		m.refresh(r.Context(), token, nodeID, r.URL.Path)
		buf.flush(w)

		return
	}
	lock, err := m.fs.client.LockDataroomNode(r.Context(), nodeID, api.LockExclusive, api.LockTimeoutMax)
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
		buf.flush(w)

		return
	}
	m.mu.Lock()
	m.locks[token] = &mirroredLock{lockID: lock.ID, apiToken: lock.Token, nodeID: nodeID, path: r.URL.Path}
	m.mu.Unlock()
	buf.flush(w)
}

// handleUnlock releases the server lock once the WebDAV handler released
// the local one.
func (m *lockMirror) handleUnlock(w http.ResponseWriter, r *http.Request, next http.Handler) {
	buf := newBufferedResponse()
	next.ServeHTTP(buf, r)
	if buf.status == http.StatusNoContent {
		token := strings.Trim(r.Header.Get("Lock-Token"), "<>")
		m.release(r.Context(), token)
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
	drID, err := m.fs.cache.idForName(ctx, drName)
	if err != nil {
		return "", false
	}
	parent, name := splitWebdavPath(sub)
	n, err := m.fs.findListedNode(ctx, drID, parent, name)
	if err != nil || n.Type != "file" {
		return "", false
	}

	return n.ID, true
}

// refresh renews the server lock behind token, taking a new one when the
// previous lease ended (a lock lost to a slow refresh is not fatal).
func (m *lockMirror) refresh(ctx context.Context, token, nodeID, urlPath string) {
	m.mu.Lock()
	ml := m.locks[token]
	m.mu.Unlock()
	if ml != nil {
		_, err := m.fs.client.RefreshDataroomNodeLock(ctx, ml.lockID, ml.apiToken, api.LockTimeoutMax)
		if err == nil {
			return
		}
		if !errors.Is(err, api.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "webdav: LOCK %s: server lock not refreshed: %s\n",
				ui.Escape(urlPath), ui.EscapeLines(err.Error()))

			return
		}
		m.mu.Lock()
		delete(m.locks, token)
		m.mu.Unlock()
	}
	lock, err := m.fs.client.LockDataroomNode(ctx, nodeID, api.LockExclusive, api.LockTimeoutMax)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webdav: LOCK %s: server lock not retaken: %s\n",
			ui.Escape(urlPath), ui.EscapeLines(err.Error()))

		return
	}
	m.mu.Lock()
	m.locks[token] = &mirroredLock{lockID: lock.ID, apiToken: lock.Token, nodeID: nodeID, path: urlPath}
	m.mu.Unlock()
}

// release drops the server lock behind token, if any.
func (m *lockMirror) release(ctx context.Context, token string) {
	m.mu.Lock()
	ml := m.locks[token]
	delete(m.locks, token)
	m.mu.Unlock()
	if ml == nil {
		return
	}
	if err := m.fs.client.UnlockDataroomNode(ctx, ml.lockID, ml.apiToken); err != nil && !errors.Is(err, api.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "webdav: UNLOCK %s: server lock not released: %s\n",
			ui.Escape(ml.path), ui.EscapeLines(err.Error()))
	}
}

// run renews the mirrored locks every lockRefreshEvery until ctx ends, then
// releases them all: the server would let them lapse within the lease, but
// a clean shutdown should not leave files locked for five minutes.
func (m *lockMirror) run(ctx context.Context) {
	ticker := time.NewTicker(lockRefreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.releaseAll()

			return
		case <-ticker.C:
			m.refreshAll(ctx)
		}
	}
}

// refreshAll renews every mirrored lock; a lock whose lease ended is retaken.
func (m *lockMirror) refreshAll(ctx context.Context) {
	m.mu.Lock()
	tokens := make([]string, 0, len(m.locks))
	byToken := make(map[string]*mirroredLock, len(m.locks))
	for token, ml := range m.locks {
		tokens = append(tokens, token)
		byToken[token] = ml
	}
	m.mu.Unlock()
	for _, token := range tokens {
		ml := byToken[token]
		m.refresh(ctx, token, ml.nodeID, ml.path)
	}
}

// releaseAll drops every mirrored lock, best effort, on its own short timeout.
func (m *lockMirror) releaseAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m.mu.Lock()
	tokens := make([]string, 0, len(m.locks))
	for token := range m.locks {
		tokens = append(tokens, token)
	}
	m.mu.Unlock()
	for _, token := range tokens {
		m.release(ctx, token)
	}
}

// held returns the number of mirrored locks (tests, metrics).
func (m *lockMirror) held() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.locks)
}

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
