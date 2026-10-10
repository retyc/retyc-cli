package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/ui"
	"go.opentelemetry.io/otel/trace"
)

// webdavContextKey is a private type for context keys in the WebDAV handler.
type webdavContextKey int

const (
	webdavContentLengthKey webdavContextKey = 1
	webdavIsPutKey         webdavContextKey = 2
)

func withContentLength(ctx context.Context, n int64) context.Context {
	return context.WithValue(ctx, webdavContentLengthKey, n)
}

func contentLengthFromCtx(ctx context.Context) int64 {
	if v, ok := ctx.Value(webdavContentLengthKey).(int64); ok {
		return v
	}

	return -1
}

func withIsPut(ctx context.Context) context.Context {
	return context.WithValue(ctx, webdavIsPutKey, true)
}

// isPutFromCtx reports whether the OpenFile call originates from a real PUT (as
// opposed to a LOCK creating a lock-null resource). It lets the buffered upload
// path distinguish an intentional empty-file PUT from a LOCK placeholder.
func isPutFromCtx(ctx context.Context) bool {
	v, _ := ctx.Value(webdavIsPutKey).(bool)

	return v
}

// webdavFileInfo implements os.FileInfo for virtual WebDAV entries.
type webdavFileInfo struct {
	name        string
	size        int64
	isDir       bool
	modTime     time.Time
	mode        os.FileMode // permission bits stored with the node, 0 for the default
	nodeID      string      // non-empty for file nodes
	versionID   string      // current version ID — avoids GetDataroomNode on download
	chunkCount  int         // number of AGE-encrypted chunks
	contentType string      // decrypted MIME type from node metadata
}

// fileInfoFromNode builds the WebDAV view of a listed node.
func fileInfoFromNode(n service.DataroomNodeInfo) *webdavFileInfo {
	return &webdavFileInfo{
		name:        n.Name,
		size:        n.Size,
		isDir:       n.Type == "dir",
		modTime:     n.ModTime(),
		mode:        n.Mode(),
		nodeID:      n.ID,
		versionID:   n.VersionID,
		chunkCount:  n.ChunkCount,
		contentType: n.MIMEType,
	}
}

func (fi *webdavFileInfo) Name() string       { return fi.name }
func (fi *webdavFileInfo) Size() int64        { return fi.size }
func (fi *webdavFileInfo) IsDir() bool        { return fi.isDir }
func (fi *webdavFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *webdavFileInfo) Sys() any           { return nil }

// Mode returns the node's stored permission bits, or 0644 / 0755 when the API
// stores none. The setuid, setgid and sticky bits are never presented: a
// remote file system has no business granting them.
func (fi *webdavFileInfo) Mode() os.FileMode {
	perm := fi.mode.Perm()
	if fi.isDir {
		if perm == 0 {
			perm = 0755
		}

		return os.ModeDir | perm
	}
	if perm == 0 {
		perm = 0644
	}

	return perm
}

// ETag implements webdav.ETager. The version ID identifies the file's content
// exactly, whereas the x/net/webdav default (ModTime+Size) gives two versions of
// equal size the same ETag and lets clients keep stale content. Folders and
// versionless nodes fall back to the default.
func (fi *webdavFileInfo) ETag(_ context.Context) (string, error) {
	if fi.isDir || fi.versionID == "" {
		return "", webdav.ErrNotImplemented
	}

	return `"` + fi.versionID + `"`, nil
}

// ContentType implements the webdav.ContentTyper interface, avoiding file downloads during PROPFIND.
func (fi *webdavFileInfo) ContentType(_ context.Context) (string, error) {
	if fi.isDir {
		return "inode/directory", nil
	}
	if fi.contentType != "" {
		return fi.contentType, nil
	}
	ctype := mime.TypeByExtension(filepath.Ext(fi.name))
	if ctype != "" {
		return ctype, nil
	}

	return "application/octet-stream", nil
}

// webdavPathKind classifies a parsed WebDAV path.
type webdavPathKind int

const (
	pathRoot         webdavPathKind = iota // "/"
	pathDataroomRoot                       // "/dataroom"
	pathDataroomNode                       // "/dataroom/<name>[/...]"
	pathUnknown                            // any other top-level entry
)

// webdavSectionDataroom is the root folder under which datarooms are exposed.
// The root is namespaced by section so future element types can live alongside it.
const webdavSectionDataroom = "dataroom"

// parseWebdavPath classifies a WebDAV path and extracts the dataroom name and sub-path.
//
//	"/"                                 → (pathRoot, "", "")
//	"/dataroom" or "/dataroom/"         → (pathDataroomRoot, "", "")
//	"/dataroom/My DR"                   → (pathDataroomNode, "My DR", "/")
//	"/dataroom/My DR/folder/file.txt"   → (pathDataroomNode, "My DR", "/folder/file.txt")
//	"/anything-else"                    → (pathUnknown, "", "")
func parseWebdavPath(name string) (kind webdavPathKind, drName, subPath string) {
	name = path.Clean(name)
	if name == "/" || name == "." {
		return pathRoot, "", ""
	}
	section, rest, _ := strings.Cut(name[1:], "/") // strip leading "/"
	if section != webdavSectionDataroom {
		return pathUnknown, "", ""
	}
	if rest == "" {
		return pathDataroomRoot, "", ""
	}
	drName, sub, found := strings.Cut(rest, "/")
	if !found {
		return pathDataroomNode, drName, "/"
	}

	return pathDataroomNode, drName, "/" + sub
}

// splitWebdavPath returns the parent path and the final component of p.
//
//	"/file.txt"          → ("/", "file.txt")
//	"/folder/sub/f.txt"  → ("/folder/sub", "f.txt")
//	"/"                  → ("/", "")
func splitWebdavPath(p string) (parentPath, name string) {
	p = path.Clean(p)
	idx := strings.LastIndex(p, "/")
	if idx < 0 {
		return "/", p
	}
	if idx == 0 {
		return "/", p[1:]
	}

	return p[:idx], p[idx+1:]
}

// dataroomURI builds a retyc:// URI from a dataroom ID and a sub-path.
func dataroomURI(drID, subPath string) string {
	return "retyc://" + drID + subPath
}

// dataroomCacheItem is a (id, title) pair fed to dataroomCache.
type dataroomCacheItem struct {
	id    string
	title string
}

// dataroomCacheEntry holds a resolved name→ID mapping and its fetch timestamp.
type dataroomCacheEntry struct {
	byName    map[string]string // display name → ID
	names     []string          // sorted display names
	fetchedAt time.Time
}

// detachedFetchTimeout bounds a fetch shared by several requests, which is
// detached from the request that started it so that one client giving up
// cannot fail the others. The API client has no overall timeout (an upload
// can take as long as it needs): without this bound, an API that sends its
// headers then stalls would keep the fetch in flight forever, and every later
// request needing it would wait on it. Tests shorten it per instance
// (dataroomCache.fetchTimeout, webdavFS.fetchTimeout), never globally: a
// background fetch of another test may still be reading it.
const detachedFetchTimeout = 2 * time.Minute

// orDetachedFetchTimeout returns d, or detachedFetchTimeout when d is zero.
func orDetachedFetchTimeout(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}

	return detachedFetchTimeout
}

// linkRefresh links the request span of ctx to the cache.refresh trace of a
// background refresh it waited for (a lookup that joined it: a name missing
// from the expired listing, an entry past max stale): the API work the request
// waited for lives in that other trace. An invalid refresh (the fetch was not
// a background one) adds nothing.
func linkRefresh(ctx context.Context, refresh trace.SpanContext) {
	if refresh.IsValid() {
		trace.SpanFromContext(ctx).AddLink(trace.Link{SpanContext: refresh})
	}
}

// startRefreshSpan opens the root span of a background cache refresh, named
// "cache.refresh", linked to the request whose lookup triggered it.
//
// The refresh runs after that request has answered from the expired entry: as
// a child of the request span it would outlive its parent, and read as if the
// request had waited for it. A trace of its own keeps the request's duration
// honest, and the link still leads from one to the other. cache is the
// retyc.cache.name of the entry (nodes, datarooms), never a path or a title.
func startRefreshSpan(ctx context.Context, link trace.Link, cache string) (context.Context, trace.Span) {
	return telemetry.Tracer().Start(ctx, "cache.refresh",
		trace.WithNewRoot(),
		trace.WithLinks(link),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(telemetry.AttrCacheName.String(cache)))
}

// dataroomCache is a thread-safe, TTL-based cache mapping dataroom display names to IDs.
//
// An expired list is served for up to maxStale more while a single background
// fetch replaces it (stale-while-revalidate): every request resolves its
// dataroom here, so a refresh made under the lock stalled the whole server for
// the /dataroom round trip once per TTL. Only the very first resolution, a
// list older than ttl+maxStale, and a lookup of a name the expired list does
// not hold (a dataroom created since) wait for a fetch.
type dataroomCache struct {
	mu       sync.Mutex
	entry    *dataroomCacheEntry
	incoming *dataroomFetch // fetch in flight, nil when idle
	fetchFn  func(ctx context.Context) ([]dataroomCacheItem, error)
	// fetchTimeout bounds a fetch; zero means detachedFetchTimeout.
	fetchTimeout time.Duration
	// ttl and maxStale come from webdav.cache (see config.WebdavCacheConfig).
	ttl      time.Duration
	maxStale time.Duration
}

// dataroomFetch is a fetch of the list shared by every caller that needs it
// while it runs. entry and err are written once, before done is closed.
//
// refresh is the span context of the fetch's own trace when it runs as a
// background refresh (see startRefreshSpan), invalid otherwise.
type dataroomFetch struct {
	done    chan struct{}
	entry   *dataroomCacheEntry
	err     error
	refresh trace.SpanContext
}

// newDataroomCache returns a cache with the default webdav.cache settings;
// webdav serve overrides ttl and maxStale from the configuration.
func newDataroomCache(fetchFn func(ctx context.Context) ([]dataroomCacheItem, error)) *dataroomCache {
	return &dataroomCache{
		fetchFn:  fetchFn,
		ttl:      config.DefaultWebdavCacheTTL,
		maxStale: config.DefaultWebdavCacheMaxStale,
	}
}

// cacheTTL returns the TTL, config.DefaultWebdavCacheTTL when unset (as
// webdavFS.nodeTTL does).
func (c *dataroomCache) cacheTTL() time.Duration {
	if c.ttl > 0 {
		return c.ttl
	}

	return config.DefaultWebdavCacheTTL
}

// fresh reports whether e is younger than the TTL.
func (c *dataroomCache) fresh(e *dataroomCacheEntry) bool {
	return e != nil && time.Since(e.fetchedAt) < c.cacheTTL()
}

// servable reports whether e may still be served while a refresh runs.
func (c *dataroomCache) servable(e *dataroomCacheEntry) bool {
	return e != nil && time.Since(e.fetchedAt) < c.cacheTTL()+c.maxStale
}

// resolve returns the cached list and starts a refresh when it is expired. It
// waits only when nothing is cached yet, or the list is past ttl+maxStale.
func (c *dataroomCache) resolve(ctx context.Context) (*dataroomCacheEntry, error) {
	c.mu.Lock()
	e := c.entry
	if c.fresh(e) {
		c.mu.Unlock()

		return e, nil
	}
	servable := c.servable(e)
	f := c.fetchLocked(ctx, servable)
	c.mu.Unlock()
	if servable {
		return e, nil
	}

	return f.wait(ctx)
}

// refreshed returns a fresh list, waiting for the fetch if needed.
func (c *dataroomCache) refreshed(ctx context.Context) (*dataroomCacheEntry, error) {
	c.mu.Lock()
	if c.fresh(c.entry) {
		e := c.entry
		c.mu.Unlock()

		return e, nil
	}
	f := c.fetchLocked(ctx, false)
	c.mu.Unlock()

	return f.wait(ctx)
}

func (f *dataroomFetch) wait(ctx context.Context) (*dataroomCacheEntry, error) {
	select {
	case <-f.done:
		linkRefresh(ctx, f.refresh)

		return f.entry, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// fetchLocked returns the fetch in flight, or starts one. The fetch outlives
// the request that started it (it serves every waiter); a failed one leaves
// the stale list in place, and the next request starts another. background
// is true when the caller serves the expired list instead of waiting: the
// fetch then gets a trace of its own (see startRefreshSpan). The caller holds
// c.mu.
func (c *dataroomCache) fetchLocked(ctx context.Context, background bool) *dataroomFetch {
	if c.incoming != nil {
		return c.incoming
	}
	f := &dataroomFetch{done: make(chan struct{})}
	c.incoming = f
	link := trace.LinkFromContext(ctx)
	go func() {
		metrics.WebdavDataroomCacheRefreshes.Inc()
		fctx := context.WithoutCancel(ctx)
		var span trace.Span
		if background {
			fctx, span = startRefreshSpan(fctx, link, "datarooms")
			f.refresh = span.SpanContext()
		}
		fctx, cancel := context.WithTimeout(fctx, orDetachedFetchTimeout(c.fetchTimeout))
		items, err := c.fetchFn(fctx)
		cancel()
		if span != nil {
			telemetry.RecordError(span, err)
			span.End()
		}
		var e *dataroomCacheEntry
		if err == nil {
			e = newDataroomCacheEntry(items)
		}
		c.mu.Lock()
		if err == nil {
			c.entry = e
		}
		c.incoming = nil
		c.mu.Unlock()
		f.entry, f.err = e, err
		close(f.done)
	}()

	return f
}

func newDataroomCacheEntry(items []dataroomCacheItem) *dataroomCacheEntry {
	// Assign collision suffixes ("Docs (2)") deterministically by ID so a given
	// dataroom always maps to the same display name across cache refreshes,
	// regardless of the order the API returns items in. Without this a mounted
	// client's bookmarked paths could silently point at a different dataroom.
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })

	byName := make(map[string]string, len(items))
	for _, item := range items {
		name := item.title
		if _, exists := byName[name]; exists {
			for i := 2; ; i++ {
				candidate := fmt.Sprintf("%s (%d)", item.title, i)
				if _, exists := byName[candidate]; !exists {
					name = candidate

					break
				}
			}
		}
		byName[name] = item.id
	}

	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	return &dataroomCacheEntry{
		byName:    byName,
		names:     names,
		fetchedAt: time.Now(),
	}
}

// idForName returns the dataroom ID for the given display name, or os.ErrNotExist.
// A name missing from an expired list waits for the refresh: it may be a
// dataroom created since.
func (c *dataroomCache) idForName(ctx context.Context, name string) (string, error) {
	e, err := c.resolve(ctx)
	if err != nil {
		return "", err
	}
	id, ok := e.byName[name]
	if !ok && !c.fresh(e) {
		if e, err = c.refreshed(ctx); err != nil {
			return "", err
		}
		id, ok = e.byName[name]
	}
	if !ok {
		return "", os.ErrNotExist
	}
	// The title stays local; the ID is what a trace needs to join requests.
	trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrDataroomID.String(id))

	return id, nil
}

// allNames returns all display names, sorted.
func (c *dataroomCache) allNames(ctx context.Context) ([]string, error) {
	e, err := c.resolve(ctx)
	if err != nil {
		return nil, err
	}

	return e.names, nil
}

// dirHandle is a webdav.File for directories.
//
// Entries are either given up front (static sections) or produced by load on the
// first Readdir. Laziness matters: PROPFIND opens every listed resource just to
// Stat it (x/net/webdav props()), and only walkFS goes on to Readdir — listing
// children eagerly would cost one API listing per sub-folder per PROPFIND.
type dirHandle struct {
	info    os.FileInfo
	entries []os.FileInfo
	offset  int
	load    func() ([]os.FileInfo, error) // nil = entries already populated
	loaded  bool
	// quota reports the dataroom's storage counters (RFC 4331), nil for a
	// folder outside a dataroom.
	quota quotaFunc
}

// DeadProps implements webdav.DeadPropsHolder: a dataroom folder reports the
// RFC 4331 quota properties (quota-used-bytes, quota-available-bytes), which
// file managers read on the mount root to show the space left.
func (h *dirHandle) DeadProps() (map[xml.Name]webdav.Property, error) {
	if h.quota == nil {
		return nil, nil
	}
	used, free, ok := h.quota()
	if !ok {
		return nil, nil
	}
	props := make(map[xml.Name]webdav.Property, 2)
	for local, value := range quotaProps(used, free) {
		name := xml.Name{Space: "DAV:", Local: local}
		props[name] = webdav.Property{XMLName: name, InnerXML: []byte(value)}
	}

	return props, nil
}

// Patch implements webdav.DeadPropsHolder: no dead property is writable.
func (h *dirHandle) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	pstat := webdav.Propstat{Status: http.StatusForbidden}
	for _, patch := range patches {
		for _, p := range patch.Props {
			pstat.Props = append(pstat.Props, webdav.Property{XMLName: p.XMLName})
		}
	}

	return []webdav.Propstat{pstat}, nil
}

func (h *dirHandle) Close() error                       { return nil }
func (h *dirHandle) Read(_ []byte) (int, error)         { return 0, os.ErrInvalid }
func (h *dirHandle) Write(_ []byte) (int, error)        { return 0, os.ErrPermission }
func (h *dirHandle) Seek(_ int64, _ int) (int64, error) { return 0, os.ErrPermission }
func (h *dirHandle) Stat() (os.FileInfo, error)         { return h.info, nil }
func (h *dirHandle) Readdir(count int) ([]os.FileInfo, error) {
	if h.load != nil && !h.loaded {
		entries, err := h.load()
		if err != nil {
			return nil, err
		}
		h.entries = entries
		h.loaded = true
	}
	if count <= 0 {
		result := h.entries[h.offset:]
		h.offset = len(h.entries)

		return result, nil
	}
	if h.offset >= len(h.entries) {
		return nil, io.EOF
	}
	end := h.offset + count
	if end > len(h.entries) {
		end = len(h.entries)
	}
	result := h.entries[h.offset:end]
	h.offset = end

	return result, nil
}

// readFileHandle is a webdav.File for reading a file.
// The download is deferred until the first Read or Seek call.
type readFileHandle struct {
	// Parameters for lazy download — all sourced from the listing cache.
	ctx        context.Context
	wfs        *webdavFS
	drID       string
	versionID  string // avoids a GetDataroomNode round-trip on download
	chunkCount int
	parentURI  string // retyc://id/parent — the listing this handle was built from
	info       os.FileInfo
	// Buffered path (set by ensureDownloaded)
	file    *os.File
	tempDir string
	// Streaming path (set by startStream)
	pipeR *io.PipeReader
}

func (h *readFileHandle) ensureDownloaded() error {
	if h.file != nil {
		return nil
	}
	tempDir, err := os.MkdirTemp("", "retyc-webdav-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}

	sess, err := h.wfs.getSession(h.ctx, h.drID)
	if err != nil {
		_ = os.RemoveAll(tempDir)

		return fmt.Errorf("dataroom session: %w", err)
	}

	// tempDir is private to this handle: a fixed file name spares mapping the
	// decrypted name to a local one (service sanitizes it) and back.
	const tempName = "content"
	err = service.DownloadChunks(
		h.ctx, tempDir, tempName,
		h.info.Size(), h.chunkCount, sess.Identity, nil,
		func(ctx context.Context, chunkID int) ([]byte, error) {
			return h.wfs.client.DownloadDataroomChunk(ctx, h.versionID, chunkID)
		},
	)
	if err != nil {
		h.onDownloadError(err)
		_ = os.RemoveAll(tempDir)

		return err
	}

	localPath := filepath.Join(tempDir, tempName)
	//nolint:gosec // G304: localPath is within our own tempDir
	f, err := os.Open(localPath)
	if err != nil {
		_ = os.RemoveAll(tempDir)

		return err
	}
	h.file = f
	h.tempDir = tempDir

	return nil
}

// startStream begins a background goroutine that downloads and decrypts all chunks,
// writing them in order to pipeW. h.pipeR is set so Read can consume from it.
func (h *readFileHandle) startStream() error {
	sess, err := h.wfs.getSession(h.ctx, h.drID)
	if err != nil {
		return fmt.Errorf("dataroom session: %w", err)
	}
	pipeR, pipeW := io.Pipe()
	h.pipeR = pipeR
	go func() {
		err := service.StreamDownloadChunks(
			h.ctx, pipeW, h.info.Size(), h.chunkCount, sess.Identity, nil,
			func(ctx context.Context, chunkID int) ([]byte, error) {
				return h.wfs.client.DownloadDataroomChunk(ctx, h.versionID, chunkID)
			},
		)
		if err != nil && !isClientGoneErr(err) {
			h.onDownloadError(err)
		}
		_ = pipeW.CloseWithError(err)
	}()

	return nil
}

// isClientGoneErr reports whether err comes from the reader side going away — a
// client disconnect, or a Range seek tearing the stream down in Seek — rather than
// from a genuine download failure. Both surface on the writer side of the pipe.
func isClientGoneErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, io.ErrClosedPipe)
}

// onDownloadError reports a failed chunk download and drops the cached listing of
// the file's parent directory.
//
// That listing is what supplied this handle's versionID, so a download failure
// means it may describe a node that no longer exists — typically deleted from the
// web app or another client, which never goes through invalidateNodeCache. Without
// this, every read until the listing is refreshed replays the dead version and dies
// mid-body: http.ServeContent has already committed 200 plus the stale
// Content-Length by the time the first chunk is fetched, so the client sees a
// truncated response and reports an I/O error. Dropping the entry makes the next
// request re-list and answer a clean 404.
func (h *readFileHandle) onDownloadError(err error) {
	fmt.Fprintf(os.Stderr, "webdav: download error (%s): %s\n", ui.Escape(h.info.Name()), ui.EscapeLines(err.Error()))
	if h.parentURI != "" {
		h.wfs.invalidateNodeCache(h.parentURI)
	}
}

func (h *readFileHandle) Close() error {
	if h.pipeR != nil {
		_ = h.pipeR.CloseWithError(context.Canceled)

		return nil
	}
	if h.file == nil {
		return nil
	}
	err := h.file.Close()
	_ = os.RemoveAll(h.tempDir)

	return err
}
func (h *readFileHandle) Read(p []byte) (int, error) {
	n, err := h.read(p)
	metrics.WebdavBytes.WithLabelValues("download").Add(float64(n))

	return n, err
}

func (h *readFileHandle) read(p []byte) (int, error) {
	if h.file != nil {
		return h.file.Read(p)
	}
	if h.pipeR == nil {
		// First Read with no prior Range seek: stream straight from the API.
		if err := h.startStream(); err != nil {
			return 0, err
		}
	}

	return h.pipeR.Read(p)
}
func (h *readFileHandle) Write(_ []byte) (int, error) { return 0, os.ErrPermission }
func (h *readFileHandle) Seek(off int64, whence int) (int64, error) {
	// http.ServeContent probes the size with Seek(0,End) then rewinds with
	// Seek(0,Start). Neither needs a download, and crucially we must NOT start the
	// stream on the rewind: a Range request issues a follow-up Seek(off>0) that has
	// to be served from the buffered file instead. Streaming therefore begins
	// lazily on the first Read (see Read).
	if h.file == nil && h.pipeR == nil {
		if whence == io.SeekEnd && off == 0 {
			return h.info.Size(), nil
		}
		if whence == io.SeekStart && off == 0 {
			return 0, nil
		}
	}
	// Range request or re-seek: tear down any in-flight stream and fall back to the
	// buffered file so Read serves bytes from the seeked offset (not from offset 0).
	if h.pipeR != nil {
		_ = h.pipeR.CloseWithError(context.Canceled)
		h.pipeR = nil
	}
	if err := h.ensureDownloaded(); err != nil {
		return 0, err
	}

	return h.file.Seek(off, whence)
}
func (h *readFileHandle) Stat() (os.FileInfo, error)           { return h.info, nil }
func (h *readFileHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

// writeFileHandle is a webdav.File for uploading a file. Writes accumulate in a temp file;
// Close uploads the temp file then deletes the temp directory.
type writeFileHandle struct {
	// ctx is the OpenFile (request) context: the upload from Close runs on
	// it without its cancellation, so the API and crypto spans nest under the
	// request span instead of becoming orphan traces.
	ctx          context.Context
	file         *os.File
	tempDir      string
	tempFilePath string
	drID         string
	parentPath   string
	fileName     string
	wfs          *webdavFS
	isPut        bool // true = real PUT; false = LOCK-driven create
	// info is what Stat reports. The WebDAV handler Stats the file before
	// Close and reads the ETag after it: Close fills in the new version, so
	// the PUT response carries its ETag rather than the ModTime+Size default.
	info *webdavFileInfo
}

func (h *writeFileHandle) Close() error {
	if err := h.file.Close(); err != nil {
		_ = os.RemoveAll(h.tempDir)

		return err
	}
	// A zero-byte create that did NOT come from a PUT is a WebDAV LOCK creating a
	// lock-null resource (macOS Finder, MS Office); uploading it would create a
	// phantom empty node, so skip it. A real PUT — even an empty one sent with
	// chunked transfer (unknown Content-Length, hence this buffered path) — is an
	// intentional upload and must go through.
	if !h.isPut {
		if fi, statErr := os.Stat(h.tempFilePath); statErr == nil && fi.Size() == 0 {
			_ = os.RemoveAll(h.tempDir)

			return nil
		}
	}
	defer func() { _ = os.RemoveAll(h.tempDir) }()
	src, err := os.Open(h.tempFilePath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	fi, err := src.Stat()
	if err != nil {
		return err
	}
	// The size is known now: upload through the path of a PUT with a
	// Content-Length, which resolves the folder and an existing node from the
	// cached listings, cleans up a failed upload and updates the listing in
	// place.
	w, err := h.wfs.openUpload(context.WithoutCancel(h.ctx), h.drID, h.parentPath, h.fileName, fi.Size())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(writerFunc(w.write), src)
	if err := w.Close(); err != nil {
		return err
	}
	if fi, err := w.Stat(); err == nil {
		if uploaded, ok := fi.(*webdavFileInfo); ok {
			h.info.nodeID, h.info.versionID = uploaded.nodeID, uploaded.versionID
		}
	}

	return copyErr
}
func (h *writeFileHandle) Read(_ []byte) (int, error) { return 0, os.ErrPermission }
func (h *writeFileHandle) Write(p []byte) (int, error) {
	n, err := h.file.Write(p)
	h.info.size += int64(n)
	metrics.WebdavBytes.WithLabelValues("upload").Add(float64(n))

	return n, err
}
func (h *writeFileHandle) Seek(_ int64, _ int) (int64, error)   { return 0, os.ErrPermission }
func (h *writeFileHandle) Stat() (os.FileInfo, error)           { return h.info, nil }
func (h *writeFileHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

// nodeCacheEntry caches the result of a ListNodes call for a given URI.
//
// etag is the ETag the API answered the listing with (the dataroom's
// revision), "" when it sent none or when this server edited the listing in
// place since. An expired listing that has one is refreshed with
// If-None-Match: an unchanged dataroom answers 304, and the listing is kept
// for another TTL at the cost of one round trip, no page and no decryption.
type nodeCacheEntry struct {
	nodes     []service.DataroomNodeInfo
	fetchedAt time.Time
	etag      string
}

// nodeFetch is an in-flight listing shared by every caller that misses the cache
// for the same URI while it runs (single-flight). nodes/err are written once,
// before done is closed.
//
// A background refresh of an expired listing queues for a refresh slot before
// it starts. A request that misses the cache and joins it closes promoted
// (through promote) so the fetch starts at once: a request never waits behind
// the refresh queue, and a refresh holding a slot never waits for one held by
// another refresh queued behind it.
//
// refresh is the span context of the fetch's own trace when it runs as a
// background refresh (see startRefreshSpan), invalid otherwise.
type nodeFetch struct {
	done     chan struct{}
	promoted chan struct{}
	once     sync.Once
	nodes    []service.DataroomNodeInfo
	err      error
	refresh  trace.SpanContext
}

// promote lets a queued background refresh start without a refresh slot.
func (f *nodeFetch) promote() {
	f.once.Do(func() { close(f.promoted) })
}

// webdavFS implements webdav.FileSystem over RETYC datarooms.
type webdavFS struct {
	cfg              *config.Config
	client           *api.Client
	cache            *dataroomCache
	passphraseReader service.PassphraseReader
	// identity is the user's AGE identity unlocked once at startup; when set,
	// sessions are resolved from it without fetching the user key or running
	// scrypt again. nil falls back to passphraseReader (tests).
	identity *age.HybridIdentity
	// listFn performs the actual listing; nil means fetchNodes (tests inject a fake).
	listFn func(ctx context.Context, drID, nodePath string) ([]service.DataroomNodeInfo, error)
	// fetchTimeout bounds a shared listing; zero means detachedFetchTimeout.
	fetchTimeout time.Duration
	// sessionFn resolves a dataroom session; nil means service.GetDataroomSession
	// (tests inject a fake).
	sessionFn func(ctx context.Context, drID string) (*service.DataroomSession, error)
	// cacheTTL and cacheMaxStale come from webdav.cache (see
	// config.WebdavCacheConfig). A zero cacheTTL means
	// config.DefaultWebdavCacheTTL; a zero cacheMaxStale never serves an
	// expired listing.
	cacheTTL      time.Duration
	cacheMaxStale time.Duration

	nodeMu       sync.Mutex
	nodeCache    map[string]*nodeCacheEntry
	nodeGen      map[string]uint64     // bumped by every invalidation of that URI
	nodeInflight map[string]*nodeFetch // listings currently running, by URI
	// refreshSlots bounds the background refreshes running at once to
	// api.concurrency.list: a client walking a tree served from expired
	// listings would otherwise start one API listing per folder at once.
	refreshSlots chan struct{}

	// sessions holds one resolved session per dataroom for the life of the
	// process (no TTL, single-flight, one scrypt at a time — see service.SessionCache).
	sessions service.SessionCache

	// quotaCache holds each dataroom's storage counters for the listing TTL
	// (see dataroomQuota).
	quotaMu    sync.Mutex
	quotaCache map[string]quotaCacheEntry
}

var _ webdav.FileSystem = (*webdavFS)(nil)

// invalidateNodeCache removes uri from the node listing cache.
// Called after any mutation (upload, mkdir, delete, rename) so that the next
// PROPFIND or Stat on the affected directory fetches fresh data from the API.
//
// It also bumps the URI's generation so that a listing already in flight — which
// may have been answered by the API before the mutation landed — is not stored
// on completion (see listNodes). Without that, a read racing a write from
// another client could pin a pre-mutation listing for a whole TTL.
func (fs *webdavFS) invalidateNodeCache(uri string) {
	fs.nodeMu.Lock()
	delete(fs.nodeCache, uri)
	if fs.nodeGen == nil {
		fs.nodeGen = make(map[string]uint64)
	}
	fs.nodeGen[uri]++
	fs.nodeMu.Unlock()
}

// invalidateNodeSubtree invalidates uri and every cached listing below it.
// Deleting or renaming a directory must not leave its own listing and its
// sub-listings cached: a folder re-created under the same name within the TTL
// would otherwise serve the ghost children of the deleted tree. Harmless for
// a file (nothing is cached below it).
func (fs *webdavFS) invalidateNodeSubtree(uri string) {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	fs.invalidateNodeSubtreeLocked(uri)
}

// invalidateNodeSubtreeLocked is invalidateNodeSubtree for a caller that
// holds nodeMu.
func (fs *webdavFS) invalidateNodeSubtreeLocked(uri string) {
	prefix := strings.TrimSuffix(uri, "/") + "/"
	if fs.nodeGen == nil {
		fs.nodeGen = make(map[string]uint64)
	}
	delete(fs.nodeCache, uri)
	fs.nodeGen[uri]++
	for cached := range fs.nodeCache {
		if strings.HasPrefix(cached, prefix) {
			delete(fs.nodeCache, cached)
			fs.nodeGen[cached]++
		}
	}
	for inflight := range fs.nodeInflight {
		if strings.HasPrefix(inflight, prefix) {
			fs.nodeGen[inflight]++
		}
	}
}

// getSession returns the session for drID, resolved on first access and cached
// for the life of the process. Caching avoids two API calls (GetDataroom +
// GetActiveKey) and an scrypt per listing or download.
func (fs *webdavFS) getSession(ctx context.Context, drID string) (*service.DataroomSession, error) {
	return fs.sessions.Get(ctx, drID, fs.resolveSession)
}

// resolveSession performs the actual resolution (see sessionFn).
func (fs *webdavFS) resolveSession(ctx context.Context, drID string) (*service.DataroomSession, error) {
	if fs.sessionFn != nil {
		return fs.sessionFn(ctx, drID)
	}
	if fs.identity != nil {
		return service.GetDataroomSessionWithIdentity(ctx, fs.client, drID, fs.identity)
	}

	return service.GetDataroomSession(ctx, fs.cfg, fs.client, drID, fs.passphraseReader)
}

// parentNodeID resolves nodePath to its node ID using the cached listings.
//
// service.resolvePath walks the tree with one uncached API listing per level on
// every upload; going through listNodes reuses the listing a PROPFIND has almost
// always already fetched. On a cache miss the cost falls back to the same single
// listing, so this is never slower.
//
// Returns (nil, nil) for the dataroom root, which has no node ID.
func (fs *webdavFS) parentNodeID(ctx context.Context, drID, nodePath string) (*string, error) {
	if strings.Trim(nodePath, "/") == "" {
		return nil, nil
	}
	grandParent, name := splitWebdavPath(nodePath)
	n, err := fs.findListedNode(ctx, drID, grandParent, name)
	if err != nil {
		return nil, err
	}
	if n.Type != "dir" {
		return nil, os.ErrInvalid
	}
	id := n.ID

	return &id, nil
}

// upsertNodeCache refreshes a single node inside the cached listing of uri.
//
// After an upload we know everything a listing would report for that node, so
// replacing the entry in place avoids the full re-listing — and its API
// round-trips — that a plain invalidation forces on the next PROPFIND. WebDAV
// clients revalidate aggressively (davfs2 defaults to dir_refresh 5 /
// file_refresh 1), so that re-listing lands on nearly every written file.
//
// fetchedAt is deliberately carried over rather than reset: the rest of the
// listing is no fresher than it was, and the TTL must keep running from the
// real fetch. The slice is copied because listNodes hands its backing array to
// callers without copying, so mutating in place would be a data race.
//
// Like invalidateNodeCache, it bumps the URI's generation: a listing already in
// flight was answered by the API before this upload landed, so storing it on
// completion would hide the file the server just accepted — and, for a new
// version of an existing file, would keep serving the previous VersionID and
// ChunkCount for a whole TTL after the PUT returned 201. Nothing is cached for
// a URI whose fetch is still running (the fetch was triggered by a miss), so
// dropping the generation bump into the no-entry path is exactly what that race
// needs.
func (fs *webdavFS) upsertNodeCache(uri string, node service.DataroomNodeInfo) {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	fs.upsertNodeCacheLocked(uri, node)
}

// removeFromNodeCache drops the child name from the cached listing of uri,
// after this server deleted or moved it away: the PROPFIND a client sends
// right after is then served from cache instead of re-listing the folder.
// Same generation and copy rules as upsertNodeCache.
func (fs *webdavFS) removeFromNodeCache(uri, name string) {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	fs.removeFromNodeCacheLocked(uri, name)
}

// moveInNodeCache moves the child srcName of the cached listing srcURI to
// dstName in the listing dstURI, after this server renamed it. The node keeps
// every field but its name. When the source listing no longer names the node
// (expired meanwhile), its fields are unknown: the destination listing is
// dropped instead, so the next request re-lists it.
func (fs *webdavFS) moveInNodeCache(srcURI, srcName, dstURI, dstName string) {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	var moved *service.DataroomNodeInfo
	if entry, ok := fs.nodeCache[srcURI]; ok {
		for _, n := range entry.nodes {
			if n.Name == srcName {
				moved = &n

				break
			}
		}
	}
	fs.removeFromNodeCacheLocked(srcURI, srcName)
	if moved == nil {
		delete(fs.nodeCache, dstURI)
		fs.nodeGen[dstURI]++

		return
	}
	moved.Name = dstName
	fs.upsertNodeCacheLocked(dstURI, *moved)
}

func (fs *webdavFS) upsertNodeCacheLocked(uri string, node service.DataroomNodeInfo) {
	fs.editNodeCacheLocked(uri, func(nodes []service.DataroomNodeInfo) []service.DataroomNodeInfo {
		for i := range nodes {
			if nodes[i].Name == node.Name {
				nodes[i] = node

				return nodes
			}
		}

		return append(nodes, node)
	})
}

func (fs *webdavFS) removeFromNodeCacheLocked(uri, name string) {
	fs.editNodeCacheLocked(uri, func(nodes []service.DataroomNodeInfo) []service.DataroomNodeInfo {
		return slices.DeleteFunc(nodes, func(n service.DataroomNodeInfo) bool { return n.Name == name })
	})
}

// editNodeCacheLocked applies edit to a copy of the cached listing of uri and
// bumps the URI's generation, whether or not a listing is cached (see
// upsertNodeCache). The caller holds nodeMu.
func (fs *webdavFS) editNodeCacheLocked(uri string, edit func([]service.DataroomNodeInfo) []service.DataroomNodeInfo) {
	if fs.nodeGen == nil {
		fs.nodeGen = make(map[string]uint64)
	}
	fs.nodeGen[uri]++
	entry, ok := fs.nodeCache[uri]
	if !ok {
		return
	}
	nodes := make([]service.DataroomNodeInfo, len(entry.nodes), len(entry.nodes)+1)
	copy(nodes, entry.nodes)
	fs.nodeCache[uri] = &nodeCacheEntry{nodes: edit(nodes), fetchedAt: entry.fetchedAt}
}

// cachedFileNodeID looks up a file by name in the cached listing of a folder,
// without ever triggering a fetch. A miss simply means the caller takes its
// normal path, so this can only save round-trips, never add one.
//
// Directories are not reported: a folder sharing the name is a genuine conflict,
// and the full upload path produces the right error for it.
func (fs *webdavFS) cachedFileNodeID(drID, parentPath, fileName string) (string, bool) {
	uri := dataroomURI(drID, parentPath)
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	entry, ok := fs.nodeCache[uri]
	if !ok || time.Since(entry.fetchedAt) >= fs.nodeTTL() {
		return "", false
	}
	for _, n := range entry.nodes {
		if n.Name == fileName {
			return n.ID, n.Type == "file"
		}
	}

	return "", false
}

// initUpload creates the node version the PUT will stream into.
//
// When the parent's cached listing already shows a file under that name, the
// upload is an overwrite and the node ID is known: its version can be created
// directly. That skips the CreateDataroomNode call which would answer 409, and
// the uncached folder listing InitStreamUploadInto then runs to locate the node
// again — two round-trips out of four on every overwrite.
//
// The listing may be up to the cache TTL old, so the node can have been deleted
// elsewhere in the meantime. The API answers 404 for exactly that case, or 410
// while the node's purge is pending (both match api.ErrNotFound): drop the
// stale listing and redo the upload through the full path, which recreates the
// node. Any other error is the caller's to handle, and retrying it through a
// second path would only double the failure cost.
func (fs *webdavFS) initUpload(
	ctx context.Context, drID, parentPath, fileName string,
	parentID *string, size int64, sess *service.DataroomSession,
) (service.StreamUploadInit, error) {
	if nodeID, ok := fs.cachedFileNodeID(drID, parentPath, fileName); ok {
		init, err := service.AddVersionToNodeIn(ctx, fs.client, drID, nodeID, fileName, size, sess)
		if err == nil {
			return init, nil
		}
		if !errors.Is(err, api.ErrNotFound) {
			return service.StreamUploadInit{}, err
		}
		fs.invalidateNodeCache(dataroomURI(drID, parentPath))
	}

	return service.InitStreamUploadInto(ctx, fs.client, drID, parentID, fileName, size, sess)
}

// nodeTTL returns how long a cached listing is served without a refresh.
func (fs *webdavFS) nodeTTL() time.Duration {
	if fs.cacheTTL > 0 {
		return fs.cacheTTL
	}

	return config.DefaultWebdavCacheTTL
}

// listNodes returns the decrypted children of drID at nodePath, using a TTL cache.
//
// A listing younger than the TTL is served as is. An expired one is still
// served for cacheMaxStale more, while a background refresh replaces it
// (stale-while-revalidate): a client walking a tree it has not touched for a
// while — PrivateBin's purge lists every folder of its store — is answered from
// memory instead of paying one API round trip per folder, in sequence.
//
// Cache misses are single-flighted: concurrent callers for the same URI (a file
// manager fires PROPFINDs in parallel) share one API listing instead of each
// running their own. The result is stored only if the URI was not invalidated
// while the listing ran, so a mutation that lands mid-fetch wins.
func (fs *webdavFS) listNodes(ctx context.Context, drID, nodePath string) ([]service.DataroomNodeInfo, error) {
	nodes, _, err := fs.listNodesStale(ctx, drID, nodePath)

	return nodes, err
}

// findListedNode returns the child name of parentPath, or os.ErrNotExist.
//
// A name missing from an expired listing waits for its refresh before
// answering, as dataroomCache.idForName does: it may be a node created
// elsewhere since, and answering 404 from the old listing would turn staleness
// into an error for up to ttl+max_stale. A name the listing holds is answered
// at once, expired or not.
func (fs *webdavFS) findListedNode(
	ctx context.Context, drID, parentPath, name string,
) (service.DataroomNodeInfo, error) {
	nodes, stale, err := fs.listNodesStale(ctx, drID, parentPath)
	for attempt := 0; err == nil; attempt++ {
		for _, n := range nodes {
			if n.Name == name {
				return n, nil
			}
		}
		if !stale || attempt > 0 {
			return service.DataroomNodeInfo{}, os.ErrNotExist
		}
		nodes, err = fs.listNodesRefreshed(ctx, drID, parentPath)
	}

	return service.DataroomNodeInfo{}, err
}

// listNodesRefreshed returns a listing no older than the TTL, joining the
// refresh in flight (and starting it at once if it is queued) when the cached
// one has expired.
func (fs *webdavFS) listNodesRefreshed(ctx context.Context, drID, nodePath string) ([]service.DataroomNodeInfo, error) {
	uri := dataroomURI(drID, nodePath)
	fs.nodeMu.Lock()
	if e, ok := fs.nodeCache[uri]; ok && time.Since(e.fetchedAt) < fs.nodeTTL() {
		fs.nodeMu.Unlock()

		return e.nodes, nil
	}
	f := fs.nodeFetchLocked(ctx, drID, nodePath, uri, false)
	fs.nodeMu.Unlock()

	return f.wait(ctx)
}

// wait returns the result of the fetch, or the context error if ctx ends first.
func (f *nodeFetch) wait(ctx context.Context) ([]service.DataroomNodeInfo, error) {
	select {
	case <-f.done:
		linkRefresh(ctx, f.refresh)

		return f.nodes, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// listNodesStale is listNodes, also reporting whether the listing was served
// expired (while a background refresh replaces it).
func (fs *webdavFS) listNodesStale(
	ctx context.Context, drID, nodePath string,
) (nodes []service.DataroomNodeInfo, stale bool, err error) {
	uri := dataroomURI(drID, nodePath)

	fs.nodeMu.Lock()
	if e, ok := fs.nodeCache[uri]; ok {
		age := time.Since(e.fetchedAt)
		if age < fs.nodeTTL() {
			fs.nodeMu.Unlock()
			recordNodeCacheLookup(ctx, "hit")

			return e.nodes, false, nil
		}
		if age < fs.nodeTTL()+fs.cacheMaxStale {
			fs.nodeFetchLocked(ctx, drID, nodePath, uri, true)
			fs.nodeMu.Unlock()
			recordNodeCacheLookup(ctx, "stale")

			return e.nodes, true, nil
		}
	}
	f := fs.nodeFetchLocked(ctx, drID, nodePath, uri, false)
	fs.nodeMu.Unlock()
	recordNodeCacheLookup(ctx, "miss")
	nodes, err = f.wait(ctx)

	return nodes, false, err
}

// recordNodeCacheLookup counts a listing cache lookup and records it on the
// request span. result is hit, stale (expired, served while refreshed) or miss.
func recordNodeCacheLookup(ctx context.Context, result string) {
	metrics.WebdavNodeCacheLookups.WithLabelValues(result).Inc()
	trace.SpanFromContext(ctx).AddEvent("cache.lookup", trace.WithAttributes(
		telemetry.AttrCacheName.String("nodes"),
		telemetry.AttrCacheHit.Bool(result != "miss"),
		telemetry.AttrCacheStale.Bool(result == "stale")))
}

// nodeFetchLocked returns the listing of uri in flight, or starts one. A
// background fetch (refresh of an expired listing) waits for a refresh slot
// unless a request joins it, and gets a trace of its own (startRefreshSpan); a
// request's fetch promotes any fetch it joins. A fetch the request starts
// itself runs in its trace; a background one it joins is linked from its span
// once done (linkRefresh). The caller holds nodeMu.
//
// The fetch is shared by every caller of this URI: it is detached from the
// request that started it, so one aborted PROPFIND cannot fail the others. A
// failed refresh leaves the expired listing in place, except when the folder
// is gone: its listing is then dropped, so the next request answers 404
// instead of replaying it until it is past cacheMaxStale.
func (fs *webdavFS) nodeFetchLocked(ctx context.Context, drID, nodePath, uri string, background bool) *nodeFetch {
	if f, ok := fs.nodeInflight[uri]; ok {
		if !background {
			f.promote()
		}

		return f
	}
	f := &nodeFetch{done: make(chan struct{}), promoted: make(chan struct{})}
	if !background {
		f.promote()
	}
	if fs.nodeInflight == nil {
		fs.nodeInflight = make(map[string]*nodeFetch)
	}
	fs.nodeInflight[uri] = f
	if fs.refreshSlots == nil {
		fs.refreshSlots = make(chan struct{}, service.Concurrency().List)
	}
	slots := fs.refreshSlots

	fetch := fs.listFn // nil: fetchNodes
	detached := context.WithoutCancel(ctx)
	link := trace.LinkFromContext(ctx)
	go func() {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-f.promoted:
		}
		// The span starts once the fetch leaves the refresh queue: it
		// measures the API work, and the time spent queued behind
		// api.concurrency.list shows as the gap after the linked request.
		fctx := detached
		var span trace.Span
		if background {
			fctx, span = startRefreshSpan(fctx, link, "nodes")
			span.SetAttributes(telemetry.AttrDataroomID.String(drID))
			f.refresh = span.SpanContext()
		}
		// The generation is read when the fetch starts, not when it was
		// queued: a mutation made through this server before that is in the
		// API's answer, so only one landing during the fetch must discard it.
		// The listing to revalidate is read with it: an edit made in place
		// after that bumps the generation, and the answer is discarded.
		fs.nodeMu.Lock()
		gen := fs.nodeGen[uri]
		held := fs.nodeCache[uri]
		fs.nodeMu.Unlock()
		fctx, cancel := context.WithTimeout(fctx, orDetachedFetchTimeout(fs.fetchTimeout))
		var etag string
		if fetch != nil {
			f.nodes, f.err = fetch(fctx, drID, nodePath)
		} else {
			f.nodes, etag, f.err = fs.fetchNodes(fctx, drID, nodePath, held)
		}
		cancel()
		if span != nil {
			telemetry.RecordError(span, f.err)
			span.End()
		}

		fs.nodeMu.Lock()
		delete(fs.nodeInflight, uri)
		if fs.nodeGen[uri] == gen {
			switch {
			case f.err == nil:
				if fs.nodeCache == nil {
					fs.nodeCache = make(map[string]*nodeCacheEntry)
				}
				fs.nodeCache[uri] = &nodeCacheEntry{nodes: f.nodes, fetchedAt: time.Now(), etag: etag}
			case errors.Is(f.err, os.ErrNotExist):
				delete(fs.nodeCache, uri)
			}
		}
		fs.nodeMu.Unlock()
		close(f.done)
	}()

	return f
}

// fetchNodes is the real listing behind listNodes: cached session + one API
// listing of the folder.
//
// The folder ID comes from its parent's listing through parentNodeID, which is
// cached and single-flighted, so a miss costs the folder's own listing instead
// of a walk from the root (service.resolvePath lists every level again, often
// while a concurrent PROPFIND is fetching the very same listings). Names are
// matched literally: WebDAV paths are client names, never glob patterns.
//
// The parent listing can be expired (see listNodes) and name a folder deleted
// elsewhere: listing its children then answers 404, or 410 while its purge is
// pending, and the listing is retried once against a fresh parent listing. As
// for RemoveAll and Rename, a folder moved elsewhere within that window is
// listed at its new location until the parent listing is refreshed.
//
// held is the listing of the folder still in cache, nil when there is none.
// When it carries an ETag the listing is conditional: a dataroom that has not
// changed since answers 304 and held's nodes are returned as they are, with
// the same ETag. A folder deleted elsewhere changed the dataroom, so it never
// answers 304. The ETag returned is the one to keep with the nodes.
func (fs *webdavFS) fetchNodes(
	ctx context.Context, drID, nodePath string, held *nodeCacheEntry,
) ([]service.DataroomNodeInfo, string, error) {
	sess, err := fs.getSession(ctx, drID)
	if err != nil {
		return nil, "", err
	}
	var heldETag string
	if held != nil {
		heldETag = held.etag
	}

	nodes, etag, err := fs.fetchNodesOnce(ctx, drID, nodePath, sess, heldETag)
	if errors.Is(err, api.ErrNotModified) {
		return held.nodes, held.etag, nil
	}
	if errors.Is(err, api.ErrNotFound) && strings.Trim(nodePath, "/") != "" {
		grandParent, _ := splitWebdavPath(nodePath)
		fs.invalidateNodeCache(dataroomURI(drID, grandParent))
		nodes, etag, err = fs.fetchNodesOnce(ctx, drID, nodePath, sess, "")
		if errors.Is(err, api.ErrNotFound) {
			err = os.ErrNotExist
		}
	}

	return nodes, etag, err
}

// fetchNodesOnce resolves the folder ID of nodePath and lists its children,
// unless the dataroom still answers etag (api.ErrNotModified).
func (fs *webdavFS) fetchNodesOnce(
	ctx context.Context, drID, nodePath string, sess *service.DataroomSession, etag string,
) ([]service.DataroomNodeInfo, string, error) {
	folderID, err := fs.parentNodeID(ctx, drID, nodePath)
	if errors.Is(err, os.ErrInvalid) {
		// The path names a file, which has no children: not found (404), where
		// ErrInvalid would reach the client as a 405.
		return nil, "", os.ErrNotExist
	}
	if err != nil {
		return nil, "", err
	}
	if folderID != nil {
		trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrNodeID.String(*folderID))
	}

	return service.ListNodesByIDIfChanged(ctx, fs.client, drID, folderID, sess, etag)
}

// nodesToFileInfos converts a slice of DataroomNodeInfo to []os.FileInfo.
func nodesToFileInfos(nodes []service.DataroomNodeInfo) []os.FileInfo {
	infos := make([]os.FileInfo, 0, len(nodes))
	for _, n := range nodes {
		// A decrypted name containing a slash cannot be addressed as a single
		// WebDAV path component; exposing it would create an unreachable, ambiguous
		// entry, so skip it with a warning rather than listing a broken node.
		if strings.ContainsRune(n.Name, '/') {
			fmt.Fprintf(os.Stderr, "webdav: skipping node with unsupported name %q\n", n.Name)

			continue
		}
		infos = append(infos, fileInfoFromNode(n))
	}

	return infos
}

// OpenFile implements webdav.FileSystem.
func (fs *webdavFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	kind, drName, subPath := parseWebdavPath(name)

	switch kind {
	case pathRoot:
		return fs.openRootDir(), nil
	case pathDataroomRoot:
		return fs.openDataroomRootDir(ctx)
	case pathUnknown:
		return nil, os.ErrNotExist
	case pathDataroomNode:
	}

	drID, err := fs.cache.idForName(ctx, drName)
	if err != nil {
		return nil, err
	}

	if subPath == "/" {
		return fs.openNodeDir(ctx, drName, drID, "/")
	}

	// Write path (PUT)
	if flag&os.O_WRONLY != 0 || flag&os.O_RDWR != 0 {
		return fs.openForWrite(ctx, drID, subPath)
	}

	// Read path — determine whether the target is a file or directory.
	info, err := fs.Stat(ctx, name)
	if err != nil {
		return nil, err
	}
	wfi := info.(*webdavFileInfo)
	if wfi.isDir {
		return fs.openNodeDirInfo(ctx, wfi, drID, subPath)
	}
	parentPath, _ := splitWebdavPath(subPath)

	return fs.openForRead(ctx, drID, parentPath, wfi)
}

// openRootDir lists the static top-level sections ("dataroom" for now).
func (fs *webdavFS) openRootDir() webdav.File {
	return &dirHandle{
		info: &webdavFileInfo{name: "/", isDir: true},
		entries: []os.FileInfo{
			&webdavFileInfo{name: webdavSectionDataroom, isDir: true},
		},
	}
}

// openDataroomRootDir lists all datarooms under the "dataroom" section.
func (fs *webdavFS) openDataroomRootDir(ctx context.Context) (webdav.File, error) {
	names, err := fs.cache.allNames(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]os.FileInfo, len(names))
	for i, n := range names {
		entries[i] = &webdavFileInfo{name: n, isDir: true}
	}

	return &dirHandle{
		info:    &webdavFileInfo{name: webdavSectionDataroom, isDir: true},
		entries: entries,
	}, nil
}

// openNodeDir opens a folder that has no listed node of its own (the
// dataroom root): no timestamp, no mode.
func (fs *webdavFS) openNodeDir(ctx context.Context, displayName, drID, subPath string) (webdav.File, error) {
	return fs.openNodeDirInfo(ctx, &webdavFileInfo{name: displayName, isDir: true}, drID, subPath)
}

// openNodeDirInfo opens a folder with the info its listing gave it. PROPFIND
// reads a resource's properties from OpenFile(...).Stat(), not from
// FileSystem.Stat, so the handle must carry the folder's modification time
// and mode for them to be reported.
func (fs *webdavFS) openNodeDirInfo(
	ctx context.Context, info *webdavFileInfo, drID, subPath string,
) (webdav.File, error) {
	return &dirHandle{
		info:  info,
		quota: quotaOnce(func() (int64, int64, bool) { return fs.dataroomQuota(ctx, drID) }),
		load: func() ([]os.FileInfo, error) {
			nodes, err := fs.listNodes(ctx, drID, subPath)
			if err != nil {
				return nil, err
			}

			return nodesToFileInfos(nodes), nil
		},
	}, nil
}

func (fs *webdavFS) openForRead(
	ctx context.Context, drID, parentPath string, wfi *webdavFileInfo,
) (webdav.File, error) {
	return &readFileHandle{
		ctx:        ctx,
		wfs:        fs,
		drID:       drID,
		versionID:  wfi.versionID,
		chunkCount: wfi.chunkCount,
		parentURI:  dataroomURI(drID, parentPath),
		info:       wfi,
	}, nil
}

func (fs *webdavFS) openForWriteTempFile(
	ctx context.Context, drID, parentPath, fileName string, isPut bool,
) (webdav.File, error) {
	tempDir, err := os.MkdirTemp("", "retyc-webdav-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	tempFilePath := filepath.Join(tempDir, fileName)

	//nolint:gosec // G304: tempDir is our own MkdirTemp, fileName is the last WebDAV path component
	f, err := os.OpenFile(tempFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		_ = os.RemoveAll(tempDir)

		return nil, err
	}

	return &writeFileHandle{
		ctx:          ctx,
		file:         f,
		tempDir:      tempDir,
		tempFilePath: tempFilePath,
		drID:         drID,
		parentPath:   parentPath,
		fileName:     fileName,
		wfs:          fs,
		isPut:        isPut,
		info:         &webdavFileInfo{name: fileName, modTime: time.Now()},
	}, nil
}

// streamWriteHandle is a webdav.File for streaming PUT uploads. The dataroom node and
// version are created upfront in openForWriteStream; incoming Write calls are piped to
// a background goroutine that encrypts and uploads 8 MB chunks in real time.
type streamWriteHandle struct {
	wfs       *webdavFS
	nodeID    string
	newNode   bool // true = we created the node; delete on upload error
	pipeW     *io.PipeWriter
	done      chan error
	parentURI string
	info      *webdavFileInfo
	written   int64     // bytes accepted from the client, for short-upload detection
	mimeType  string    // MIME type stored with the node, for the cached listing entry
	createdAt time.Time // version creation time, as a later listing will report it
}

func (h *streamWriteHandle) Write(p []byte) (int, error) {
	n, err := h.write(p)
	metrics.WebdavBytes.WithLabelValues("upload").Add(float64(n))

	return n, err
}

// write feeds the upload without observing the ingress metric: the buffered
// PUT replays through it bytes writeFileHandle.Write has already counted.
func (h *streamWriteHandle) write(p []byte) (int, error) {
	n, err := h.pipeW.Write(p)
	h.written += int64(n)

	return n, err
}

// writerFunc adapts a function to io.Writer.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error)        { return f(p) }
func (h *streamWriteHandle) Stat() (os.FileInfo, error) { return h.info, nil }
func (h *streamWriteHandle) Close() error {
	_ = h.pipeW.Close()
	err := <-h.done
	// Guard against a truncated body: the node version was created upfront with the
	// client-declared Content-Length, so committing fewer bytes would leave a
	// version whose chunk_count never matches its stored chunks (later downloads
	// would 404 mid-stream or silently truncate). UploadChunks already fails on a
	// clean pipe EOF short of the declared size; the byte count is checked here
	// too so the guard does not rest on that alone.
	if err == nil && h.written != h.info.size {
		err = fmt.Errorf("incomplete upload: wrote %d of %d bytes", h.written, h.info.size)
	}
	if err != nil {
		h.cleanup()

		return err
	}
	// The listing is refreshed in place rather than dropped: every field a
	// listing would return for this node is known here, so the next PROPFIND
	// is served from cache instead of paying a fresh round-trip to the API.
	h.wfs.upsertNodeCache(h.parentURI, service.DataroomNodeInfo{
		ID:        h.nodeID,
		Name:      h.info.name,
		Type:      "file",
		MIMEType:  h.mimeType,
		Size:      h.info.size,
		VersionID: h.info.versionID,
		// A successful UploadChunks sent exactly the count announced when the
		// version was created.
		ChunkCount: service.ChunkCount(h.info.size),
	}.WithModTime(h.createdAt))

	return nil
}

// cleanup removes what a failed streaming upload left behind: the node it
// created, or only its new version on a node that already existed, whose prior
// versions must survive (see service.DiscardFailedUpload).
func (h *streamWriteHandle) cleanup() {
	err := service.DiscardFailedUpload(h.wfs.client, h.nodeID, h.info.versionID, h.newNode)
	switch {
	case err == nil && h.newNode:
		fmt.Fprintf(os.Stderr, "webdav: cleaned up orphaned node: %s\n", ui.Escape(h.info.Name()))
	case err == nil:
		fmt.Fprintf(os.Stderr, "webdav: discarded the failed version of %s\n", ui.Escape(h.info.Name()))
	default:
		fmt.Fprintf(os.Stderr, "webdav: upload of %s failed and could not be cleaned up: %s\n",
			ui.Escape(h.info.Name()), ui.EscapeLines(err.Error()))
	}
}
func (h *streamWriteHandle) Read(_ []byte) (int, error)           { return 0, os.ErrPermission }
func (h *streamWriteHandle) Seek(_ int64, _ int) (int64, error)   { return 0, os.ErrPermission }
func (h *streamWriteHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

// uploadHandle is a webdav.File that uploads what is written to it. write
// feeds it without observing the WebDAV ingress metric: the buffered PUT
// replays through it bytes writeFileHandle.Write has already counted.
type uploadHandle interface {
	webdav.File
	write(p []byte) (int, error)
}

// openUpload opens the upload of size bytes to parentPath/fileName. A file
// that fits in one chunk is kept in memory and sent on Close in a single
// request (smallWriteHandle); a larger one is streamed chunk by chunk into a
// version created now (streamWriteHandle).
func (fs *webdavFS) openUpload(
	ctx context.Context, drID, parentPath, fileName string, size int64,
) (uploadHandle, error) {
	sess, err := fs.getSession(ctx, drID)
	if err != nil {
		return nil, fmt.Errorf("dataroom session: %w", err)
	}

	parentID, err := fs.parentNodeID(ctx, drID, parentPath)
	if err != nil {
		return nil, fmt.Errorf("resolving parent path: %w", err)
	}

	if size <= service.UploadChunkSize {
		return &smallWriteHandle{
			ctx: ctx, wfs: fs, drID: drID, parentPath: parentPath, parentID: parentID, sess: sess,
			info: &webdavFileInfo{name: fileName, size: size},
		}, nil
	}

	h, err := fs.openForWriteStream(ctx, drID, parentPath, fileName, parentID, size, sess)
	if err != nil {
		return nil, err // a nil *streamWriteHandle would be a non-nil uploadHandle
	}

	return h, nil
}

// smallWriteHandle is a webdav.File for a PUT that fits in one chunk: the body
// is kept in memory and sent on Close with service.UploadSmallFile, node,
// version and content in a single request — one round trip instead of three.
type smallWriteHandle struct {
	ctx        context.Context
	wfs        *webdavFS
	drID       string
	parentPath string
	parentID   *string
	sess       *service.DataroomSession
	buf        bytes.Buffer
	closed     bool
	// info.versionID is set on Close: the WebDAV handler Stats the file before
	// Close but reads the ETag after it, so the PUT response carries the new
	// version's ETag.
	info *webdavFileInfo
}

func (h *smallWriteHandle) Write(p []byte) (int, error) {
	n, err := h.write(p)
	metrics.WebdavBytes.WithLabelValues("upload").Add(float64(n))

	return n, err
}

// write buffers p, refusing anything beyond the declared size: the request
// would announce a size its content does not have.
func (h *smallWriteHandle) write(p []byte) (int, error) {
	if h.closed {
		return 0, os.ErrClosed
	}
	if int64(h.buf.Len()+len(p)) > h.info.size {
		return 0, fmt.Errorf("source is larger than its declared %d bytes", h.info.size)
	}

	return h.buf.Write(p)
}

func (h *smallWriteHandle) Close() error {
	if h.closed {
		return os.ErrClosed
	}
	h.closed = true
	if got := int64(h.buf.Len()); got != h.info.size {
		return fmt.Errorf("incomplete upload: wrote %d of %d bytes", got, h.info.size)
	}
	node, _, err := service.UploadSmallFile(context.WithoutCancel(h.ctx), h.wfs.client,
		h.drID, h.parentID, h.info.name, h.buf.Bytes(), h.sess)
	if errors.Is(err, api.ErrNotFound) {
		// The cached listing named a parent deleted elsewhere since.
		grandParent, _ := splitWebdavPath(h.parentPath)
		h.wfs.invalidateNodeCache(dataroomURI(h.drID, grandParent))
		h.wfs.invalidateNodeSubtree(dataroomURI(h.drID, h.parentPath))
	}
	if err != nil {
		return err
	}
	h.info.nodeID, h.info.versionID = node.ID, node.VersionID
	h.wfs.upsertNodeCache(dataroomURI(h.drID, h.parentPath), node)

	return nil
}

func (h *smallWriteHandle) Stat() (os.FileInfo, error)           { return h.info, nil }
func (h *smallWriteHandle) Read(_ []byte) (int, error)           { return 0, os.ErrPermission }
func (h *smallWriteHandle) Seek(_ int64, _ int) (int64, error)   { return 0, os.ErrPermission }
func (h *smallWriteHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

// openForWriteStream creates the version a file larger than one chunk is
// streamed into, chunk by chunk as the client sends it.
func (fs *webdavFS) openForWriteStream(
	ctx context.Context, drID, parentPath, fileName string, parentID *string, size int64,
	sess *service.DataroomSession,
) (*streamWriteHandle, error) {
	init, err := fs.initUpload(ctx, drID, parentPath, fileName, parentID, size, sess)
	if err != nil {
		return nil, err
	}

	pipeR, pipeW := io.Pipe()
	done := make(chan error, 1)

	h := &streamWriteHandle{
		wfs:       fs,
		nodeID:    init.NodeID,
		newNode:   init.NewNode,
		pipeW:     pipeW,
		done:      done,
		mimeType:  init.MIMEType,
		createdAt: init.CreatedAt,
		parentURI: dataroomURI(drID, parentPath),
		// versionID lets the PUT response carry the new version's ETag.
		info: &webdavFileInfo{
			name: fileName, size: size, nodeID: init.NodeID, versionID: init.VersionID,
		},
	}

	go func() {
		uploadErr := service.UploadChunks(
			ctx, pipeR, size, fileName, sess.PublicKey, nil,
			func(gctx context.Context, chunkID int, data []byte) error {
				return fs.client.UploadDataroomChunk(gctx, init.VersionID, chunkID, data)
			},
		)
		if uploadErr != nil {
			_ = pipeR.CloseWithError(uploadErr)
		}
		done <- uploadErr
	}()

	return h, nil
}

func (fs *webdavFS) openForWrite(ctx context.Context, drID, subPath string) (webdav.File, error) {
	parentPath, fileName := splitWebdavPath(subPath)
	if fileName == "" {
		return nil, os.ErrPermission
	}
	if size := contentLengthFromCtx(ctx); size >= 0 {
		return fs.openUpload(ctx, drID, parentPath, fileName, size)
	}

	return fs.openForWriteTempFile(ctx, drID, parentPath, fileName, isPutFromCtx(ctx))
}

// Mkdir implements webdav.FileSystem.
func (fs *webdavFS) Mkdir(ctx context.Context, name string, _ os.FileMode) error {
	kind, drName, subPath := parseWebdavPath(name)
	if kind != pathDataroomNode || subPath == "/" {
		return os.ErrPermission
	}
	drID, err := fs.cache.idForName(ctx, drName)
	if err != nil {
		return err
	}
	sess, err := fs.getSession(ctx, drID)
	if err != nil {
		return fmt.Errorf("dataroom session: %w", err)
	}
	parentPath, dirName := splitWebdavPath(subPath)
	parentURI := dataroomURI(drID, parentPath)
	parentID, err := fs.parentNodeID(ctx, drID, parentPath)
	if errors.Is(err, os.ErrInvalid) {
		// The parent is a file: not a collection, 409 Conflict (RFC 4918 §9.3.1).
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	id, err := service.MkdirDataroomInto(ctx, fs.client, drID, parentID, dirName, sess)
	if errors.Is(err, api.ErrConflict) && parentID != nil {
		id, err = fs.mkdirAfterConflict(ctx, drID, parentPath, dirName, *parentID, sess, err)
	}
	if errors.Is(err, api.ErrNotFound) {
		// The cached listing named a parent deleted elsewhere since.
		grandParent, _ := splitWebdavPath(parentPath)
		fs.invalidateNodeCache(dataroomURI(drID, grandParent))
		fs.invalidateNodeSubtree(parentURI)

		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	// Both listings the next requests need are known without asking the API:
	// the parent's gains the new folder (so a nested MKCOL or a PUT inside it
	// finds its ID), and the new folder's own is empty (so the first PUT in it
	// needs no listing, and the following overwrite finds the file it created).
	fs.cacheNewFolder(parentURI, dataroomURI(drID, subPath),
		service.DataroomNodeInfo{ID: id, Name: dirName, Type: "dir"})

	return nil
}

// cacheNewFolder records a folder this server has just created: an empty
// listing for the folder itself (it cannot have children yet), then the folder
// in its parent's listing. Both happen under one lock, the folder's own
// listing first: once a request can find the folder in the cache, a child it
// creates there lands in that listing instead of being hidden by a seed
// arriving after it.
//
// Any older listing at or below uri (a folder of the same name deleted
// elsewhere, and its sub-folders) is dropped, and its generation bumped so a
// listing already in flight is not stored over it.
func (fs *webdavFS) cacheNewFolder(parentURI, uri string, folder service.DataroomNodeInfo) {
	fs.nodeMu.Lock()
	defer fs.nodeMu.Unlock()
	fs.invalidateNodeSubtreeLocked(uri)
	if fs.nodeCache == nil {
		fs.nodeCache = make(map[string]*nodeCacheEntry)
	}
	fs.nodeCache[uri] = &nodeCacheEntry{nodes: []service.DataroomNodeInfo{}, fetchedAt: time.Now()}
	fs.upsertNodeCacheLocked(parentURI, folder)
}

// mkdirAfterConflict sorts out a 409 on folder creation. The API answers it
// for a name already taken, and for a parent_id naming a folder deleted since
// its listing was cached (the dangling reference fails a foreign key). The
// parent is re-resolved from a fresh listing: gone, or now a file → 409
// Conflict for the client (os.ErrNotExist); re-created under another ID → one
// retry there; unchanged → the conflict is genuine and returned as is (405).
func (fs *webdavFS) mkdirAfterConflict(
	ctx context.Context, drID, parentPath, dirName, staleID string,
	sess *service.DataroomSession, conflict error,
) (string, error) {
	grandParent, _ := splitWebdavPath(parentPath)
	fs.invalidateNodeCache(dataroomURI(drID, grandParent))
	freshID, err := fs.parentNodeID(ctx, drID, parentPath)
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, os.ErrInvalid):
		fs.invalidateNodeSubtree(dataroomURI(drID, parentPath))

		return "", os.ErrNotExist
	case err != nil:
		return "", err
	case freshID == nil || *freshID == staleID:
		return "", conflict
	}
	// The listings cached under the path belong to the deleted folder.
	fs.invalidateNodeSubtree(dataroomURI(drID, parentPath))

	return service.MkdirDataroomInto(ctx, fs.client, drID, freshID, dirName, sess)
}

// RemoveAll implements webdav.FileSystem.
func (fs *webdavFS) RemoveAll(ctx context.Context, name string) error {
	kind, drName, subPath := parseWebdavPath(name)
	if kind != pathDataroomNode || subPath == "/" {
		return os.ErrPermission
	}
	drID, err := fs.cache.idForName(ctx, drName)
	if err != nil {
		return err
	}
	parentPath, nodeName := splitWebdavPath(subPath)
	err = fs.deleteListedNode(ctx, drID, parentPath, nodeName)
	if errors.Is(err, api.ErrNotFound) {
		// The listing was stale (404, or 410 while the purge is pending): its
		// node is gone, possibly replaced by a new one under the same name.
		// Retry once against a fresh listing.
		fs.invalidateNodeCache(dataroomURI(drID, parentPath))
		err = fs.deleteListedNode(ctx, drID, parentPath, nodeName)
		if errors.Is(err, api.ErrNotFound) {
			err = os.ErrNotExist
		}
	}
	if err == nil {
		fs.removeFromNodeCache(dataroomURI(drID, parentPath), nodeName)
		fs.invalidateNodeSubtree(dataroomURI(drID, subPath))
	}

	return err
}

// listedNodeID returns the ID of the child name of parentPath, found in the
// parent listing, and tags the request span with it.
//
// That listing is almost always cached: the WebDAV handler Stats the path
// before RemoveAll, and a client moves a node out of a folder it has just
// listed (the handler Stats only the destination of a MOVE). The mutation is
// then the only round trip, whereas service.resolvePath would list the API once
// per path level first; a miss costs one listing, never more. The cost of
// trusting a cached, possibly expired listing is accepted: a node moved elsewhere
// by another client within that window is deleted or renamed at its new
// location. A node deleted elsewhere makes the mutation answer 404, or 410
// while its purge is pending (both match api.ErrNotFound), which callers retry
// against a fresh listing.
func (fs *webdavFS) listedNodeID(ctx context.Context, drID, parentPath, name string) (string, error) {
	n, err := fs.findListedNode(ctx, drID, parentPath, name)
	if err != nil {
		return "", err
	}
	trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrNodeID.String(n.ID))

	return n.ID, nil
}

// deleteListedNode deletes the child name of parentPath (see listedNodeID).
func (fs *webdavFS) deleteListedNode(ctx context.Context, drID, parentPath, name string) error {
	nodeID, err := fs.listedNodeID(ctx, drID, parentPath, name)
	if err != nil {
		return err
	}

	return fs.client.DeleteDataroomNode(ctx, nodeID)
}

// Rename implements webdav.FileSystem.
func (fs *webdavFS) Rename(ctx context.Context, oldName, newName string) error {
	oldKind, oldDR, oldSub := parseWebdavPath(oldName)
	newKind, newDR, newSub := parseWebdavPath(newName)

	if oldKind != pathDataroomNode || newKind != pathDataroomNode || oldSub == "/" || newSub == "/" {
		return os.ErrPermission
	}

	oldID, err := fs.cache.idForName(ctx, oldDR)
	if err != nil {
		return err
	}
	newID, err := fs.cache.idForName(ctx, newDR)
	if err != nil {
		return err
	}
	if oldID != newID {
		return fmt.Errorf("moving between datarooms is not supported: %w", os.ErrPermission)
	}

	oldParent, oldBase := splitWebdavPath(oldSub)
	newParent, newBase := splitWebdavPath(newSub)
	dstParentID, err := fs.moveListedNode(ctx, oldID, oldParent, oldBase, newParent, newBase)
	if retry, staleErr := fs.staleRename(ctx, oldID, oldParent, newParent, dstParentID, err); retry {
		_, err = fs.moveListedNode(ctx, oldID, oldParent, oldBase, newParent, newBase)
		if errors.Is(err, api.ErrNotFound) {
			err = os.ErrNotExist
		}
	} else if staleErr != nil {
		err = staleErr
	}
	if err == nil {
		fs.moveInNodeCache(dataroomURI(oldID, oldParent), oldBase, dataroomURI(newID, newParent), newBase)
		fs.invalidateNodeSubtree(dataroomURI(oldID, oldSub))
		fs.invalidateNodeSubtree(dataroomURI(newID, newSub))
	}

	return err
}

// staleRename tells whether a failed rename came from a stale listing and is
// worth one retry, after invalidating the listings involved so that the retry
// resolves them afresh. dstParentID is the destination folder the failed
// attempt used (nil for the root, or when it was not resolved).
//
//   - 404 or 410 (api.ErrNotFound): the source node is gone, possibly replaced
//     by a new node under the same name.
//   - 409: the API answers it both for a name already taken in the destination
//     and for a destination folder deleted since its listing was cached (the
//     dangling parent_id fails a foreign key). The destination is re-resolved
//     from a fresh listing: only a folder whose ID changed is worth a retry. A
//     folder that is gone replaces the conflict with os.ErrNotExist; an
//     unchanged one is a genuine conflict, returned without repeating the PUT.
//     The root cannot be deleted, so a conflict there is always genuine.
//
// A non-nil error with retry false replaces the rename's error.
func (fs *webdavFS) staleRename(
	ctx context.Context, drID, srcParent, dstParent string, dstParentID *string, err error,
) (retry bool, replaced error) {
	switch {
	case errors.Is(err, api.ErrNotFound):
		fs.invalidateNodeCache(dataroomURI(drID, srcParent))

		return true, nil
	case errors.Is(err, api.ErrConflict) && dstParentID != nil:
		dstGrandParent, _ := splitWebdavPath(dstParent)
		fs.invalidateNodeCache(dataroomURI(drID, dstGrandParent))
		freshID, freshErr := fs.parentNodeID(ctx, drID, dstParent)
		if freshErr != nil {
			return false, freshErr
		}

		return freshID != nil && *freshID != *dstParentID, nil
	default:
		return false, nil
	}
}

// moveListedNode renames the child srcName of srcParent to dstName under
// dstParent, both IDs taken from the cached listings (see listedNodeID). It
// returns the destination folder ID it used, once resolved.
func (fs *webdavFS) moveListedNode(
	ctx context.Context, drID, srcParent, srcName, dstParent, dstName string,
) (*string, error) {
	nodeID, err := fs.listedNodeID(ctx, drID, srcParent, srcName)
	if err != nil {
		return nil, err
	}
	dstParentID, err := fs.parentNodeID(ctx, drID, dstParent)
	if err != nil {
		return nil, err
	}
	sess, err := fs.getSession(ctx, drID)
	if err != nil {
		return dstParentID, fmt.Errorf("dataroom session: %w", err)
	}

	return dstParentID, service.MoveDataroomNodeByID(ctx, fs.client, nodeID, dstParentID, dstName, sess)
}

// Stat implements webdav.FileSystem.
func (fs *webdavFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	kind, drName, subPath := parseWebdavPath(name)

	switch kind {
	case pathRoot:
		return &webdavFileInfo{name: "/", isDir: true}, nil
	case pathDataroomRoot:
		return &webdavFileInfo{name: webdavSectionDataroom, isDir: true}, nil
	case pathUnknown:
		return nil, os.ErrNotExist
	case pathDataroomNode:
	}

	drID, err := fs.cache.idForName(ctx, drName)
	if err != nil {
		return nil, err
	}

	if subPath == "/" {
		return &webdavFileInfo{name: drName, isDir: true}, nil
	}

	parentPath, nodeName := splitWebdavPath(subPath)
	n, err := fs.findListedNode(ctx, drID, parentPath, nodeName)
	if err != nil {
		return nil, err
	}

	return fileInfoFromNode(n), nil
}

// contentTypeForPath resolves the Content-Type for a GET/HEAD target, preferring
// the node's decrypted MIME type (via a cached Stat) over the filename extension.
func (fs *webdavFS) contentTypeForPath(ctx context.Context, urlPath string) string {
	if info, err := fs.Stat(ctx, urlPath); err == nil {
		if wfi, ok := info.(*webdavFileInfo); ok && !wfi.isDir {
			if ct, _ := wfi.ContentType(ctx); ct != "" {
				return ct
			}
		}
	}
	if ct := mime.TypeByExtension(filepath.Ext(urlPath)); ct != "" {
		return ct
	}

	return "application/octet-stream"
}

// webdavPassphraseReader returns the key passphrase from the environment.
// No interactive prompt — identical to mcpPassphraseReader.
func webdavPassphraseReader() (string, error) {
	return config.RequireKeyPassphrase()
}

// webdavAuthUser is the fixed Basic auth username when --auth is enabled.
const webdavAuthUser = "retyc"

// generateWebdavPassword returns a random URL-safe password (128 bits of entropy).
func generateWebdavPassword() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating password: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// basicAuthMiddleware wraps next with HTTP Basic authentication. Credentials are
// compared via SHA-256 digests so the comparison is constant-time regardless of
// the length of the submitted values.
func basicAuthMiddleware(next http.Handler, username, password string) http.Handler {
	userHash := sha256.Sum256([]byte(username))
	passHash := sha256.Sum256([]byte(password))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok {
			uh := sha256.Sum256([]byte(user))
			ph := sha256.Sum256([]byte(pass))
			// Bitwise & (not &&) so both comparisons always run.
			if subtle.ConstantTimeCompare(uh[:], userHash[:])&subtle.ConstantTimeCompare(ph[:], passHash[:]) == 1 {
				next.ServeHTTP(w, r)

				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="RETYC WebDAV", charset="UTF-8"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// isLoopbackAddr reports whether the host:port bind address is loopback-only.
// An empty host (":8888") means "all interfaces" and is therefore not loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// bindUnsafeWrite binds --unsafe-write to api.unsafe_write, which config.Load
// then reads: call it before. Like the other flags, bound in RunE, never in
// init().
func bindUnsafeWrite(flags *pflag.FlagSet) {
	_ = viper.BindPFlag("api.unsafe_write", flags.Lookup("unsafe-write"))
}

// resolveWebdavAddr returns the host:port to bind, with the usual precedence
// (flag > env > config file > default); same binding strategy as
// resolveMetricsAddr. A value without a port ("0.0.0.0", the form --addr took
// before it included the port) is an error.
func resolveWebdavAddr(flags *pflag.FlagSet) (string, error) {
	_ = viper.BindPFlag("webdav.addr", flags.Lookup("addr"))
	addr := viper.GetString("webdav.addr")
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return "", fmt.Errorf("--addr %q: expected host:port, e.g. 127.0.0.1:8888", addr)
	}

	return addr, nil
}

// tokenKeepalive pings tokenSource every 60s to keep the access token warm.
// If the refresh token expires it invokes onFail(err) and returns, letting the
// caller shut the server down gracefully (so in-flight uploads, orphaned-node
// cleanup, and temp-dir removal all run). Stops when ctx is cancelled.
func tokenKeepalive(ctx context.Context, src oauth2.TokenSource, onFail func(error)) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := checkToken(src); err != nil {
				onFail(err)

				return
			}
		}
	}
}

// checkToken asks src for a valid token (refreshing it when needed) and feeds
// the retyc_cli_token_* metrics: the result counter and the seconds left on
// the access token, 0 when unknown.
func checkToken(src oauth2.TokenSource) error {
	tok, err := src.Token()
	if err != nil {
		metrics.TokenRefreshes.WithLabelValues("error").Inc()
		metrics.TokenExpiry.Set(0)

		return err
	}
	metrics.TokenRefreshes.WithLabelValues("ok").Inc()
	if tok.Expiry.IsZero() {
		metrics.TokenExpiry.Set(0)
	} else {
		metrics.TokenExpiry.Set(max(time.Until(tok.Expiry).Seconds(), 0))
	}

	return nil
}

var webdavCmd = &cobra.Command{
	Use:   "webdav",
	Short: "WebDAV server integration",
}

// webdavStartupCheck runs the validation calls performed before the server
// binds its port: a dataroom listing (auth + API reachability) and the key
// unlock, which bypasses the keyring so a wrong RETYC_KEY_PASSPHRASE fails at
// startup rather than at the first dataroom access. The unlocked identity is
// returned so the server never runs scrypt again.
func webdavStartupCheck(
	ctx context.Context, client *api.Client, reader service.PassphraseReader,
) (*age.HybridIdentity, error) {
	if _, err := service.ListDatarooms(ctx, client); err != nil {
		return nil, fmt.Errorf("API connectivity check failed: %w", err)
	}
	identity, err := service.UnlockUserIdentity(ctx, client, reader)
	if err != nil {
		return nil, fmt.Errorf("key passphrase check failed: %w", err)
	}

	return identity, nil
}

var webdavServeCmd = &cobra.Command{
	Use:         "serve",
	Annotations: map[string]string{annotationLongRunning: "true"},
	Short:       "Start a local WebDAV server exposing your datarooms",
	Long: `Start a local WebDAV server on localhost that exposes all your RETYC datarooms.

Datarooms are exposed under the /dataroom folder; other element types may be
added at the root in the future.

Key passphrase: set RETYC_KEY_PASSPHRASE (env var).

Authentication: pass --auth to require HTTP Basic credentials (user "retyc").
The password is read from RETYC_WEBDAV_PASSWORD, or generated randomly and
printed at startup when the variable is unset.

Example:
  RETYC_KEY_PASSPHRASE=your-passphrase retyc webdav serve --addr 127.0.0.1:8888 --auth
  # Then mount http://localhost:8888 in your WebDAV client
  # Datarooms appear under /dataroom`,
	RunE: func(cmd *cobra.Command, args []string) (retErr error) {
		// The init span covers everything before the port is bound (token,
		// API reachability, key unlock, listeners) and is the only span
		// parented to TRACEPARENT: the driver's NodeStageVolume trace must
		// close once the server is up. Requests get their own roots. It
		// starts before the passphrase check so a missing passphrase is
		// still recorded as a failed init.
		initCtx, initSpan := telemetry.Tracer().Start(cmd.Context(), "retyc webdav serve init")
		initDone := false
		defer func() {
			if !initDone {
				telemetry.RecordError(initSpan, retErr)
				initSpan.End()
			}
		}()

		// Fail-fast: a malformed address would otherwise only surface once the
		// token, the API and the key passphrase have all been checked.
		addr, err := resolveWebdavAddr(cmd.Flags())
		if err != nil {
			return err
		}

		// Fail-fast: passphrase must be set before any crypto operation.
		if config.KeyPassphrase() == "" {
			return config.ErrNoKeyPassphrase
		}

		bindUnsafeWrite(cmd.Flags())
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		tokSrc, err := mustGetToken(initCtx, cfg)
		if err != nil {
			return err
		}
		client := api.New(cfg.API.BaseURL, cliUserAgent(), tokSrc, insecure, debug,
			apiTransport(), api.WithUnsafeWrite(cfg.API.UnsafeWrite))

		// Fail-fast before binding the port: auth + API reachability, then the
		// key passphrase itself (a wrong one would otherwise only surface on the
		// first dataroom access). The unlocked identity is kept for the whole run.
		identity, err := webdavStartupCheck(initCtx, client, webdavPassphraseReader)
		if err != nil {
			return err
		}

		fs := &webdavFS{
			cfg:    cfg,
			client: client,
			cache: newDataroomCache(func(ctx context.Context) ([]dataroomCacheItem, error) {
				result, err := service.ListDatarooms(ctx, client)
				if err != nil {
					return nil, err
				}
				items := make([]dataroomCacheItem, len(result.Items))
				for i, dr := range result.Items {
					items[i] = dataroomCacheItem{id: dr.ID, title: dr.Title}
				}

				return items, nil
			}),
			passphraseReader: webdavPassphraseReader,
			identity:         identity,
			cacheTTL:         cfg.Webdav.Cache.TTL,
			cacheMaxStale:    cfg.Webdav.Cache.MaxStale,
		}
		fs.cache.ttl, fs.cache.maxStale = cfg.Webdav.Cache.TTL, cfg.Webdav.Cache.MaxStale

		lockSystem := webdav.NewMemLS()
		handler := &webdav.Handler{
			FileSystem: fs,
			LockSystem: lockSystem,
			Logger: func(r *http.Request, err error) {
				// URL.Path is percent-decoded: "%1b" arrives as a raw ESC.
				if err != nil {
					fmt.Fprintf(os.Stderr, "webdav: %s %s: %s\n",
						r.Method, ui.Escape(r.URL.Path), ui.EscapeLines(err.Error()))

					return
				}
				fmt.Fprintf(os.Stderr, "webdav: %s %s\n", r.Method, ui.Escape(r.URL.Path))
			},
		}

		// WebDAV locks on files are mirrored onto the API's node locks, so other
		// RETYC clients see them and theirs are honoured here (see lockMirror).
		mirror := newLockMirror(fs, lockSystem)
		davHandler := mirror.middleware(handler)

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "COPY" {
				// Server-side copy: the storage duplicates the chunks, nothing
				// transits through this process (see handleCopy).
				fs.handleCopy(w, r)

				return
			}
			if r.Method == "PUT" {
				rctx := withIsPut(r.Context())
				if r.ContentLength >= 0 {
					rctx = withContentLength(rctx, r.ContentLength)
				}
				r = r.WithContext(rctx)
			}
			// Pre-set Content-Type to skip http.ServeContent's 512-byte sniff read,
			// which would otherwise trigger a full buffered download before the
			// streaming path engages. We use the node's decrypted MIME type when
			// available (cached Stat), falling back to the filename extension.
			if r.Method == "GET" || r.Method == "HEAD" {
				w.Header().Set("Content-Type", fs.contentTypeForPath(r.Context(), r.URL.Path))
			}
			davHandler.ServeHTTP(w, r)
		})

		authEnabled, _ := cmd.Flags().GetBool("auth")
		var rootHandler http.Handler = mux
		if authEnabled {
			password := config.WebdavPassword()
			if password == "" {
				password, err = generateWebdavPassword()
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "WebDAV credentials: user %q, password %q (generated for this session)\n",
					webdavAuthUser, password)
			} else {
				fmt.Fprintf(os.Stderr, "WebDAV auth enabled: user %q, password from RETYC_WEBDAV_PASSWORD\n",
					webdavAuthUser)
			}
			rootHandler = basicAuthMiddleware(rootHandler, webdavAuthUser, password)
		} else if !isLoopbackAddr(addr) {
			fmt.Fprintf(os.Stderr,
				"WARNING: binding to %s without authentication exposes all dataroom contents "+
					"in cleartext to the network; consider --auth\n", addr)
		}
		// Outermost, so rejected credentials (401) are counted and traced too.
		rootHandler = instrumentWebdav(rootHandler)

		srv := &http.Server{ //nolint:gosec // G112: local-only server; Slowloris not a concern
			Addr:              addr,
			Handler:           rootHandler,
			ReadHeaderTimeout: 30 * time.Second,
		}
		// Optional observability listener (Prometheus metrics + probes), bound
		// before the WebDAV port so a bad address fails fast. /readyz answers
		// 503 until the WebDAV listener is actually bound below.
		health := newWebdavHealth()
		var metricsSrv *http.Server
		if metricsAddr := resolveMetricsAddr(cmd.Flags()); metricsAddr != "" {
			labels, err := parseMetricsLabels(resolveMetricsLabels(cmd.Flags()))
			if err != nil {
				return err
			}
			handler, err := newObservabilityHandler(health, observabilityOptions{
				runtime: resolveMetricsRuntime(cmd.Flags()),
				extra:   []prometheus.Collector{sessionsCachedGauge(fs)},
				labels:  labels,
			})
			if err != nil {
				return err
			}
			metricsSrv, err = startObservabilityServer(metricsAddr, handler)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Metrics and probes listening on http://%s (/metrics, /healthz, /readyz)\n",
				metricsSrv.Addr)
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// Single shutdown path shared by SIGINT/SIGTERM and auth expiry, so the
		// server always drains gracefully instead of being killed mid-request.
		var shutdownOnce sync.Once
		shutdown := func() {
			shutdownOnce.Do(func() {
				// Flip readiness first so an orchestrator stops routing to this
				// instance while the in-flight requests drain.
				health.setReady(false)
				cancel()
				// Bound the drain: a stuck streaming client must not keep the CLI
				// process alive forever. After the timeout, Shutdown returns and the
				// process exits, dropping any still-open connections.
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer shutdownCancel()
				_ = srv.Shutdown(shutdownCtx)
				if metricsSrv != nil {
					_ = metricsSrv.Shutdown(shutdownCtx)
				}
			})
		}

		// Renew the mirrored server locks while the WebDAV locks stand, and
		// release them on shutdown.
		go mirror.run(ctx)

		authErrCh := make(chan error, 1)
		go tokenKeepalive(ctx, tokSrc, func(err error) {
			select {
			case authErrCh <- err:
			default:
			}
			shutdown()
		})

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigCh)
		go func() {
			select {
			case <-sigCh:
				shutdown()
			case <-ctx.Done():
			}
		}()

		// Bind explicitly rather than ListenAndServe so readiness flips only
		// once the port really accepts connections.
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			shutdown()

			return fmt.Errorf("WebDAV server: %w", err)
		}
		fmt.Fprintf(os.Stderr, "WebDAV server listening on http://%s\n", ln.Addr())
		health.setReady(true)
		initSpan.End()
		initDone = true

		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("WebDAV server: %w", err)
		}

		// Surface an auth-expiry shutdown as a non-zero exit with a clear message.
		select {
		case err := <-authErrCh:
			return fmt.Errorf(
				"authentication expired: %w\nRun `retyc auth login` and restart the WebDAV server", err)
		default:
		}

		return nil
	},
}

// Compile-time interface checks.
var _ webdav.File = (*dirHandle)(nil)
var _ webdav.File = (*readFileHandle)(nil)
var _ webdav.File = (*writeFileHandle)(nil)
var _ webdav.File = (*streamWriteHandle)(nil)

func init() {
	webdavServeCmd.Flags().String("addr", "127.0.0.1:8888", "host:port to bind")
	webdavServeCmd.Flags().Bool("unsafe-write", false,
		"let the API acknowledge uploads before they are stored (faster; a failed background store is not reported)")
	webdavServeCmd.Flags().Bool("auth", false,
		"require HTTP Basic auth (password from RETYC_WEBDAV_PASSWORD or generated)")
	webdavServeCmd.Flags().String("metrics-addr", "",
		"address for Prometheus metrics and health probes (e.g. 127.0.0.1:9090)")
	webdavServeCmd.Flags().Bool("metrics-runtime", true,
		"include Go runtime and process metrics on /metrics")
	webdavServeCmd.Flags().StringArray("metrics-label", nil,
		"constant label key=value added to every metric (repeatable)")
	webdavCmd.AddCommand(webdavServeCmd)
	rootCmd.AddCommand(webdavCmd)
}
