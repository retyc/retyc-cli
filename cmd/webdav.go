package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
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
	nodeID      string // non-empty for file nodes
	versionID   string // current version ID — avoids GetDataroomNode on download
	chunkCount  int    // number of AGE-encrypted chunks
	contentType string // decrypted MIME type from node metadata
}

func (fi *webdavFileInfo) Name() string       { return fi.name }
func (fi *webdavFileInfo) Size() int64        { return fi.size }
func (fi *webdavFileInfo) IsDir() bool        { return fi.isDir }
func (fi *webdavFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *webdavFileInfo) Sys() any           { return nil }
func (fi *webdavFileInfo) Mode() os.FileMode {
	if fi.isDir {
		return os.ModeDir | 0755
	}

	return 0644
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

const dataroomCacheTTL = 60 * time.Second

// dataroomCache is a thread-safe, TTL-based cache mapping dataroom display names to IDs.
type dataroomCache struct {
	mu      sync.RWMutex
	entry   *dataroomCacheEntry
	fetchFn func(ctx context.Context) ([]dataroomCacheItem, error)
}

func newDataroomCache(fetchFn func(ctx context.Context) ([]dataroomCacheItem, error)) *dataroomCache {
	return &dataroomCache{fetchFn: fetchFn}
}

func (c *dataroomCache) resolve(ctx context.Context) (*dataroomCacheEntry, error) {
	c.mu.RLock()
	if c.entry != nil && time.Since(c.entry.fetchedAt) < dataroomCacheTTL {
		e := c.entry
		c.mu.RUnlock()

		return e, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check after acquiring write lock (another goroutine may have refreshed).
	if c.entry != nil && time.Since(c.entry.fetchedAt) < dataroomCacheTTL {
		return c.entry, nil
	}

	items, err := c.fetchFn(ctx)
	if err != nil {
		return nil, err
	}

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

	c.entry = &dataroomCacheEntry{
		byName:    byName,
		names:     names,
		fetchedAt: time.Now(),
	}

	return c.entry, nil
}

// idForName returns the dataroom ID for the given display name, or os.ErrNotExist.
func (c *dataroomCache) idForName(ctx context.Context, name string) (string, error) {
	e, err := c.resolve(ctx)
	if err != nil {
		return "", err
	}
	id, ok := e.byName[name]
	if !ok {
		return "", os.ErrNotExist
	}

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

// dirHandle is a webdav.File for directories. It holds a pre-built list of entries.
type dirHandle struct {
	info    os.FileInfo
	entries []os.FileInfo
	offset  int
}

func (h *dirHandle) Close() error                       { return nil }
func (h *dirHandle) Read(_ []byte) (int, error)         { return 0, os.ErrInvalid }
func (h *dirHandle) Write(_ []byte) (int, error)        { return 0, os.ErrPermission }
func (h *dirHandle) Seek(_ int64, _ int) (int64, error) { return 0, os.ErrPermission }
func (h *dirHandle) Stat() (os.FileInfo, error)         { return h.info, nil }
func (h *dirHandle) Readdir(count int) ([]os.FileInfo, error) {
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

	name := h.info.Name()
	err = service.DownloadChunks(
		h.ctx, tempDir, name,
		h.info.Size(), h.chunkCount, sess.Identity, nil,
		func(ctx context.Context, chunkID int) ([]byte, error) {
			return h.wfs.client.DownloadDataroomChunk(ctx, h.versionID, chunkID)
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webdav: download error (%s): %v\n", name, err)
		_ = os.RemoveAll(tempDir)

		return err
	}

	localPath := filepath.Join(tempDir, filepath.Base(name))
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
		_ = pipeW.CloseWithError(err)
	}()

	return nil
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
	file             *os.File
	tempDir          string
	tempFilePath     string
	parentURI        string // retyc://id/parent — passed to UploadToDataroom
	wfs              *webdavFS
	cfg              *config.Config
	client           *api.Client
	passphraseReader service.PassphraseReader
	isPut            bool // true = real PUT; false = LOCK-driven create
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
	err := service.UploadToDataroom(
		context.Background(),
		h.cfg, h.client,
		[]string{h.tempFilePath},
		h.parentURI,
		h.passphraseReader,
		nil,
	)
	_ = os.RemoveAll(h.tempDir)
	if err == nil {
		h.wfs.invalidateNodeCache(h.parentURI)
	}

	return err
}
func (h *writeFileHandle) Read(_ []byte) (int, error)           { return 0, os.ErrPermission }
func (h *writeFileHandle) Write(p []byte) (int, error)          { return h.file.Write(p) }
func (h *writeFileHandle) Seek(_ int64, _ int) (int64, error)   { return 0, os.ErrPermission }
func (h *writeFileHandle) Stat() (os.FileInfo, error)           { return h.file.Stat() }
func (h *writeFileHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

// nodeCacheEntry caches the result of a ListNodes call for a given URI.
type nodeCacheEntry struct {
	nodes     []service.DataroomNodeInfo
	fetchedAt time.Time
}

// sessionCacheEntry caches a resolved dataroom session (2 API calls + AGE crypto).
type sessionCacheEntry struct {
	sess      *service.DataroomSession
	fetchedAt time.Time
}

// nodeCacheTTL is longer than before because mutations now explicitly invalidate the cache.
const nodeCacheTTL = 30 * time.Second

// sessionCacheTTL: sessions only change on dataroom rekey (user add/remove), which WebDAV doesn't perform.
const sessionCacheTTL = 30 * time.Minute

// webdavFS implements webdav.FileSystem over RETYC datarooms.
type webdavFS struct {
	cfg              *config.Config
	client           *api.Client
	cache            *dataroomCache
	passphraseReader service.PassphraseReader
	nodeMu           sync.RWMutex
	nodeCache        map[string]*nodeCacheEntry
	sessMu           sync.RWMutex
	sessionCache     map[string]*sessionCacheEntry
}

var _ webdav.FileSystem = (*webdavFS)(nil)

// invalidateNodeCache removes uri from the node listing cache.
// Called after any mutation (upload, mkdir, delete, rename) so that the next
// PROPFIND or Stat on the affected directory fetches fresh data from the API.
func (fs *webdavFS) invalidateNodeCache(uri string) {
	fs.nodeMu.Lock()
	delete(fs.nodeCache, uri)
	fs.nodeMu.Unlock()
}

// getSession returns the cached session for drID, resolving it on first access or after TTL expiry.
// Caching avoids two API calls (GetDataroom + GetActiveKey) per listing or download.
func (fs *webdavFS) getSession(ctx context.Context, drID string) (*service.DataroomSession, error) {
	fs.sessMu.RLock()
	if e, ok := fs.sessionCache[drID]; ok && time.Since(e.fetchedAt) < sessionCacheTTL {
		sess := e.sess
		fs.sessMu.RUnlock()

		return sess, nil
	}
	fs.sessMu.RUnlock()

	sess, err := service.GetDataroomSession(ctx, fs.cfg, fs.client, drID, fs.passphraseReader)
	if err != nil {
		return nil, err
	}

	fs.sessMu.Lock()
	if fs.sessionCache == nil {
		fs.sessionCache = make(map[string]*sessionCacheEntry)
	}
	fs.sessionCache[drID] = &sessionCacheEntry{sess: sess, fetchedAt: time.Now()}
	fs.sessMu.Unlock()

	return sess, nil
}

// listNodes returns the decrypted children of drID at nodePath, using a TTL cache.
// Uses the session cache to avoid redundant resolveDataroomSession calls.
func (fs *webdavFS) listNodes(ctx context.Context, drID, nodePath string) ([]service.DataroomNodeInfo, error) {
	uri := dataroomURI(drID, nodePath)

	fs.nodeMu.RLock()
	if e, ok := fs.nodeCache[uri]; ok && time.Since(e.fetchedAt) < nodeCacheTTL {
		nodes := e.nodes
		fs.nodeMu.RUnlock()

		return nodes, nil
	}
	fs.nodeMu.RUnlock()

	sess, err := fs.getSession(ctx, drID)
	if err != nil {
		return nil, err
	}

	nodes, err := service.ListNodesWithSession(ctx, fs.client, drID, nodePath, sess)
	if err != nil {
		return nil, err
	}

	fs.nodeMu.Lock()
	if fs.nodeCache == nil {
		fs.nodeCache = make(map[string]*nodeCacheEntry)
	}
	fs.nodeCache[uri] = &nodeCacheEntry{nodes: nodes, fetchedAt: time.Now()}
	fs.nodeMu.Unlock()

	return nodes, nil
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
		infos = append(infos, &webdavFileInfo{
			name:        n.Name,
			size:        n.Size,
			isDir:       n.Type == "dir",
			contentType: n.MIMEType,
		})
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
		return fs.openNodeDir(ctx, wfi.name, drID, subPath)
	}

	return fs.openForRead(ctx, drID, wfi)
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

func (fs *webdavFS) openNodeDir(ctx context.Context, displayName, drID, subPath string) (webdav.File, error) {
	nodes, err := fs.listNodes(ctx, drID, subPath)
	if err != nil {
		return nil, err
	}

	return &dirHandle{
		info:    &webdavFileInfo{name: displayName, isDir: true},
		entries: nodesToFileInfos(nodes),
	}, nil
}

func (fs *webdavFS) openForRead(ctx context.Context, drID string, wfi *webdavFileInfo) (webdav.File, error) {
	return &readFileHandle{
		ctx:        ctx,
		wfs:        fs,
		drID:       drID,
		versionID:  wfi.versionID,
		chunkCount: wfi.chunkCount,
		info:       wfi,
	}, nil
}

func (fs *webdavFS) openForWriteTempFile(drID, parentPath, fileName string, isPut bool) (webdav.File, error) {
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
		file:             f,
		tempDir:          tempDir,
		tempFilePath:     tempFilePath,
		parentURI:        dataroomURI(drID, parentPath),
		wfs:              fs,
		cfg:              fs.cfg,
		client:           fs.client,
		passphraseReader: fs.passphraseReader,
		isPut:            isPut,
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
	written   int64 // bytes accepted from the client, for short-upload detection
}

func (h *streamWriteHandle) Write(p []byte) (int, error) {
	n, err := h.pipeW.Write(p)
	h.written += int64(n)

	return n, err
}
func (h *streamWriteHandle) Stat() (os.FileInfo, error) { return h.info, nil }
func (h *streamWriteHandle) Close() error {
	_ = h.pipeW.Close()
	err := <-h.done
	// Guard against a truncated body: the node version was created upfront with the
	// client-declared Content-Length, so committing fewer bytes would leave a
	// version whose chunk_count never matches its stored chunks (later downloads
	// would 404 mid-stream or silently truncate). A clean pipe EOF after a client
	// abort otherwise looks like success, so validate the byte count explicitly.
	if err == nil && h.written != h.info.size {
		err = fmt.Errorf("incomplete upload: wrote %d of %d bytes", h.written, h.info.size)
	}
	if err != nil {
		h.cleanup()

		return err
	}
	h.wfs.invalidateNodeCache(h.parentURI)

	return nil
}

// cleanup removes the orphaned node after a failed streaming upload. It can only
// delete brand-new nodes: for a new version of a pre-existing node, deleting the
// node would destroy good prior versions, so we only warn (no per-version delete
// API is available).
func (h *streamWriteHandle) cleanup() {
	if !h.newNode {
		fmt.Fprintf(os.Stderr,
			"webdav: upload of %s failed; its new version may be incomplete\n", h.info.Name())

		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if delErr := h.wfs.client.DeleteDataroomNode(cleanupCtx, h.nodeID); delErr == nil {
		fmt.Fprintf(os.Stderr, "webdav: cleaned up orphaned node: %s\n", h.info.Name())
	}
	cancel()
}
func (h *streamWriteHandle) Read(_ []byte) (int, error)           { return 0, os.ErrPermission }
func (h *streamWriteHandle) Seek(_ int64, _ int) (int64, error)   { return 0, os.ErrPermission }
func (h *streamWriteHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

func (fs *webdavFS) openForWriteStream(
	ctx context.Context, drID, parentPath, fileName string, size int64,
) (webdav.File, error) {
	sess, err := fs.getSession(ctx, drID)
	if err != nil {
		return nil, fmt.Errorf("dataroom session: %w", err)
	}

	nodeID, versionID, newNode, err := service.InitStreamUpload(
		ctx, fs.client, drID, parentPath, fileName, size, sess,
	)
	if err != nil {
		return nil, err
	}

	pipeR, pipeW := io.Pipe()
	done := make(chan error, 1)

	go func() {
		uploadErr := service.UploadChunks(
			ctx, pipeR, size, fileName, sess.PublicKey, nil,
			func(gctx context.Context, chunkID int, data []byte) error {
				return fs.client.UploadDataroomChunk(gctx, versionID, chunkID, data)
			},
		)
		if uploadErr != nil {
			_ = pipeR.CloseWithError(uploadErr)
		}
		done <- uploadErr
	}()

	return &streamWriteHandle{
		wfs:       fs,
		nodeID:    nodeID,
		newNode:   newNode,
		pipeW:     pipeW,
		done:      done,
		parentURI: dataroomURI(drID, parentPath),
		info:      &webdavFileInfo{name: fileName, size: size},
	}, nil
}

func (fs *webdavFS) openForWrite(ctx context.Context, drID, subPath string) (webdav.File, error) {
	parentPath, fileName := splitWebdavPath(subPath)
	if fileName == "" {
		return nil, os.ErrPermission
	}
	if size := contentLengthFromCtx(ctx); size >= 0 {
		return fs.openForWriteStream(ctx, drID, parentPath, fileName, size)
	}

	return fs.openForWriteTempFile(drID, parentPath, fileName, isPutFromCtx(ctx))
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
	_, err = service.MkdirDataroom(ctx, fs.cfg, fs.client, dataroomURI(drID, subPath), fs.passphraseReader)
	if err == nil {
		parentPath, _ := splitWebdavPath(subPath)
		fs.invalidateNodeCache(dataroomURI(drID, parentPath))
	}

	return err
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
	_, err = service.DeleteDataroomNode(ctx, fs.cfg, fs.client, dataroomURI(drID, subPath), fs.passphraseReader)
	if err == nil {
		parentPath, _ := splitWebdavPath(subPath)
		fs.invalidateNodeCache(dataroomURI(drID, parentPath))
	}

	return err
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

	err = service.MoveDataroomNode(
		ctx, fs.cfg, fs.client,
		dataroomURI(oldID, oldSub),
		dataroomURI(newID, newSub),
		fs.passphraseReader,
	)
	if err == nil {
		oldParent, _ := splitWebdavPath(oldSub)
		fs.invalidateNodeCache(dataroomURI(oldID, oldParent))
		newParent, _ := splitWebdavPath(newSub)
		fs.invalidateNodeCache(dataroomURI(newID, newParent))
	}

	return err
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
	nodes, err := fs.listNodes(ctx, drID, parentPath)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if n.Name == nodeName {
			return &webdavFileInfo{
				name:        n.Name,
				size:        n.Size,
				isDir:       n.Type == "dir",
				nodeID:      n.ID,
				versionID:   n.VersionID,
				chunkCount:  n.ChunkCount,
				contentType: n.MIMEType,
			}, nil
		}
	}

	return nil, os.ErrNotExist
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

// webdavPassphraseReader reads the key passphrase from RETYC_KEY_PASSPHRASE.
// No interactive prompt — identical to mcpPassphraseReader.
func webdavPassphraseReader() (string, error) {
	v := os.Getenv("RETYC_KEY_PASSPHRASE")
	if v == "" {
		return "", fmt.Errorf("RETYC_KEY_PASSPHRASE environment variable is required in WebDAV mode")
	}

	return v, nil
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

// isLoopbackAddr reports whether the bind address is loopback-only.
// An empty address means "all interfaces" and is therefore not loopback.
func isLoopbackAddr(addr string) bool {
	if addr == "localhost" {
		return true
	}
	ip := net.ParseIP(addr)

	return ip != nil && ip.IsLoopback()
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
			if _, err := src.Token(); err != nil {
				onFail(err)

				return
			}
		}
	}
}

var webdavCmd = &cobra.Command{
	Use:   "webdav",
	Short: "WebDAV server integration",
}

var webdavServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a local WebDAV server exposing your datarooms",
	Long: `Start a local WebDAV server on localhost that exposes all your RETYC datarooms.

Datarooms are exposed under the /dataroom folder; other element types may be
added at the root in the future.

Key passphrase: set RETYC_KEY_PASSPHRASE (env var).

Authentication: pass --auth to require HTTP Basic credentials (user "retyc").
The password is read from RETYC_WEBDAV_PASSWORD, or generated randomly and
printed at startup when the variable is unset.

Example:
  RETYC_KEY_PASSPHRASE=your-passphrase retyc webdav serve --port 8888 --auth
  # Then mount http://localhost:8888 in your WebDAV client
  # Datarooms appear under /dataroom`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Fail-fast: passphrase must be set before any crypto operation.
		if os.Getenv("RETYC_KEY_PASSPHRASE") == "" {
			return fmt.Errorf("RETYC_KEY_PASSPHRASE environment variable is required")
		}

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		tokSrc, err := mustGetToken(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		client := api.New(cfg.API.BaseURL, cliUserAgent(), tokSrc, insecure, debug)

		// Validation call — confirms auth + API reachability before binding the port.
		if _, err := service.ListDatarooms(cmd.Context(), client); err != nil {
			return fmt.Errorf("API connectivity check failed: %w", err)
		}

		addr, _ := cmd.Flags().GetString("addr")
		port, _ := cmd.Flags().GetInt("port")

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
		}

		handler := &webdav.Handler{
			FileSystem: fs,
			LockSystem: webdav.NewMemLS(),
			Logger: func(r *http.Request, err error) {
				if err != nil {
					fmt.Fprintf(os.Stderr, "webdav: %s %s: %v\n", r.Method, r.URL.Path, err)

					return
				}
				fmt.Fprintf(os.Stderr, "webdav: %s %s\n", r.Method, r.URL.Path)
			},
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "COPY" {
				http.Error(w,
					"COPY not supported: server-side copy is not available in the dataroom API",
					http.StatusNotImplemented)

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
			handler.ServeHTTP(w, r)
		})

		authEnabled, _ := cmd.Flags().GetBool("auth")
		var rootHandler http.Handler = mux
		if authEnabled {
			password := os.Getenv("RETYC_WEBDAV_PASSWORD")
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
			rootHandler = basicAuthMiddleware(mux, webdavAuthUser, password)
		} else if !isLoopbackAddr(addr) {
			fmt.Fprintf(os.Stderr,
				"WARNING: binding to %s without authentication exposes all dataroom contents "+
					"in cleartext to the network; consider --auth\n", addr)
		}

		srv := &http.Server{ //nolint:gosec // G112: local-only server; Slowloris not a concern
			Addr:              fmt.Sprintf("%s:%d", addr, port),
			Handler:           rootHandler,
			ReadHeaderTimeout: 30 * time.Second,
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// Single shutdown path shared by SIGINT/SIGTERM and auth expiry, so the
		// server always drains gracefully instead of being killed mid-request.
		var shutdownOnce sync.Once
		shutdown := func() {
			shutdownOnce.Do(func() {
				cancel()
				// Bound the drain: a stuck streaming client must not keep the CLI
				// process alive forever. After the timeout, Shutdown returns and the
				// process exits, dropping any still-open connections.
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer shutdownCancel()
				_ = srv.Shutdown(shutdownCtx)
			})
		}

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

		fmt.Fprintf(os.Stderr, "WebDAV server listening on http://%s\n", srv.Addr)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	webdavServeCmd.Flags().IntP("port", "p", 8888, "port to listen on")
	webdavServeCmd.Flags().String("addr", "127.0.0.1", "address to bind")
	webdavServeCmd.Flags().Bool("auth", false,
		"require HTTP Basic auth (password from RETYC_WEBDAV_PASSWORD or generated)")
	webdavCmd.AddCommand(webdavServeCmd)
	rootCmd.AddCommand(webdavCmd)
}
