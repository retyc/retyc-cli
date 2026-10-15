package cmd

import (
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// webdavContextKey is a private type for context keys in the WebDAV handler.
type webdavContextKey int

const (
	webdavContentLengthKey webdavContextKey = 1
	webdavIsPutKey         webdavContextKey = 2
	webdavReadHintKey      webdavContextKey = 3
	webdavListedKey        webdavContextKey = 4
)

// requestListings holds the folder listings a PROPFIND read, for the time of
// that request. x/net/webdav lists a folder and then opens each of its
// children by path for their properties: every one of those is a lookup by
// name, free from a listing in memory, one round trip each from a store over
// the network. They are answered from the listing the request just read
// instead. A name the listing does not hold, or holds as a symbolic link
// (hidden from WebDAV), is still looked up.
type requestListings struct {
	mu     sync.Mutex
	byPath map[vfs.ListingKey][]vfs.Node
}

func (l *requestListings) put(dataroomID, path string, nodes []vfs.Node) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byPath == nil {
		l.byPath = make(map[vfs.ListingKey][]vfs.Node)
	}
	l.byPath[vfs.ListingKey{DataroomID: dataroomID, Path: path}] = nodes
}

func (l *requestListings) find(dataroomID, path, name string) (vfs.Node, bool) {
	if l == nil {
		return vfs.Node{}, false
	}
	l.mu.Lock()
	nodes := l.byPath[vfs.ListingKey{DataroomID: dataroomID, Path: path}]
	l.mu.Unlock()
	n, ok := vfs.FindNode(nodes, name)
	if !ok || n.Type == vfs.TypeSymlink {
		return vfs.Node{}, false
	}

	return n, true
}

func requestListingsFromCtx(ctx context.Context) *requestListings {
	l, _ := ctx.Value(webdavListedKey).(*requestListings)

	return l
}

// readHint is what the HTTP request tells a read handle before it is read,
// which a webdav.File has no other way to learn.
type readHint struct {
	// ranged: the request carries a Range header that asks for a part of the
	// file. The handle reads at offsets from its first byte, offset 0
	// included, instead of starting the stream of the whole file.
	ranged bool
	// noBody: a HEAD. No byte will be read, whatever the handler seeks to.
	noBody bool
}

// markReadRequests records in the request context what its method and
// headers tell of the read to come (see readHint). A Range header is taken
// as it is, valid or not, honoured or not (If-Range): a handle that reads at
// offsets serves a whole file as well, only with fewer chunks in flight. The
// one exception is the range that is the whole file, "bytes=0-" (the first
// request of a browser's media element, of download managers): it is read
// like a GET without Range, through the parallel stream.
func markReadRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hint := readHint{
			ranged: isPartialRange(r.Header.Get("Range")),
			noBody: r.Method == http.MethodHead,
		}
		if hint != (readHint{}) {
			r = r.WithContext(context.WithValue(r.Context(), webdavReadHintKey, hint))
		}
		if r.Method == "PROPFIND" {
			r = r.WithContext(context.WithValue(r.Context(), webdavListedKey, &requestListings{}))
		}
		next.ServeHTTP(w, r)
	})
}

// isPartialRange reports whether a Range header asks for less than the whole
// resource, as far as the header alone tells: any header but none and
// "bytes=0-", whitespace and case aside.
func isPartialRange(header string) bool {
	spec := strings.ToLower(strings.Join(strings.Fields(header), ""))

	return spec != "" && spec != "bytes=0-"
}

func readHintFromCtx(ctx context.Context) readHint {
	hint, _ := ctx.Value(webdavReadHintKey).(readHint)

	return hint
}

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
	mode        os.FileMode // permission bits stored with the node
	modeSet     bool        // the API stores mode, an explicit 0 included (vfs.Node.HasMode)
	nodeID      string      // non-empty for file nodes
	versionID   string      // current version ID — avoids GetDataroomNode on download
	chunkCount  int         // number of AGE-encrypted chunks
	contentType string      // decrypted MIME type from node metadata
}

// fileInfoFromNode builds the WebDAV view of a listed node.
func fileInfoFromNode(n vfs.Node) *webdavFileInfo {
	return &webdavFileInfo{
		name:        n.Name,
		size:        n.Size,
		isDir:       n.Type == vfs.TypeDir,
		modTime:     n.ModTime,
		mode:        n.Mode,
		modeSet:     n.HasMode(),
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

// Mode returns the node's stored permission bits, an explicit 0 included, or
// 0644 / 0755 when the API stores none. The setuid, setgid and sticky bits are never presented: a
// remote file system has no business granting them.
func (fi *webdavFileInfo) Mode() os.FileMode {
	perm := fi.mode.Perm()
	if fi.isDir {
		if !fi.modeSet {
			perm = 0755
		}

		return os.ModeDir | perm
	}
	if !fi.modeSet {
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
	return vfs.SplitPath(p)
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

// positionedFile is what readFileHandle needs of a vfs.File.
type positionedFile interface {
	ReadAtContext(ctx context.Context, p []byte, off int64) (int, error)
	io.Closer
}

// readFileHandle is a webdav.File for reading a file. Nothing is downloaded
// before the first Read, or the first Seek to the inside of the file.
//
// It reads in one of two ways, chosen by what the request does:
//
//   - a read of the whole file from its start (a GET without Range, or with
//     the range "bytes=0-") is a stream: service.StreamDownloadChunks
//     downloads api.concurrency.download chunks at once and the handle reads
//     them in order from a pipe;
//   - a request with any other Range header (readHint.ranged), and any
//     request from the Seek that leaves the stream on (a read that is not
//     sequential), reads at the offset through a vfs.File, which downloads
//     the chunks the reads enter and no other, bar the one chunk it fetches
//     ahead of a reader it sees to be sequential.
//
// A version the vfs.File cannot read at an offset (vfs.ErrChunkLayout: chunks
// that are not uniform, or too large) is read the only way left, which works
// for any cut: the stream, read from the start and thrown away up to the
// offset wanted (sequentialOnly). That is what every Seek cost before reads
// were positioned.
//
// The fallback is right when the vfs.File finds the cut out before the handle
// has returned a byte read through it: the Read that gets ErrChunkLayout
// returns nothing of what that call copied, and reads its bytes from the
// stream. Bytes returned by an earlier Read are gone, and they were wrong if
// the chunks they came from had the lengths a uniform cut gives while lying
// elsewhere in the file: a cut that is not uniform and yet agrees in length
// with a uniform one, on the chunks read so far, cannot be detected. No
// client makes such a version.
//
// http.ServeContent learns the size with Seek(0, End) then goes back with
// Seek(0, Start): both only move pos. The stream starts on the first Read at
// offset 0, never on a Seek, since a Range request seeks again before it
// reads.
//
// Like any webdav.File, a handle serves one request, on one goroutine, and
// reads the version the listing named when it was opened, even if the file
// is replaced while the request runs.
type readFileHandle struct {
	// Parameters for lazy download — all sourced from the listing cache.
	ctx        context.Context
	wfs        *webdavFS
	drID       string
	versionID  string // avoids a GetDataroomNode round-trip on download
	chunkCount int
	parentPath string // the folder whose listing this handle was built from
	info       os.FileInfo
	hint       readHint
	// pos is the offset of the next Read.
	pos int64
	// Stream (set by startStream, unset by endStream): the file from offset
	// 0, streamPos bytes of it already taken from the pipe. streamPos is pos,
	// except under sequentialOnly between a Seek and the Read that follows.
	pipeR      *io.PipeReader
	streamPos  int64
	stopStream context.CancelFunc
	// streamDone is closed when the goroutine of the last stream started has
	// returned.
	streamDone chan struct{}
	// Positioned reads (set by openPositioned).
	file positionedFile
	// sequentialOnly is set once the version proved unreadable at an offset.
	sequentialOnly bool
}

// openPositioned switches the handle to positioned reads. The request
// context bounds the opening and each read (ReadAtContext); the downloads of
// the vfs.File stop when the handle is closed, at the end of the request.
func (h *readFileHandle) openPositioned() error {
	f, err := h.wfs.tree.Open(h.ctx, h.drID, vfs.Node{
		Type:       vfs.TypeFile,
		VersionID:  h.versionID,
		ChunkCount: h.chunkCount,
		Size:       h.info.Size(),
	})
	if err != nil {
		return err
	}
	h.file = f

	return nil
}

// startStream begins a background goroutine that downloads and decrypts all chunks,
// writing them in order to pipeW. h.pipeR is set so Read can consume from it.
func (h *readFileHandle) startStream() error {
	sess, err := h.wfs.tree.Session(h.ctx, h.drID)
	if err != nil {
		return fmt.Errorf("dataroom session: %w", err)
	}
	// A context of its own: leaving the stream stops its downloads at once,
	// where closing the pipe alone lets the chunks in flight run to their end.
	ctx, cancel := context.WithCancel(h.ctx)
	pipeR, pipeW := io.Pipe()
	done := make(chan struct{})
	h.pipeR, h.streamPos, h.stopStream, h.streamDone = pipeR, 0, cancel, done
	go func() {
		defer close(done)
		defer cancel()
		err := service.StreamDownloadChunks(
			ctx, pipeW, h.info.Size(), h.chunkCount, sess.Identity, nil,
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

// endStream leaves the stream, if any, and stops its downloads.
func (h *readFileHandle) endStream() {
	if h.pipeR == nil {
		return
	}
	h.stopStream()
	_ = h.pipeR.CloseWithError(context.Canceled)
	h.pipeR, h.stopStream = nil, nil
}

// streamTo brings the stream to pos: started when there is none, started
// again when it is past pos, read and thrown away up to pos.
func (h *readFileHandle) streamTo(pos int64) error {
	if h.pipeR != nil && h.streamPos > pos {
		h.endStream()
	}
	if h.pipeR == nil {
		if err := h.startStream(); err != nil {
			return err
		}
	}
	if h.streamPos == pos {
		return nil
	}
	n, err := io.CopyN(io.Discard, h.pipeR, pos-h.streamPos)
	h.streamPos += n

	return err
}

// leavePositioned gives up reading at offsets for the life of the handle:
// the version is not cut in a way a vfs.File can address (vfs.ErrChunkLayout).
//
// That is no download failure, and onDownloadError is not called for it: the
// version exists, so dropping the listing that named it would repair nothing
// and cost a listing and a line in the journal at every request for the file.
func (h *readFileHandle) leavePositioned() {
	h.sequentialOnly = true
	if h.file != nil {
		_ = h.file.Close()
		h.file = nil
	}
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
// web app or another client, which never goes through an invalidation here. Without
// this, every read until the listing is refreshed replays the dead version and dies
// mid-body: http.ServeContent has already committed 200 plus the stale
// Content-Length by the time the first chunk is fetched, so the client sees a
// truncated response and reports an I/O error. Dropping the entry makes the next
// request re-list and answer a clean 404.
func (h *readFileHandle) onDownloadError(err error) {
	fmt.Fprintf(os.Stderr, "webdav: download error (%s): %s\n", ui.Escape(h.info.Name()), ui.EscapeLines(err.Error()))
	if h.parentPath != "" {
		h.wfs.tree.InvalidateListing(h.drID, h.parentPath)
	}
}

func (h *readFileHandle) Close() error {
	h.endStream()
	if h.file == nil {
		return nil
	}
	err := h.file.Close()
	h.file = nil

	return err
}

func (h *readFileHandle) Read(p []byte) (int, error) {
	n, err := h.read(p)
	h.pos += int64(n)
	metrics.WebdavBytes.WithLabelValues("download").Add(float64(n))

	return n, err
}

func (h *readFileHandle) read(p []byte) (int, error) {
	if h.file == nil && h.pipeR == nil && !h.sequentialOnly {
		switch {
		case h.pos >= h.info.Size():
			return 0, io.EOF
		case h.pos == 0 && !h.hint.ranged:
			// First Read with no Seek away from the start, of a request that
			// asks for no range: stream straight from the API.
			if err := h.startStream(); err != nil {
				return 0, err
			}
		default:
			if err := h.openPositioned(); err != nil {
				return 0, err
			}
		}
	}
	if h.file == nil {
		return h.readStream(p)
	}

	n, err := h.file.ReadAtContext(h.ctx, p, h.pos)
	switch {
	case errors.Is(err, vfs.ErrChunkLayout):
		// The n bytes this call copied are dropped, not returned: they come
		// from chunks placed by a chunk size the version just disproved, so
		// they may be the bytes of another offset. The stream reads them
		// again where they are.
		h.leavePositioned()

		return h.readStream(p)
	case n > 0 && errors.Is(err, io.EOF):
		// io.ReaderAt reports the end of the file along with the last bytes;
		// io.Reader callers expect it on its own.
		return n, nil
	case err != nil && !errors.Is(err, io.EOF) && !isReadAbandonedErr(err):
		h.onDownloadError(err)
	}

	return n, err
}

// isReadAbandonedErr reports whether a positioned read failed for a reason
// that says nothing of the version: the client left, or the server is
// shutting down and closed the vfs.FS under the handle (vfs.ErrClosed).
// Neither is a download failure: nothing is logged, no listing is dropped.
func isReadAbandonedErr(err error) bool {
	return isClientGoneErr(err) || errors.Is(err, vfs.ErrClosed)
}

// readStream reads from the stream at pos. A failed download is reported by
// the goroutine of the stream (onDownloadError).
func (h *readFileHandle) readStream(p []byte) (int, error) {
	if err := h.streamTo(h.pos); err != nil {
		return 0, err
	}
	n, err := h.pipeR.Read(p)
	h.streamPos += int64(n)

	return n, err
}

func (h *readFileHandle) Write(_ []byte) (int, error) { return 0, os.ErrPermission }

func (h *readFileHandle) Seek(off int64, whence int) (int64, error) {
	pos := off
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		pos += h.pos
	case io.SeekEnd:
		pos += h.info.Size()
	default:
		return 0, os.ErrInvalid
	}
	if pos < 0 {
		return 0, os.ErrInvalid
	}
	// The start is where a stream begins and the end has nothing to read:
	// neither tells how the file will be read, so neither downloads anything.
	// This is the Seek(0, End), Seek(0, Start) of http.ServeContent.
	inside := pos > 0 && pos < h.info.Size()

	switch {
	case h.hint.noBody:
		// A HEAD seeks to the start of its range like a GET, and reads
		// nothing: no chunk is worth downloading for it.
	case h.sequentialOnly:
		if inside {
			if err := h.streamTo(pos); err != nil {
				return 0, err
			}
		}
	case h.file != nil:
	case pos == h.pos:
		// Where the stream is, or nothing started yet.
	default:
		// A Seek away from the stream ends it: what follows is read at its
		// offset.
		h.endStream()
		if inside {
			if err := h.warm(pos); err != nil {
				return 0, err
			}
		}
	}
	h.pos = pos

	return pos, nil
}

// warm opens the positioned reader and downloads the chunk holding pos, the
// one the next Read needs. If that chunk cannot be had the Seek fails:
// http.ServeContent seeks to the start of a range before it writes the
// headers, so the client gets an error status in place of a 206 cut short.
//
// The promise stops there. Only the first Seek of a handle warms, to an
// offset inside the file, and only the chunk of that offset: a later chunk of
// the range, a range that starts at offset 0 (no Seek tells it from the size
// probe), or the second range of a multi-range request fail while the body is
// being sent, as any chunk of a GET of the whole file does. On a version read
// through the stream (sequentialOnly), every chunk up to pos is downloaded.
func (h *readFileHandle) warm(pos int64) error {
	if err := h.openPositioned(); err != nil {
		return err
	}
	// One byte is enough to have the chunk fetched. The Read that follows
	// starts at pos, not after that byte: the vfs.File does not take the two
	// for a sequential reader, and fetches nothing ahead on their account.
	var b [1]byte
	_, err := h.file.ReadAtContext(h.ctx, b[:], pos)
	switch {
	case err == nil || errors.Is(err, io.EOF):
		return nil
	case errors.Is(err, vfs.ErrChunkLayout):
		h.leavePositioned()

		return h.streamTo(pos)
	case !isReadAbandonedErr(err):
		h.onDownloadError(err)
	}

	return err
}

func (h *readFileHandle) Stat() (os.FileInfo, error)           { return h.info, nil }
func (h *readFileHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

// writeFileHandle is a webdav.File for a write whose size is not known when
// it starts (a PUT sent chunked, the placeholder a LOCK creates, the target
// of a PROPPATCH). Writes accumulate in a spool of the tree (vfs.Spool, a
// local file); Close sends it with vfs.FS.Create, now that the size is known,
// then removes the spool.
//
// The spool is not flushed (vfs.Spool.Flush): a flush declares the time of
// the last write as the version's client_mtime, and a WebDAV upload declares
// none, with or without a Content-Length.
type writeFileHandle struct {
	// ctx is the OpenFile (request) context: the upload from Close runs on
	// it without its cancellation, so the API and crypto spans nest under the
	// request span instead of becoming orphan traces.
	ctx        context.Context
	spool      vfs.Spool
	drID       string
	parentPath string
	fileName   string
	wfs        *webdavFS
	isPut      bool // true = real PUT; false = LOCK-driven create
	// info is what Stat reports. The WebDAV handler Stats the file before
	// Close and reads the ETag after it: Close fills in the new version, so
	// the PUT response carries its ETag rather than the ModTime+Size default.
	info *webdavFileInfo
}

func (h *writeFileHandle) Close() error {
	defer func() { _ = h.spool.Close() }()
	size := h.spool.Size()
	// A zero-byte create that did NOT come from a PUT is a WebDAV LOCK creating a
	// lock-null resource (macOS Finder, MS Office); uploading it would create a
	// phantom empty node, so skip it. A real PUT — even an empty one sent with
	// chunked transfer (unknown Content-Length, hence this buffered path) — is an
	// intentional upload and must go through.
	if !h.isPut && size == 0 {
		return nil
	}
	// The size is known now: upload as a PUT with a Content-Length does,
	// which resolves the folder and an existing node from the cached
	// listings, cleans up a failed upload and updates the listing in place.
	node, err := h.wfs.tree.Create(context.WithoutCancel(h.ctx), h.drID, path.Join(h.parentPath, h.fileName),
		size, time.Time{}, io.NewSectionReader(h.spool, 0, size))
	if err != nil {
		return err
	}
	h.info.nodeID, h.info.versionID = node.ID, node.VersionID

	return nil
}
func (h *writeFileHandle) Read(_ []byte) (int, error) { return 0, os.ErrPermission }
func (h *writeFileHandle) Write(p []byte) (int, error) {
	n, err := h.spool.WriteAt(p, h.info.size)
	h.info.size += int64(n)
	metrics.WebdavBytes.WithLabelValues("upload").Add(float64(n))

	return n, err
}
func (h *writeFileHandle) Seek(_ int64, _ int) (int64, error)   { return 0, os.ErrPermission }
func (h *writeFileHandle) Stat() (os.FileInfo, error)           { return h.info, nil }
func (h *writeFileHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

// webdavFS implements webdav.FileSystem over RETYC datarooms.
type webdavFS struct {
	client *api.Client
	// tree is the service layer the server presents (see vfs.FS): the list of
	// datarooms, the folder listings and the dataroom sessions, cached, the
	// resolution of names and paths through them, the mutations of the tree
	// and the uploads. client is only what the streamed download of a whole
	// file still reads its chunks through (readFileHandle).
	tree *vfs.FS

	// locks is the WebDAV lock system of the handler, which COPY must honour
	// itself since it does not go through the handler (see confirmCopyLocks);
	// nil checks nothing (tests).
	locks webdav.LockSystem
}

// newWebdavFS returns a webdavFS over client. opts are the settings of the
// caches, to which the WebDAV view adds that a symbolic link does not exist
// (WebDAV has none), the pacing of a COPY onto a replaced destination, and
// stderr as where the tree reports what no request can be told.
func newWebdavFS(client *api.Client, opts vfs.Options) *webdavFS {
	opts.HideSymlinks = true
	opts.CopyReplaceRetry, opts.CopyReplaceWait = copyReplaceRetry, copyReplaceWait
	if opts.Logf == nil {
		opts.Logf = webdavLogf
	}

	return &webdavFS{client: client, tree: vfs.New(client, opts)}
}

// webdavLogf prints a message of the tree on stderr, as the server prints its
// own. The arguments come raw: names and API answers are escaped here, since a
// name is whatever a client chose and a body whatever the API sent.
func webdavLogf(format string, args ...any) {
	escaped := make([]any, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case error:
			escaped[i] = ui.EscapeLines(v.Error())
		case string:
			escaped[i] = ui.Escape(v)
		default:
			escaped[i] = arg
		}
	}
	fmt.Fprintf(os.Stderr, "webdav: "+format+"\n", escaped...)
}

// webdavErr gives an error of the tree the form x/net/webdav reads. The
// handler tells a missing resource with os.IsNotExist, which does not unwrap:
// a vfs.ErrNotExist that still carries the API's answer would be taken for
// another failure. It is flattened to the bare os.ErrNotExist.
func webdavErr(err error) error {
	if errors.Is(err, vfs.ErrNotExist) {
		return os.ErrNotExist
	}

	return err
}

var _ webdav.FileSystem = (*webdavFS)(nil)

// nodesToFileInfos converts a listing to []os.FileInfo.
func nodesToFileInfos(nodes []vfs.Node) []os.FileInfo {
	infos := make([]os.FileInfo, 0, len(nodes))
	for _, n := range nodes {
		// A decrypted name containing a slash cannot be addressed as a single
		// WebDAV path component; exposing it would create an unreachable, ambiguous
		// entry, so skip it with a warning rather than listing a broken node.
		if strings.ContainsRune(n.Name, '/') {
			fmt.Fprintf(os.Stderr, "webdav: skipping node with unsupported name %q\n", n.Name)

			continue
		}
		// WebDAV has no symbolic links: a symlink node is left out rather
		// than shown as a file no client could read or write.
		if n.Type == vfs.TypeSymlink {
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

	drID, err := fs.tree.DataroomByName(ctx, drName)
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
	datarooms, err := fs.tree.Datarooms(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]os.FileInfo, len(datarooms))
	for i, dr := range datarooms {
		entries[i] = &webdavFileInfo{name: dr.DisplayName, isDir: true}
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
		quota: quotaOnce(func() (int64, int64, bool) { return fs.tree.Quota(ctx, drID) }),
		load: func() ([]os.FileInfo, error) {
			nodes, err := fs.tree.ReadDir(ctx, drID, subPath)
			if err != nil {
				return nil, err
			}
			requestListingsFromCtx(ctx).put(drID, subPath, nodes)

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
		parentPath: parentPath,
		info:       wfi,
		hint:       readHintFromCtx(ctx),
	}, nil
}

// openSpooled opens a write of unknown size: a spool the tree creates, sent
// on Close (see writeFileHandle). Nothing is asked of the API before Close.
func (fs *webdavFS) openSpooled(
	ctx context.Context, drID, parentPath, fileName string, isPut bool,
) (webdav.File, error) {
	spool, err := fs.tree.OpenSpool(ctx, drID, path.Join(parentPath, fileName), nil, true)
	if err != nil {
		return nil, err
	}

	return &writeFileHandle{
		ctx:        ctx,
		spool:      spool,
		drID:       drID,
		parentPath: parentPath,
		fileName:   fileName,
		wfs:        fs,
		isPut:      isPut,
		info:       &webdavFileInfo{name: fileName, modTime: time.Now()},
	}, nil
}

// createHandle is a webdav.File for a PUT whose Content-Length is known: what
// the client sends is piped to vfs.FS.Create, running in a goroutine since
// OpenFile. The tree decides how the content travels: a small file is read
// in memory and sent in one request once the body is complete, a larger one
// is encrypted and uploaded chunk by chunk as it arrives. No temporary file
// either way.
type createHandle struct {
	pw *io.PipeWriter
	// done is closed when Create has returned, node and err set.
	done chan struct{}
	node vfs.Node
	err  error
	// cancel ends the context Create runs on. detach stops the end of the
	// request from doing so: see Close.
	cancel context.CancelFunc
	detach func() bool
	// size is the Content-Length, written how much of it was received. Once
	// they are equal the upload no longer ends with the request: see Write.
	size, written int64
	closed        bool
	// info.nodeID and info.versionID are set on Close: the WebDAV handler
	// Stats the file before Close but reads the ETag after it, so the PUT
	// response carries the new version's ETag.
	info *webdavFileInfo
}

// startReader tells, by closing started, when its first Read is made:
// vfs.FS.Create only reads the content once the upload is accepted.
type startReader struct {
	r       io.Reader
	once    sync.Once
	started chan struct{}
}

func (r *startReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })

	return r.r.Read(p)
}

// openCreate starts the upload of size bytes to subPath and returns once the
// tree has accepted it: the session and the folder resolved and, for a file
// streamed chunk by chunk, its node and version created. A failure before
// that is the error of OpenFile, as when those steps ran in OpenFile itself.
func (fs *webdavFS) openCreate(ctx context.Context, drID, subPath string, size int64) (webdav.File, error) {
	_, fileName := splitWebdavPath(subPath)
	pr, pw := io.Pipe()
	// The upload lives on the request context, and ends with it, until Close
	// says otherwise.
	uctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &createHandle{
		pw:     pw,
		done:   make(chan struct{}),
		cancel: cancel,
		detach: context.AfterFunc(ctx, cancel),
		size:   size,
		info:   &webdavFileInfo{name: fileName, size: size},
	}
	body := &startReader{r: pr, started: make(chan struct{})}
	go func() {
		h.node, h.err = fs.tree.Create(uctx, drID, subPath, size, time.Time{}, body)
		// A Write the upload no longer reads must not block.
		closeErr := h.err
		if closeErr == nil {
			closeErr = io.ErrClosedPipe
		}
		_ = pr.CloseWithError(closeErr)
		close(h.done)
	}()

	select {
	case <-body.started:
		return h, nil
	case <-h.done:
		h.detach()
		cancel()
		if h.err != nil {
			return nil, h.err
		}

		return h, nil
	}
}

func (h *createHandle) Write(p []byte) (int, error) {
	if h.closed {
		return 0, os.ErrClosed
	}
	n, err := h.pw.Write(p)
	metrics.WebdavBytes.WithLabelValues("upload").Add(float64(n))
	h.written += int64(n)
	h.keepComplete()

	return n, err
}

// keepComplete detaches the upload from the request once the whole body was
// received: like the upload of a spooled PUT, it is then no longer given up
// when the client leaves, be it before the single request of a small file is
// sent or while the last chunks of a larger one are. It is called from the
// Write that completes the body, not only from Close: the client can leave
// between the two. A body still short stays on the request context, so a
// client that leaves halfway cancels the upload and what it created is
// discarded.
func (h *createHandle) keepComplete() {
	if h.written == h.size && h.detach != nil {
		h.detach()
	}
}

// Close ends the content and waits for the upload: a body shorter than the
// Content-Length fails it, and nothing is kept (vfs.FS.Create).
func (h *createHandle) Close() error {
	if h.closed {
		return os.ErrClosed
	}
	h.closed = true
	// An empty body is complete without a Write.
	h.keepComplete()
	_ = h.pw.Close()
	<-h.done
	h.detach()
	h.cancel()
	if h.err != nil {
		return h.err
	}
	h.info.nodeID, h.info.versionID = h.node.ID, h.node.VersionID

	return nil
}

func (h *createHandle) Stat() (os.FileInfo, error)           { return h.info, nil }
func (h *createHandle) Read(_ []byte) (int, error)           { return 0, os.ErrPermission }
func (h *createHandle) Seek(_ int64, _ int) (int64, error)   { return 0, os.ErrPermission }
func (h *createHandle) Readdir(_ int) ([]os.FileInfo, error) { return nil, os.ErrInvalid }

func (fs *webdavFS) openForWrite(ctx context.Context, drID, subPath string) (webdav.File, error) {
	parentPath, fileName := splitWebdavPath(subPath)
	if fileName == "" {
		return nil, os.ErrPermission
	}
	if size := contentLengthFromCtx(ctx); size >= 0 {
		return fs.openCreate(ctx, drID, subPath, size)
	}

	return fs.openSpooled(ctx, drID, parentPath, fileName, isPutFromCtx(ctx))
}

// Mkdir implements webdav.FileSystem.
func (fs *webdavFS) Mkdir(ctx context.Context, name string, _ os.FileMode) error {
	kind, drName, subPath := parseWebdavPath(name)
	if kind != pathDataroomNode || subPath == "/" {
		return os.ErrPermission
	}
	drID, err := fs.tree.DataroomByName(ctx, drName)
	if err != nil {
		return err
	}
	_, err = fs.tree.Mkdir(ctx, drID, subPath)
	if errors.Is(err, vfs.ErrNotDir) {
		// The parent is a file: not a collection, 409 Conflict (RFC 4918
		// §9.3.1), which the handler answers to a parent that does not exist.
		return os.ErrNotExist
	}

	// A missing parent is a 409 too; a name already taken (vfs.ErrExist) is
	// not os.IsNotExist and answers 405.
	return webdavErr(err)
}

// RemoveAll implements webdav.FileSystem.
func (fs *webdavFS) RemoveAll(ctx context.Context, name string) error {
	kind, drName, subPath := parseWebdavPath(name)
	if kind != pathDataroomNode || subPath == "/" {
		return os.ErrPermission
	}
	drID, err := fs.tree.DataroomByName(ctx, drName)
	if err != nil {
		return err
	}

	return webdavErr(fs.tree.Remove(ctx, drID, subPath, true))
}

// Rename implements webdav.FileSystem. The handler deletes an existing
// destination itself before calling it (MOVE with Overwrite: T), so the rename
// never replaces.
func (fs *webdavFS) Rename(ctx context.Context, oldName, newName string) error {
	oldKind, oldDR, oldSub := parseWebdavPath(oldName)
	newKind, newDR, newSub := parseWebdavPath(newName)

	if oldKind != pathDataroomNode || newKind != pathDataroomNode || oldSub == "/" || newSub == "/" {
		return os.ErrPermission
	}

	oldID, err := fs.tree.DataroomByName(ctx, oldDR)
	if err != nil {
		return err
	}
	newID, err := fs.tree.DataroomByName(ctx, newDR)
	if err != nil {
		return err
	}
	if oldID != newID {
		return fmt.Errorf("moving between datarooms is not supported: %w", os.ErrPermission)
	}

	return webdavErr(fs.tree.Rename(ctx, oldID, oldSub, newSub, false))
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

	drID, err := fs.tree.DataroomByName(ctx, drName)
	if err != nil {
		return nil, err
	}

	if subPath == "/" {
		return &webdavFileInfo{name: drName, isDir: true}, nil
	}

	parentPath, nodeName := splitWebdavPath(subPath)
	if n, ok := requestListingsFromCtx(ctx).find(drID, parentPath, nodeName); ok {
		return fileInfoFromNode(n), nil
	}
	n, err := fs.tree.Lookup(ctx, drID, parentPath, nodeName)
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

var webdavCmd = &cobra.Command{
	Use:   "webdav",
	Short: "WebDAV server integration",
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
  RETYC_KEY_PASSPHRASE=your-passphrase retyc fs webdav serve --addr 127.0.0.1:8888 --auth
  # Then mount http://localhost:8888 in your WebDAV client
  # Datarooms appear under /dataroom`,
	RunE: func(cmd *cobra.Command, args []string) (retErr error) {
		// The init span covers everything before the port is bound (token,
		// API reachability, key unlock, listeners) and is the only span
		// parented to TRACEPARENT: the driver's NodeStageVolume trace must
		// close once the server is up. Requests get their own roots. It
		// starts before the passphrase check so a missing passphrase is
		// still recorded as a failed init.
		initCtx, initSpan := telemetry.Tracer().Start(cmd.Context(), "retyc fs webdav serve init")
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
		resolveCacheFlags(cmd.Flags())
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		tokSrc, err := mustGetToken(initCtx, cfg)
		if err != nil {
			return err
		}
		client := api.New(cfg.API.BaseURL, cliUserAgent(), tokSrc, insecure, debug,
			apiTransport(), apiRetry(cfg), api.WithUnsafeWrite(cfg.API.UnsafeWrite))

		// Fail-fast before binding the port: auth + API reachability, then the
		// key passphrase itself (a wrong one would otherwise only surface on the
		// first dataroom access). The unlocked identity is kept for the whole run.
		identity, err := serveStartupCheck(initCtx, client, servePassphraseReader)
		if err != nil {
			return err
		}

		store, err := newMetaStore(initCtx, cfg, cfg.Cache.MaxStale)
		if err != nil {
			return err
		}
		fs := newWebdavFS(client, vfs.Options{
			TTL:               cfg.Cache.TTL,
			MaxStale:          cfg.Cache.MaxStale,
			NegativeTTL:       cfg.Cache.NegativeTTL,
			Store:             store,
			KeepSealed:        store != nil && cfg.Cache.Redis.HighConfidentiality,
			Identity:          identity,
			ListConcurrency:   service.Concurrency().List,
			UploadConcurrency: service.Concurrency().Upload,
		})
		// Runs once the server has stopped accepting requests, on every way
		// out of this function.
		defer func() { _ = fs.tree.Close() }()

		lockSystem := webdav.NewMemLS()
		fs.locks = lockSystem
		// A request the API rate limit defeated is answered 429 instead of
		// the status x/net/webdav picks (see rateLimitStatus).
		handler := newWebdavHandler(fs, lockSystem, func(r *http.Request, err error) {
			// URL.Path is percent-decoded: "%1b" arrives as a raw ESC.
			if err != nil {
				fmt.Fprintf(os.Stderr, "webdav: %s %s: %s\n",
					r.Method, ui.Escape(r.URL.Path), ui.EscapeLines(err.Error()))

				return
			}
			fmt.Fprintf(os.Stderr, "webdav: %s %s\n", r.Method, ui.Escape(r.URL.Path))
		})

		// WebDAV locks on files are mirrored onto the API's node locks, so other
		// RETYC clients see them and theirs are honoured here (see lockMirror).
		mirror := newLockMirror(fs, lockSystem)
		davHandler := markReadRequests(mirror.middleware(handler))

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
		health := newServeHealth()
		metricsSrv, err := startObservability(resolveWebdavMetrics(cmd.Flags()), health, fs.tree)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// Single shutdown path shared by SIGINT/SIGTERM and auth expiry, so the
		// server always drains gracefully instead of being killed mid-request.
		shutdown := newWebdavShutdown(srv, metricsSrv, health, cancel, webdavDrainTimeout)

		// Renew the mirrored server locks while the WebDAV locks stand, and
		// release them on shutdown. locksDone closes once they are released:
		// the command does not return before (see serveUntilDrained).
		locksDone := make(chan struct{})
		go func() {
			defer close(locksDone)
			mirror.run(ctx)
		}()

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
			<-locksDone

			return fmt.Errorf("WebDAV server: %w", err)
		}
		fmt.Fprintf(os.Stderr, "WebDAV server listening on http://%s\n", ln.Addr())
		health.setReady(true)
		initSpan.End()
		initDone = true

		if err := serveUntilDrained(srv, ln, shutdown, locksDone); err != nil {
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

// webdavDrainTimeout bounds the drain of the in-flight requests on shutdown: a
// stuck streaming client must not keep the process alive forever. Past it,
// Shutdown returns and the process exits, dropping the connections still open.
const webdavDrainTimeout = 15 * time.Second

// newWebdavShutdown returns the single shutdown path of webdav serve, shared
// by SIGINT/SIGTERM, auth expiry and a server that stopped on its own. It
// runs once; every call returns when that run is over, the first as the
// others, so a caller that needs the drain finished only has to call it.
func newWebdavShutdown(
	srv, metricsSrv *http.Server, health *serveHealth, cancel context.CancelFunc, drain time.Duration,
) func() {
	var once sync.Once

	return func() {
		once.Do(func() {
			// Flip readiness first so an orchestrator stops routing to this
			// instance while the in-flight requests drain.
			health.setReady(false)
			cancel()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), drain)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
			if metricsSrv != nil {
				_ = metricsSrv.Shutdown(shutdownCtx)
			}
		})
	}
}

// serveUntilDrained serves ln and returns once the server is done for good:
// the requests in flight have finished (or the drain timed out), and
// everything in background has closed.
//
// http.Server.Serve returns as soon as Shutdown closes the listener, while
// Shutdown is still waiting for the requests in flight. Returning then let
// the process exit under them, and under the release of the API locks, which
// then stood for their whole lease. shutdown is called here for the case of a
// server that stopped on its own, and to wait for the one already running.
// A server closed by shutdown is no error.
func serveUntilDrained(srv *http.Server, ln net.Listener, shutdown func(), background ...<-chan struct{}) error {
	err := srv.Serve(ln)
	shutdown()
	for _, done := range background {
		<-done
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

// Compile-time interface checks.
var _ webdav.File = (*dirHandle)(nil)
var _ webdav.File = (*readFileHandle)(nil)
var _ webdav.File = (*writeFileHandle)(nil)
var _ webdav.File = (*createHandle)(nil)

func init() {
	webdavServeCmd.Flags().String("addr", "127.0.0.1:8888", "host:port to bind")
	webdavServeCmd.Flags().Bool("unsafe-write", false,
		"let the API acknowledge uploads before they are stored (faster; a failed background store is not reported)")
	addCacheFlags(webdavServeCmd, true)
	webdavServeCmd.Flags().Bool("auth", false,
		"require HTTP Basic auth (password from RETYC_WEBDAV_PASSWORD or generated)")
	webdavServeCmd.Flags().String("metrics-addr", "",
		"address for Prometheus metrics and health probes (e.g. 127.0.0.1:9090)")
	webdavServeCmd.Flags().Bool("metrics-runtime", true,
		"include Go runtime and process metrics on /metrics")
	webdavServeCmd.Flags().StringArray("metrics-label", nil,
		"constant label key=value added to every metric (repeatable)")
	webdavCmd.AddCommand(webdavServeCmd)
	fsCmd.AddCommand(webdavCmd)
}
