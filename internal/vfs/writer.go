package vfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
)

// The methods of this file write the content of files: Create for a caller
// that knows the size before the first byte, OpenSpool for one that does not
// (a file written at any offset, whose size is only known when it is closed).
// Both end in upload, which resolves the folder through the cache, sends the
// content by the route its size calls for, cleans up after a failure and
// records the new version in the cached listing.

// Errors of the uploads, besides those of errors.go.
var (
	// ErrSpoolFull: the file system holding the spool has no room left for a
	// write, a truncation or the copy of the version being modified.
	ErrSpoolFull = errors.New("vfs: no space left for the spool")
	// ErrNameBeingDeleted: the API still holds the name for a node being
	// deleted (410 on creation). It is service.ErrNameBeingDeleted, so an
	// error of the service layer carries it as it is.
	ErrNameBeingDeleted = service.ErrNameBeingDeleted
	// ErrSpoolNotEmpty: Spool.CopyFrom was asked of a spool that is not a
	// file still to be created, with no content.
	ErrSpoolNotEmpty = errors.New("vfs: the spool already holds a file or some content")
)

// content is what an upload sends.
type content struct {
	size int64
	// mtime is declared as the client_mtime of the version; nil declares
	// none, and the version is then dated by the API.
	mtime *time.Time
	// r yields exactly size bytes.
	r io.Reader
	// nodeID is the node the caller knows to hold the path, "" when it knows
	// none: a version larger than one request is then added to it directly.
	nodeID string
	// mode is declared as the access mode of the node when the upload creates
	// it, in the request that does; nil declares none, 0 is "0000".
	mode *os.FileMode
}

// Create writes size bytes read from r as the content of the file at path and
// returns its node. A file that exists gets them as a new version; one that
// does not is created. Nothing is written to disk: the content goes from r to
// the API.
//
// A file of at most service.SmallUploadMaxSize bytes is read in memory and
// sent in one request, node, version and content together, which the server
// discards as a whole when it fails. A larger one is streamed chunk by chunk
// into a version created first; when that fails, what was created is removed
// (service.DiscardFailedUpload: the node when this call created it, otherwise
// only the new version), best effort, the outcome reported through
// Options.Logf.
//
// A zero mtime declares no modification time: the version is dated by the
// API. Otherwise mtime becomes its client_mtime.
//
// r must yield exactly size bytes: more, or fewer, fails the upload. It is
// first read once the destination is resolved (session, folder and, for a
// streamed file, node and version): a call that fails before that never
// touches r. A front end that feeds r as its client sends can tell from it
// that the upload was accepted.
//
// On success the cached listing of the folder is edited in place. The errors
// carry the sentinels of the package, added to the error they were made from:
// ErrNotExist for a folder that is missing, or was deleted elsewhere since it
// was listed (the listings that named it are then dropped); ErrNotDir when
// the parent is a file; ErrIsDir for the dataroom root; ErrForbidden (403: a
// viewer, a dataroom over its plan); ErrStorageExceeded when the API refuses
// the size, at the creation of the version or at any chunk;
// ErrNameBeingDeleted (410 on creation); ErrUnauthenticated. A request the
// rate limit defeated is returned as it is (api.ErrRateLimited).
func (fs *FS) Create(
	ctx context.Context, dataroomID, path string, size int64, mtime time.Time, r io.Reader,
) (Node, error) {
	c := content{size: size, r: r}
	if !mtime.IsZero() {
		c.mtime = &mtime
	}

	node, _, err := fs.upload(ctx, dataroomID, path, c)

	return node, err
}

// upload sends c as the content of the file at path (see Create). created
// tells that the upload made the node, rather than adding a version to one
// that held the name.
func (fs *FS) upload(ctx context.Context, dataroomID, path string, c content) (node Node, created bool, err error) {
	defer func() {
		result := "ok"
		if err != nil {
			result = "error"
		}
		metrics.Uploads.WithLabelValues(result).Inc()
	}()
	parentPath, name := SplitPath(path)
	if name == "" {
		return Node{}, false, as(ErrIsDir, errors.New("the dataroom root is not a file"))
	}
	if c.size < 0 {
		return Node{}, false, fmt.Errorf("negative size %d: %w", c.size, os.ErrInvalid)
	}
	sess, err := fs.Session(ctx, dataroomID)
	if err != nil {
		return Node{}, false, fmt.Errorf("dataroom session: %w", err)
	}
	parentID, err := fs.folderID(ctx, dataroomID, parentPath)
	if err != nil {
		return Node{}, false, fmt.Errorf("resolving parent path: %w", err)
	}
	// One slot per upload, for as long as it sends (see
	// Options.UploadConcurrency); the content is not read before.
	select {
	case fs.uploadSlots <- struct{}{}:
		defer func() { <-fs.uploadSlots }()
	case <-ctx.Done():
		return Node{}, false, ctx.Err()
	}

	if c.size <= service.SmallUploadMaxSize {
		return fs.uploadSmall(ctx, dataroomID, parentPath, name, parentID, c, sess)
	}

	return fs.uploadChunked(ctx, dataroomID, parentPath, name, parentID, c, sess)
}

// uploadSmall reads the whole content in memory and sends it in one request
// (service.UploadSmallFile). Nothing is sent when the source does not hold
// exactly the size announced.
func (fs *FS) uploadSmall(
	ctx context.Context, dataroomID, parentPath, name string, parentID *string,
	c content, sess *service.DataroomSession,
) (Node, bool, error) {
	data := make([]byte, c.size)
	n, err := io.ReadFull(c.r, data)
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return Node{}, false, fmt.Errorf("incomplete upload: wrote %d of %d bytes", n, c.size)
	case err != nil:
		return Node{}, false, fmt.Errorf("reading the content: %w", err)
	}
	// The source must end here. This read is also the first one of an empty
	// file (see Create).
	var extra [1]byte
	switch m, err := io.ReadFull(c.r, extra[:]); {
	case m > 0:
		return Node{}, false, fmt.Errorf("source is larger than its declared %d bytes", c.size)
	case !errors.Is(err, io.EOF):
		return Node{}, false, fmt.Errorf("reading the content: %w", err)
	}

	info, created, err := service.UploadSmallFileWithAttrs(
		ctx, fs.client, dataroomID, parentID, name, data, c.mtime, c.mode, sess)
	if err != nil {
		return Node{}, false, fs.uploadFailed(dataroomID, parentPath, name, err)
	}

	return fs.upsert(dataroomID, parentPath, fs.nodeFromInfo(info)), created, nil
}

// uploadChunked creates the version and streams the content into it chunk by
// chunk (service.UploadChunks), then records the node in the cached listing.
//
// Every field a listing would report for the node is known once the chunks
// are in, so the listing is edited rather than dropped. The node's mode is
// answered by its creation alone: for a version added to a node that existed
// it is left zero, and the entry keeps the one its listing gave it (see
// keepKnown), as it keeps its creation time when the version was added to a
// node known by its ID alone.
//
// Chunks that fail on a node that existed leave the cache unable to vouch for
// it: the entry it holds was not checked by a node creation, and the failure
// (a 404 among others) may be the node deleted or replaced elsewhere. Unless
// the caller's context ended, which says nothing of the node, the listing of
// the parent and its entries are dropped, and the next request resolves the
// name again.
func (fs *FS) uploadChunked(
	ctx context.Context, dataroomID, parentPath, name string, parentID *string,
	c content, sess *service.DataroomSession,
) (Node, bool, error) {
	init, err := fs.initUpload(ctx, dataroomID, parentPath, name, parentID, c, sess)
	if err != nil {
		return Node{}, false, fs.uploadFailed(dataroomID, parentPath, name, err)
	}

	err = service.UploadChunks(ctx, c.r, c.size, name, sess.PublicKey, nil,
		func(gctx context.Context, chunkID int, data []byte) error {
			return fs.client.UploadDataroomChunk(gctx, init.VersionID, chunkID, data)
		})
	if err != nil {
		fs.discardUpload(dataroomID, init)
		if !init.NewNode && ctx.Err() == nil {
			fs.InvalidateListing(dataroomID, parentPath)
		}

		return Node{}, false, uploadError(err)
	}

	node := Node{
		ID:        init.NodeID,
		ParentID:  idOrRoot(parentID),
		CreatedAt: init.NodeCreatedAt,
		Name:      name,
		Type:      TypeFile,
		Mode:      init.NodeMode,
		ModeSet:   init.NodeModeSet,
		MIMEType:  init.MIMEType,
		Size:      c.size,
		VersionID: init.VersionID,
		// A successful UploadChunks sent exactly the count announced when the
		// version was created.
		ChunkCount: service.ChunkCount(c.size),
		// What a later listing will report, not the local clock when the last
		// chunk went: an upload closing minutes after its version was created
		// would otherwise cache a time that jumps backwards at the next
		// listing.
		ModTime: init.ModTime,
	}

	return fs.upsert(dataroomID, parentPath, node), init.NewNode, nil
}

// initUpload creates the version a file is streamed into.
//
// When the node is known (c.nodeID, or a file of that name in the parent's
// cached listing), the upload is an overwrite and its version can be created
// directly. That skips the CreateDataroomNode call which would answer 409,
// and the lookup InitStreamUploadInto then runs to locate the node again: two
// round trips out of four on every overwrite.
//
// The listing may be up to the cache TTL old, so the node can have been
// deleted elsewhere in the meantime. The API answers 404 for exactly that
// case, or 410 while the node's purge is pending (both match api.ErrNotFound):
// the stale listing is dropped and the upload redone through the full path,
// which recreates the node. Any other error is the caller's to handle, and
// retrying it through a second path would only double the failure cost.
func (fs *FS) initUpload(
	ctx context.Context, dataroomID, parentPath, name string, parentID *string,
	c content, sess *service.DataroomSession,
) (service.StreamUploadInit, error) {
	nodeID, known := c.nodeID, c.nodeID != ""
	if !known {
		nodeID, known = fs.cachedFileID(dataroomID, parentPath, name)
	}
	if known {
		init, err := service.AddVersionToNodeInWithMtime(ctx, fs.client, dataroomID, nodeID, name, c.size, c.mtime, sess)
		if err == nil {
			return init, nil
		}
		if !errors.Is(err, api.ErrNotFound) {
			return service.StreamUploadInit{}, err
		}
		fs.InvalidateListing(dataroomID, parentPath)
	}

	return service.InitStreamUploadIntoWithAttrs(ctx, fs.client, dataroomID, parentID, name, c.size, c.mtime, c.mode, sess)
}

// uploadFailed takes the error of a request that creates a node or a version,
// puts the cache right for what it shows, and returns it with its sentinel.
//
//   - 404, or 410 on the creation of a version (both match api.ErrNotFound):
//     the cached listing named a parent deleted elsewhere since. The listings
//     that named it are dropped, and the error is ErrNotExist.
//   - a refusal for lack of storage: when the node had no version yet, the API
//     deletes it along with the refusal, so an entry of the listing that names
//     a node without a version is forgotten.
func (fs *FS) uploadFailed(dataroomID, parentPath, name string, err error) error {
	switch {
	case errors.Is(err, api.ErrNotFound):
		grandParent, _ := SplitPath(parentPath)
		fs.InvalidateListing(dataroomID, grandParent)
		fs.invalidateSubtree(dataroomID, parentPath)

		return as(ErrNotExist, err)
	case isStorageExceeded(err):
		fs.forgetVersionless(dataroomID, parentPath, name)
	}

	return uploadError(err)
}

// uploadError gives the error of an upload its sentinel: ErrStorageExceeded
// for a refusal for lack of storage, otherwise what classify gives it.
// ErrNameBeingDeleted is carried by the error of the service layer already.
func uploadError(err error) error {
	if isStorageExceeded(err) {
		return as(ErrStorageExceeded, err)
	}

	return classify(err)
}

// forgetVersionless drops the child name from the cached listing of the
// folder at parentPath when it is listed without a version.
func (fs *FS) forgetVersionless(dataroomID, parentPath, name string) {
	key := listingKey(dataroomID, parentPath)
	fs.mu.Lock()
	defer fs.unlock()
	n, _, ok := fs.heldNodeLocked(sealedStoreCtx, key, name)
	if ok && n != nil && n.Type == TypeFile && n.VersionID == "" {
		fs.forgetLocked(key, name)
	}
}

// discardUpload removes what a failed streamed upload left behind: the node
// it created, or only its new version on a node that already existed, whose
// earlier versions must survive (see service.DiscardFailedUpload). The
// outcome goes to Options.Logf: the caller gets the error of the upload.
//
// The file is told by its identifiers, never by its name: what goes to
// Options.Logf ends on the error output of a server, which must not hold the
// names the dataroom encrypts.
func (fs *FS) discardUpload(dataroomID string, init service.StreamUploadInit) {
	err := service.DiscardFailedUpload(fs.client, init.NodeID, init.VersionID, init.NewNode)
	switch {
	case err == nil && init.NewNode:
		fs.logf("cleaned up orphaned node: dataroom %s, node %s", dataroomID, init.NodeID)
	case err == nil:
		fs.logf("discarded the failed version: dataroom %s, node %s, version %s",
			dataroomID, init.NodeID, init.VersionID)
	default:
		fs.logf("a failed upload could not be cleaned up: dataroom %s, node %s, version %s: %s",
			dataroomID, init.NodeID, init.VersionID, err)
	}
}

// undoUpload removes what an upload that succeeded sent for a file unlinked
// meanwhile (see Spool.Unlinked): the node when the upload created it, its
// version when it landed on a node other than prior, the one the front end
// removed itself. Best effort, a failure reported through Options.Logf, by
// identifiers like discardUpload. The listing of the parent, which the upload
// edited, is dropped either way.
func (fs *FS) undoUpload(dataroomID, path string, node Node, created bool, prior string) {
	parentPath, _ := SplitPath(path)
	if created || node.ID != prior {
		if err := service.DiscardFailedUpload(fs.client, node.ID, node.VersionID, created); err != nil {
			fs.logf("a file unlinked while it was sent could not be removed: dataroom %s, node %s, version %s: %s",
				dataroomID, node.ID, node.VersionID, err)
		}
	}
	fs.InvalidateListing(dataroomID, parentPath)
}

// — Spool —————————————————————————————————————————————————————————————————————

// Spool is a file open for writing at any offset, kept in a local file until
// it is flushed. The API wants the size of a version before its first byte
// and never changes a version: a file whose size is only known when it is
// closed (every write of a mounted file system) is therefore written locally,
// and Flush sends it whole as a new version.
//
// A Spool is one of three things, which Node and Dirty tell apart:
//
//   - pending: opened on a path that names no file yet. Nothing exists at the
//     API until the first Flush that succeeds; until then the front end
//     answers for the file from the spool (Size, ModTime). It is dirty from
//     the start: flushing it without a write creates an empty file. Closed
//     without a successful Flush, it leaves nothing at the API. That holds
//     strictly for a content sent in one request (at most
//     service.SmallUploadMaxSize bytes), which the server stores or drops as
//     a whole. A larger one has its node and version created before its
//     chunks: a Flush that fails then deletes them, best effort, so a node
//     without a complete version can outlive a failed Flush whose cleanup
//     failed too;
//   - clean: its content is the one of the version Node reports. Flush sends
//     nothing;
//   - dirty: written, truncated or opened with truncate since. Flush sends
//     its content as a new version of the file.
//
// It is safe for concurrent use. Reads run together; a write, a truncation
// and the copy of the current version into the spool exclude each other and
// the reads. A Flush sends a content no write changes under it: a write
// issued meanwhile waits for it to end, and so does a read issued behind that
// write.
//
// Unlinked makes it a fourth thing, for good: a local file and nothing else,
// that no method sends to the API any more.
type Spool interface {
	// ReadAt reads the content as it will be flushed. Like WriteAt, it first
	// brings in the version being modified when the spool was opened on one
	// (see FS.OpenSpool).
	io.ReaderAt
	// WriteAt writes at any offset, a hole reading as zeros. A write the
	// file system of the spool has no room for is ErrSpoolFull; the bytes it
	// could store are counted and the spool is dirty. What it did not store
	// keeps the content it had, the one of the version being modified
	// included.
	io.WriterAt
	// Truncate sets the size: a shorter content is cut, a longer one grows
	// with zeros. It never downloads anything: of a version not brought in
	// yet, only what the new size keeps will be (and the chunk after it, when
	// the File reading it fetches ahead).
	Truncate(size int64) error
	// Size returns the current size of the content.
	Size() int64
	// ModTime returns the modification time of the content: the one given to
	// SetModTime, otherwise the time of the last write or truncation, or of
	// the opening that created or truncated the file, and for a clean spool
	// the one of its version. It is what Flush declares as client_mtime.
	ModTime() time.Time
	// SetModTime sets the modification time. On a dirty spool it is kept for
	// the next Flush and costs nothing; on a clean one it is declared at once
	// for the current version, as FS.SetModTime does, without a new version.
	// A later write dates the content again.
	SetModTime(ctx context.Context, t time.Time) error
	// Node returns the file as the API holds it: the node the spool was
	// opened on, then the one of the last Flush that succeeded. exists is
	// false for a pending spool, which has no node yet.
	Node() (node Node, exists bool)
	// Dirty reports whether Flush has something to send.
	Dirty() bool
	// SetPath tells the spool its file was renamed or moved to path, so that
	// the next Flush sends it there. It moves nothing itself.
	SetPath(path string)
	// Rename renames the file with the spool looking on: it waits for the
	// Flush in flight, calls rename, and when rename succeeds records newPath
	// as SetPath does, all of it with Flush, CopyFrom and SetModTime excluded.
	// exists tells rename whether the API holds the file at that instant: it
	// is then the one that asks the API to move it (FS.Rename); a file the API
	// holds nothing of is renamed by the change of path alone, and rename only
	// has to say whether the name may be taken.
	//
	// Without it a rename that crosses the first Flush of a pending spool is
	// lost: the Flush read the path when it started, the file is born under
	// its old name, and nothing was asked of the API since it held nothing
	// when the rename looked. SetPath remains for a path that changed without
	// the file being renamed (a folder above it moved).
	//
	// The error of rename is returned as it is and the path is kept.
	// ErrNotExist for an unlinked spool, ErrClosed for a closed one, the error
	// of ctx when it ends while a Flush is waited for: rename is not called.
	Rename(ctx context.Context, newPath string, rename func(exists bool) error) error
	// SetMode sets the access mode a pending spool gives its file: the Flush
	// that creates the node declares it in the request that does, at no
	// request of its own. A spool never given one declares none; 0 is
	// "0000". It does nothing for a file the
	// API already holds, whose mode is changed by FS.Chmod; the node a Flush
	// returns tells which mode the file has.
	SetMode(mode os.FileMode)
	// CopyFrom makes a pending spool with no content the server-side copy of
	// the file at srcPath, in the same dataroom (FS.Copy, which never
	// replaces: the path of the spool must be free): the storage duplicates
	// the chunks, nothing is downloaded and nothing is sent. The spool is
	// then clean on the node of the copy, which it returns, as if it had been
	// opened on it: its content comes in at the first ReadAt or WriteAt, and
	// a write makes the next Flush send a new version of the copy. The copy
	// keeps the mode and the modification time of its source.
	//
	// It excludes Flush, the writes and the truncations while it runs, so the
	// spool is either copied whole or left as it was. ErrSpoolNotEmpty when
	// the spool is not pending (a node, an unlink) or holds content: nothing
	// is asked of the API. Otherwise its errors are those of FS.Copy, and
	// ErrClosed. Unlinked and Close cancel it like a Flush; a copy that
	// completed for a file unlinked meanwhile is deleted, best effort, and
	// CopyFrom returns a zero Node and no error.
	CopyFrom(ctx context.Context, srcPath string) (Node, error)
	// Flush sends the content as a new version when the spool is dirty and
	// returns the node of the file; a clean spool returns its node and sends
	// nothing. Concurrent calls send one version: the second finds the spool
	// clean. A write after a Flush makes the spool dirty again, and the next
	// Flush sends another version.
	//
	// When it fails, what was created is removed as Create does, the spool
	// stays dirty with its content untouched, and Flush can be called again.
	// That includes a ctx that ends meanwhile. Its errors are those of
	// Create, plus ErrClosed, and ErrSpoolFull when the version being
	// modified still had to be brought in.
	Flush(ctx context.Context) (Node, error)
	// Unlinked tells the spool its file was removed (the unlink of an open
	// file): the front end calls it once it has removed the node, or at once
	// for a pending spool, which has none. From then on the spool is a local
	// file only. Node answers exists false and Dirty false; Flush sends
	// nothing and returns a zero Node and no error; SetModTime dates the
	// local content at no request; ReadAt, WriteAt and Truncate go on until
	// Close. It cannot be undone, and does nothing on a closed spool.
	//
	// It cancels a Flush in flight and returns once that Flush is over, so no
	// request that writes is made after it returns. That Flush answers a
	// zero Node and no error too: when it was cancelled in time, what it had
	// created was removed as after any failed Flush; when it completed
	// first, the node it created, or the version it added to a node other
	// than the one unlinked, is deleted, best effort (Options.Logf tells a
	// failure), and the cached listing of the folder is dropped. A single
	// request cancelled once the server had it may still have been stored:
	// as for any cancelled Flush, that cannot be told.
	//
	// The only requests left are reads: a version not brought into the spool
	// yet still comes in at the first ReadAt or WriteAt, for as long as the
	// API serves the chunks of a deleted file. Unlinked downloads nothing.
	Unlinked()
	// Close stops a Flush in flight, which fails, and removes the spool file.
	// Whatever was not flushed is lost. Every other method then answers
	// ErrClosed; a second Close does nothing.
	io.Closer
}

// spoolFile is the local file of a spool. Close removes it.
type spoolFile interface {
	io.ReaderAt
	io.WriterAt
	Truncate(size int64) error
	io.Closer
}

// osSpoolFile is a spoolFile on disk.
type osSpoolFile struct{ *os.File }

// Close closes the file and removes it.
func (f osSpoolFile) Close() error {
	err := f.File.Close()
	if rmErr := os.Remove(f.Name()); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		err = errors.Join(err, rmErr)
	}

	return err
}

// createSpoolFile creates the file of a spool in dir, the default directory
// for temporary files when dir is empty. os.CreateTemp gives it mode 0600 and
// a name that says nothing of the file it stands for.
func createSpoolFile(dir string) (spoolFile, error) {
	f, err := os.CreateTemp(dir, "retyc-spool-*")
	if err != nil {
		return nil, err
	}

	return osSpoolFile{f}, nil
}

// spoolError gives an error of the spool file its sentinel: ErrSpoolFull when
// the file system has no room left, or the user no quota.
func spoolError(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return as(ErrSpoolFull, err)
	}

	return err
}

// hydrateBufferSize is how much of a version is copied into the spool per
// read: large enough for the File to see a sequential reader and fetch ahead.
const hydrateBufferSize = 1 << 20

// spool is the Spool of OpenSpool.
//
// Three locks, always taken in this order. flushing serialises Flush,
// CopyFrom, Rename and SetModTime and is the only one waited for with a context. content guards
// the bytes of the file: shared by reads and by the upload of a Flush,
// exclusive for writes, truncations, hydration and Close. mu guards the
// fields below it and is never held across I/O.
type spool struct {
	fs         *FS
	dataroomID string

	flushing chan struct{}

	content sync.RWMutex
	file    spoolFile

	mu     sync.Mutex
	path   string
	size   int64
	mtime  time.Time
	dirty  bool
	closed bool
	// mode is what the creation of the node declares (see Spool.SetMode),
	// nil for none.
	mode *os.FileMode
	// node is the file at the API, exists false while there is none.
	node   Node
	exists bool
	// unlinked: the file was removed (see Spool.Unlinked). Nothing is sent
	// any more.
	unlinked bool
	// src is the version the spool was opened on while its content is not in
	// the spool file yet, nil otherwise. The content still takes the bytes
	// [srcFrom, srcSize) of it: a truncation lowers srcSize, and a write from
	// offset 0 that the spool file cut short raises srcFrom to what it
	// stored. Until src is brought in, the spool file holds nothing in that
	// range, and src is dropped as soon as the range is empty.
	src     File
	srcFrom int64
	srcSize int64
	// cancelFlush stops the upload of the Flush in flight.
	cancelFlush context.CancelFunc
	// accounted is what the spool counts for in metrics.SpoolBytes.
	accounted int64
}

// accountLocked brings the gauge of the bytes held in spool files up to date
// with this spool: its size once its content is in the spool file, what was
// written of it while the version it was opened on is not brought in yet
// (nothing, short of a write the spool file cut short), nothing once closed.
// It is called wherever size, src or closed change. The caller holds mu.
func (s *spool) accountLocked() {
	held := s.size
	switch {
	case s.closed:
		held = 0
	case s.src != nil:
		held = min(s.srcFrom, s.size)
	}
	metrics.SpoolBytes.Add(float64(held - s.accounted))
	s.accounted = held
}

// OpenSpool opens the file at path for writing at any offset.
//
// existing is the node at path, nil when there is none: the spool is then
// pending (see Spool) and the file is created by its first Flush. With
// truncate, an existing file starts empty and dirty, as open(O_TRUNC) leaves
// it. Otherwise the spool starts clean with the content of existing's
// version, brought in lazily: nothing is downloaded before the first ReadAt
// or WriteAt, and nothing at all when a Truncate(0) comes first. It is then
// copied whole into the spool file, through FS.Open (any chunk size), except
// by a write that starts at 0 and covers all of it, which needs none of it.
// A Truncate before that copy only bounds it.
//
// The spool file is created here, with mode 0600, in Options.SpoolDir: one
// per spool, removed by Close. No request is made to the API; ctx bounds the
// resolution of the dataroom session when an existing version is opened.
//
// ErrIsDir when existing is a folder or path the dataroom root, ErrNotFile
// for any other node that is not a file, ErrSpoolFull when the spool file
// cannot be created for lack of room.
func (fs *FS) OpenSpool(ctx context.Context, dataroomID, path string, existing *Node, truncate bool) (Spool, error) {
	if _, name := SplitPath(path); name == "" {
		return nil, as(ErrIsDir, errors.New("the dataroom root is not a file"))
	}
	s := &spool{fs: fs, dataroomID: dataroomID, flushing: make(chan struct{}, 1), path: cleanPath(path)}
	switch {
	case existing == nil:
		s.dirty, s.mtime = true, time.Now()
	case existing.Type == TypeDir:
		return nil, ErrIsDir
	case existing.Type != TypeFile:
		return nil, ErrNotFile
	case truncate:
		s.node, s.exists = *existing, true
		s.dirty, s.mtime = true, time.Now()
	default:
		s.node, s.exists = *existing, true
		s.size, s.mtime = existing.Size, existing.ModTime
		if existing.Size > 0 {
			src, err := fs.Open(ctx, dataroomID, *existing)
			if err != nil {
				return nil, err
			}
			s.src, s.srcSize = src, existing.Size
		}
	}

	create := fs.newSpoolFile
	if create == nil {
		create = createSpoolFile
	}
	file, err := create(fs.opts.SpoolDir)
	if err != nil {
		if s.src != nil {
			_ = s.src.Close()
		}

		return nil, spoolError(fmt.Errorf("creating the spool file: %w", err))
	}
	s.file = file

	return s, nil
}

func (s *spool) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.size
}

func (s *spool) ModTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.mtime
}

func (s *spool) Node() (Node, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.node, s.exists
}

func (s *spool) Dirty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dirty && !s.unlinked
}

func (s *spool) Unlinked() {
	s.mu.Lock()
	if s.closed || s.unlinked {
		s.mu.Unlock()

		return
	}
	s.unlinked = true
	s.node, s.exists = Node{}, false
	cancel := s.cancelFlush
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	// A Flush or a SetModTime in flight ends first: a Flush undoes what it
	// sent before it releases, and those that follow find the spool unlinked.
	s.flushing <- struct{}{}
	s.release()
}

func (s *spool) SetPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = cleanPath(path)
}

func (s *spool) Rename(ctx context.Context, newPath string, rename func(exists bool) error) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()

	// flushing is held: exists cannot change before rename returns, short of
	// an unlink, which waits for it too.
	s.mu.Lock()
	closed, unlinked, exists := s.closed, s.unlinked, s.exists
	s.mu.Unlock()
	switch {
	case closed:
		return ErrClosed
	case unlinked:
		return ErrNotExist
	}
	if err := rename(exists); err != nil {
		return err
	}
	s.SetPath(newPath)

	return nil
}

func (s *spool) SetMode(mode os.FileMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	perm := mode.Perm()
	s.mode = &perm
}

func (s *spool) CopyFrom(ctx context.Context, srcPath string) (Node, error) {
	if err := s.acquire(ctx); err != nil {
		return Node{}, err
	}
	defer s.release()
	// No write lands between the check below and the adoption of the copy.
	s.content.Lock()
	defer s.content.Unlock()

	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()

		return Node{}, ErrClosed
	case s.unlinked || s.exists || s.size != 0 || s.src != nil:
		s.mu.Unlock()

		return Node{}, ErrSpoolNotEmpty
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.cancelFlush = cancel
	path := s.path
	s.mu.Unlock()

	node, _, err := s.fs.Copy(cctx, s.dataroomID, srcPath, path, false)
	var src File
	if err == nil && node.Size > 0 {
		// Asks nothing: the session is the one the copy just used.
		if src, err = s.fs.Open(ctx, s.dataroomID, node); err != nil {
			// A copy the spool cannot read is not its file.
			s.fs.undoUpload(s.dataroomID, path, node, true, "")
		}
	}

	s.mu.Lock()
	s.cancelFlush = nil
	unlinked, closed := s.unlinked, s.closed
	if err == nil && !unlinked {
		s.node, s.exists = node, true
		s.size, s.mtime, s.dirty = node.Size, node.ModTime, false
		if !closed {
			s.src, s.srcFrom, s.srcSize = src, 0, node.Size
			src = nil
		}
		s.accountLocked()
	}
	s.mu.Unlock()
	if src != nil {
		_ = src.Close()
	}

	switch {
	case unlinked:
		// As a Flush that completed for a file removed meanwhile.
		if err == nil {
			s.fs.undoUpload(s.dataroomID, path, node, true, "")
		}

		return Node{}, nil
	case err != nil && closed:
		return Node{}, ErrClosed
	case err != nil:
		return Node{}, err
	}

	return node, nil
}

// isClosed reports whether Close was called.
func (s *spool) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.closed
}

func (s *spool) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	if err := s.hydrate(); err != nil {
		return 0, err
	}
	s.content.RLock()
	defer s.content.RUnlock()
	if s.isClosed() {
		return 0, ErrClosed
	}

	return s.file.ReadAt(p, off)
}

func (s *spool) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	s.content.Lock()
	defer s.content.Unlock()
	if s.isClosed() {
		return 0, ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	// A write that covers everything the version still has to give replaces
	// it: nothing of it needs to come in. The version is only let go once the
	// bytes are stored (see covered).
	s.mu.Lock()
	covers := s.src != nil && off == 0 && int64(len(p)) >= s.srcSize
	s.mu.Unlock()
	if !covers {
		if err := s.hydrateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := s.file.WriteAt(p, off)
	if covers {
		s.covered(int64(n))
	}
	if n > 0 {
		s.mu.Lock()
		s.size = max(s.size, off+int64(n))
		s.dirty, s.mtime = true, time.Now()
		s.accountLocked()
		s.mu.Unlock()
	}

	return n, spoolError(err)
}

func (s *spool) Truncate(size int64) error {
	if size < 0 {
		return fmt.Errorf("negative size %d: %w", size, os.ErrInvalid)
	}
	s.content.Lock()
	defer s.content.Unlock()
	if s.isClosed() {
		return ErrClosed
	}
	if size == s.Size() {
		return nil
	}
	// The spool file follows, whether or not the version is in it yet: its
	// leading bytes land below srcSize, which never exceeds the size.
	if err := s.file.Truncate(size); err != nil {
		return spoolError(err)
	}

	s.mu.Lock()
	s.size = size
	s.dirty, s.mtime = true, time.Now()
	var dropped File
	if s.src != nil {
		s.srcSize = min(s.srcSize, size)
		if s.srcSize <= s.srcFrom {
			dropped, s.src = s.src, nil
		}
	}
	s.accountLocked()
	s.mu.Unlock()
	if dropped != nil {
		_ = dropped.Close()
	}

	return nil
}

// covered records that a write from offset 0, meant to replace everything the
// version still had to give, stored n bytes. The caller holds content
// exclusively.
//
// A complete write lets the version go. One the spool file cut short (no room
// left) replaced its first n bytes only: the rest is still the content, and
// is brought in now, behind the bytes written, so that the spool stays a
// whole file that reads and flushes. When that copy fails too, which is the
// likely outcome on a file system that just ran out of room, the version is
// kept with srcFrom past the bytes written: the next read, write or Flush
// brings the rest in, or answers the error of the copy, and never reads a
// hole where the version had bytes.
func (s *spool) covered(n int64) {
	s.mu.Lock()
	var done File
	if s.src != nil {
		s.srcFrom = max(s.srcFrom, n)
		if s.srcFrom >= s.srcSize {
			done, s.src = s.src, nil
		}
	}
	s.accountLocked()
	s.mu.Unlock()
	if done != nil {
		_ = done.Close()

		return
	}
	_ = s.hydrateLocked()
}

// hydrate copies into the spool file what the content keeps of the version
// the spool was opened on, unless it is there already.
func (s *spool) hydrate() error {
	s.mu.Lock()
	pending, closed := s.src != nil, s.closed
	s.mu.Unlock()
	switch {
	case closed:
		return ErrClosed
	case !pending:
		return nil
	}
	s.content.Lock()
	defer s.content.Unlock()

	return s.hydrateLocked()
}

// hydrateLocked is hydrate for a caller that holds content exclusively. A
// copy that fails leaves the version to be brought in again, from the start
// of what the content takes of it, by the next call. Close interrupts it by
// closing the File it reads.
func (s *spool) hydrateLocked() error {
	s.mu.Lock()
	src, from, size, closed := s.src, s.srcFrom, s.srcSize, s.closed
	s.mu.Unlock()
	switch {
	case closed:
		return ErrClosed
	case src == nil:
		return nil
	}

	buf := make([]byte, min(max(size-from, 0), hydrateBufferSize))
	for off := from; off < size; {
		n, err := src.ReadAt(buf[:min(int64(len(buf)), size-off)], off)
		if n > 0 {
			if _, werr := s.file.WriteAt(buf[:n], off); werr != nil {
				return spoolError(fmt.Errorf("copying the current version into the spool: %w", werr))
			}
			off += int64(n)
		}
		switch {
		case err == nil, errors.Is(err, io.EOF) && off >= size:
		case errors.Is(err, io.EOF):
			return fmt.Errorf("the current version ends after %d of its %d bytes: %w", off, size, io.ErrUnexpectedEOF)
		default:
			return fmt.Errorf("reading the current version: %w", err)
		}
	}

	s.mu.Lock()
	if s.src == src {
		s.src = nil
	}
	s.accountLocked()
	s.mu.Unlock()
	_ = src.Close()

	return nil
}

// acquire takes flushing, or gives up when ctx ends first.
func (s *spool) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.flushing <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *spool) release() { <-s.flushing }

func (s *spool) SetModTime(ctx context.Context, t time.Time) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return ErrClosed
	}
	// Unlinked, there is no version left to date.
	if s.dirty || s.unlinked {
		s.mtime = t
		s.mu.Unlock()

		return nil
	}
	path := s.path
	s.mu.Unlock()

	// Clean: the content is a version of the API, which is dated there.
	if err := s.fs.SetModTime(ctx, s.dataroomID, path, t); err != nil {
		return err
	}
	s.mu.Lock()
	// A write that landed meanwhile dated the content again.
	if !s.dirty {
		s.mtime, s.node.ModTime = t, t
	}
	s.mu.Unlock()

	return nil
}

func (s *spool) Flush(ctx context.Context) (Node, error) {
	if err := s.acquire(ctx); err != nil {
		return Node{}, err
	}
	defer s.release()

	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()

		return Node{}, ErrClosed
	case s.unlinked:
		s.mu.Unlock()

		return Node{}, nil
	case !s.dirty:
		node := s.node
		s.mu.Unlock()

		return node, nil
	}
	s.mu.Unlock()

	// A truncation may have left the spool dirty with its version still to
	// come in.
	if err := s.hydrate(); err != nil {
		return Node{}, err
	}

	// From here to the end no write changes the content: what is sent is one
	// state of the file, and the spool is marked clean before a write can
	// make it dirty again.
	s.content.RLock()
	defer s.content.RUnlock()

	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()

		return Node{}, ErrClosed
	case s.unlinked:
		s.mu.Unlock()

		return Node{}, nil
	}
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.cancelFlush = cancel
	mtime, path := s.mtime, s.path
	c := content{size: s.size, mtime: &mtime}
	if s.exists {
		c.nodeID = s.node.ID
	} else {
		c.mode = s.mode
	}
	s.mu.Unlock()
	c.r = io.NewSectionReader(s.file, 0, c.size)

	node, created, err := s.fs.upload(fctx, s.dataroomID, path, c)

	s.mu.Lock()
	s.cancelFlush = nil
	unlinked, closed := s.unlinked, s.closed
	if err == nil && !unlinked {
		s.node, s.exists = node, true
		// SetModTime waits for the Flush, and writes for content: nothing
		// changed what was sent.
		s.dirty = false
	}
	s.mu.Unlock()

	switch {
	case unlinked:
		// The file was removed while it was sent: a failed upload cleaned up
		// after itself, one that completed is undone. Unlinked waits for it.
		if err == nil {
			s.fs.undoUpload(s.dataroomID, path, node, created, c.nodeID)
		}

		return Node{}, nil
	case err != nil && closed:
		return Node{}, ErrClosed
	case err != nil:
		return Node{}, err
	}

	return node, nil
}

func (s *spool) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return nil
	}
	s.closed = true
	cancel, src := s.cancelFlush, s.src
	s.src = nil
	s.accountLocked()
	s.mu.Unlock()

	// Both hold content: the upload of a Flush, and a hydration reading src.
	if cancel != nil {
		cancel()
	}
	if src != nil {
		_ = src.Close()
	}
	s.content.Lock()
	defer s.content.Unlock()

	return s.file.Close()
}
