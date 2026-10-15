package vfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
)

// The methods of this file change the tree: each resolves its paths through
// the cached listings, calls the API, and records the outcome in the cache
// (see edit.go), so the request that follows is served without listing again.
//
// The listings they resolve from can be expired and name a node deleted or
// re-created elsewhere; the API then answers 404, 410 or 409, and each method
// says how it sorts that out. Their errors carry the sentinels of errors.go.

// DefaultCopyReplaceRetry and DefaultCopyReplaceWait pace Copy onto a
// destination it just deleted when Options leaves them unset: how often the
// copy is tried again while the API still holds the name, and for how long
// before the conflict is reported.
const (
	DefaultCopyReplaceRetry = 500 * time.Millisecond
	DefaultCopyReplaceWait  = 15 * time.Second
)

// Mkdir creates the folder at path and returns its node. The parent must
// exist: ErrNotExist when it does not, ErrNotDir when it is not a folder,
// ErrExist when the name is taken.
//
// The node carries its ID, name, type and ParentID. Its CreatedAt and ModTime
// are zero: the creation is asked for its ID only, and the next listing of
// the parent brings them.
func (fs *FS) Mkdir(ctx context.Context, dataroomID, path string) (Node, error) {
	sess, err := fs.Session(ctx, dataroomID)
	if err != nil {
		return Node{}, fmt.Errorf("dataroom session: %w", err)
	}
	parentPath, dirName := SplitPath(path)
	if dirName == "" {
		return Node{}, as(ErrExist, errors.New("the dataroom root already exists"))
	}
	parentID, err := fs.resolveFolderID(ctx, dataroomID, parentPath)
	if errors.Is(err, os.ErrInvalid) {
		// The parent is a file.
		return Node{}, as(ErrNotDir, err)
	}
	if err != nil {
		return Node{}, err
	}
	id, err := service.MkdirDataroomInto(ctx, fs.client, dataroomID, parentID, dirName, sess)
	if isConcurrentUpdate(err) {
		id, err = service.MkdirDataroomInto(ctx, fs.client, dataroomID, parentID, dirName, sess)
	}
	if errors.Is(err, api.ErrConflict) && parentID != nil && api.ErrorCode(err) == "" {
		// Without codes a 409 may be a parent deleted elsewhere; with them
		// that is a 404 PARENT_NOT_FOUND, and a 409 is the name taken.
		id, parentID, err = fs.mkdirAfterConflict(ctx, dataroomID, parentPath, dirName, parentID, sess, err)
	}
	switch {
	case errors.Is(err, api.ErrNotFound):
		// The cached listing named a parent deleted elsewhere since.
		grandParent, _ := SplitPath(parentPath)
		fs.InvalidateListing(dataroomID, grandParent)
		fs.invalidateSubtree(dataroomID, parentPath)

		return Node{}, as(ErrNotExist, err)
	case errors.Is(err, api.ErrConflict):
		fs.nameTaken(dataroomID, parentPath, dirName, false)

		return Node{}, as(ErrExist, err)
	case err != nil:
		return Node{}, classify(err)
	}
	// Both listings the next requests need are known without asking the API:
	// the parent's gains the new folder (so a nested Mkdir or an upload inside
	// it finds its ID), and the new folder's own is empty (so the first upload
	// in it needs no listing, and the following overwrite finds the file it
	// created).
	node := Node{ID: id, ParentID: idOrRoot(parentID), Name: dirName, Type: TypeDir}
	fs.addFolder(dataroomID, path, node)

	return node, nil
}

// mkdirAfterConflict sorts out a 409 on folder creation (see
// parentAfterConflict) and creates the folder again when the parent was
// re-created under another ID. It returns the parent the folder was created
// under with its ID.
func (fs *FS) mkdirAfterConflict(
	ctx context.Context, dataroomID, parentPath, dirName string, staleID *string,
	sess *service.DataroomSession, conflict error,
) (string, *string, error) {
	freshID, err := fs.parentAfterConflict(ctx, dataroomID, parentPath, staleID, conflict)
	if err != nil {
		return "", staleID, err
	}
	id, err := service.MkdirDataroomInto(ctx, fs.client, dataroomID, freshID, dirName, sess)

	return id, freshID, err
}

// parentAfterConflict sorts out a 409 on the creation of a node under the
// folder staleID. The API answers it for a name already taken, and for a
// parent_id naming a folder deleted since its listing was cached (the
// dangling reference fails a foreign key). The parent is re-resolved from a
// fresh listing: gone → ErrNotExist, now a file → ErrNotDir; unchanged → the
// conflict is genuine and returned as is; re-created under another ID → that
// ID, for the caller to try once more there.
func (fs *FS) parentAfterConflict(
	ctx context.Context, dataroomID, parentPath string, staleID *string, conflict error,
) (*string, error) {
	grandParent, _ := SplitPath(parentPath)
	fs.InvalidateListing(dataroomID, grandParent)
	freshID, err := fs.resolveFolderID(ctx, dataroomID, parentPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		fs.invalidateSubtree(dataroomID, parentPath)

		return nil, ErrNotExist
	case errors.Is(err, os.ErrInvalid):
		fs.invalidateSubtree(dataroomID, parentPath)

		return nil, as(ErrNotDir, err)
	case err != nil:
		return nil, err
	case freshID == nil || *freshID == *staleID:
		return nil, conflict
	}
	// The listings cached under the path belong to the deleted folder.
	fs.invalidateSubtree(dataroomID, parentPath)

	return freshID, nil
}

// Symlink creates the symbolic link at path, pointing at target, and returns
// its node (TypeSymlink, Target, Size the length of target). The target is
// kept as it is given, relative or absolute, dangling or not: nothing here
// resolves it. The parent must exist: ErrNotExist when it does not, ErrNotDir
// when it is not a folder, ErrExist when the name is taken, ErrForbidden when
// the user may not create there (a viewer, a dataroom over its plan).
//
// An API without symbolic links is ErrSymlinkUnsupported, and nothing is
// sent to one known to be older; when the API could not be told apart, the
// error is the one of that probe, as it is.
//
// With Options.HideSymlinks the link is created and cached like any other,
// and then hidden from Lookup like any other.
func (fs *FS) Symlink(ctx context.Context, dataroomID, path, target string) (Node, error) {
	sess, err := fs.Session(ctx, dataroomID)
	if err != nil {
		return Node{}, fmt.Errorf("dataroom session: %w", err)
	}
	parentPath, name := SplitPath(path)
	if name == "" {
		return Node{}, as(ErrExist, errors.New("the dataroom root already exists"))
	}
	parentID, err := fs.folderID(ctx, dataroomID, parentPath)
	if err != nil {
		return Node{}, err
	}
	info, err := service.SymlinkDataroomInto(ctx, fs.client, dataroomID, parentID, name, target, sess)
	// As for Mkdir: with codes, a parent deleted elsewhere is a 404.
	if errors.Is(err, api.ErrConflict) && parentID != nil && api.ErrorCode(err) == "" {
		var freshID *string
		if freshID, err = fs.parentAfterConflict(ctx, dataroomID, parentPath, parentID, err); err == nil {
			parentID = freshID
			info, err = service.SymlinkDataroomInto(ctx, fs.client, dataroomID, parentID, name, target, sess)
		}
	}
	switch {
	case errors.Is(err, ErrSymlinkUnsupported):
		return Node{}, err
	case errors.Is(err, api.ErrNotFound):
		// The cached listing named a parent deleted elsewhere since.
		grandParent, _ := SplitPath(parentPath)
		fs.InvalidateListing(dataroomID, grandParent)
		fs.invalidateSubtree(dataroomID, parentPath)

		return Node{}, as(ErrNotExist, err)
	case errors.Is(err, api.ErrConflict):
		fs.nameTaken(dataroomID, parentPath, name, false)

		return Node{}, as(ErrExist, err)
	case err != nil:
		return Node{}, classify(err)
	}
	node := fs.nodeFromInfo(info)
	// The folder the link was asked into: what placed the node, whether or
	// not the API echoes it.
	node.ParentID = idOrRoot(parentID)

	return fs.upsert(dataroomID, parentPath, node), nil
}

// nameTaken records that the API just refused name in the folder at
// parentPath as already taken (409): the name exists, as a folder when isDir.
// What the cache holds to the contrary must not outlive that answer: an Entry
// saying the name is missing would otherwise keep answering so for
// Options.NegativeTTL (mkdir d: EEXIST, then ls d: ENOENT), and a listing that
// does not name it for Options.TTL.
//
// The entries of the folder are dropped. Its listing is dropped too unless it
// agrees with the API, in which case the refusal taught nothing (a mkdir on a
// folder the client could see) and re-listing would be a round trip for
// nothing. A name it holds as a symbolic link the FS hides agrees as well.
// The generation is bumped either way: a lookup of the name in flight may
// have been answered before the name was taken.
func (fs *FS) nameTaken(dataroomID, parentPath, name string, isDir bool) {
	key := listingKey(dataroomID, parentPath)
	fs.mu.Lock()
	defer fs.unlock()
	if n, _, ok := fs.heldNodeLocked(sealedStoreCtx, key, name); ok && n != nil && (!isDir || n.Type == TypeDir) {
		fs.dropEntriesLocked(key)
		fs.bumpGenLocked(key)

		return
	}
	fs.invalidateLocked(key)
}

// idOrRoot returns the ID a folder ID points at, "" for the dataroom root:
// the form Node.ParentID takes.
func idOrRoot(folderID *string) string {
	if folderID == nil {
		return ""
	}

	return *folderID
}

// Remove deletes the node at path: ErrNotExist when there is none.
//
// The API deletes a folder with everything below it. With recursive that is
// what happens; without, the folder is listed first and ErrNotEmpty returned
// when it has children, as rmdir(2) expects. That listing is asked of the API
// every time, never read from the cache: a cached listing, even a fresh one,
// may miss a child another client created since, and deleting on its word
// would take that child with the folder. One request per rmdir is the price
// of ErrNotEmpty. The check and the deletion are still two requests: a child
// created elsewhere in between goes with the folder.
func (fs *FS) Remove(ctx context.Context, dataroomID, path string, recursive bool) error {
	parentPath, name := SplitPath(path)
	if name == "" {
		return fmt.Errorf("the dataroom root cannot be removed: %w", os.ErrInvalid)
	}
	err := fs.removeListed(ctx, dataroomID, parentPath, name, recursive)
	if errors.Is(err, api.ErrNotFound) {
		// The listing was stale (404, or 410 while the purge is pending): its
		// node is gone, possibly replaced by a new one under the same name.
		// Retry once against a fresh listing.
		fs.InvalidateListing(dataroomID, parentPath)
		err = fs.removeListed(ctx, dataroomID, parentPath, name, recursive)
		if errors.Is(err, api.ErrNotFound) {
			// Resolved afresh and gone all the same: what the retry cached
			// about the name is wrong too.
			fs.InvalidateListing(dataroomID, parentPath)
			err = as(ErrNotExist, err)
		}
	}
	if err == nil {
		fs.forget(dataroomID, parentPath, name)
		fs.invalidateSubtree(dataroomID, path)
	}

	return err
}

// listedNode returns the child name of parentPath, found in the parent
// listing, and tags the request span with its ID.
//
// That listing is almost always cached: a client deletes or moves a node out
// of a folder it has just listed. The mutation is then the only round trip,
// whereas service.resolvePath would list the API once per path level first; a
// miss costs one listing, never more. The cost of trusting a cached, possibly
// expired listing is accepted: a node moved elsewhere by another client within
// that window is deleted or renamed at its new location. A node deleted
// elsewhere makes the mutation answer 404, or 410 while its purge is pending
// (both match api.ErrNotFound), which callers retry against a fresh listing.
func (fs *FS) listedNode(ctx context.Context, dataroomID, parentPath, name string) (Node, error) {
	n, err := fs.Lookup(ctx, dataroomID, parentPath, name)
	if err != nil {
		return Node{}, err
	}
	trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrNodeID.String(n.ID))

	return n, nil
}

// removeListed deletes the child name of parentPath (see listedNode), after
// checking that a folder is empty unless recursive.
func (fs *FS) removeListed(ctx context.Context, dataroomID, parentPath, name string, recursive bool) error {
	node, err := fs.listedNode(ctx, dataroomID, parentPath, name)
	if err != nil {
		return err
	}
	if !recursive && node.Type == TypeDir {
		children, listErr := fs.readDirFetched(ctx, dataroomID, joinPath(parentPath, name))
		if listErr != nil {
			return listErr
		}
		if len(children) > 0 {
			return ErrNotEmpty
		}
	}

	return classify(fs.client.DeleteDataroomNode(ctx, node.ID))
}

// Rename renames or moves the node at oldPath to newPath, in the same
// dataroom: ErrNotExist when the source or the destination folder is missing,
// ErrNotDir when the destination's parent is not a folder.
//
// Without replace a destination that exists is ErrExist. With replace a file
// holding the destination name is replaced, in one request and atomically for
// other clients (api.NodeUpdate.Replace); a folder holding it is ErrIsDir, a
// file the user may not delete ErrForbidden. A folder never replaces a file
// (ErrNotDir, as rename(2) answers): the API would do it, so the destination
// of a folder is looked up first (see moveListed) and nothing is sent. That needs an API with the node
// types: on an older one the error is ErrReplaceUnsupported (which still
// matches service.ErrReplaceUnsupported); when the API could not be told
// apart, the error is the one of that probe, as it is, and nothing is renamed.
//
// Two replaces of one destination that cross answer one of them 409, the name
// being held for an instant by the node the other just put there. An API with
// error codes says so (CONCURRENT_UPDATE, on any rename): it is tried once
// more, and NAME_TAKEN is ErrExist at once. Without a code, a 409 on a replace
// that does not name a folder is tried once more before it is reported. One
// that names a folder is ErrIsDir at once, whatever the state of the listings.
func (fs *FS) Rename(ctx context.Context, dataroomID, oldPath, newPath string, replace bool) error {
	oldParent, oldName := SplitPath(oldPath)
	newParent, newName := SplitPath(newPath)
	if oldName == "" || newName == "" {
		return fmt.Errorf("the dataroom root cannot be renamed: %w", os.ErrInvalid)
	}
	dstParentID, err := fs.moveListed(ctx, dataroomID, oldParent, oldName, newParent, newName, replace)
	if renameRetries(err, replace) {
		dstParentID, err = fs.moveListed(ctx, dataroomID, oldParent, oldName, newParent, newName, replace)
	}
	if isReplaceFolder(err) {
		// The destination is a folder: nothing a fresh listing would change.
		fs.nameTaken(dataroomID, newParent, newName, true)

		return renameError(err)
	}
	if retry, staleErr := fs.staleRename(ctx, dataroomID, oldParent, newParent, dstParentID, err); retry {
		dstParentID, err = fs.moveListed(ctx, dataroomID, oldParent, oldName, newParent, newName, replace)
		if errors.Is(err, api.ErrNotFound) {
			// Resolved afresh and gone all the same: what the retry cached
			// about the source is wrong too.
			fs.InvalidateListing(dataroomID, oldParent)
			err = as(ErrNotExist, err)
		}
	} else if staleErr != nil {
		err = staleErr
	}
	if err != nil {
		if errors.Is(err, api.ErrConflict) {
			// A genuine conflict: the destination exists, whatever the cache
			// said of it.
			fs.nameTaken(dataroomID, newParent, newName, isReplaceFolder(err))
		}

		return renameError(err)
	}
	fs.move(dataroomID, oldParent, oldName, newParent, newName, idOrRoot(dstParentID))
	fs.invalidateSubtree(dataroomID, oldPath)
	fs.invalidateSubtree(dataroomID, newPath)

	return nil
}

// renameError gives a refused rename its sentinel: a 409 is a destination
// that exists, or a folder a replace cannot remove.
func renameError(err error) error {
	if !errors.Is(err, api.ErrConflict) {
		return err
	}
	if isReplaceFolder(err) {
		return as(ErrIsDir, err)
	}

	return as(ErrExist, err)
}

// renameRetries tells whether a 409 on a rename is the race of a concurrent
// request, worth one more try: CONCURRENT_UPDATE, or, from an API without
// codes, any 409 on a replace that does not name a folder.
func renameRetries(err error, replace bool) bool {
	if !errors.Is(err, api.ErrConflict) {
		return false
	}
	if api.ErrorCode(err) != "" {
		return isConcurrentUpdate(err)
	}

	return replace && !isReplaceFolder(err)
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
//     folder that is gone replaces the conflict with ErrNotExist; an
//     unchanged one is a genuine conflict, returned without repeating the PUT.
//     The root cannot be deleted, so a conflict there is always genuine, and
//     so is a 409 with an error code: such an API answers 404 for a deleted
//     folder.
//
// A non-nil error with retry false replaces the rename's error.
func (fs *FS) staleRename(
	ctx context.Context, dataroomID, srcParent, dstParent string, dstParentID *string, err error,
) (retry bool, replaced error) {
	switch {
	case errors.Is(err, api.ErrNotFound):
		fs.InvalidateListing(dataroomID, srcParent)

		return true, nil
	case errors.Is(err, api.ErrConflict) && dstParentID != nil && api.ErrorCode(err) == "":
		dstGrandParent, _ := SplitPath(dstParent)
		fs.InvalidateListing(dataroomID, dstGrandParent)
		freshID, freshErr := fs.folderID(ctx, dataroomID, dstParent)
		if freshErr != nil {
			return false, freshErr
		}

		return freshID != nil && *freshID != *dstParentID, nil
	default:
		return false, nil
	}
}

// folderID is resolveFolderID for a mutation: a path that names something else than
// a folder is ErrNotDir.
func (fs *FS) folderID(ctx context.Context, dataroomID, path string) (*string, error) {
	id, err := fs.resolveFolderID(ctx, dataroomID, path)
	if errors.Is(err, os.ErrInvalid) {
		return nil, as(ErrNotDir, err)
	}

	return id, err
}

// moveListed renames the child srcName of srcParent to dstName under
// dstParent, both IDs taken from the cached listings (see listedNode). It
// returns the destination folder ID it used, once resolved.
func (fs *FS) moveListed(
	ctx context.Context, dataroomID, srcParent, srcName, dstParent, dstName string, replace bool,
) (*string, error) {
	node, err := fs.listedNode(ctx, dataroomID, srcParent, srcName)
	if err != nil {
		return nil, err
	}
	dstParentID, err := fs.folderID(ctx, dataroomID, dstParent)
	if err != nil {
		return nil, err
	}
	if replace && node.Type == TypeDir {
		if err := fs.folderReplaces(ctx, dataroomID, node, dstParent, dstName); err != nil {
			return dstParentID, err
		}
	}
	sess, err := fs.Session(ctx, dataroomID)
	if err != nil {
		return dstParentID, fmt.Errorf("dataroom session: %w", err)
	}
	if replace {
		err := service.ReplaceDataroomNodeByID(ctx, fs.client, dataroomID, node.ID, dstParentID, dstName, sess)
		if errors.Is(err, service.ErrReplaceUnsupported) {
			return dstParentID, as(ErrReplaceUnsupported, err)
		}

		return dstParentID, classify(err)
	}

	return dstParentID, classify(service.MoveDataroomNodeByID(ctx, fs.client, node.ID, dstParentID, dstName, sess))
}

// folderReplaces checks that the folder src may take the name dstName in
// dstParent with replace: ErrNotDir when a file or a symbolic link holds it.
// The API tells a file from a folder on the holder alone and would replace
// the file by the folder, which rename(2) refuses (ENOTDIR). A source that is
// a file needs no such check: the API refuses a folder holder itself (409,
// ErrIsDir).
//
// The destination is looked up through the cache (Lookup): no request when
// the listing of dstParent is cached or an Entry holds the name, one lookup
// by name otherwise (a listing on an API without it), whose answer is cached.
// A name the cache holds is trusted as everywhere else: a file deleted
// elsewhere since refuses the rename until its listing is refreshed. The
// check and the rename are two requests: a file created elsewhere in between
// is replaced. A lookup that fails otherwise than on a missing name is
// returned as it is, and nothing is renamed.
//
// A destination held by a folder is left to the API, which refuses it
// whether or not it is empty (ErrIsDir).
func (fs *FS) folderReplaces(ctx context.Context, dataroomID string, src Node, dstParent, dstName string) error {
	dst, err := fs.Lookup(ctx, dataroomID, dstParent, dstName)
	switch {
	case errors.Is(err, ErrNotExist):
		return nil
	case err != nil:
		return err
	case dst.ID != src.ID && dst.Type != TypeDir:
		return as(ErrNotDir, errors.New("a folder cannot replace a file"))
	}

	return nil
}

// CopyStep names the step of a Copy that failed.
type CopyStep int

// The steps of a Copy, in the order they run.
const (
	// CopySource: resolving the source, or a source that is a folder (ErrIsDir).
	CopySource CopyStep = iota
	// CopyDestinationFolder: resolving the folder of the destination.
	CopyDestinationFolder
	// CopySession: resolving the dataroom session.
	CopySession
	// CopyDestination: the destination as it stands refuses the copy: it is
	// the source (ErrSameNode), it exists and replace was not asked
	// (ErrExist), or it is a folder (ErrIsDir). Or it could not be looked up:
	// the error then carries none of those three.
	CopyDestination
	// CopyReplace: deleting the destination to replace.
	CopyReplace
	// CopyTransfer: the server-side copy itself.
	CopyTransfer
)

// CopyError is the error of a failed Copy. A front end that answers by what
// went wrong reads the sentinels with errors.Is and ignores Step; WebDAV, whose
// statuses depend on which resource failed (RFC 4918 §9.8.5), reads Step. The
// message is the one of Err.
type CopyError struct {
	Step CopyStep
	Err  error
}

func (e *CopyError) Error() string { return e.Err.Error() }
func (e *CopyError) Unwrap() error { return e.Err }

// copyGone tells which resource a 404 or 410 of the copy route is about:
// CopySource for the node copied, CopyDestinationFolder for the folder copied
// into, CopyTransfer when the refusal carries no code that says (an API
// without codes, or another code: DATAROOM_NOT_FOUND, VERSION_*).
func copyGone(err error) CopyStep {
	switch api.ErrorCode(err) {
	case api.CodeNodeNotFound, api.CodeNodeDeleted:
		return CopySource
	case api.CodeParentNotFound, api.CodeParentDeleted:
		return CopyDestinationFolder
	}

	return CopyTransfer
}

// copyFailed builds the error return of Copy. A rate limit is returned as it
// is, whatever the step it defeated.
func copyFailed(step CopyStep, err error) (Node, bool, error) {
	if errors.Is(err, api.ErrRateLimited) {
		return Node{}, false, err
	}

	return Node{}, false, &CopyError{Step: step, Err: err}
}

// Copy copies the file at srcPath to dstPath, in the same dataroom, through
// the API's server-side copy: the storage duplicates the chunks, nothing is
// downloaded or re-encrypted. It returns the new node, sealed (the copy can be
// read at once), and whether a destination was replaced. A failure is a
// *CopyError, a rate limit excepted.
//
// Folders are not copied: the API copies files only. A destination held by a
// file is ErrExist unless replace; with replace it is deleted first, since the
// API only copies into a new node: its versions go with it, and it is not
// restored when the copy then fails. The API keeps the name of the file just
// deleted until its purge has run and answers 409 meanwhile: the copy is tried
// again every Options.CopyReplaceRetry for Options.CopyReplaceWait. An API
// with error codes frees the name with the delete: its NAME_TAKEN is another
// holder of the name and ends the wait at once, its CONCURRENT_UPDATE is
// tried again as above.
func (fs *FS) Copy(
	ctx context.Context, dataroomID, srcPath, dstPath string, replace bool,
) (node Node, replaced bool, err error) {
	srcParent, srcName := SplitPath(srcPath)
	src, err := fs.Lookup(ctx, dataroomID, srcParent, srcName)
	if err != nil {
		return copyFailed(CopySource, err)
	}
	if src.Type == TypeDir {
		return copyFailed(CopySource, as(ErrIsDir, errors.New("copying a folder is not supported: copy its files")))
	}
	dstParent, dstName := SplitPath(dstPath)
	dstParentID, err := fs.folderID(ctx, dataroomID, dstParent)
	if err != nil {
		return copyFailed(CopyDestinationFolder, err)
	}

	// Resolved before the destination is deleted: nothing but the copy
	// itself may fail once it is gone.
	sess, err := fs.Session(ctx, dataroomID)
	if err != nil {
		return copyFailed(CopySession, err)
	}

	// Only a name that does not exist is a free destination: when the lookup
	// fails otherwise, nothing is known of it, and copying anyway could meet a
	// file the caller did not ask to replace.
	existing, err := fs.Lookup(ctx, dataroomID, dstParent, dstName)
	if err != nil && !errors.Is(err, ErrNotExist) {
		return copyFailed(CopyDestination, err)
	}
	if err == nil {
		switch {
		case existing.ID == src.ID:
			// Two spellings of one path: replacing it would delete the source.
			return copyFailed(CopyDestination, as(ErrSameNode, errors.New("destination equals source")))
		case !replace:
			return copyFailed(CopyDestination, as(ErrExist, errors.New("destination exists")))
		case existing.Type == TypeDir:
			return copyFailed(CopyDestination, as(ErrIsDir, errors.New("destination is a folder")))
		}
		if err := fs.client.DeleteDataroomNode(ctx, existing.ID); err != nil && !errors.Is(err, api.ErrNotFound) {
			return copyFailed(CopyReplace, classify(err))
		}
		fs.forget(dataroomID, dstParent, dstName)
		replaced = true
	}

	info, err := service.CopyDataroomNodeByID(ctx, fs.client, dataroomID, src.ID, dstParentID, dstName, sess)
	// The API keeps the name of the file just deleted until its purge has run
	// (seconds with the workers keeping up) and answers 409 meanwhile.
	retry, wait := fs.opts.copyReplacePacing()
	for waited := time.Duration(0); replaced && copyNameHeld(err) && waited < wait; waited += retry {
		select {
		case <-ctx.Done():
			return copyFailed(CopyTransfer, ctx.Err())
		case <-time.After(retry):
		}
		info, err = service.CopyDataroomNodeByID(ctx, fs.client, dataroomID, src.ID, dstParentID, dstName, sess)
	}
	if err != nil {
		switch {
		case errors.Is(err, api.ErrConflict):
			// The destination exists, whatever the cache said of it.
			fs.nameTaken(dataroomID, dstParent, dstName, false)
		case errors.Is(err, api.ErrNotFound):
			// The source, or the destination folder, was deleted elsewhere
			// since the cache named it. The code tells which; without one,
			// both listings go.
			gone := copyGone(err)
			if gone != CopyDestinationFolder {
				fs.InvalidateListing(dataroomID, srcParent)
			}
			if gone != CopySource && dstParentID != nil {
				dstGrandParent, _ := SplitPath(dstParent)
				fs.InvalidateListing(dataroomID, dstGrandParent)
			}
			if gone != CopyTransfer {
				return copyFailed(gone, copyError(err))
			}
		}

		return copyFailed(CopyTransfer, copyError(err))
	}
	node = fs.nodeFromInfo(info)
	// The folder the copy was asked into: what placed the node, whether or
	// not the API echoes it.
	node.ParentID = idOrRoot(dstParentID)
	fs.upsert(dataroomID, dstParent, node)

	return node, replaced, nil
}

// copyNameHeld tells whether the 409 of a copy onto a destination just
// deleted may be that name still held by the deleted node: any 409 without a
// code (an API that purges names late), CONCURRENT_UPDATE with one.
func copyNameHeld(err error) bool {
	if !errors.Is(err, api.ErrConflict) {
		return false
	}

	return api.ErrorCode(err) == "" || isConcurrentUpdate(err)
}

// copyError gives a refused server-side copy its sentinel. A 404 or 410 is
// the source or the destination folder gone (see copyGone; never the name);
// a 409, a name taken; a 400 that says so, a copy that exceeds the storage
// (see isStorageExceeded: the API has other 400s).
func copyError(err error) error {
	switch {
	case errors.Is(err, api.ErrConflict):
		return as(ErrExist, err)
	case errors.Is(err, api.ErrNotFound):
		return as(ErrNotExist, err)
	case isStorageExceeded(err):
		return as(ErrStorageExceeded, err)
	}

	return classify(err)
}
