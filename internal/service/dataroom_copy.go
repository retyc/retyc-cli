package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// ErrCopyDiscarded reports a server-side copy whose version vanished before
// it was sealed: the storage failed to duplicate the chunks, or the task was
// never sealed. The copy no longer exists; the caller may retry.
var ErrCopyDiscarded = errors.New("the server discarded the copy before it completed")

// ErrCopyTargetDeleted reports a copy whose new node was deleted while the
// chunks were still being duplicated.
var ErrCopyTargetDeleted = errors.New("the copied node was deleted before the copy completed")

// copyPollInterval paces the polling of a copy's version. The storage
// duplicates about 1 GiB per second, so a second is a round trip on a small
// file and a negligible lag on a large one.
var copyPollInterval = time.Second

// CopyDataroomNodeByID copies the file srcNodeID into a new node named
// newName under dstParentID (nil for the dataroom root), in the same
// dataroom, and waits for the server to finish duplicating the chunks. The
// chunks never transit through the client. It returns the new node as a
// listing would report it.
//
// A name already held in the destination answers api.ErrConflict, also while
// its holder is deleted and not purged yet; the source or the destination
// folder missing, api.ErrNotFound, which a source pending deletion (410)
// matches too; a folder, or a file without a complete version, a 422.
func CopyDataroomNodeByID(
	ctx context.Context, client *api.Client, srcNodeID string, dstParentID *string, newName string,
	sess *DataroomSession,
) (DataroomNodeInfo, error) {
	nameEnc, err := crypto.EncryptStringForKeys(newName, []string{sess.PublicKey})
	if err != nil {
		return DataroomNodeInfo{}, fmt.Errorf("encrypting new name: %w", err)
	}
	item, err := client.CopyDataroomNode(ctx, srcNodeID, dstParentID, nameEnc, nodeNameHash(newName, sess.NameSalt))
	switch {
	case err != nil:
		return DataroomNodeInfo{}, fmt.Errorf("copying node: %w", err)
	case item.Version == nil:
		return DataroomNodeInfo{}, fmt.Errorf("copying node: the API returned no version")
	}
	version, err := waitForVersion(ctx, client, item.Version)
	if err != nil {
		return DataroomNodeInfo{}, err
	}
	item.Version = version
	info := nodeFromItem(ctx, client, item.Node.ID, item, sess)
	info.Name = newName

	return info, nil
}

// waitForVersion polls version until every announced chunk is stored. A 404
// on the version means the copy was discarded, a 410 that its node was
// deleted meanwhile.
func waitForVersion(
	ctx context.Context, client *api.Client, version *api.DataroomNodeVersion,
) (*api.DataroomNodeVersion, error) {
	for !version.Complete() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(copyPollInterval):
		}
		fresh, err := client.GetDataroomNodeVersion(ctx, version.ID)
		switch {
		case errors.Is(err, api.ErrGone):
			return nil, ErrCopyTargetDeleted
		case errors.Is(err, api.ErrNotFound):
			return nil, ErrCopyDiscarded
		case err != nil:
			return nil, fmt.Errorf("polling the copy: %w", err)
		}
		version = fresh
	}

	return version, nil
}

// CopyDataroomNodeWithSession copies the file at srcPath to dstPath (its new
// name included) within one dataroom, for callers that already hold the
// dataroom session.
func CopyDataroomNodeWithSession(
	ctx context.Context, client *api.Client, dataroomID, srcPath, dstPath string, sess *DataroomSession,
) (DataroomNodeInfo, error) {
	src, err := resolvePathItemWithSession(ctx, client, dataroomID, srcPath, sess)
	if err != nil {
		return DataroomNodeInfo{}, err
	}
	if src == nil {
		return DataroomNodeInfo{}, fmt.Errorf("cannot copy the root folder")
	}
	if src.Node.IsFolder() {
		return DataroomNodeInfo{}, fmt.Errorf("%s is a folder: server-side copy applies to files only", srcPath)
	}

	dstParentPath, newName := splitPathParent(dstPath)
	if newName == "" {
		return DataroomNodeInfo{}, fmt.Errorf("destination path must include a name: %s", dstPath)
	}
	dstParentID, err := resolvePathWithSession(ctx, client, dataroomID, dstParentPath, sess)
	if err != nil {
		return DataroomNodeInfo{}, err
	}

	return CopyDataroomNodeByID(ctx, client, src.Node.ID, dstParentID, newName, sess)
}

// CopyDataroomNode copies a file between two retyc:// URIs of the same
// dataroom, server side.
func CopyDataroomNode(
	ctx context.Context, cfg *config.Config, client *api.Client, srcURI, dstURI string, reader PassphraseReader,
) (DataroomNodeInfo, error) {
	src, err := ParseRetycURI(srcURI)
	if err != nil {
		return DataroomNodeInfo{}, fmt.Errorf("source: %w", err)
	}
	dst, err := ParseRetycURI(dstURI)
	if err != nil {
		return DataroomNodeInfo{}, fmt.Errorf("destination: %w", err)
	}
	if src.DataroomID != dst.DataroomID {
		return DataroomNodeInfo{}, fmt.Errorf("source and destination must be in the same dataroom")
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, src.DataroomID, reader)
	if err != nil {
		return DataroomNodeInfo{}, err
	}

	return CopyDataroomNodeWithSession(ctx, client, src.DataroomID, src.Path, dst.Path, sess)
}
