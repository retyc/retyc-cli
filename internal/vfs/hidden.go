package vfs

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
)

// The methods of this file split the removal of a node in two for a front end
// that answers before the API does (the FUSE driver with
// Options.BackgroundDelete): HideNode makes the node absent from this FS at
// once, DeleteNode asks the API, RevealNode records the outcome.
//
// A hidden node is absent by its ID, not by its name: a listing or a lookup
// answered by the API while the deletion is on its way still names the node,
// and must not bring it back. Every answer of the API goes through the filter
// (fetchLocked, findByNameOnce) before it is cached or returned, and so does
// what is read from the store (heldLocked, heldNodeLocked, namedLocked): a
// store shared with other processes holds what they listed and looked up,
// and they know nothing of what is hidden here. With nothing hidden the
// filter costs a length test.

// hiddenUntil is the state of a hidden node: the zero time while its deletion
// is pending, otherwise the instant from which nothing can name it any more.
type hiddenUntil = time.Time

// HideNode makes node, a child of the folder at parentPath, absent from the
// FS: it leaves the cached listing of the folder, and no answer of the API
// brings it back until RevealNode. Nothing is asked of the API.
func (fs *FS) HideNode(dataroomID, parentPath string, node Node) {
	key := listingKey(dataroomID, parentPath)
	fs.mu.Lock()
	defer fs.unlock()
	fs.pruneHiddenLocked()
	// Dropped from the listing first: once hidden, the node is no longer
	// read from the store (see heldLocked), and could not be found there.
	fs.forgetIDLocked(key, node.ID, node.Name)
	fs.hidden[node.ID] = hiddenUntil{}
}

// DeleteNode asks the API to delete the node, whatever the cache holds. A
// node the API no longer holds (404, or 410 while its purge is pending) is
// deleted: that is no error.
func (fs *FS) DeleteNode(ctx context.Context, nodeID string) error {
	err := fs.client.DeleteDataroomNode(ctx, nodeID)
	if errors.Is(err, api.ErrNotFound) {
		return nil
	}

	return classify(err)
}

// RevealNode ends what HideNode started for the node nodeID, once the API has
// answered its deletion; parentPath is the folder that held it.
//
// Deleted, the node stays hidden for the time a request already on its way
// may take (Options.FetchTimeout): the API may have answered a listing that
// names it just before it deleted it. Not deleted, the node is shown again
// and the listing of the folder is dropped, so that the next request finds
// the node where the API still holds it.
func (fs *FS) RevealNode(dataroomID, parentPath, nodeID string, deleted bool) {
	fs.mu.Lock()
	defer fs.unlock()
	if deleted {
		fs.hidden[nodeID] = time.Now().Add(fs.opts.fetchTimeout())

		return
	}
	delete(fs.hidden, nodeID)
	fs.invalidateLocked(listingKey(dataroomID, parentPath))
}

// isHidden reports whether the node is hidden (see HideNode).
func (fs *FS) isHidden(nodeID string) bool {
	fs.mu.Lock()
	defer fs.unlock()

	return fs.hiddenLocked(nodeID)
}

// hiddenLocked is isHidden for a caller that holds mu.
func (fs *FS) hiddenLocked(nodeID string) bool {
	until, ok := fs.hidden[nodeID]

	return ok && (until.IsZero() || time.Now().Before(until))
}

// withoutHiddenLocked returns nodes, the answer of the API to a listing or a
// listing read from the store, without the hidden nodes, and the ETag to keep with it: none when a node
// was left out, the listing no longer being what the API answered. nodes is
// never written through. The caller holds mu.
func (fs *FS) withoutHiddenLocked(nodes []Node, etag string) ([]Node, string) {
	if len(fs.hidden) == 0 || !slices.ContainsFunc(nodes, func(n Node) bool { return fs.hiddenLocked(n.ID) }) {
		return nodes, etag
	}
	kept := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		if !fs.hiddenLocked(n.ID) {
			kept = append(kept, n)
		}
	}

	return kept, ""
}

// pruneHiddenLocked forgets the deleted nodes nothing can name any more, at
// most once per Options.FetchTimeout: the set stays bounded by what was
// deleted within two of them. The caller holds mu.
func (fs *FS) pruneHiddenLocked() {
	now := time.Now()
	if now.Sub(fs.hiddenPruned) < fs.opts.fetchTimeout() {
		return
	}
	fs.hiddenPruned = now
	for id, until := range fs.hidden {
		if !until.IsZero() && !now.Before(until) {
			delete(fs.hidden, id)
		}
	}
}
