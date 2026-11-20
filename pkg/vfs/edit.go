package vfs

import (
	"context"
	"slices"
	"time"
)

// The methods of this file record in the cache a mutation just made through
// the API (by the methods of mutate.go, attrs.go and writer.go), so that the
// next request is served from the cache instead of listing the folder again.
// They do not call the API.
//
// All of them bump the generation of the listing they touch and drop the
// entries single lookups cached for that folder (see dropEntriesLocked),
// whether or not a listing is cached: a fetch already in flight was answered by the API before
// the mutation landed, so storing it on completion would hide what the server
// just accepted. An edited listing keeps its fetch time (the rest of it is no
// fresher than it was, and the TTL must keep running from the real fetch) and
// loses its ETag (it no longer is what the API answered, so its next refresh
// is a full listing).

// upsert replaces the child named like node in the cached listing of the
// folder at parentPath, or adds it. For a folder without a cached listing,
// the node is kept as the Entry of its name instead (see upsertLocked).
//
// After an upload we know everything a listing would report for that node, so
// replacing the entry in place avoids the full re-listing — and its API
// round-trips — that a plain invalidation forces on the next PROPFIND. WebDAV
// clients revalidate aggressively (davfs2 defaults to dir_refresh 5 /
// file_refresh 1), so that re-listing lands on nearly every written file.
//
// A node given without a mode or without a creation time keeps those of the
// entry it replaces (see keepKnown): the write handles of a front end do not
// learn them from every upload route.
//
// It returns the node as the cache now holds it.
func (fs *FS) upsert(dataroomID, parentPath string, node Node) Node {
	fs.mu.Lock()
	defer fs.unlock()

	return fs.upsertLocked(listingKey(dataroomID, parentPath), node)
}

// forget drops the child name from the cached listing of the folder at
// parentPath, after it was deleted or moved away: the listing a client asks
// for right after is then served from cache instead of fetched again.
func (fs *FS) forget(dataroomID, parentPath, name string) {
	fs.mu.Lock()
	defer fs.unlock()
	fs.forgetLocked(listingKey(dataroomID, parentPath), name)
}

// move moves the child srcName of the cached listing of srcParent to dstName
// in the listing of dstParent, after it was renamed. The node keeps
// every field but its name and its ParentID, dstParentID being the ID of the
// folder at dstParent ("" for the root). When the source listing no longer names the node
// (expired meanwhile), its fields are unknown: the destination listing is
// dropped instead, so the next request re-lists it.
func (fs *FS) move(dataroomID, srcParent, srcName, dstParent, dstName, dstParentID string) {
	src := listingKey(dataroomID, srcParent)
	dst := listingKey(dataroomID, dstParent)
	fs.mu.Lock()
	defer fs.unlock()
	// Opened by the store, mu held: the node goes back to the store with its
	// decrypted target and MIME type, and a store may hold clear and sealed
	// nodes side by side. One node, which the memo of the codec most often
	// holds already.
	moved, _, _ := fs.heldNodeLocked(storeCtx(), src, srcName)
	fs.forgetLocked(src, srcName)
	if moved == nil {
		fs.invalidateLocked(dst)

		return
	}
	// The name it was sealed under is not the one it now has.
	moved.Name, moved.ParentID, moved.Sealed = dstName, dstParentID, nil
	fs.upsertLocked(dst, *moved)
}

// addFolder records a folder just created at path: an empty
// listing for the folder itself (it cannot have children yet), then the folder
// in its parent's listing. Both happen under one lock, the folder's own
// listing first: once a request can find the folder in the cache, a child it
// creates there lands in that listing instead of being hidden by a seed
// arriving after it.
//
// Any older listing at or below path (a folder of the same name deleted
// elsewhere, and its sub-folders) is dropped, and its generation bumped so a
// listing already in flight is not stored over it.
func (fs *FS) addFolder(dataroomID, path string, folder Node) {
	parent, _ := SplitPath(path)
	fs.mu.Lock()
	defer fs.unlock()
	fs.invalidateSubtreeLocked(dataroomID, path)
	fs.wroteLocked(fs.store.PutListing(storeCtx(), listingKey(dataroomID, path),
		&Listing{Nodes: []Node{}, FetchedAt: time.Now()}))
	fs.dropEntriesLocked(listingKey(dataroomID, path))
	fs.upsertLocked(listingKey(dataroomID, parent), folder)
}

// upsertLocked is upsert for a caller that holds mu.
//
// When no listing is cached for the folder, or one too old for Lookup to
// serve, there is nothing to edit that a lookup would read, and the node
// would be forgotten at once: the next lookup of its name would go to
// the API, and could keep "missing" for Options.NegativeTTL should the answer
// be late or the API not hold the node yet. The node is then kept as the
// Entry of its name, written after the edit, which drops the entries of the
// folder. It keeps what the Entry it replaces knew (see keepKnown).
func (fs *FS) upsertLocked(key ListingKey, node Node) Node {
	// One child is read, not the listing: all that is needed of it is its age
	// and the node the new one replaces, of which keepKnown reads nothing
	// sealed: neither it nor the Entry below is opened.
	old, meta, listed := fs.heldNodeLocked(sealedStoreCtx, key, node.Name)
	// A listing too old to be served is as good as none: Lookup skips it.
	served := listed && time.Since(meta.FetchedAt) < fs.opts.ttl()+fs.opts.MaxStale
	ek := EntryKey{DataroomID: key.DataroomID, ParentPath: key.Path, Name: node.Name}
	if !served {
		e, ok, err := fs.store.GetEntry(sealedStoreCtx, ek)
		fs.readLocked(sealedStoreCtx, err)
		if err == nil && ok && e != nil && e.Node != nil {
			node = keepKnown(node, *e.Node)
		}
	}
	if old != nil {
		node = keepKnown(node, *old)
	}
	f := fs.editLocked(key, func(nodes []Node) []Node {
		for i := range nodes {
			if nodes[i].Name == node.Name {
				nodes[i] = keepKnown(node, nodes[i])

				return nodes
			}
		}

		return append(nodes, node)
	})
	epoch := fs.storeEpoch
	gen, ok := editedLocked(fs, f, fs.store.UpsertNode, key, node)
	if !served {
		// Under the generation the edit left: a process sharing the store
		// that changed the folder since (it deleted the node) is not
		// answered by an entry that predates its change.
		kept := node
		fs.putEntryLocked(storeCtx(), ek, &Entry{Node: &kept, FetchedAt: time.Now()}, gen, ok && epoch == fs.storeEpoch)
	}

	return node
}

// forgetLocked is forget for a caller that holds mu.
func (fs *FS) forgetLocked(key ListingKey, name string) {
	f := fs.editLocked(key, func(nodes []Node) []Node {
		return slices.DeleteFunc(nodes, func(n Node) bool { return n.Name == name })
	})
	editedLocked(fs, f, fs.store.RemoveNode, key, name)
}

// forgetIDLocked drops the node id, last known as name, from the cached
// listing of key. The store removes a child by its name: the listing is only
// read in full when it does not hold the node under that one (renamed
// elsewhere, or not listed), to find the name it has there.
func (fs *FS) forgetIDLocked(key ListingKey, id, name string) {
	f := fs.editLocked(key, func(nodes []Node) []Node {
		return slices.DeleteFunc(nodes, func(n Node) bool { return n.ID == id })
	})
	n, _, listed := fs.heldNodeLocked(sealedStoreCtx, key, name) // its ID only
	if listed && (n == nil || n.ID != id) {
		listed = false
		// Opened by the store, mu held: the name of the node is what is
		// looked for. Rare: the node was renamed elsewhere.
		if l, ok := fs.heldLocked(storeCtx(), key); ok {
			if i := slices.IndexFunc(l.Nodes, func(n Node) bool { return n.ID == id }); i >= 0 {
				name, listed = l.Nodes[i].Name, true
			}
		}
	}
	if listed {
		editedLocked(fs, f, fs.store.RemoveNode, key, name)
	}
}

// editLocked opens an edit of one child of the cached listing of key: it
// bumps the listing's generation and drops the entries of the folder, whether
// or not a listing is cached. The edit itself is one atomic operation of the
// store (UpsertNode, RemoveNode), which the caller hands to editedLocked: the
// stored listing is never read, changed and written back from here, where
// another process sharing the store could write in between. The caller holds
// mu.
//
// replay is that same edit as a function of a node slice. A fetch of the
// folder's listing that replays edits (listingFetch.replays), and whose answer
// may predate this one, is handed it to replay on that answer, and returned:
// replay must give the same result on a listing that already shows the
// change. Not when something else changed the folder since that fetch
// started: its answer is discarded anyway, and nil is returned.
func (fs *FS) editLocked(key ListingKey, replay func([]Node) []Node) *listingFetch {
	f, ok := fs.inflight[key]
	if ok && f.replays && f.started && f.currentLocked(fs.genLocked(key)) {
		f.edits = append(f.edits, replay)
	} else {
		f = nil
	}
	fs.bumpGenLocked(key)
	fs.dropEntriesLocked(key)

	return f
}

// editedLocked makes the write of an edit opened by editLocked, f being the
// fetch that replays it, if any. The store answers the generation the listing
// has once written: when it is the one f expects plus one, this edit is all
// that happened to the listing in the store since f started, and f expects
// the new one. Anything else is the write of another process sharing the
// store, which the answer of f may predate: f keeps its answer for those who
// wait for it and no longer stores it (see listingFetch.storeGen). The caller
// holds mu.
//
// It returns the generation the write left the listing at, ok being false
// when the store failed it.
func editedLocked[T any](
	fs *FS, f *listingFetch, write func(context.Context, ListingKey, T) (uint64, error), key ListingKey, arg T,
) (gen uint64, ok bool) {
	epoch := fs.storeEpoch
	gen, err := write(storeCtx(), key, arg)
	fs.wroteLocked(err)
	if f == nil {
		return gen, err == nil
	}
	if err == nil && f.storable && f.storeEpoch == epoch && gen == f.storeGen+1 {
		f.storeGen = gen
	} else {
		f.storable = false
	}

	return gen, err == nil
}

// keepKnown returns node with the mode and the creation time of the cached
// entry it replaces when it carries none (an explicit 0 is a mode): an upload changes neither, and not
// every upload path learns them from the API.
func keepKnown(node, cached Node) Node {
	if node.ID != cached.ID {
		return node
	}
	if !node.HasMode() {
		node.Mode, node.ModeSet = cached.Mode, cached.ModeSet
	}
	if node.CreatedAt.IsZero() {
		node.CreatedAt = cached.CreatedAt
	}

	return node
}
