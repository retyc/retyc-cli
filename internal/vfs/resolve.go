package vfs

import (
	"context"
	"errors"
	"maps"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
)

// Lookup returns the child name of the folder at parentPath, or
// ErrNotExist (os.ErrNotExist). With Options.HideSymlinks a symbolic link is not found.
//
// It is the lookup of one name on its own (a stat, an open, a path component
// the kernel resolves). A caller answering for the entries of a folder it has
// just listed must not come here for each of them: see ReadDir. The answer
// comes from the first of these that has one:
//
//  1. The listing of the parent, when it is cached and still served (younger
//     than Options.TTL + Options.MaxStale). A name it holds is answered at
//     once, expired or not. A name missing from a listing younger than the TTL
//     does not exist. A name missing from an expired one waits for its
//     refresh before answering, as DataroomCache.IDForName does: it may be a
//     node created elsewhere since, and answering not found from the old
//     listing would turn staleness into an error for up to ttl+max_stale.
//  2. The Entry cached for (parent, name) by an earlier lookup: a node found
//     is trusted for Options.TTL, a name found missing for
//     Options.NegativeTTL.
//  3. On an API with the lookup by name, the listing of the parent again,
//     refreshed and waited for, when it is cached, too old to be served, and
//     stopped being served less than listingRefreshWindow ago: the answer is
//     read from the refreshed listing, found or not, and a failed refresh is
//     the error returned.
//  4. The API, by name hash (service.LookupNodeByName): one request whatever
//     the size of the folder, nothing decrypted but the node found. The
//     answer, found or not, is kept as an Entry. The folder's ID is resolved
//     the same way, through resolveFolderID: a path four folders deep that nothing
//     cached costs four such requests, and no listing. From the second such
//     lookup in one folder within Options.TTL, of another name, the listing of that folder is
//     also fetched in the background, for the lookups that follow (see
//     noteNameLookup); this one does not wait for it.
//  5. On an API without that lookup, the listing of the parent, fetched and
//     cached: what every lookup cost before.
//
// Concurrent lookups of one name that reach the API share its answer. An
// answer is kept only if nothing changed the folder through this FS while it
// was on its way (see dropEntriesLocked): a name created here is never
// answered missing from an Entry older than its creation.
//
// The cost of trusting a cached listing or Entry is accepted: a node moved
// elsewhere by another client within that window is found at its old path,
// and what the caller then does with its ID lands on the node where it now
// is. A node deleted elsewhere makes the API answer 404, or 410 while its
// purge is pending, which the caller retries against a fresh answer
// (InvalidateListing, which drops the entries of the folder too, then Lookup
// again). A name created elsewhere is not found for up to
// Options.NegativeTTL after a lookup that missed it.
func (fs *FS) Lookup(ctx context.Context, dataroomID, parentPath, name string) (Node, error) {
	key := listingKey(dataroomID, parentPath)

	refresh := false
	fs.mu.Lock()
	// One child of the listing is read, never the listing: a store outside
	// the process would send the whole folder for each name looked up.
	// The Entry of the name comes with it, in the same read: it is what the
	// lookup turns to when the listing does not answer.
	held, meta, listed, entry, cached := fs.namedLocked(fs.leaveSealed(ctx), key, name)
	if listed {
		age := time.Since(meta.FetchedAt)
		fresh := age < fs.opts.ttl()
		served := fs.opts.ttl() + fs.opts.MaxStale
		refresh = age < served+listingRefreshWindow(fs.opts.ttl())
		if fresh || age < served {
			if !fresh {
				fs.fetchLocked(ctx, key, true)
			}
			fs.unlock()
			if !fs.openNode(ctx, dataroomID, held) {
				// Opened out of mu (see leaveSealed). A node that does not
				// open is no listing, as when the store opened it itself:
				// the lookup goes on as below.
				return fs.lookupUnlisted(ctx, dataroomID, parentPath, name, entry, cached, false)
			}
			if fresh {
				recordListingLookup(ctx, "hit")
			} else {
				recordListingLookup(ctx, "stale")
			}
			if n, found := fs.visibleNode(held); found || fresh {
				return orNotExist(n, found)
			}
			nodes, err := fs.readDirRefreshed(ctx, dataroomID, parentPath)
			if err != nil {
				return Node{}, err
			}

			return orNotExist(fs.visible(nodes, name))
		}
	}
	fs.unlock()
	if listed && !fs.openNode(ctx, dataroomID, held) { // out of mu, as above
		refresh = false
	}

	return fs.lookupUnlisted(ctx, dataroomID, parentPath, name, entry, cached, refresh)
}

// lookupUnlisted is Lookup once the listing of the parent did not answer:
// from the Entry of the name when one is cached and trusted, else from the
// API. refresh tells that the listing is cached but no longer served, and
// recent enough to be refreshed rather than the name looked up on its own.
// The Entry's node is opened here, out of mu (see leaveSealed): one that
// does not open is no Entry, as when the store opened it itself.
func (fs *FS) lookupUnlisted(
	ctx context.Context, dataroomID, parentPath, name string, entry *Entry, cached, refresh bool,
) (Node, error) {
	key := listingKey(dataroomID, parentPath)
	if cached && entry != nil && !fs.openNode(ctx, dataroomID, entry.Node) {
		cached = false
	}
	if cached {
		recordEntryLookup(ctx, true)

		return fs.fromEntry(entry)
	}

	byName, err := fs.lookupsByName(ctx, dataroomID)
	if err != nil {
		return Node{}, err
	}
	if !byName {
		return fs.lookupListed(ctx, dataroomID, parentPath, name)
	}
	if refresh {
		// The listing is of no use as it is, which is a miss, but it is what
		// the refresh revalidates. The fetch is shared: the lookups of a
		// sweep that arrive together wait for one listing.
		recordListingLookup(ctx, "miss")
		nodes, err := fs.readDirRefreshed(ctx, dataroomID, parentPath)
		if err != nil {
			return Node{}, err
		}

		return orNotExist(fs.visible(nodes, name))
	}
	recordEntryLookup(ctx, false)
	fs.noteNameLookup(ctx, key, name)
	node, err := fs.lookupByName(ctx, dataroomID, parentPath, name)
	if errors.Is(err, service.ErrNoNameLookup) {
		// The API could not be told apart for this call after all.
		return fs.lookupListed(ctx, dataroomID, parentPath, name)
	}
	if err != nil {
		return Node{}, err
	}

	return fs.fromEntry(&Entry{Node: node})
}

// nameLookupRun is the run of lookups by name made in one folder that has no
// listing to answer them: n of them since the first, at since, counting a
// name looked up several times in a row once. last is the name of the latest.
//
// held is until when the run starts no listing of the folder: one Options.TTL
// from the listing it last started, whatever became of it, and
// listingRefreshWindow from the moment that listing found the folder larger
// than maxListingAhead. It outlives the run it was set in.
type nameLookupRun struct {
	since time.Time
	last  string
	n     int
	held  time.Time
}

const (
	// listAfterNameLookups is how many lookups by name in one folder, within
	// Options.TTL of the first and each of another name than the one before,
	// start the listing of that folder.
	listAfterNameLookups = 2
	// maxNameLookupRuns bounds the folders whose lookups are counted.
	maxNameLookupRuns = 1024
)

// noteNameLookup counts a lookup about to ask the API for one name of the
// folder key, which has no listing a lookup can use. From the
// listAfterNameLookups-th within Options.TTL of the first, the listing of the
// folder is fetched in the background, as an expired listing is refreshed
// (refresh slot, trace of its own, shared with whoever lists the folder
// meanwhile): the caller still goes by name and does not wait, and the
// lookups that come once the listing is cached are answered by it.
//
// A folder whose names are looked up one after the other is a folder being
// worked in: a shell loop creating files in a folder nobody listed costs one
// lookup per new name (the kernel looks a name up before creating it), each
// a round trip, for as long as it runs. With the listing cached, a name it
// does not hold is answered at once, and each creation edits it in place.
// A single lookup starts nothing: an isolated stat must not pay the listing
// of a large folder. Neither does one name looked up again and again (the
// retry of a mutation, a prompt that probes the same missing file): it says
// nothing of the other names of the folder.
//
// That fetch replays the edits made to the folder while it runs (see
// listingFetch.replays): each creation of the loop would otherwise discard
// the listing fetched during the lookup before it, forever.
//
// A folder gets one such listing per Options.TTL, counted from the moment it
// is started, whatever becomes of it (nameLookupRun.held): one that failed
// (timeout, 5xx, 403, folder gone) or whose answer was discarded by an
// invalidation is not started again by each lookup that follows, which would
// turn every lookup into a listing. The lookups go by name meanwhile, as they
// did before.
//
// A folder of more than maxListingAhead nodes gets none: the fetch gives up
// on the first page, which reports the size, stores nothing, and the folder
// is left alone for listingRefreshWindow (holdListingAheadLocked), the time
// for which a listing is taken to be worth refreshing. Only this fetch is
// capped: a folder somebody lists is listed whatever its size.
//
// The count of a folder is dropped when its listing is cached, and starts
// again after Options.TTL; the table is bounded (maxNameLookupRuns), the runs
// past the TTL that hold nothing back being dropped first, then all of them.
func (fs *FS) noteNameLookup(ctx context.Context, key ListingKey, name string) {
	if fs.opts.NoListingAhead {
		return
	}
	now := time.Now()
	ttl := fs.opts.ttl()

	fs.mu.Lock()
	defer fs.unlock()
	run, ok := fs.nameLookups[key]
	if !ok || now.Sub(run.since) >= ttl {
		if !ok && len(fs.nameLookups) >= maxNameLookupRuns {
			maps.DeleteFunc(fs.nameLookups, func(_ ListingKey, r nameLookupRun) bool {
				return now.Sub(r.since) >= ttl && !now.Before(r.held)
			})
			if len(fs.nameLookups) >= maxNameLookupRuns {
				clear(fs.nameLookups)
			}
		}
		run = nameLookupRun{since: now, held: run.held}
	}
	if run.n < listAfterNameLookups && (run.n == 0 || run.last != name) {
		run.n++
	}
	run.last = name
	start := run.n >= listAfterNameLookups && !now.Before(run.held)
	if start {
		run.held = now.Add(ttl)
	}
	fs.nameLookups[key] = run
	if start {
		fs.startFetchLocked(ctx, key, true, true)
	}
}

// holdListingAheadLocked keeps the lookups by name of the folder key from
// starting its listing for d (see noteNameLookup). The caller holds mu.
func (fs *FS) holdListingAheadLocked(key ListingKey, d time.Duration) {
	now := time.Now()
	run, ok := fs.nameLookups[key]
	if !ok {
		run.since = now
	}
	run.held = now.Add(d)
	fs.nameLookups[key] = run
}

// listingRefreshFactor is listingRefreshWindow in TTLs.
const listingRefreshFactor = 10

// listingRefreshWindow is for how long, once a cached listing is too old to
// be served (Options.TTL + Options.MaxStale), a lookup of one of its names
// still refreshes the listing instead of asking the API for the name alone.
//
// A folder listed that recently is a folder being browsed: a file manager
// that opens its 1,000 files one by one would otherwise cost one request per
// name as soon as the listing expires (a FUSE mount serves no expired
// listing), where one listing answers them all, and that listing is
// conditional: an unchanged dataroom answers 304, one round trip and nothing
// decrypted. Past the window the listing is taken for forgotten: an isolated
// stat must not pay the listing of a large folder, and goes by name.
func listingRefreshWindow(ttl time.Duration) time.Duration {
	return listingRefreshFactor * ttl
}

// LookupRemote is Lookup asked of the API whatever the cache holds: one
// request by name hash, which a cached listing or Entry saying the name is
// missing does not spare. It is for the caller about to rely on a name being
// free in a way the API will not check for it (an exclusive creation whose
// content is only sent later, see the FUSE driver): a name created elsewhere
// within Options.TTL of a listing, or Options.NegativeTTL of a lookup, is
// found.
//
// The answer is kept as an Entry. A cached listing of the folder that says
// otherwise (it lacks a name the API holds, or names one it no longer does)
// is known to be out of date and is dropped, with the entries of the folder.
//
// authoritative is false when the API was not asked: it has no lookup by
// name (a legacy API, or one that could not be told apart for this call) and
// listing the folder is not a price this pays. The answer is then the one of
// Lookup.
func (fs *FS) LookupRemote(
	ctx context.Context, dataroomID, parentPath, name string,
) (n Node, authoritative bool, err error) {
	byName, err := fs.lookupsByName(ctx, dataroomID)
	if err != nil {
		return Node{}, false, err
	}
	if byName {
		recordEntryLookup(ctx, false)
		node, err := fs.lookupByName(ctx, dataroomID, parentPath, name)
		switch {
		case errors.Is(err, service.ErrNoNameLookup):
			// The API could not be told apart for this call after all.
		case err != nil:
			return Node{}, false, err
		default:
			fs.dropListingUnless(dataroomID, parentPath, name, node != nil)
			n, err = fs.fromEntry(&Entry{Node: node})

			return n, true, err
		}
	}
	n, err = fs.Lookup(ctx, dataroomID, parentPath, name)

	return n, false, err
}

// dropListingUnless drops the cached listing of the folder at parentPath
// unless it agrees with what the API just answered about name: exists.
func (fs *FS) dropListingUnless(dataroomID, parentPath, name string, exists bool) {
	key := listingKey(dataroomID, parentPath)
	fs.mu.Lock()
	defer fs.unlock()
	if n, _, ok := fs.heldNodeLocked(sealedStoreCtx, key, name); ok && (n != nil) != exists {
		fs.invalidateLocked(key)
	}
}

// orNotExist turns the result of a search into the return of Lookup.
func orNotExist(n Node, found bool) (Node, error) {
	if !found {
		return Node{}, os.ErrNotExist
	}

	return n, nil
}

// visible returns the node called name in nodes, unless it is a symbolic
// link the FS hides.
func (fs *FS) visible(nodes []Node, name string) (Node, bool) {
	n, ok := FindNode(nodes, name)
	if ok && fs.opts.HideSymlinks && n.Type == TypeSymlink {
		return Node{}, false
	}

	return n, ok
}

// visibleNode is visible for the child a store answered for a name, nil when
// its listing does not hold it.
func (fs *FS) visibleNode(n *Node) (Node, bool) {
	if n == nil || (fs.opts.HideSymlinks && n.Type == TypeSymlink) {
		return Node{}, false
	}

	return *n, true
}

// fromEntry turns an entry into the return of Lookup: a negative one, or a
// symbolic link the FS hides, is a name that does not exist.
func (fs *FS) fromEntry(e *Entry) (Node, error) {
	if e.Node == nil || (fs.opts.HideSymlinks && e.Node.Type == TypeSymlink) {
		return Node{}, os.ErrNotExist
	}

	return *e.Node, nil
}

// lookupListed is Lookup through the listing of the parent, fetched when it
// is not cached: the only way on an API without the lookup by name.
func (fs *FS) lookupListed(ctx context.Context, dataroomID, parentPath, name string) (Node, error) {
	nodes, stale, err := fs.readDirStale(ctx, dataroomID, parentPath)
	for attempt := 0; err == nil; attempt++ {
		if n, ok := fs.visible(nodes, name); ok {
			return n, nil
		}
		if !stale || attempt > 0 {
			return Node{}, os.ErrNotExist
		}
		nodes, err = fs.readDirRefreshed(ctx, dataroomID, parentPath)
	}

	return Node{}, err
}

// lookupsByName reports whether a name of the dataroom can be looked up
// through the API on its own. Not when the listings come from Options.List
// (a test that fakes the listings fakes no lookup), nor on an API that has no
// such lookup, nor when the probe that tells the APIs apart failed: listing
// the folder works on both, and meets the same failure if it lasts. The error
// is the one of the session: listing the folder would meet it too, and return
// it as it is.
func (fs *FS) lookupsByName(ctx context.Context, dataroomID string) (bool, error) {
	if fs.opts.List != nil || fs.client == nil {
		return false, nil
	}
	sess, err := fs.Session(ctx, dataroomID)
	if err != nil {
		return false, err
	}

	supported, err := sess.SupportsNameLookup(ctx, fs.client, dataroomID)

	return supported && err == nil, nil
}

// entryLookup is a lookup by name in flight, shared by every caller that
// looks the same name up while it runs. node and err are written once,
// before done is closed.
type entryLookup struct {
	done chan struct{}
	// gen is the generation of the parent's listing when the lookup started:
	// a change of the folder made through this FS since then makes its answer
	// one nobody new may share, and one that is not kept.
	gen uint64
	// storeGen is the generation the store held for the parent's listing
	// then, storeEpoch the store it was read from and storable whether it
	// could be read: the answer is kept under it (MetaStore.PutEntryIf), so
	// that a change another process sharing the store made to the folder
	// meanwhile, which gen knows nothing of, is not answered by an entry that
	// predates it (a name deleted there found for a TTL, a name created
	// there missing for everyone).
	storeGen   uint64
	storeEpoch uint64
	storable   bool
	node       *Node // nil when the folder holds no such name
	err        error
}

// lookupByName looks name up in the folder at parentPath through the API,
// sharing the request with the lookups of that name already in flight, and
// keeps the answer as an Entry. It returns nil for a name the folder does not
// hold.
//
// The lookup is detached from the request that started it, like a listing
// (see fetchLocked): one client giving up cannot fail the others.
func (fs *FS) lookupByName(ctx context.Context, dataroomID, parentPath, name string) (*Node, error) {
	key := listingKey(dataroomID, parentPath)
	ek := entryKey(dataroomID, parentPath, name)

	fs.mu.Lock()
	f, ok := fs.lookups[ek]
	if !ok || f.gen != fs.genLocked(key) {
		f = &entryLookup{done: make(chan struct{}), gen: fs.genLocked(key)}
		fs.lookups[ek] = f
		detached := context.WithoutCancel(ctx)
		// As for a listing (see startFetchLocked): a store keyed by the
		// dataroom's name hash answers generation 0 until the session is
		// resolved, and the generation is then read again before the API is
		// asked. Lookup and LookupRemote resolve the session before they come
		// here, so this is the exception.
		_, keyed := fs.sessions.Peek(dataroomID)
		f.storeGen, f.storeEpoch, f.storable = fs.storeGenLocked(detached, key)
		go func() {
			fctx, cancel := context.WithTimeout(detached, fs.opts.fetchTimeout())
			if !keyed {
				if _, f.err = fs.Session(fctx, dataroomID); f.err == nil {
					fs.mu.Lock()
					if fs.genLocked(key) == f.gen {
						f.storeGen, f.storeEpoch, f.storable = fs.storeGenLocked(fctx, key)
					}
					fs.unlock()
				}
			}
			if f.err == nil {
				f.node, f.err = fs.findByName(fctx, dataroomID, parentPath, name)
			}
			cancel()

			fs.mu.Lock()
			if fs.lookups[ek] == f {
				delete(fs.lookups, ek)
			}
			if f.err == nil && fs.genLocked(key) == f.gen && (f.node != nil || fs.opts.NegativeTTL > 0) {
				fs.putEntryLocked(detached, ek, &Entry{Node: f.node, FetchedAt: time.Now()},
					f.storeGen, f.storable && f.storeEpoch == fs.storeEpoch)
			}
			fs.unlock()
			close(f.done)
		}()
	}
	fs.unlock()

	select {
	case <-f.done:
		return f.node, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// findByName resolves the folder at parentPath and asks the API for its child
// called name.
//
// The folder's ID comes from a cached listing or Entry, which can name a
// folder deleted elsewhere: the API then answers 404, or 410 while its purge
// is pending, and the lookup is made once more with the folder resolved
// afresh, as a listing is (see fetchNodes).
func (fs *FS) findByName(ctx context.Context, dataroomID, parentPath, name string) (*Node, error) {
	sess, err := fs.Session(ctx, dataroomID)
	if err != nil {
		return nil, err
	}
	trace.SpanFromContext(ctx).AddEvent("dataroom.resolve_path", trace.WithAttributes(
		telemetry.AttrDataroomID.String(dataroomID),
		telemetry.AttrPathDepth.Int(strings.Count(joinPath(parentPath, name), "/"))))

	node, err := fs.findByNameOnce(ctx, dataroomID, parentPath, name, sess)
	if errors.Is(err, api.ErrNotFound) && strings.Trim(parentPath, "/") != "" {
		grandParent, _ := SplitPath(parentPath)
		fs.InvalidateListing(dataroomID, grandParent)
		node, err = fs.findByNameOnce(ctx, dataroomID, parentPath, name, sess)
		if errors.Is(err, api.ErrNotFound) {
			err = os.ErrNotExist
		}
	}

	return node, err
}

// findByNameOnce is one attempt of findByName.
func (fs *FS) findByNameOnce(
	ctx context.Context, dataroomID, parentPath, name string, sess *service.DataroomSession,
) (*Node, error) {
	parentID, err := fs.resolveFolderID(ctx, dataroomID, parentPath)
	if errors.Is(err, os.ErrInvalid) {
		// The parent is a file, which has no children: not found, as its
		// listing answers (see fetchNodesOnce).
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	info, found, err := service.LookupNodeByName(ctx, fs.client, dataroomID, parentID, name, sess)
	if err != nil || !found {
		return nil, err
	}
	node := fs.nodeFromInfo(info)
	if fs.isHidden(node.ID) {
		// Being deleted in the background: absent already (see HideNode).
		return nil, nil
	}

	return &node, nil
}

// trustedEntryLocked returns the Entry a store answered for a name (see
// namedLocked) when it may still be trusted: Options.TTL for a node found,
// Options.NegativeTTL for a name found missing. An entry that holds a node
// hidden here is answered as a negative one. The caller holds mu.
func (fs *FS) trustedEntryLocked(e *Entry, ok bool) (*Entry, bool) {
	if !ok || e == nil {
		return nil, false
	}
	limit := fs.opts.ttl()
	if e.Node == nil {
		limit = fs.opts.NegativeTTL
	}
	if time.Since(e.FetchedAt) >= limit {
		return nil, false
	}
	if e.Node != nil && len(fs.hidden) > 0 && fs.hiddenLocked(e.Node.ID) {
		// Kept by another process sharing the store, which does not know the
		// node is being deleted here: the name is missing (see HideNode).
		return &Entry{FetchedAt: e.FetchedAt}, true
	}

	return e, true
}

// dropEntriesLocked forgets what single lookups learnt about the folder key
// names. It is called whenever something changes that folder through this FS
// (every edit and every invalidation of its listing, which each also bump its
// generation): an Entry may say a name is missing that was just created, or
// hold a node that was just written, renamed or deleted. A lookup in flight
// is covered by the generation it started under. The caller holds mu.
//
// A listing put in the cache drops them too (see fetchLocked): it says
// everything they say, and is the one consulted.
func (fs *FS) dropEntriesLocked(key ListingKey) {
	fs.wroteLocked(fs.store.DeleteEntries(storeCtx(), key.DataroomID, key.Path))
}

// recordEntryLookup counts a lookup the Entry cache answered, or one that
// goes to the API by name, with the listing lookups (hit, miss), and records
// it on the request span.
func recordEntryLookup(ctx context.Context, hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}
	recordCacheLookup(ctx, "entries", result)
}

// resolveFolderID resolves the folder at path to its node ID the way Lookup resolves
// a name, one component at a time, each from the cache when it is there:
// os.ErrNotExist when the path names nothing, os.ErrInvalid when it names
// something that is not a folder.
//
// service.resolvePath walks the tree with one uncached API listing per level on
// every upload; going through the cache reuses the listing a PROPFIND has
// almost always already fetched, and a component nothing cached costs one
// lookup by name, or one listing on an API without it.
//
// Returns (nil, nil) for the dataroom root, which has no node ID.
func (fs *FS) resolveFolderID(ctx context.Context, dataroomID, path string) (*string, error) {
	if strings.Trim(path, "/") == "" {
		return nil, nil
	}
	parent, name := SplitPath(path)
	n, err := fs.Lookup(ctx, dataroomID, parent, name)
	if err != nil {
		return nil, err
	}
	if n.Type != TypeDir {
		return nil, os.ErrInvalid
	}
	id := n.ID

	return &id, nil
}

// cachedFileID looks a file up by name in what the cache holds of a folder,
// without ever triggering a fetch: its listing when it is younger than the
// TTL, otherwise the Entry an earlier lookup or upload left for the name,
// when it may still be trusted. A miss simply means the caller takes its
// normal path, so this can only save round trips, never add one.
//
// Folders are not reported: a folder sharing the name is a genuine conflict,
// and the full upload path produces the right error for it.
func (fs *FS) cachedFileID(dataroomID, parentPath, name string) (string, bool) {
	key := listingKey(dataroomID, parentPath)
	fs.mu.Lock()
	defer fs.unlock()
	// Only the ID and the type are read: the node is not opened.
	n, meta, listed, e, cached := fs.namedLocked(sealedStoreCtx, key, name)
	if listed && time.Since(meta.FetchedAt) < fs.opts.ttl() {
		if n != nil {
			return n.ID, n.Type == TypeFile
		}

		return "", false
	}
	if cached && e.Node != nil {
		return e.Node.ID, e.Node.Type == TypeFile
	}

	return "", false
}
