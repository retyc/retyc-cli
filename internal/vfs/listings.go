package vfs

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
)

// A cached listing (Listing) carries the ETag the API answered it with (the
// dataroom's revision), "" when it sent none or when this process edited the
// listing in place since. An expired listing that has one is refreshed with
// If-None-Match: an unchanged dataroom answers 304, and the listing is kept
// for another TTL at the cost of one round trip, no page and no decryption.

// listingFetch is an in-flight listing shared by every caller that misses the
// cache for the same folder while it runs (single-flight). nodes/err are
// written once, before done is closed.
//
// A background refresh of an expired listing queues for a refresh slot before
// it starts. A request that misses the cache and joins it closes promoted
// (through promote) so the fetch starts at once: a request never waits behind
// the refresh queue, and a refresh holding a slot never waits for one held by
// another refresh queued behind it.
//
// refresh is the span context of the fetch's own trace when it runs as a
// background refresh (see startRefreshSpan), invalid otherwise.
//
// started and gen are written once, together and under FS.mu, when the fetch
// leaves the queue: gen is the generation of the listing it read then. From
// there on its answer may predate anything that bumps the generation, and a
// caller arriving after such a change must not share it (see fetchLocked).
//
// replays is set on a fetch started, or joined, to load the listing of a
// folder its lookups keep missing (see noteNameLookup). Such a fetch holds in
// edits, in order, the edits made in place to the folder through this FS
// since it started (see editLocked), for as long as nothing else changed its
// generation: its answer with them replayed is stored, and shared, where the
// answer of any other fetch is discarded by the first edit.
//
// What the replay guarantees is the existence of the names edited here: a
// name created here is listed, a name deleted here is not, whatever the API
// answered. It does not make the node of such a name as recent as the answer:
// when another client deleted and created again, or updated, a name edited
// here while the fetch ran, the replay puts back the node as this FS left it,
// over the newer one of the answer, until the listing is refreshed, one
// Options.TTL at most. That is the delay an edit made in place to a listing
// already cached has always had; a name not edited here is as the API
// answered.
//
// capped is set on the fetch noteNameLookup started itself, and on no other:
// that listing was asked for by nobody, so it gives up on a folder of more
// than maxListingAhead nodes (service.ErrFolderTooLarge) and stores nothing.
// A caller that needs the listing takes the cap off a fetch still queued and
// does not join one that runs (see fetchLocked). All three are written under
// FS.mu.
type listingFetch struct {
	done     chan struct{}
	promoted chan struct{}
	once     sync.Once
	started  bool
	gen      uint64
	replays  bool
	capped   bool
	// storeGen is the generation the store held for the listing when the
	// fetch started, read with gen and advanced by each edit this FS made
	// since that was the only write the store saw (see editedLocked): the
	// answer is stored under it (MetaStore.PutListingIf), so the write of
	// another process sharing the store, which gen knows nothing of, is not
	// overwritten by an answer that may predate it. storable is false once
	// that cannot be told any more: the generation could not be read, or a
	// write that was not ours went by. storeEpoch is the store it was read
	// from (see FS.storeEpoch): a store suspended or taken back since is
	// another one, whose generations are not these, and the answer is not
	// stored in it.
	storeGen   uint64
	storeEpoch uint64
	storable   bool
	edits      []func([]Node) []Node
	nodes      []Node
	// unchanged tells that nodes are those of the listing held, which the
	// API answered still current (304): the store is asked to renew it
	// rather than sent the same nodes again (see storeFetchedLocked).
	unchanged bool
	err       error
	refresh   trace.SpanContext
}

// currentLocked reports whether the answer of a fetch that started cannot
// predate a change made to the folder through this FS, gen being the
// generation its listing has now: every change since it started is an edit it
// holds, which is replayed on its answer. An invalidation is not one: the
// answer is then of no use. The caller holds FS.mu.
func (f *listingFetch) currentLocked(gen uint64) bool {
	return f.gen+uint64(len(f.edits)) == gen
}

// promote lets a queued background refresh start without a refresh slot.
func (f *listingFetch) promote() {
	f.once.Do(func() { close(f.promoted) })
}

// wait returns the result of the fetch, or the context error if ctx ends first.
func (f *listingFetch) wait(ctx context.Context) ([]Node, error) {
	select {
	case <-f.done:
		linkRefresh(ctx, f.refresh)

		return f.nodes, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReadDir returns the decrypted children of the folder at path in the
// dataroom, using a TTL cache. Symbolic links are part of it, whatever
// Options.HideSymlinks says. The slice is shared with the cache: the caller
// must not modify it.
//
// The nodes are complete: each is what Lookup returns for its name. That is
// the rule for a caller that lists a folder and then answers for its entries
// one by one (FUSE READDIRPLUS: the kernel bridge asks for every entry of the
// listing it just read, 1,000 times for 1,000 entries, cached or not). Such a
// caller keeps the slice with its directory handle and finds each entry in it
// with FindNode, which reads the slice and nothing else. It does not call
// Lookup for them: Lookup is the lookup of a name on its own, which may wait
// for a refresh or ask the API, and must never do so once per entry of a
// listing. Lookup is for everything else.
//
// A listing younger than the TTL is served as is. An expired one is still
// served for Options.MaxStale more, while a background refresh replaces it
// (stale-while-revalidate): a client walking a tree it has not touched for a
// while — PrivateBin's purge lists every folder of its store — is answered from
// memory instead of paying one API round trip per folder, in sequence.
//
// Cache misses are single-flighted: concurrent callers for the same folder (a
// file manager fires PROPFINDs in parallel) share one API listing instead of
// each running their own. The result is stored only if the listing was not
// invalidated while the fetch ran, so a mutation that lands mid-fetch wins.
func (fs *FS) ReadDir(ctx context.Context, dataroomID, path string) ([]Node, error) {
	nodes, _, err := fs.readDirStale(ctx, dataroomID, path)

	return nodes, err
}

// readDirStale is ReadDir, also reporting whether the listing was served
// expired (while a background refresh replaces it).
func (fs *FS) readDirStale(ctx context.Context, dataroomID, path string) (nodes []Node, stale bool, err error) {
	key := listingKey(dataroomID, path)

	fs.mu.Lock()
	if l, ok := fs.heldLocked(fs.leaveSealed(ctx), key); ok {
		age := time.Since(l.FetchedAt)
		fresh := age < fs.opts.ttl()
		if fresh || age < fs.opts.ttl()+fs.opts.MaxStale {
			if !fresh {
				fs.fetchLocked(ctx, key, true)
			}
			fs.unlock()
			// Its sealed nodes are opened out of mu (see leaveSealed). One
			// that does not open makes the listing a miss, as when the
			// store opened them itself.
			if l, ok = fs.openListing(ctx, dataroomID, l); ok {
				if fresh {
					recordListingLookup(ctx, "hit")

					return l.Nodes, false, nil
				}
				recordListingLookup(ctx, "stale")

				return l.Nodes, true, nil
			}
			fs.mu.Lock()
		}
	}
	f := fs.fetchLocked(ctx, key, false)
	fs.unlock()
	recordListingLookup(ctx, "miss")
	nodes, err = f.wait(ctx)

	return nodes, false, err
}

// readDirRefreshed returns a listing no older than the TTL, joining the
// refresh in flight (and starting it at once if it is queued) when the cached
// one has expired. A refresh older than the last change made to the folder
// here is not joined (see fetchLocked).
func (fs *FS) readDirRefreshed(ctx context.Context, dataroomID, path string) ([]Node, error) {
	key := listingKey(dataroomID, path)
	fs.mu.Lock()
	if l, ok := fs.heldLocked(fs.leaveSealed(ctx), key); ok && time.Since(l.FetchedAt) < fs.opts.ttl() {
		fs.unlock()
		if l, ok = fs.openListing(ctx, dataroomID, l); ok { // out of mu (see leaveSealed)
			return l.Nodes, nil
		}
		fs.mu.Lock()
	}
	f := fs.fetchLocked(ctx, key, false)
	fs.unlock()

	return f.wait(ctx)
}

// readDirFetched returns the listing of the folder as the API has it now,
// whatever is cached: it starts a fetch, or joins the one in flight, and waits
// for it. The cached listing is still what the fetch revalidates (an ETag
// that holds costs one round trip), and is replaced by the answer.
func (fs *FS) readDirFetched(ctx context.Context, dataroomID, path string) ([]Node, error) {
	fs.mu.Lock()
	f := fs.fetchLocked(ctx, listingKey(dataroomID, path), false)
	fs.unlock()

	return f.wait(ctx)
}

// recordListingLookup counts a listing cache lookup and records it on the
// request span. result is hit, stale (expired, served while refreshed) or miss.
func recordListingLookup(ctx context.Context, result string) {
	recordCacheLookup(ctx, "nodes", result)
}

// recordCacheLookup counts a lookup of the tree caches and records it on the
// request span. cache is the retyc.cache.name of the cache that answered or
// missed: nodes (a listing) or entries (a single name, see Lookup). Both feed
// one counter: what it tells is whether a lookup was answered without the API.
func recordCacheLookup(ctx context.Context, cache, result string) {
	metrics.VFSNodeCacheLookups.WithLabelValues(result).Inc()
	trace.SpanFromContext(ctx).AddEvent("cache.lookup", trace.WithAttributes(
		telemetry.AttrCacheName.String(cache),
		telemetry.AttrCacheHit.Bool(result != "miss"),
		telemetry.AttrCacheStale.Bool(result == "stale")))
}

// fetchLocked returns the listing of key in flight, or starts one. The fetch
// in flight is joined only while its answer cannot predate a change made to
// the folder through this FS: it is still queued (it will read the generation
// when it starts), or it started under the generation the listing has now, or
// it is one that replays the edits made in place since (listingFetch.replays)
// and nothing else changed the folder: a loop that creates files in a folder
// whose listing is on its way does not discard that listing once per file,
// and the listing arrives.
// Otherwise the folder was edited or invalidated while the API was answering,
// and a caller that comes after that change (rm f; stat f) must not be handed
// what the API said before it: a new fetch takes the place of the old one,
// which still answers whoever was waiting for it before the change, and whose
// answer is not stored. A
// background fetch (refresh of an expired listing) waits for a refresh slot
// unless a request joins it, and gets a trace of its own (startRefreshSpan); a
// request's fetch promotes any fetch it joins. A fetch the request starts
// itself runs in its trace; a background one it joins is linked from its span
// once done (linkRefresh). The caller holds mu.
//
// The fetch is shared by every caller of this folder: it is detached from the
// request that started it, so one aborted PROPFIND cannot fail the others. A
// failed refresh leaves the expired listing in place, except when the folder
// is gone: its listing is then dropped, so the next request answers not found
// instead of replaying it until it is past Options.MaxStale.
func (fs *FS) fetchLocked(ctx context.Context, key ListingKey, background bool) *listingFetch {
	return fs.startFetchLocked(ctx, key, background, false)
}

// maxListingAhead is the largest folder, in nodes, whose listing a run of
// lookups by name loads (see noteNameLookup). That listing is a bet nobody
// asked for: every page of it is a round trip and every name a decryption,
// and once cached it is refreshed in full at each expiry for as long as the
// folder is worked in, since an edit made in place drops its ETag. Past this
// size a lookup by name, one indexed request whatever the folder holds, is
// the cheaper answer. The cap also bounds the replay of the edits made while
// that listing was fetched, which runs under FS.mu and costs
// O(edits × nodes). Not configurable: 50 pages at most.
const maxListingAhead = 5000

// startFetchLocked is fetchLocked, ahead telling the fetch of noteNameLookup
// from every other: the one it starts replays the edits made meanwhile and is
// capped (see listingFetch), and it marks the one it joins as replaying
// without capping it, since somebody needs that listing whole.
//
// A capped fetch cannot answer the others: one still queued has its cap taken
// off, one that runs is left to finish and a fetch without cap takes its
// place. Only the fetch in place stores its answer, so the capped one cannot
// then overwrite a listing fetched after it. The caller holds mu.
func (fs *FS) startFetchLocked(ctx context.Context, key ListingKey, background, ahead bool) *listingFetch {
	if f, ok := fs.inflight[key]; ok && (!f.started || f.currentLocked(fs.genLocked(key))) {
		if !ahead && f.capped && !f.started {
			f.capped = false
		}
		if ahead || !f.capped {
			if !background {
				f.promote()
			}
			f.replays = f.replays || ahead

			return f
		}
	}
	f := &listingFetch{done: make(chan struct{}), promoted: make(chan struct{}), replays: ahead, capped: ahead}
	if !background {
		f.promote()
	}
	fs.inflight[key] = f
	slots := fs.slots

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
		// Options.ListConcurrency shows as the gap after the linked request.
		fctx := detached
		var span trace.Span
		if background {
			fctx, span = startRefreshSpan(fctx, link, "nodes")
			span.SetAttributes(telemetry.AttrDataroomID.String(key.DataroomID))
			f.refresh = span.SpanContext()
		}
		// The generation is read when the fetch starts, not when it was
		// queued: a mutation made through this process before that is in the
		// API's answer, so only one landing during the fetch must discard it.
		// The listing to revalidate is read with it: an edit made in place
		// after that bumps the generation, and the answer is discarded.
		fs.mu.Lock()
		gen := fs.genLocked(key)
		f.started, f.gen = true, gen
		limit := 0
		if f.capped {
			limit = maxListingAhead
		}
		// A store that names its keys by the dataroom's name hash (see
		// metastore.Codec) knows nothing of a dataroom whose session is not
		// resolved: it answers generation 0 and holds no listing.
		_, keyed := fs.sessions.Peek(key.DataroomID)
		var held *Listing
		read := func() {
			// The store's generation first, then what it holds: a write
			// landing between the two leaves a generation the answer is not
			// stored under.
			f.storeGen, f.storeEpoch, f.storable = fs.storeGenLocked(fctx, key)
			// Only a listing that carries an ETag is of use to the fetch,
			// which revalidates it: its nodes are not read for nothing.
			held = nil
			if meta, ok := fs.metaLocked(fctx, key); ok && meta.ETag != "" && fs.opts.List == nil {
				held, _ = fs.heldLocked(fs.leaveSealed(fctx), key)
			}
		}
		read()
		fs.unlock()
		fctx, cancel := context.WithTimeout(fctx, fs.opts.fetchTimeout())
		var sessErr error
		if !keyed && fs.opts.List == nil {
			// The first listing of a dataroom: the session is resolved here,
			// and the store read again before the API is asked, or the answer
			// would be stored under a generation another process sharing the
			// store has long left, that is never. A session that does not
			// resolve is the error of the listing, which is not asked.
			if _, sessErr = fs.Session(fctx, key.DataroomID); sessErr == nil {
				fs.mu.Lock()
				if f.currentLocked(fs.genLocked(key)) {
					// Whatever this FS did to the folder meanwhile is in the
					// generation read now, and in the answer to come.
					read()
				}
				fs.unlock()
			}
		}
		if held != nil {
			// Its sealed nodes are opened out of mu (see leaveSealed): a
			// listing whose nodes do not all open is none, as when the store
			// opened them itself. A 304 hands these nodes on and stores them
			// back, by name.
			var ok bool
			if held, ok = fs.openListing(fctx, key.DataroomID, held); !ok {
				held = nil
			}
		}
		var etag string
		if fs.opts.List != nil {
			var infos []service.DataroomNodeInfo
			infos, f.err = fs.opts.List(fctx, key.DataroomID, key.Path)
			f.nodes = fs.nodesFromInfos(infos)
			if f.err == nil && limit > 0 && len(infos) > limit {
				f.nodes, f.err = nil, service.ErrFolderTooLarge
			}
		} else if f.err = sessErr; sessErr == nil {
			f.nodes, etag, f.unchanged, f.err = fs.fetchNodes(fctx, key, held, limit)
		}
		cancel()
		tooLarge := errors.Is(f.err, service.ErrFolderTooLarge)
		if span != nil {
			if !tooLarge { // a listing given up on purpose is not a failure
				telemetry.RecordError(span, f.err)
			}
			span.End()
		}

		fs.mu.Lock()
		// A node being deleted in the background is absent whatever the API
		// still answers (see HideNode).
		f.nodes, etag = fs.withoutHiddenLocked(f.nodes, etag)
		inPlace := fs.inflight[key] == f
		if inPlace {
			// Not when a newer fetch took its place (see above).
			delete(fs.inflight, key)
		}
		if tooLarge {
			fs.holdListingAheadLocked(key, listingRefreshWindow(fs.opts.ttl()))
		}
		if inPlace && f.currentLocked(fs.genLocked(key)) {
			switch {
			case f.err == nil:
				if len(f.edits) > 0 {
					// The answer may predate the edits made here meanwhile:
					// they are replayed on a copy (a 304 answers the cached
					// slice, which is shared with the callers of ReadDir).
					// Each is the change of one name, the same whether or not
					// the answer already shows it. The listing no longer is
					// the one the API gave the ETag for.
					nodes := slices.Clone(f.nodes)
					for _, edit := range f.edits {
						nodes = edit(nodes)
					}
					f.nodes, etag = nodes, ""
				}
				// Stored only under the generation the store had when the
				// listing was asked for, a 304 that renews the held nodes
				// included: gen above tells what this FS did meanwhile, not
				// what another process sharing the store wrote.
				if !fs.storeFetchedLocked(context.WithoutCancel(fctx), key, f, etag) {
					break
				}
				// The listing says everything the single lookups learnt about
				// this folder, and is the one consulted from now on.
				fs.dropEntriesLocked(key)
				delete(fs.nameLookups, key)
			case errors.Is(f.err, os.ErrNotExist):
				fs.wroteLocked(fs.store.DeleteListing(context.WithoutCancel(fctx), key))
				fs.dropEntriesLocked(key)
			}
		}
		fs.unlock()
		close(f.done)
	}()

	return f
}

// storeFetchedLocked stores the answer of f as the listing of key, unless the
// store holds another generation of it than the one f expects (see
// listingFetch.storeGen), and reports whether it did. ctx only carries the
// trace of the fetch, it must not end. The caller holds mu.
func (fs *FS) storeFetchedLocked(ctx context.Context, key ListingKey, f *listingFetch, etag string) bool {
	if !f.storable || f.storeEpoch != fs.storeEpoch {
		return false
	}
	now := time.Now()
	if f.unchanged && etag != "" {
		// A 304: the store holds these very nodes as long as its generation
		// is the one they were read under, and only has to be told they are
		// fresh again. An ETag emptied since means the nodes are no longer
		// those held (edits replayed, a node hidden here): they are put. So
		// are they when the listing left the store meanwhile, the generation
		// then being the one the renewal left.
		renewed, err := fs.store.RenewListingIf(ctx, key, etag, now, f.storeGen)
		fs.wroteLocked(err)
		if err != nil {
			return false
		}
		if renewed {
			return true
		}
	}
	stored, err := fs.store.PutListingIf(ctx, key,
		&Listing{Nodes: f.nodes, FetchedAt: now, ETag: etag}, f.storeGen)
	fs.wroteLocked(err)

	return stored && err == nil
}

// fetchNodes is the real listing behind ReadDir: cached session + one API
// listing of the folder.
//
// The folder ID comes from its parent's listing through resolveFolderID, which is
// cached and single-flighted, so a miss costs the folder's own listing instead
// of a walk from the root (service.resolvePath lists every level again, often
// while a concurrent PROPFIND is fetching the very same listings). Names are
// matched literally: paths are client names, never glob patterns.
//
// The parent listing can be expired (see ReadDir) and name a folder deleted
// elsewhere: listing its children then answers 404, or 410 while its purge is
// pending, and the listing is retried once against a fresh parent listing. As
// for a deletion or a rename, a folder moved elsewhere within that window is
// listed at its new location until the parent listing is refreshed.
//
// held is the listing of the folder still in cache, nil when there is none.
// When it carries an ETag the listing is conditional: a dataroom that has not
// changed since answers 304 and held's nodes are returned as they are, with
// the same ETag. A folder deleted elsewhere changed the dataroom, so it never
// answers 304. The ETag returned is the one to keep with the nodes.
//
// limit, when not 0, is the size past which the folder is not listed
// (service.ErrFolderTooLarge, see maxListingAhead). A 304 is not subject to
// it: the nodes are held already.
//
// unchanged tells that the nodes returned are held's, on a 304.
func (fs *FS) fetchNodes(ctx context.Context, key ListingKey, held *Listing, limit int) (
	nodes []Node, etag string, unchanged bool, err error,
) {
	sess, err := fs.Session(ctx, key.DataroomID)
	if err != nil {
		return nil, "", false, err
	}
	var heldETag string
	if held != nil {
		heldETag = held.ETag
	}

	nodes, etag, err = fs.fetchNodesOnce(ctx, key, sess, heldETag, limit)
	if errors.Is(err, api.ErrNotModified) {
		return held.Nodes, held.ETag, true, nil
	}
	if errors.Is(err, api.ErrNotFound) && strings.Trim(key.Path, "/") != "" {
		grandParent, _ := SplitPath(key.Path)
		fs.InvalidateListing(key.DataroomID, grandParent)
		nodes, etag, err = fs.fetchNodesOnce(ctx, key, sess, "", limit)
		if errors.Is(err, api.ErrNotFound) {
			err = os.ErrNotExist
		}
	}

	return nodes, etag, false, err
}

// fetchNodesOnce resolves the folder ID of key and lists its children, unless
// the dataroom still answers etag (api.ErrNotModified), or the folder holds
// more than limit nodes (service.ErrFolderTooLarge; 0 for no limit).
func (fs *FS) fetchNodesOnce(
	ctx context.Context, key ListingKey, sess *service.DataroomSession, etag string, limit int,
) ([]Node, string, error) {
	folderID, err := fs.resolveFolderID(ctx, key.DataroomID, key.Path)
	if errors.Is(err, os.ErrInvalid) {
		// The path names a file, which has no children: not found, where
		// ErrInvalid would reach a WebDAV client as a 405.
		return nil, "", os.ErrNotExist
	}
	if err != nil {
		return nil, "", err
	}
	if folderID != nil {
		trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrNodeID.String(*folderID))
	}
	infos, newETag, err := service.ListNodesByIDWithin(ctx, fs.client, key.DataroomID, folderID, sess, etag, limit)

	return fs.nodesFromInfos(infos), newETag, err
}

// InvalidateListing drops the cached listing of the folder at path, and what
// single lookups learnt about its names (see Lookup).
// Called after a mutation the listing cannot be edited for, or when an answer
// of the API shows the listing no longer describes the folder, so that the
// next request for it fetches fresh data from the API.
//
// It also bumps the listing's generation so that a fetch already in flight —
// which may have been answered by the API before the mutation landed — is not
// stored on completion (see ReadDir). Without that, a read racing a write from
// another client could pin a pre-mutation listing for a whole TTL.
func (fs *FS) InvalidateListing(dataroomID, path string) {
	fs.mu.Lock()
	defer fs.unlock()
	fs.invalidateLocked(listingKey(dataroomID, path))
}

// invalidateLocked is InvalidateListing for a caller that holds mu.
func (fs *FS) invalidateLocked(key ListingKey) {
	fs.wroteLocked(fs.store.DeleteListing(storeCtx(), key))
	fs.dropEntriesLocked(key)
	fs.bumpGenLocked(key)
}

// invalidateSubtree drops the cached listing of the folder at path and of
// every folder below it, with what single lookups learnt about their names.
// Deleting or renaming a folder must not leave its own
// listing and its sub-listings cached: a folder re-created under the same name
// within the TTL would otherwise serve the ghost children of the deleted tree.
// Harmless for a file (nothing is cached below it).
func (fs *FS) invalidateSubtree(dataroomID, path string) {
	fs.mu.Lock()
	defer fs.unlock()
	fs.invalidateSubtreeLocked(dataroomID, path)
}

// invalidateSubtreeLocked is invalidateSubtree for a caller that holds mu.
//
// Only the fetches in flight need their generation bumped: a listing that is
// cached and not being fetched has no answer on its way to discard. The same
// goes for the lookups by name in flight below path, whose answer must not be
// kept as an Entry either.
func (fs *FS) invalidateSubtreeLocked(dataroomID, path string) {
	root := listingKey(dataroomID, path)
	prefix := strings.TrimSuffix(root.Path, "/") + "/"
	fs.wroteLocked(fs.store.DeleteSubtree(storeCtx(), dataroomID, root.Path))
	fs.wroteLocked(fs.store.DeleteEntriesBelow(storeCtx(), dataroomID, root.Path))
	fs.bumpGenLocked(root)
	below := make(map[ListingKey]struct{})
	for key := range fs.inflight {
		if key.DataroomID == dataroomID && strings.HasPrefix(key.Path, prefix) {
			below[key] = struct{}{}
		}
	}
	for ek := range fs.lookups {
		if ek.DataroomID == dataroomID && strings.HasPrefix(ek.ParentPath, prefix) {
			below[ListingKey{DataroomID: dataroomID, Path: ek.ParentPath}] = struct{}{}
		}
	}
	for key := range below {
		fs.bumpGenLocked(key)
	}
}
