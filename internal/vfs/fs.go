package vfs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// FS presents the datarooms of one user as trees of folders, addressed by
// dataroom ID and path, over an API addressed by node ID. It caches the list
// of datarooms, folder listings, the results of single lookups and dataroom
// sessions, and is safe for concurrent use.
//
// Two things make the cache, kept apart (see metastore):
//
//   - the data, in Options.Store: the listings, the entries (the result of
//     looking one name up, see Lookup), the list of datarooms;
//   - the coordination around it, in memory in the FS: the generation of
//     each listing, the fetches and lookups in flight, the refresh slots, the
//     sessions.
//
// mu covers both: a listing is read, written or dropped in the store with mu
// held, so that a generation check and the write that depends on it are one
// step. A fetch from the API never runs under mu.
//
// A path is absolute, "/" being the dataroom root; a listing is cached under
// the clean form of the path its caller gave (see listingKey).
type FS struct {
	client *api.Client
	opts   Options

	// ctx is the context the files opened with Open download on: it ends
	// with Close.
	ctx    context.Context
	cancel context.CancelFunc

	// sessions holds one resolved session per dataroom for the life of the
	// process (no TTL, single-flight: one resolution per dataroom at a time, see
	// service.SessionCache).
	sessions service.SessionCache

	mu sync.Mutex
	// store keeps the listings: shared, the configured store, or a private
	// in-memory one while shared is suspended after it failed (see
	// wroteLocked), until resume, the zero time otherwise. storeEpoch counts
	// the changes of store: a generation read from one says nothing of the
	// other (see storeGenLocked).
	store      metastore.MetaStore
	shared     metastore.MetaStore
	resume     time.Time
	storeEpoch uint64
	// storeReports is what unlock has to tell the operator of the store: its
	// suspension, its return.
	storeReports []string
	// now is the clock the suspension of the store goes by; tests replace it.
	now func() time.Time
	// gen is bumped by every invalidation or edit of that listing (see
	// bumpGenLocked); genFloor is what a listing it does not hold reads,
	// genMax the highest value it ever held, genSweepAt the size at which it
	// is next pruned (see pruneGensLocked).
	gen        map[ListingKey]uint64
	genFloor   uint64
	genMax     uint64
	genSweepAt int
	inflight   map[ListingKey]*listingFetch // listings currently queued or running
	lookups    map[EntryKey]*entryLookup    // lookups by name currently running (see Lookup)
	// nameLookups counts, per folder, the lookups that went to the API by
	// name for want of a listing, and holds until when they start no listing
	// of it (see noteNameLookup).
	nameLookups map[ListingKey]nameLookupRun
	// slots bounds the background refreshes running at once.
	slots chan struct{}
	// uploadSlots bounds the uploads sending at once (see
	// Options.UploadConcurrency).
	uploadSlots chan struct{}
	// hidden holds the nodes HideNode made absent, by ID; hiddenPruned is
	// when those nothing can name any more were last forgotten.
	hidden       map[string]hiddenUntil
	hiddenPruned time.Time

	// quota holds each dataroom's storage counters for the listing TTL (see
	// Quota).
	quotaMu sync.Mutex
	quota   map[string]quotaEntry

	// chunkSizes remembers the chunk size of the versions read (see file).
	chunkSizes chunkSizes
	// sealed remembers what the sealed nodes read from the store decrypt to
	// (see sealedMemo). It has its own mutex, never mu.
	sealed sealedMemo
	// openLater is set for a store that may hold sealed nodes (one bound to
	// the codec): what is read from it under mu is read unopened, and opened
	// once mu is let go (see leaveSealed, openListing). Never for a memstore,
	// which costs nothing then.
	openLater bool
	// openHook, when set (tests), is called at the start of every
	// codec.Open, which fails with its error.
	openHook func() error

	// locks holds the API locks taken through Locks.
	locks LockManager

	// newSpoolFile creates the local file of a spool (see OpenSpool); nil
	// means createSpoolFile. Tests replace it to fail its writes.
	newSpoolFile func(dir string) (spoolFile, error)

	// datarooms resolves the names of the user's datarooms; its list is kept
	// in the store (see fsDataroomStore).
	datarooms *DataroomCache
}

// New returns an FS over client. client may be nil when Options.List is set
// and no session is resolved through the API (tests).
func New(client *api.Client, opts Options) *FS {
	var fs *FS
	store := opts.Store
	if store == nil {
		store = newMemStore(opts, func() time.Time { return fs.now() })
	}

	ctx, cancel := context.WithCancel(context.Background())
	fs = &FS{
		client:      client,
		opts:        opts,
		ctx:         ctx,
		cancel:      cancel,
		store:       store,
		shared:      store,
		now:         time.Now,
		gen:         make(map[ListingKey]uint64),
		genSweepAt:  minGenSweep,
		inflight:    make(map[ListingKey]*listingFetch),
		lookups:     make(map[EntryKey]*entryLookup),
		nameLookups: make(map[ListingKey]nameLookupRun),
		hidden:      make(map[string]hiddenUntil),
		slots:       make(chan struct{}, opts.listConcurrency()),
		uploadSlots: make(chan struct{}, opts.uploadConcurrency()),
		quota:       make(map[string]quotaEntry),
	}
	fs.locks = LockManager{fs: fs, locks: make(map[string]*heldLock)}
	if b, ok := store.(metastore.Binder); ok {
		b.Bind(codec{fs})
		fs.openLater = true
	}
	fs.datarooms = newDataroomCache(fs.listDatarooms, opts, fsDataroomStore{fs})

	return fs
}

// minGenSweep is the size of FS.gen below which it is never pruned.
const minGenSweep = 1024

// genLocked returns the generation of the listing of key in this process:
// what a fetch or a lookup by name reads when it starts and compares when it
// ends (see listingFetch.currentLocked). The caller holds mu.
func (fs *FS) genLocked(key ListingKey) uint64 {
	if gen, ok := fs.gen[key]; ok {
		return gen
	}

	return fs.genFloor
}

// bumpGenLocked moves the generation of the listing of key by one, which a
// fetch replaying edits counts on (see listingFetch.currentLocked), and
// prunes the map once it has doubled since it was last pruned. The caller
// holds mu.
func (fs *FS) bumpGenLocked(key ListingKey) {
	gen := fs.genLocked(key) + 1
	fs.gen[key] = gen
	fs.genMax = max(fs.genMax, gen)
	if len(fs.gen) >= fs.genSweepAt {
		fs.pruneGensLocked()
	}
}

// pruneGensLocked forgets the generations nobody can compare any more, so
// that FS.gen holds the folders being fetched or looked up, not every folder
// this process ever edited or invalidated.
//
// A generation is compared by the fetch in place for its listing
// (FS.inflight) and the lookups by name in flight in its folder (FS.lookups):
// those keep theirs, materialized at the floor when they read it there. Every
// other key goes, and the floor is raised above every value held so far: a
// fetch or a lookup that was superseded, which no map holds, can then never
// find the value it read again, and stores nothing, as it would not have
// anyway. O(len(gen) + inflight + lookups), run when the map has doubled:
// amortized O(1) per bump. The caller holds mu.
func (fs *FS) pruneGensLocked() {
	busy := make(map[ListingKey]struct{}, len(fs.inflight)+len(fs.lookups))
	for key := range fs.inflight {
		busy[key] = struct{}{}
	}
	for ek := range fs.lookups {
		busy[ListingKey{DataroomID: ek.DataroomID, Path: ek.ParentPath}] = struct{}{}
	}
	for key := range busy {
		fs.gen[key] = fs.genLocked(key)
	}
	for key := range fs.gen {
		if _, ok := busy[key]; !ok {
			delete(fs.gen, key)
		}
	}
	fs.genFloor = fs.genMax + 1
	fs.genMax = fs.genFloor
	fs.genSweepAt = max(2*len(fs.gen), minGenSweep)
}

// newMemStore returns the in-memory store of an FS built with opts: it keeps
// what it holds for the lifetimes the Redis store gives the same values (see
// cmd's newMetaStore), so that a folder nobody reads any more, deleted or
// renamed elsewhere included, leaves it: a listing for ListingRetention, an
// entry for the TTL or the negative TTL, a generation, once its listing is
// gone, for twice the longest a fetch that read it may take (FetchTimeout,
// the margin for the waits on FS.mu around it). Its lifetimes go by now,
// read under FS.mu like the store itself.
func newMemStore(opts Options, now func() time.Time) *memstore.Store {
	negative := opts.NegativeTTL
	if negative <= 0 {
		// No negative entry is kept then; should one be, it goes with the
		// positive ones.
		negative = opts.ttl()
	}

	return memstore.NewWithOptions(memstore.Options{
		ListingLife:       ListingRetention(opts.TTL, opts.MaxStale),
		EntryLife:         opts.ttl(),
		NegativeEntryLife: negative,
		GenerationLife:    2 * opts.fetchTimeout(),
		Now:               now,
	})
}

// logf reports a message to the operator through Options.Logf, if any.
func (fs *FS) logf(format string, args ...any) {
	if fs.opts.Logf != nil {
		fs.opts.Logf(format, args...)
	}
}

// Close closes the store, forgets the chunk sizes learnt and stops the
// downloads of the files still open, whose reads then fail with ErrClosed.
// Listing fetches still in flight complete on their own. The API locks are
// not released here: whoever runs LockManager.Run ends it.
func (fs *FS) Close() error {
	fs.cancel()
	fs.chunkSizes.reset()
	fs.sealed.reset()
	fs.mu.Lock()
	defer fs.unlock()
	// The private store of a suspension holds nothing to release.
	return fs.shared.Close()
}

// Session returns the session for dataroomID, resolved on first access and
// cached for the life of the process. Caching avoids, per listing or
// download, a GetDataroom and the AGE decryptions of the session key (from
// Options.Identity: no scrypt, no user-key fetch).
func (fs *FS) Session(ctx context.Context, dataroomID string) (*service.DataroomSession, error) {
	return fs.sessions.Get(ctx, dataroomID, fs.resolveSession)
}

// SessionsCached returns the number of dataroom sessions held unlocked.
func (fs *FS) SessionsCached() int { return fs.sessions.Len() }

// SeedSession makes sess the session of dataroomID without resolving it:
// tests warm the cache with it, as would a front end that already holds the
// session.
func (fs *FS) SeedSession(dataroomID string, sess *service.DataroomSession) {
	fs.sessions.Store(dataroomID, sess)
}

// resolveSession performs the actual resolution (see Options.Session).
func (fs *FS) resolveSession(ctx context.Context, dataroomID string) (*service.DataroomSession, error) {
	if fs.opts.Session != nil {
		return fs.opts.Session(ctx, dataroomID)
	}
	if fs.opts.Identity == nil {
		return nil, errors.New("no identity to resolve the dataroom session with")
	}

	return service.GetDataroomSessionWithIdentity(ctx, fs.client, dataroomID, fs.opts.Identity)
}

// Datarooms returns the datarooms the user can reach, sorted by the name each
// is presented under (DataroomInfo.DisplayName: its title, with a suffix that
// tells apart the datarooms sharing one), in a slice of the caller's own.
//
// The list is cached like a listing: served for Options.TTL, then served
// expired for Options.MaxStale more while one background fetch replaces it,
// then waited for (see DataroomCache).
func (fs *FS) Datarooms(ctx context.Context) ([]DataroomInfo, error) {
	return fs.datarooms.List(ctx)
}

// DataroomByName returns the ID of the dataroom presented under displayName,
// or ErrNotExist. A name missing from an expired list waits for its refresh:
// it may be a dataroom created since. The request span is tagged with the ID
// found, never with the name.
func (fs *FS) DataroomByName(ctx context.Context, displayName string) (string, error) {
	return fs.datarooms.IDForName(ctx, displayName)
}

// SeedDatarooms makes items the list of datarooms, as if just fetched: tests
// warm the cache with it, as would a front end that already holds the list.
func (fs *FS) SeedDatarooms(items []Dataroom) {
	fs.datarooms.seed(items)
}

// listDatarooms lists the user's datarooms (see Options.ListDatarooms).
func (fs *FS) listDatarooms(ctx context.Context) ([]Dataroom, error) {
	if fs.opts.ListDatarooms != nil {
		return fs.opts.ListDatarooms(ctx)
	}
	if fs.client == nil {
		return nil, errors.New("no API client to list the datarooms with")
	}
	result, err := service.ListDatarooms(ctx, fs.client)
	if err != nil {
		return nil, err
	}
	items := make([]Dataroom, len(result.Items))
	for i, dr := range result.Items {
		items[i] = Dataroom{ID: dr.ID, Title: dr.Title, Role: dr.Role}
	}

	return items, nil
}

// fsDataroomStore keeps the dataroom list of an FS in its store, under mu
// like every other access to it. The cache calls it with its own mutex held
// and the FS never calls the cache under mu, so the two never deadlock.
type fsDataroomStore struct{ fs *FS }

func (s fsDataroomStore) datarooms(ctx context.Context) (*DataroomList, bool) {
	s.fs.mu.Lock()
	defer s.fs.unlock()
	list, ok, err := s.fs.store.GetDatarooms(ctx)
	s.fs.readLocked(ctx, err)

	return list, err == nil && ok && list != nil
}

func (s fsDataroomStore) putDatarooms(list *DataroomList) {
	s.fs.mu.Lock()
	defer s.fs.unlock()
	if err := s.fs.store.PutDatarooms(storeCtx(), list); err != nil {
		// The store is suspended for an empty one, which takes the list.
		s.fs.wroteLocked(err)
		_ = s.fs.store.PutDatarooms(storeCtx(), list)
	}
}

// unlock releases mu, then reports through Options.Logf what was noted under
// it (see wroteLocked). Options.Logf is the caller's code: it is never called
// with mu held, where it could block every request or call back into the FS.
// Every release of mu goes through here, which is also where a suspended
// store is taken back once its time is over: the operation that follows finds
// it in place.
func (fs *FS) unlock() {
	if !fs.resume.IsZero() && !fs.now().Before(fs.resume) {
		fs.store, fs.resume = fs.shared, time.Time{}
		fs.storeEpoch++
		fs.storeReports = append(fs.storeReports, "listing cache: back on the configured store")
	}
	reports := fs.storeReports
	fs.storeReports = nil
	fs.mu.Unlock()
	for _, report := range reports {
		fs.logf("%s", report)
	}
}

// heldLocked returns the listing stored under key, whatever its age, without
// the nodes hidden here (see HideNode). A store that fails to answer is a
// miss: the listing is then fetched from the API, which is what the cache
// stands in for. The caller holds mu.
func (fs *FS) heldLocked(ctx context.Context, key ListingKey) (*Listing, bool) {
	l, ok, err := fs.store.GetListing(ctx, key)
	fs.readLocked(ctx, err)
	if err != nil || !ok || l == nil {
		return nil, false
	}
	// A store shared with other processes holds what they listed, and they
	// know nothing of the nodes hidden here. The stored slice is not written
	// through, nor the listing handed out: the filter builds its own.
	if nodes, etag := fs.withoutHiddenLocked(l.Nodes, l.ETag); len(nodes) != len(l.Nodes) {
		return &Listing{Nodes: nodes, FetchedAt: l.FetchedAt, ETag: etag}, true
	}

	return l, true
}

// metaLocked returns what the store holds of the listing of key besides its
// nodes, whatever its age: the question of a caller that needs its age or its
// ETag, which must not cost it the whole folder. A store that fails to answer
// is a miss. The caller holds mu.
func (fs *FS) metaLocked(ctx context.Context, key ListingKey) (metastore.ListingMeta, bool) {
	meta, ok, err := fs.store.ListingMeta(ctx, key)
	fs.readLocked(ctx, err)
	if err != nil || !ok {
		return metastore.ListingMeta{}, false
	}

	return meta, true
}

// heldNodeLocked returns the child called name of the listing stored under
// key, nil when the listing does not name it or when the node is hidden here
// (see HideNode), without loading the listing; listed is false when there is
// no listing, or when the store fails to answer. The caller holds mu.
func (fs *FS) heldNodeLocked(ctx context.Context, key ListingKey, name string) (
	node *Node, meta metastore.ListingMeta, listed bool,
) {
	node, meta, listed, err := fs.store.GetNode(ctx, key, name)
	fs.readLocked(ctx, err)
	if err != nil || !listed {
		return nil, metastore.ListingMeta{}, false
	}

	return fs.unlessHiddenLocked(node), meta, true
}

// unlessHiddenLocked is node, or nil when it is hidden here (see HideNode).
// The caller holds mu.
func (fs *FS) unlessHiddenLocked(node *Node) *Node {
	if node != nil && len(fs.hidden) > 0 && fs.hiddenLocked(node.ID) {
		return nil
	}

	return node
}

// namedLocked is heldNodeLocked(key, name) and the Entry of the same name,
// when it may still be trusted (see trustedEntryLocked), read together
// (MetaStore.GetNamed): one round trip of a store outside the process where
// a lookup that goes from the listing to the entry made two.
// Each half is what its own method answers; a store that fails to answer is
// a miss of both. The caller holds mu.
func (fs *FS) namedLocked(ctx context.Context, key ListingKey, name string) (
	node *Node, meta metastore.ListingMeta, listed bool, entry *Entry, cached bool,
) {
	node, meta, listed, e, ok, err := fs.store.GetNamed(ctx, key, name)
	fs.readLocked(ctx, err)
	if err != nil {
		return nil, metastore.ListingMeta{}, false, nil, false
	}
	entry, cached = fs.trustedEntryLocked(e, ok)
	if !listed {
		return nil, metastore.ListingMeta{}, false, entry, cached
	}

	return fs.unlessHiddenLocked(node), meta, true, entry, cached
}

// wroteLocked takes the outcome of a write to the store. A store that fails
// one can no longer be trusted: it may still hold the listing an invalidation
// meant to drop, or lack the edit a mutation made, and would serve it as
// current. It is suspended: the FS goes on with an empty in-memory store of
// its own, so everything is fetched again from the API, for Options.TTL +
// Options.MaxStale, the time after which nothing this FS could not drop from
// the configured store is served by anyone as current. The configured store
// is then taken back (see unlock), the private one being thrown away with
// what it holds; should it fail again, it is suspended again. memstore never
// fails; this is the rule a store outside the process falls under, which a
// restart must not cut off for the life of a mount. The caller holds mu.
//
// A read that fails suspends the store too (see readLocked): a store that
// does not answer costs its timeout, under mu, to every operation that asks.
//
// A suspension is reported through Options.Logf once, and its end once, not
// each failure: reported once mu is released (see unlock).
func (fs *FS) wroteLocked(err error) {
	if err == nil || !fs.resume.IsZero() {
		return
	}
	d := fs.opts.ttl() + fs.opts.MaxStale
	fs.store, fs.resume = newMemStore(fs.opts, fs.now), fs.now().Add(d)
	fs.storeEpoch++
	fs.storeReports = append(fs.storeReports, fmt.Sprintf(
		"listing cache: the store failed and is set aside for an in-memory one for %s: %s", d, err))
}

// readLocked takes the outcome of a read of the store made with ctx: a
// failure suspends the store like a failed write (see wroteLocked), unless
// ctx is over, the failure then being the caller's. The read itself stays a
// miss. The caller holds mu.
func (fs *FS) readLocked(ctx context.Context, err error) {
	if err != nil && ctx.Err() == nil {
		fs.wroteLocked(err)
	}
}

// storeGenLocked returns the generation the store holds for the listing of
// key, to store under it an answer about to be asked of the API (see
// MetaStore.PutListingIf, PutEntryIf), and the epoch of the store it was read
// from: the answer is stored only while that store is still the one in place
// (see storeEpoch). ok is false when the generation could not be read. The
// caller holds mu.
func (fs *FS) storeGenLocked(ctx context.Context, key ListingKey) (gen, epoch uint64, ok bool) {
	gen, err := fs.store.Generation(ctx, key)
	fs.readLocked(ctx, err)
	if err != nil && ctx.Err() == nil {
		// The store that took its place answers.
		gen, err = fs.store.Generation(ctx, key)
	}

	return gen, fs.storeEpoch, err == nil
}

// putEntryLocked keeps e as the entry of key. conditional, it is stored only
// if the generation of the folder's listing in the store is still gen (see
// MetaStore.PutEntryIf): another process sharing the store may have changed
// the folder since. Otherwise, or when the store fails that write, the entry
// goes to the private store of a suspension, which has no other writer, and
// nowhere when there is none. ctx only carries the trace of the write, it
// must not end (storeCtx when there is none). The caller holds mu.
func (fs *FS) putEntryLocked(ctx context.Context, key EntryKey, e *Entry, gen uint64, conditional bool) {
	if conditional {
		_, err := fs.store.PutEntryIf(ctx, key, e, gen)
		if err == nil {
			return
		}
		fs.wroteLocked(err)
	}
	if !fs.resume.IsZero() {
		_ = fs.store.PutEntry(ctx, key, e)
	}
}

// storeCtx is the context of a write to the store: bookkeeping that follows a
// mutation already made, which the end of the request must not cancel.
func storeCtx() context.Context { return context.Background() }

// sealedStoreCtx is storeCtx for a read whose nodes are left sealed (see
// metastore.LeaveSealed): one that needs no decrypted field of them (their
// ID, type, version, mode, dates). A store that keeps no sealed node ignores
// it.
var sealedStoreCtx = metastore.LeaveSealed(context.Background())
