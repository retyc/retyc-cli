// Package memstore is the in-memory metastore.MetaStore: a map under a mutex,
// lost with the process. It never returns an error.
//
// Built with New, it keeps what it is given until it is replaced or deleted,
// and one generation per listing ever written, invalidated or edited: a
// store a test builds. Built with NewWithOptions and lifetimes, it lets go
// of what has outlived them, as Redis does (see Options): its memory is
// bounded by what was written within the longest of them.
package memstore

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// Options are the lifetimes of what a Store holds. Zero keeps it for ever.
//
// A value past its lifetime reads as absent, never as younger than it is,
// and is removed by the next sweep: at most one every quarter of the longest
// lifetime, run by the first call that comes once it is due (no goroutine).
// A sweep walks every listing, entry and generation under the mutex, O(what
// the store holds), so its cost per call is amortized over a quarter of that
// lifetime. A store nobody calls keeps what it holds until it is called.
type Options struct {
	// ListingLife is how long a listing is kept after its FetchedAt (the
	// time it is put when FetchedAt is zero): what vfs.ListingRetention
	// returns. An edit in place (UpsertNode, RemoveNode) does not extend it,
	// RenewListingIf does.
	ListingLife time.Duration
	// EntryLife and NegativeEntryLife are how long a positive and a negative
	// entry are kept after their FetchedAt.
	EntryLife         time.Duration
	NegativeEntryLife time.Duration
	// GenerationLife is how long the generation of a listing the store no
	// longer holds is kept after it last moved or its listing left (expired
	// or deleted): the longest a fetch that read it may take to come back
	// with its answer (vfs Options.FetchTimeout). A listing without a
	// generation reads the floor, which every drop raises above the
	// generation dropped: the generations a listing answers never go down,
	// and every write moves them up, so a value read before a drop (the
	// floor included) is never answered again once the listing changed,
	// and a write conditioned on it is refused.
	GenerationLife time.Duration
	// Now is the clock the lifetimes go by; nil is time.Now. Tests replace it.
	Now func() time.Time
}

// heldListing is a listing and when it leaves the store (zero: never).
type heldListing struct {
	l       *metastore.Listing
	expires time.Time
}

// heldEntry is an entry and when it leaves the store (zero: never).
type heldEntry struct {
	e       *metastore.Entry
	expires time.Time
}

// generation is the generation of a listing and when it last moved.
type generation struct {
	n     uint64
	moved time.Time
}

// Store is an in-memory metastore.MetaStore. The zero value is not usable:
// build one with New or NewWithOptions.
type Store struct {
	opts Options

	mu       sync.Mutex
	listings map[metastore.ListingKey]heldListing
	// entries is keyed by folder first, so that dropping the entries of one
	// folder does not walk those of every other.
	entries map[metastore.ListingKey]map[string]heldEntry
	// gens is the generation of each listing written, kept once the listing
	// is gone: a listing asked of the API before it was dropped must not be
	// put back. Dropped GenerationLife after it last moved, the listing being
	// gone (see Options.GenerationLife).
	gens map[metastore.ListingKey]generation
	// floor is the generation of a listing that has none in gens, above
	// every generation dropped: its first write moves it to floor+1.
	floor uint64
	// nextSweep is when the next sweep is due; zero before the first call.
	nextSweep time.Time
	datarooms *metastore.DataroomList
}

var _ metastore.MetaStore = (*Store)(nil)

// New returns an empty store that keeps everything (see Options).
func New() *Store {
	return NewWithOptions(Options{})
}

// NewWithOptions returns an empty store that keeps what it holds for the
// lifetimes of opts.
func NewWithOptions(opts Options) *Store {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Store{
		opts:     opts,
		listings: make(map[metastore.ListingKey]heldListing),
		entries:  make(map[metastore.ListingKey]map[string]heldEntry),
		gens:     make(map[metastore.ListingKey]generation),
	}

	return s
}

// sweepEvery is the interval between two sweeps: a quarter of the longest
// lifetime, zero when nothing expires.
func (s *Store) sweepEvery() time.Duration {
	o := s.opts

	return max(o.ListingLife, o.EntryLife, o.NegativeEntryLife, o.GenerationLife, 0) / 4
}

// lock takes the mutex, sweeps when a sweep is due, and returns the time it
// went by.
func (s *Store) lock() time.Time {
	s.mu.Lock()
	now := s.opts.Now()
	if every := s.sweepEvery(); every > 0 {
		switch {
		case s.nextSweep.IsZero(): // the first call: the clock is read from now on
			s.nextSweep = now.Add(every)
		case !now.Before(s.nextSweep):
			s.sweepLocked(now)
			s.nextSweep = now.Add(every)
		}
	}

	return now
}

// sweepLocked removes what has outlived its lifetime: listings, entries,
// then the generations of the listings gone. The caller holds mu.
func (s *Store) sweepLocked(now time.Time) {
	for key, h := range s.listings {
		if expired(h.expires, now) {
			s.dropListingLocked(key, now)
		}
	}
	for folder, names := range s.entries {
		for name, h := range names {
			if expired(h.expires, now) {
				delete(names, name)
			}
		}
		if len(names) == 0 {
			delete(s.entries, folder)
		}
	}
	if s.opts.GenerationLife <= 0 {
		return
	}
	for key, g := range s.gens {
		if _, held := s.listings[key]; !held && now.Sub(g.moved) >= s.opts.GenerationLife {
			s.floor = max(s.floor, g.n+1)
			delete(s.gens, key)
		}
	}
}

// expired reports whether a value that leaves the store at expires is gone
// at now. A zero expires never is.
func expired(expires, now time.Time) bool {
	return !expires.IsZero() && !now.Before(expires)
}

// expiry returns when a value fetched at fetchedAt leaves the store, life
// being its lifetime: zero (never) when life is not positive. A zero
// fetchedAt is now.
func expiry(life time.Duration, fetchedAt, now time.Time) time.Time {
	if life <= 0 {
		return time.Time{}
	}
	if fetchedAt.IsZero() {
		fetchedAt = now
	}

	return fetchedAt.Add(life)
}

// listingLocked returns the listing of key, if the store holds one that has
// not outlived its lifetime. The caller holds mu.
func (s *Store) listingLocked(key metastore.ListingKey, now time.Time) (*metastore.Listing, time.Time, bool) {
	h, ok := s.listings[key]
	if !ok {
		return nil, time.Time{}, false
	}
	if expired(h.expires, now) {
		s.dropListingLocked(key, now)

		return nil, time.Time{}, false
	}

	return h.l, h.expires, true
}

// dropListingLocked removes the listing of key. Its generation, if any, is
// kept GenerationLife from now: a fetch started while the listing was held
// read it, however long ago it last moved. The caller holds mu.
func (s *Store) dropListingLocked(key metastore.ListingKey, now time.Time) {
	delete(s.listings, key)
	if g, ok := s.gens[key]; ok {
		g.moved = now
		s.gens[key] = g
	}
}

// putListingLocked stores listing for its lifetime. The caller holds mu.
func (s *Store) putListingLocked(key metastore.ListingKey, listing *metastore.Listing, now time.Time) {
	s.listings[key] = heldListing{l: listing, expires: expiry(s.opts.ListingLife, listing.FetchedAt, now)}
}

// entryLocked returns the entry of key, if the store holds one that has not
// outlived its lifetime. The caller holds mu.
func (s *Store) entryLocked(key metastore.EntryKey, now time.Time) (*metastore.Entry, bool) {
	h, ok := s.entries[folderOf(key)][key.Name]
	if !ok || expired(h.expires, now) {
		return nil, false
	}

	return h.e, true
}

// putEntryLocked stores entry for its lifetime. The caller holds mu.
func (s *Store) putEntryLocked(key metastore.EntryKey, entry *metastore.Entry, now time.Time) {
	life := s.opts.EntryLife
	if entry.Node == nil {
		life = s.opts.NegativeEntryLife
	}
	folder := folderOf(key)
	if s.entries[folder] == nil {
		s.entries[folder] = make(map[string]heldEntry)
	}
	s.entries[folder][key.Name] = heldEntry{e: entry, expires: expiry(life, entry.FetchedAt, now)}
}

// genLocked returns the generation of the listing of key: the floor when it
// has none. The caller holds mu.
func (s *Store) genLocked(key metastore.ListingKey) uint64 {
	if g, ok := s.gens[key]; ok {
		return g.n
	}

	return s.floor
}

// bumpLocked moves the generation of the listing of key and returns it: one
// above what genLocked answered. The caller holds mu.
func (s *Store) bumpLocked(key metastore.ListingKey, now time.Time) uint64 {
	g, ok := s.gens[key]
	if !ok {
		g.n = s.floor
	}
	g.n++
	g.moved = now
	s.gens[key] = g

	return g.n
}

// GetListing implements metastore.MetaStore. The listing returned is a copy
// of the stored header: writing its FetchedAt or ETag changes nothing in the
// store. Its Nodes slice is the stored one, which the caller must not modify.
func (s *Store) GetListing(_ context.Context, key metastore.ListingKey) (*metastore.Listing, bool, error) {
	now := s.lock()
	defer s.mu.Unlock()
	l, _, ok := s.listingLocked(key, now)
	if !ok {
		return nil, false, nil
	}
	held := *l

	return &held, true, nil
}

// ListingMeta implements metastore.MetaStore.
func (s *Store) ListingMeta(_ context.Context, key metastore.ListingKey) (metastore.ListingMeta, bool, error) {
	now := s.lock()
	defer s.mu.Unlock()
	l, _, ok := s.listingLocked(key, now)
	if !ok {
		return metastore.ListingMeta{}, false, nil
	}

	return metaOf(l), true, nil
}

// GetNode implements metastore.MetaStore. The node returned is a copy.
func (s *Store) GetNode(
	_ context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, error) {
	now := s.lock()
	defer s.mu.Unlock()
	l, _, ok := s.listingLocked(key, now)
	if !ok {
		return nil, metastore.ListingMeta{}, false, nil
	}
	for i := range l.Nodes {
		if l.Nodes[i].Name == name {
			node := l.Nodes[i]

			return &node, metaOf(l), true, nil
		}
	}

	return nil, metaOf(l), true, nil
}

// GetNamed implements metastore.MetaStore: GetNode and GetEntry under one
// lock.
func (s *Store) GetNamed(
	_ context.Context, key metastore.ListingKey, name string,
) (node *metastore.Node, meta metastore.ListingMeta, held bool, entry *metastore.Entry, hasEntry bool, err error) {
	now := s.lock()
	defer s.mu.Unlock()
	entry, hasEntry = s.entryLocked(metastore.EntryKey{DataroomID: key.DataroomID, ParentPath: key.Path, Name: name}, now)
	l, _, held := s.listingLocked(key, now)
	if !held {
		return nil, meta, false, entry, hasEntry, nil
	}
	for i := range l.Nodes {
		if l.Nodes[i].Name == name {
			n := l.Nodes[i]
			node = &n

			break
		}
	}

	return node, metaOf(l), true, entry, hasEntry, nil
}

// metaOf returns what a listing holds besides its nodes.
func metaOf(l *metastore.Listing) metastore.ListingMeta {
	return metastore.ListingMeta{FetchedAt: l.FetchedAt, ETag: l.ETag}
}

// Generation implements metastore.MetaStore. A listing never written, or
// whose generation was dropped (see Options.GenerationLife), has the floor:
// 0 until a generation is dropped, above every one dropped afterwards.
func (s *Store) Generation(_ context.Context, key metastore.ListingKey) (uint64, error) {
	s.lock()
	defer s.mu.Unlock()

	return s.genLocked(key), nil
}

// PutListing implements metastore.MetaStore. The store keeps listing itself:
// the caller must not modify it afterwards.
func (s *Store) PutListing(_ context.Context, key metastore.ListingKey, listing *metastore.Listing) error {
	now := s.lock()
	defer s.mu.Unlock()
	s.putListingLocked(key, listing, now)
	s.bumpLocked(key, now)

	return nil
}

// PutListingIf implements metastore.MetaStore.
func (s *Store) PutListingIf(
	_ context.Context, key metastore.ListingKey, listing *metastore.Listing, gen uint64,
) (bool, error) {
	now := s.lock()
	defer s.mu.Unlock()
	if s.genLocked(key) != gen {
		return false, nil
	}
	s.putListingLocked(key, listing, now)
	s.bumpLocked(key, now)

	return true, nil
}

// RenewListingIf implements metastore.MetaStore. The listing is replaced by
// one with the new header over the same nodes: the header of one handed out
// earlier is never written through. Its lifetime starts again from fetchedAt.
func (s *Store) RenewListingIf(
	_ context.Context, key metastore.ListingKey, etag string, fetchedAt time.Time, gen uint64,
) (bool, error) {
	now := s.lock()
	defer s.mu.Unlock()
	l, _, ok := s.listingLocked(key, now)
	if !ok || s.genLocked(key) != gen {
		return false, nil
	}
	s.putListingLocked(key, &metastore.Listing{Nodes: l.Nodes, FetchedAt: fetchedAt, ETag: etag}, now)
	s.bumpLocked(key, now)

	return true, nil
}

// UpsertNode implements metastore.MetaStore. The listing is replaced by a
// copy: the slice of one handed out earlier is never written through. It
// keeps its lifetime.
func (s *Store) UpsertNode(_ context.Context, key metastore.ListingKey, node metastore.Node) (uint64, error) {
	now := s.lock()
	defer s.mu.Unlock()
	gen := s.bumpLocked(key, now)
	held, expires, ok := s.listingLocked(key, now)
	if !ok {
		return gen, nil
	}
	edited := metastore.Listing{FetchedAt: held.FetchedAt}
	edited.Nodes = make([]metastore.Node, len(held.Nodes), len(held.Nodes)+1)
	copy(edited.Nodes, held.Nodes)
	at := slices.IndexFunc(edited.Nodes, func(n metastore.Node) bool { return n.Name == node.Name })
	if at >= 0 {
		edited.Nodes[at] = node
	} else {
		edited.Nodes = append(edited.Nodes, node)
	}
	s.listings[key] = heldListing{l: &edited, expires: expires}

	return gen, nil
}

// RemoveNode implements metastore.MetaStore, on a copy like UpsertNode.
func (s *Store) RemoveNode(_ context.Context, key metastore.ListingKey, name string) (uint64, error) {
	now := s.lock()
	defer s.mu.Unlock()
	gen := s.bumpLocked(key, now)
	held, expires, ok := s.listingLocked(key, now)
	if !ok {
		return gen, nil
	}
	edited := metastore.Listing{FetchedAt: held.FetchedAt, Nodes: make([]metastore.Node, 0, len(held.Nodes))}
	for _, n := range held.Nodes {
		if n.Name != name {
			edited.Nodes = append(edited.Nodes, n)
		}
	}
	s.listings[key] = heldListing{l: &edited, expires: expires}

	return gen, nil
}

// DeleteListing implements metastore.MetaStore.
func (s *Store) DeleteListing(_ context.Context, key metastore.ListingKey) error {
	now := s.lock()
	defer s.mu.Unlock()
	s.dropListingLocked(key, now)
	s.bumpLocked(key, now)

	return nil
}

// DeleteSubtree implements metastore.MetaStore. The folder at path gets one
// bump, stored or not, and so does each folder below it that holds a
// generation: one written since its generation was last dropped, whose fetch
// may still be on its way (see Options.GenerationLife).
func (s *Store) DeleteSubtree(_ context.Context, dataroomID, path string) error {
	prefix := strings.TrimSuffix(path, "/") + "/"
	root := metastore.ListingKey{DataroomID: dataroomID, Path: path}
	now := s.lock()
	defer s.mu.Unlock()
	delete(s.listings, root)
	s.bumpLocked(root, now)
	for key := range s.gens {
		if key.DataroomID == dataroomID && key != root && strings.HasPrefix(key.Path, prefix) {
			delete(s.listings, key)
			s.bumpLocked(key, now)
		}
	}

	return nil
}

// GetEntry implements metastore.MetaStore. The entry returned is the stored
// one, which the caller must not modify.
func (s *Store) GetEntry(_ context.Context, key metastore.EntryKey) (*metastore.Entry, bool, error) {
	now := s.lock()
	defer s.mu.Unlock()
	e, ok := s.entryLocked(key, now)

	return e, ok, nil
}

// PutEntry implements metastore.MetaStore. The store keeps entry itself: the
// caller must not modify it afterwards.
func (s *Store) PutEntry(_ context.Context, key metastore.EntryKey, entry *metastore.Entry) error {
	now := s.lock()
	defer s.mu.Unlock()
	s.putEntryLocked(key, entry, now)

	return nil
}

// PutEntryIf implements metastore.MetaStore. The generation compared is the
// one of the listing of the entry's folder, which an entry never bumps.
func (s *Store) PutEntryIf(
	_ context.Context, key metastore.EntryKey, entry *metastore.Entry, gen uint64,
) (bool, error) {
	now := s.lock()
	defer s.mu.Unlock()
	if s.genLocked(folderOf(key)) != gen {
		return false, nil
	}
	s.putEntryLocked(key, entry, now)

	return true, nil
}

// DeleteEntries implements metastore.MetaStore.
func (s *Store) DeleteEntries(_ context.Context, dataroomID, parentPath string) error {
	s.lock()
	defer s.mu.Unlock()
	delete(s.entries, metastore.ListingKey{DataroomID: dataroomID, Path: parentPath})

	return nil
}

// DeleteEntriesBelow implements metastore.MetaStore.
func (s *Store) DeleteEntriesBelow(_ context.Context, dataroomID, path string) error {
	prefix := strings.TrimSuffix(path, "/") + "/"
	s.lock()
	defer s.mu.Unlock()
	for folder := range s.entries {
		if folder.DataroomID == dataroomID && (folder.Path == path || strings.HasPrefix(folder.Path, prefix)) {
			delete(s.entries, folder)
		}
	}

	return nil
}

// folderOf returns the folder an entry key belongs to.
func folderOf(key metastore.EntryKey) metastore.ListingKey {
	return metastore.ListingKey{DataroomID: key.DataroomID, Path: key.ParentPath}
}

// Held returns how many listings, entries and generations the store holds,
// once a sweep that is due has run: what tests count.
func (s *Store) Held() (listings, entries, gens int) {
	s.lock()
	defer s.mu.Unlock()
	for _, names := range s.entries {
		entries += len(names)
	}

	return len(s.listings), entries, len(s.gens)
}

// GetDatarooms implements metastore.MetaStore. The list returned is the
// stored one, which the caller must not modify.
func (s *Store) GetDatarooms(context.Context) (*metastore.DataroomList, bool, error) {
	s.lock()
	defer s.mu.Unlock()

	return s.datarooms, s.datarooms != nil, nil
}

// PutDatarooms implements metastore.MetaStore. The store keeps list itself:
// the caller must not modify it afterwards.
func (s *Store) PutDatarooms(_ context.Context, list *metastore.DataroomList) error {
	s.lock()
	defer s.mu.Unlock()
	s.datarooms = list

	return nil
}

// Close implements metastore.MetaStore. There is nothing to release.
func (s *Store) Close() error { return nil }
