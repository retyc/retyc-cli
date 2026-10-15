package vfs

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// Dataroom is an (ID, title) pair fed to DataroomCache.
type Dataroom struct {
	ID    string
	Title string
	// Role is the user's role in the dataroom, "" when the API does not tell.
	Role string
}

// ListDataroomsFunc lists every dataroom the user can reach. The cache does
// not modify or keep the slice it returns.
type ListDataroomsFunc func(ctx context.Context) ([]Dataroom, error)

// dataroomCacheEntry is a stored list (DataroomList) indexed for the lookups:
// the name→ID mapping, and the list's fetch timestamp.
type dataroomCacheEntry struct {
	byName    map[string]string // display name → ID
	names     []string          // sorted display names
	items     []DataroomInfo    // sorted by display name
	fetchedAt time.Time
}

// dataroomStore is where a DataroomCache keeps the list. The list is data
// and lives in a metastore.MetaStore; what the cache holds itself is the
// coordination (the fetch in flight) and an index of the stored list.
type dataroomStore interface {
	// datarooms returns the stored list; a store that fails to answer has
	// none.
	datarooms(ctx context.Context) (*DataroomList, bool)
	// putDatarooms stores list. It does not fail: a store that refuses the
	// write is replaced (see FS.wroteLocked).
	putDatarooms(list *DataroomList)
}

// ownDataroomStore is the dataroomStore of a DataroomCache built on its own
// (NewDataroomCache), over Options.Store or a memstore. A store that fails,
// a read or a write, is suspended as the store of an FS is (see
// FS.wroteLocked): the list goes to a private in-memory store for Options.TTL
// + Options.MaxStale, then to the configured one again.
type ownDataroomStore struct {
	mu sync.Mutex
	// store is shared, the configured store, or a private one until resume.
	store  metastore.MetaStore
	shared metastore.MetaStore
	resume time.Time
	opts   Options
	now    func() time.Time // nil for time.Now; tests replace it
}

func (s *ownDataroomStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}

	return time.Now()
}

// currentLocked returns the store to use now, and what to tell the operator
// when it just changed back. The caller holds mu.
func (s *ownDataroomStore) currentLocked() (store metastore.MetaStore, report string) {
	if !s.resume.IsZero() && !s.clock().Before(s.resume) {
		s.store, s.resume = s.shared, time.Time{}
		report = "dataroom list cache: back on the configured store"
	}

	return s.store, report
}

// failedLocked suspends the configured store after err and returns what to
// tell the operator. The caller holds mu.
func (s *ownDataroomStore) failedLocked(err error) string {
	if !s.resume.IsZero() {
		return ""
	}
	d := s.opts.ttl() + s.opts.MaxStale
	s.store, s.resume = memstore.New(), s.clock().Add(d)

	return fmt.Sprintf("dataroom list cache: the store failed and is set aside for an in-memory one for %s: %s", d, err)
}

// report tells the operator what was noted under mu, once it is released.
func (s *ownDataroomStore) report(messages ...string) {
	for _, m := range messages {
		if m != "" && s.opts.Logf != nil {
			s.opts.Logf("%s", m)
		}
	}
}

func (s *ownDataroomStore) datarooms(ctx context.Context) (*DataroomList, bool) {
	s.mu.Lock()
	store, back := s.currentLocked()
	list, ok, err := store.GetDatarooms(ctx)
	var failed string
	if err != nil && ctx.Err() == nil {
		failed = s.failedLocked(err)
	}
	s.mu.Unlock()
	s.report(back, failed)

	return list, err == nil && ok && list != nil
}

func (s *ownDataroomStore) putDatarooms(list *DataroomList) {
	s.mu.Lock()
	store, back := s.currentLocked()
	var failed string
	if err := store.PutDatarooms(storeCtx(), list); err != nil {
		// The store may still hold the list this one replaces: it is no
		// longer read until its suspension ends.
		failed = s.failedLocked(err)
		_ = s.store.PutDatarooms(storeCtx(), list)
	}
	s.mu.Unlock()
	s.report(back, failed)
}

// DataroomCache is a thread-safe, TTL-based cache mapping dataroom display names to IDs.
//
// An expired list is served for up to Options.MaxStale more while a single
// background fetch replaces it (stale-while-revalidate): every request resolves
// its dataroom here, so a refresh made under the lock stalled the whole server
// for the /dataroom round trip once per TTL. Only the very first resolution, a
// list older than TTL+MaxStale, and a lookup of a name the expired list does
// not hold (a dataroom created since) wait for a fetch.
//
// The list itself is kept by a metastore.MetaStore (GetDatarooms,
// PutDatarooms), display names included; the cache holds the fetch in flight
// and an index of the stored list, rebuilt when the list changes.
type DataroomCache struct {
	mu sync.Mutex
	// store keeps the list. index is the stored list indexed by name, nil
	// until one is read; it is that of the list fetched at index.fetchedAt.
	store    dataroomStore
	index    *dataroomCacheEntry
	incoming *dataroomFetch // fetch in flight, nil when idle
	fetchFn  ListDataroomsFunc
	opts     Options
}

// dataroomFetch is a fetch of the list shared by every caller that needs it
// while it runs. entry and err are written once, before done is closed.
//
// refresh is the span context of the fetch's own trace when it runs as a
// background refresh (see startRefreshSpan), invalid otherwise.
type dataroomFetch struct {
	done    chan struct{}
	entry   *dataroomCacheEntry
	err     error
	refresh trace.SpanContext
}

// NewDataroomCache returns a cache that lists the datarooms through list and
// keeps the list in Options.Store, a memstore of its own when nil. An FS has
// one already, over its own store: see FS.Datarooms and FS.DataroomByName.
func NewDataroomCache(list ListDataroomsFunc, opts Options) *DataroomCache {
	store := opts.Store
	if store == nil {
		store = memstore.New()
	}

	return newDataroomCache(list, opts, &ownDataroomStore{store: store, shared: store, opts: opts})
}

func newDataroomCache(list ListDataroomsFunc, opts Options, store dataroomStore) *DataroomCache {
	return &DataroomCache{fetchFn: list, opts: opts, store: store}
}

// entryLocked returns the stored list, indexed, nil when there is none. The
// index is rebuilt when the stored list is not the one it was made from. The
// caller holds c.mu.
func (c *DataroomCache) entryLocked(ctx context.Context) *dataroomCacheEntry {
	list, ok := c.store.datarooms(ctx)
	if !ok {
		return nil
	}
	if c.index == nil || !c.index.fetchedAt.Equal(list.FetchedAt) {
		c.index = indexDatarooms(list)
	}

	return c.index
}

// seed makes items the list, fetched now, without calling the API.
func (c *DataroomCache) seed(items []Dataroom) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store.putDatarooms(newDataroomList(items))
}

// fresh reports whether e is younger than the TTL.
func (c *DataroomCache) fresh(e *dataroomCacheEntry) bool {
	return e != nil && time.Since(e.fetchedAt) < c.opts.ttl()
}

// servable reports whether e may still be served while a refresh runs.
func (c *DataroomCache) servable(e *dataroomCacheEntry) bool {
	return e != nil && time.Since(e.fetchedAt) < c.opts.ttl()+c.opts.MaxStale
}

// resolve returns the cached list and starts a refresh when it is expired. It
// waits only when nothing is cached yet, or the list is past TTL+MaxStale.
func (c *DataroomCache) resolve(ctx context.Context) (*dataroomCacheEntry, error) {
	c.mu.Lock()
	e := c.entryLocked(ctx)
	if c.fresh(e) {
		c.mu.Unlock()

		return e, nil
	}
	servable := c.servable(e)
	f := c.fetchLocked(ctx, servable)
	c.mu.Unlock()
	if servable {
		return e, nil
	}

	return f.wait(ctx)
}

// refreshed returns a fresh list, waiting for the fetch if needed.
func (c *DataroomCache) refreshed(ctx context.Context) (*dataroomCacheEntry, error) {
	c.mu.Lock()
	if e := c.entryLocked(ctx); c.fresh(e) {
		c.mu.Unlock()

		return e, nil
	}
	f := c.fetchLocked(ctx, false)
	c.mu.Unlock()

	return f.wait(ctx)
}

func (f *dataroomFetch) wait(ctx context.Context) (*dataroomCacheEntry, error) {
	select {
	case <-f.done:
		linkRefresh(ctx, f.refresh)

		return f.entry, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// fetchLocked returns the fetch in flight, or starts one. The fetch outlives
// the request that started it (it serves every waiter); a failed one leaves
// the stale list in place, and the next request starts another. background
// is true when the caller serves the expired list instead of waiting: the
// fetch then gets a trace of its own (see startRefreshSpan). The caller holds
// c.mu.
func (c *DataroomCache) fetchLocked(ctx context.Context, background bool) *dataroomFetch {
	if c.incoming != nil {
		return c.incoming
	}
	f := &dataroomFetch{done: make(chan struct{})}
	c.incoming = f
	link := trace.LinkFromContext(ctx)
	go func() {
		fctx := context.WithoutCancel(ctx)
		var span trace.Span
		if background {
			fctx, span = startRefreshSpan(fctx, link, "datarooms")
			f.refresh = span.SpanContext()
		}
		fctx, cancel := context.WithTimeout(fctx, c.opts.fetchTimeout())
		items, err := c.fetchFn(fctx)
		cancel()
		result := "ok"
		if err != nil {
			result = "error"
		}
		metrics.DataroomListRefreshes.WithLabelValues(result).Inc()
		if span != nil {
			telemetry.RecordError(span, err)
			span.End()
		}
		var e *dataroomCacheEntry
		c.mu.Lock()
		if err == nil {
			list := newDataroomList(items)
			c.store.putDatarooms(list)
			e = indexDatarooms(list)
			c.index = e
		}
		c.incoming = nil
		c.mu.Unlock()
		f.entry, f.err = e, err
		close(f.done)
	}()

	return f
}

// newDataroomList gives each dataroom its display name and returns the list
// to store, fetched now and sorted by display name.
func newDataroomList(items []Dataroom) *DataroomList {
	// Assign collision suffixes ("Docs (2)") deterministically by ID so a given
	// dataroom always maps to the same display name across cache refreshes,
	// regardless of the order the API returns items in. Without this a mounted
	// client's bookmarked paths could silently point at a different dataroom.
	// The sort is made on a copy: the slice belongs to the ListDataroomsFunc.
	items = slices.Clone(items)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	taken := make(map[string]bool, len(items))
	list := &DataroomList{Items: make([]DataroomInfo, 0, len(items)), FetchedAt: time.Now()}
	for _, item := range items {
		name := item.Title
		if taken[name] {
			for i := 2; ; i++ {
				candidate := fmt.Sprintf("%s (%d)", item.Title, i)
				if !taken[candidate] {
					name = candidate

					break
				}
			}
		}
		taken[name] = true
		list.Items = append(list.Items, DataroomInfo{
			ID: item.ID, Title: item.Title, DisplayName: name, Role: item.Role,
		})
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].DisplayName < list.Items[j].DisplayName })

	return list
}

// indexDatarooms indexes a stored list by display name.
func indexDatarooms(list *DataroomList) *dataroomCacheEntry {
	e := &dataroomCacheEntry{
		byName:    make(map[string]string, len(list.Items)),
		names:     make([]string, len(list.Items)),
		items:     list.Items,
		fetchedAt: list.FetchedAt,
	}
	for i, item := range list.Items {
		e.byName[item.DisplayName] = item.ID
		e.names[i] = item.DisplayName
	}
	// A list from a store is trusted for its names, not for its order.
	sort.Strings(e.names)

	return e
}

// IDForName returns the dataroom ID for the given display name, or os.ErrNotExist.
// A name missing from an expired list waits for the refresh: it may be a
// dataroom created since.
func (c *DataroomCache) IDForName(ctx context.Context, name string) (string, error) {
	e, err := c.resolve(ctx)
	if err != nil {
		return "", err
	}
	id, ok := e.byName[name]
	if !ok && !c.fresh(e) {
		if e, err = c.refreshed(ctx); err != nil {
			return "", err
		}
		id, ok = e.byName[name]
	}
	if !ok {
		return "", os.ErrNotExist
	}
	// The title stays local; the ID is what a trace needs to join requests.
	trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrDataroomID.String(id))

	return id, nil
}

// List returns the datarooms, sorted by display name, in a slice of the
// caller's own.
func (c *DataroomCache) List(ctx context.Context) ([]DataroomInfo, error) {
	e, err := c.resolve(ctx)
	if err != nil {
		return nil, err
	}
	items := slices.Clone(e.items)
	sort.SliceStable(items, func(i, j int) bool { return items[i].DisplayName < items[j].DisplayName })

	return items, nil
}

// Names returns all display names, sorted, in a slice of the caller's own.
func (c *DataroomCache) Names(ctx context.Context) ([]string, error) {
	e, err := c.resolve(ctx)
	if err != nil {
		return nil, err
	}

	return slices.Clone(e.names), nil
}
