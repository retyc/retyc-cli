package vfs

import (
	"context"
	"time"
)

// quotaEntry is a dataroom's storage counters as last fetched, or with ok
// false the knowledge that there were none to have: an API without them, or
// a fetch that failed.
type quotaEntry struct {
	used, free int64
	ok         bool
	fetchedAt  time.Time
}

// Quota returns the storage used by the dataroom and the room left (its
// reserved capacity, or its owner's plan remainder), from
// GET /dataroom/{id}/stats, cached for the listing TTL: a front end asks the
// quota of every folder it lists. ok is false when the counters are
// unavailable (an older API, or a failed fetch, reported through
// Options.Logf), in which case there is no quota to report.
//
// The absence of counters is cached for the TTL like the counters are: a
// listing of N sub-folders asks N times, and an API that fails would
// otherwise be asked, and its failure logged, N times per listing. A failure
// is thus reported once per TTL and per dataroom.
//
// A fetch that fails because the caller gave up (its context ended) says
// nothing about the counters: it is neither cached nor reported, and the next
// caller asks again.
func (fs *FS) Quota(ctx context.Context, dataroomID string) (used, free int64, ok bool) {
	fs.quotaMu.Lock()
	entry, cached := fs.quota[dataroomID]
	fs.quotaMu.Unlock()
	if cached && time.Since(entry.fetchedAt) < fs.opts.ttl() {
		return entry.used, entry.free, entry.ok
	}
	entry = quotaEntry{}
	stats, err := fs.client.GetDataroomStats(ctx, dataroomID)
	switch {
	case err != nil && ctx.Err() != nil:
		return 0, 0, false
	case err != nil:
		fs.logf("dataroom quota: %s", err)
	case stats.StorageUsed != nil:
		// Nil is an API without storage counters.
		entry = quotaEntry{used: *stats.StorageUsed, free: stats.StorageFree, ok: true}
	}
	entry.fetchedAt = time.Now()
	fs.quotaMu.Lock()
	fs.quota[dataroomID] = entry
	fs.quotaMu.Unlock()

	return entry.used, entry.free, entry.ok
}
