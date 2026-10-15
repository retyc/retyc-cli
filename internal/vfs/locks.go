package vfs

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/metrics"
)

// lockRefreshEvery paces the renewal of the API locks: well inside the lease
// taken (api.LockTimeoutMax), so a slow round trip does not let one lapse.
const lockRefreshEvery = 2 * time.Minute

// LockManager holds the advisory locks a front end takes on files through the
// API, so that another cooperating RETYC client (a second mount; the web app
// ignores locks) sees the file as locked, and so that a file another client
// locked is refused here.
//
// A lock is known by the key its front end gives it: the token of a WebDAV
// lock, a file handle. The manager does not decide when a file is locked; it
// takes, renews and releases the API lock behind each key. API leases are
// bounded (5 min at most) while front ends hold a lock for hours: Run renews
// every lock while it stands.
//
// What the manager cannot tell a caller goes to Options.Logf: a lock the API
// did not renew, retake or release. label is what such a message names the
// file by; the manager gives it no meaning.
type LockManager struct {
	fs *FS

	mu    sync.Mutex
	locks map[string]*heldLock // by key
}

// heldLock is an API lock taken for a key.
type heldLock struct {
	lockID   string
	apiToken string
	nodeID   string
	label    string
	// expires is when the front end's own lock lapses unless it is refreshed;
	// zero for a lock without timeout.
	expires time.Time
}

// Locks returns the manager of the API locks of the FS.
func (fs *FS) Locks() *LockManager { return &fs.locks }

// Take takes an exclusive API lock on the file nodeID for key, at the longest
// lease. expires is when the front end's lock lapses (zero: never). The error
// is the API's: api.ErrLocked when another client holds the file.
//
// The API holds one lock per token, not per user: an API lock this manager
// still holds on the node for a key whose front-end lock lapsed in silence
// would refuse its own successor. The front end has just granted an exclusive
// lock on the file, so whatever lock was held for it no longer stands: those
// are released first.
func (m *LockManager) Take(ctx context.Context, key, nodeID, label string, expires time.Time) error {
	m.releaseStale(ctx, nodeID)
	lock, err := m.fs.client.LockDataroomNode(ctx, nodeID, api.LockExclusive, api.LockTimeoutMax)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.setLocked(key, &heldLock{
		lockID: lock.ID, apiToken: lock.Token, nodeID: nodeID, label: label, expires: expires,
	})
	m.mu.Unlock()

	return nil
}

// setLocked records held as the lock of key, and dropLocked forgets the lock
// of key: the only two places the map changes, so that the gauge of the locks
// held follows it. The caller holds mu.
func (m *LockManager) setLocked(key string, held *heldLock) {
	if _, known := m.locks[key]; !known {
		metrics.VFSLocksHeld.Inc()
	}
	m.locks[key] = held
}

func (m *LockManager) dropLocked(key string) {
	if _, known := m.locks[key]; known {
		metrics.VFSLocksHeld.Dec()
		delete(m.locks, key)
	}
}

// Refresh renews the API lock behind key after the front end refreshed its
// own, which now lapses at expires. A lock whose lease ended is taken again (a
// lock lost to a slow refresh is not fatal), and so is one that could not be
// taken before.
func (m *LockManager) Refresh(ctx context.Context, key, nodeID, label string, expires time.Time) {
	m.refresh(ctx, key, nodeID, label, expires, false)
}

// refresh renews the API lock behind key, taking a new one when the previous
// lease ended. expires is when the front end's lock lapses.
//
// background is the periodic renewal, which only keeps what is held: a key
// released since it was read (a release landing meanwhile) is left alone, and
// a lock retaken for it is given back. A refresh from the front end also takes
// a lock that could not be taken before.
func (m *LockManager) refresh(
	ctx context.Context, key, nodeID, label string, expires time.Time, background bool,
) {
	m.mu.Lock()
	held := m.locks[key]
	if held != nil && !background {
		held.expires = expires
	}
	m.mu.Unlock()
	if held == nil && background {
		return
	}
	if held != nil {
		_, err := m.fs.client.RefreshDataroomNodeLock(ctx, held.lockID, held.apiToken, api.LockTimeoutMax)
		if err == nil {
			return
		}
		if !errors.Is(err, api.ErrNotFound) {
			m.fs.logf("LOCK %s: server lock not refreshed: %s", label, err)

			return
		}
	}
	lock, err := m.fs.client.LockDataroomNode(ctx, nodeID, api.LockExclusive, api.LockTimeoutMax)
	if err != nil {
		m.fs.logf("LOCK %s: server lock not retaken: %s", label, err)
		m.mu.Lock()
		if m.locks[key] == held {
			m.dropLocked(key)
		}
		m.mu.Unlock()

		return
	}
	m.mu.Lock()
	released := m.locks[key] != held
	if !released {
		m.setLocked(key, &heldLock{
			lockID: lock.ID, apiToken: lock.Token, nodeID: nodeID, label: label, expires: expires,
		})
	}
	m.mu.Unlock()
	if released {
		// Released while the API lock was being retaken.
		if err := m.fs.client.UnlockDataroomNode(ctx, lock.ID, lock.Token); err != nil && !errors.Is(err, api.ErrNotFound) {
			m.fs.logf("UNLOCK %s: server lock not released: %s", label, err)
		}
	}
}

// releaseStale drops the API locks held for nodeID (see Take).
func (m *LockManager) releaseStale(ctx context.Context, nodeID string) {
	m.mu.Lock()
	var keys []string
	for key, held := range m.locks {
		if held.nodeID == nodeID {
			keys = append(keys, key)
		}
	}
	m.mu.Unlock()
	for _, key := range keys {
		m.Release(ctx, key)
	}
}

// Release drops the API lock behind key, if any.
func (m *LockManager) Release(ctx context.Context, key string) {
	m.mu.Lock()
	held := m.locks[key]
	m.dropLocked(key)
	m.mu.Unlock()
	if held == nil {
		return
	}
	err := m.fs.client.UnlockDataroomNode(ctx, held.lockID, held.apiToken)
	if err != nil && !errors.Is(err, api.ErrNotFound) {
		m.fs.logf("UNLOCK %s: server lock not released: %s", held.label, err)
	}
}

// Run renews the held locks every two minutes until ctx ends, then releases
// them all: the API would let them lapse within the lease, but a clean
// shutdown should not leave files locked for five minutes.
func (m *LockManager) Run(ctx context.Context) {
	ticker := time.NewTicker(lockRefreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.ReleaseAll()

			return
		case <-ticker.C:
			m.RefreshAll(ctx)
		}
	}
}

// RefreshAll renews every held lock; a lock whose lease ended is retaken. A
// lock whose front-end lock lapsed (its client went away without releasing it)
// is released instead: nothing holds the file any more.
func (m *LockManager) RefreshAll(ctx context.Context) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.locks))
	byKey := make(map[string]heldLock, len(m.locks))
	for key, held := range m.locks {
		keys = append(keys, key)
		byKey[key] = *held
	}
	m.mu.Unlock()
	now := time.Now()
	for _, key := range keys {
		held := byKey[key]
		if !held.expires.IsZero() && now.After(held.expires) {
			m.Release(ctx, key)

			continue
		}
		m.refresh(ctx, key, held.nodeID, held.label, held.expires, true)
	}
}

// ReleaseAll drops every held lock, best effort, on its own short timeout.
func (m *LockManager) ReleaseAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m.mu.Lock()
	keys := make([]string, 0, len(m.locks))
	for key := range m.locks {
		keys = append(keys, key)
	}
	m.mu.Unlock()
	for _, key := range keys {
		m.Release(ctx, key)
	}
}

// Holds reports whether the manager holds an API lock for key. It no longer
// does once the lock was lost for good: the API did not renew it and refused
// to give it again (see refresh). The front end may then Take it again.
func (m *LockManager) Holds(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.locks[key] != nil
}

// Held returns the number of locks held.
func (m *LockManager) Held() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.locks)
}
