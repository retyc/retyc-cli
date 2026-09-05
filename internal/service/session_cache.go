package service

import (
	"context"
	"sync"
	"sync/atomic"
)

// SessionCache caches resolved dataroom sessions for the life of the process.
// The zero value is ready to use.
//
// There is deliberately no TTL: a dataroom's session keypair never changes (a
// rekey re-encrypts the same private key for a new member set, and a member who
// lost access is refused by the API regardless), while every resolution costs two
// API calls plus an scrypt to unlock the user key when no keyring caches it.
//
// Misses are single-flighted per dataroom and the resolutions themselves are
// serialized across datarooms, so at most one scrypt (~256 MiB of working
// memory) runs at any time.
type SessionCache struct {
	mu       sync.Mutex
	sessions map[string]*DataroomSession
	inflight map[string]*sessionFetch
	// resolveMu serializes the actual resolutions across datarooms.
	resolveMu sync.Mutex
}

// sessionFetch is an in-flight resolution shared by every caller that misses the
// cache for the same dataroom while it runs. sess/err are written once, before
// done is closed.
type sessionFetch struct {
	done chan struct{}
	sess *DataroomSession
	err  error
	// dropped is set by Reset while the fetch runs: do not cache its result.
	dropped bool
}

// Get returns the session for drID, calling resolve on the first access and
// caching a successful result forever. A failed resolution is not cached.
func (c *SessionCache) Get(
	ctx context.Context, drID string, resolve func(ctx context.Context, drID string) (*DataroomSession, error),
) (*DataroomSession, error) {
	c.mu.Lock()
	if sess, ok := c.sessions[drID]; ok {
		c.mu.Unlock()

		return sess, nil
	}
	if f, ok := c.inflight[drID]; ok {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.sess, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f := &sessionFetch{done: make(chan struct{})}
	if c.inflight == nil {
		c.inflight = make(map[string]*sessionFetch)
	}
	c.inflight[drID] = f
	c.mu.Unlock()

	// The resolution is shared by every caller that misses the cache while it
	// runs, so it must not die with the leader's request: a client aborting
	// its own request (disconnect, MCP cancellation) would otherwise fail every
	// waiter with context.Canceled. Values (deadline excluded) are kept.
	c.resolveMu.Lock()
	f.sess, f.err = resolve(context.WithoutCancel(ctx), drID)
	c.resolveMu.Unlock()

	c.mu.Lock()
	delete(c.inflight, drID)
	if f.err == nil && !f.dropped {
		c.put(drID, f.sess)
	}
	c.mu.Unlock()
	close(f.done)

	return f.sess, f.err
}

// put stores sess for drID; c.mu must be held.
func (c *SessionCache) put(drID string, sess *DataroomSession) {
	if c.sessions == nil {
		c.sessions = make(map[string]*DataroomSession)
	}
	c.sessions[drID] = sess
}

// Store caches sess for drID, replacing any previous entry (pre-warming, tests).
func (c *SessionCache) Store(drID string, sess *DataroomSession) {
	c.mu.Lock()
	c.put(drID, sess)
	c.mu.Unlock()
}

// Reset drops every cached session. In-flight resolutions complete but their
// result is not stored: they were started under the identity being dropped.
func (c *SessionCache) Reset() {
	c.mu.Lock()
	c.sessions = nil
	for drID := range c.inflight {
		c.inflight[drID].dropped = true
	}
	c.mu.Unlock()
}

// processSessions is the process-wide cache consulted by resolveDataroomSession
// once EnableSessionCache has been called. nil for one-shot CLI commands, which
// resolve a session at most once per invocation anyway.
var processSessions atomic.Pointer[SessionCache]

// EnableSessionCache makes every service function that resolves a dataroom
// session share one process-wide SessionCache. Long-running servers (mcp serve)
// call it at startup; one-shot commands never do.
func EnableSessionCache() {
	processSessions.CompareAndSwap(nil, &SessionCache{})
}

// ResetSessionCache drops every session held by the process-wide cache, if any.
// Called on logout: the cache is keyed by dataroom ID only, so sessions
// decrypted under one user must not survive into a later login.
func ResetSessionCache() {
	if c := processSessions.Load(); c != nil {
		c.Reset()
	}
}

// disableSessionCacheForTest drops the process-wide cache (tests only).
func disableSessionCacheForTest() {
	processSessions.Store(nil)
}
