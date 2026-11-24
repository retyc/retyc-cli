package vfs

import "sync"

// chunkSizeMemoMax bounds the chunk sizes an FS remembers: one string and
// one integer per version, a few hundred kilobytes at the limit.
const chunkSizeMemoMax = 4096

// chunkSizes is what an FS has learnt of the chunk size of the versions its
// files read, and of the route that tells it (see file).
//
// A version never changes, so neither does its chunk size: an entry never
// expires. The memo is bounded all the same, chunkSizeMemoMax versions, the
// oldest recorded leaving first; a version that left costs its next File one
// request, as on a first open. Nothing of it is written to the store: it is
// rebuilt at that price, and dropped by FS.Close.
type chunkSizes struct {
	mu    sync.Mutex
	sizes map[string]int64
	// ring holds the versions recorded, in the order they were, and next is
	// the place of the one to replace once the ring is full.
	ring []string
	next int
	// route is what is known of the route that tells a chunk size.
	route sizeRoute
}

// sizeRoute is what an FS knows of the route that tells the size of a chunk.
type sizeRoute int

const (
	// sizeRouteUnknown: never asked, or never in a way that told.
	sizeRouteUnknown sizeRoute = iota
	// sizeRoutePresent: it answered a size once. A later 404 is then a chunk
	// or a version the API does not hold, never a missing route.
	sizeRoutePresent
	// sizeRouteAbsent: the API has no such route. It is not asked again for
	// the life of the FS.
	sizeRouteAbsent
)

// get returns the chunk size recorded for a version.
func (m *chunkSizes) get(versionID string) (int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	size, ok := m.sizes[versionID]

	return size, ok
}

// put records the chunk size of a version.
func (m *chunkSizes) put(versionID string, size int64) {
	if versionID == "" || size <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sizes[versionID]; ok {
		m.sizes[versionID] = size

		return
	}
	if m.sizes == nil {
		m.sizes = make(map[string]int64)
	}
	if len(m.ring) < chunkSizeMemoMax {
		m.ring = append(m.ring, versionID)
	} else {
		delete(m.sizes, m.ring[m.next])
		m.ring[m.next] = versionID
		m.next = (m.next + 1) % len(m.ring)
	}
	m.sizes[versionID] = size
}

// len returns the number of versions recorded.
func (m *chunkSizes) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.sizes)
}

// routeAbsent reports whether the API is known not to tell chunk sizes.
func (m *chunkSizes) routeAbsent() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.route == sizeRouteAbsent
}

// routeAnswered records that the route told a size.
func (m *chunkSizes) routeAnswered() {
	m.mu.Lock()
	m.route = sizeRoutePresent
	m.mu.Unlock()
}

// routeRefused records that the API said it has no such route.
func (m *chunkSizes) routeRefused() {
	m.mu.Lock()
	m.route = sizeRouteAbsent
	m.mu.Unlock()
}

// routeMissed records that the route answered 404 for a version that exists:
// the API has no such route, unless the route was seen to answer before, in
// which case the 404 was about a chunk.
func (m *chunkSizes) routeMissed() {
	m.mu.Lock()
	if m.route == sizeRouteUnknown {
		m.route = sizeRouteAbsent
	}
	m.mu.Unlock()
}

// reset forgets the chunk sizes. What is known of the route is kept: it
// would only matter to a file opened after the FS is closed, which reads
// nothing.
func (m *chunkSizes) reset() {
	m.mu.Lock()
	m.sizes, m.ring, m.next = nil, nil, 0
	m.mu.Unlock()
}
