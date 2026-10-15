package api

import "errors"

// ErrConflict is returned by API methods when the server responds with HTTP 409.
// Use errors.Is to check for this condition.
var ErrConflict = errors.New("conflict")

// ErrNotFound is returned by API methods when the server responds with HTTP 404.
// Use errors.Is to check for this condition; callers should not rely on the
// formatted error text.
var ErrNotFound = errors.New("not found")

// ErrGone is returned by API methods when the server responds with HTTP 410,
// which the dataroom API uses for a node in pending-deletion state (deleted,
// its asynchronous purge not run yet). Such an error also matches ErrNotFound:
// the node is gone either way, so callers that handle a missing node need no
// separate check.
var ErrGone = errors.New("gone")

// ErrNotModified is returned by a conditional GET (If-None-Match) when the
// server responds with HTTP 304: what the caller holds is still current.
var ErrNotModified = errors.New("not modified")

// ErrLocked is returned by API methods when the server responds with HTTP 423:
// another lock on the node excludes the one requested.
var ErrLocked = errors.New("locked")

// ErrChunkMissing is returned by a chunk download that still answers 404 after
// its retries, on a version the listing announces complete: the chunk was
// counted but never reached the object store (an unsafe_write upload whose
// background store failed), so the version cannot be downloaded. It also
// matches ErrNotFound.
var ErrChunkMissing = errors.New("chunk missing on the server: the file version is incomplete or corrupted")

// ErrRateLimited is matched by a 429: the API (its ingress, per source IP)
// refused the request for coming too fast. The client retries those itself
// (see retryTransport), so a caller only sees it once the retry budget is
// spent, as a RateLimitError.
var ErrRateLimited = errors.New("rate limited")

// ErrChunkTooLarge is returned by a chunk download given a limit when the
// chunk holds more bytes than it: nothing of the body is kept, and it is not
// read at all when the response announces its length.
var ErrChunkTooLarge = errors.New("chunk larger than the limit")

// ErrNoChunkSize is returned by DataroomChunkEncryptedSize when the API
// cannot tell the size of a chunk: it predates the route (405, 501), or what
// it answered is no size. A 404 is not turned into it: the route answers 404
// for a version or a chunk it does not hold, and so does an API without the
// route behind some proxies; the caller tells the two apart (see vfs.File).
var ErrNoChunkSize = errors.New("the API does not tell the size of a chunk")
