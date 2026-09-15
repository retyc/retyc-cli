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
