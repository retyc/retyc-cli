package api

import "errors"

// ErrConflict is returned by API methods when the server responds with HTTP 409.
// Use errors.Is to check for this condition.
var ErrConflict = errors.New("conflict")

// ErrNotFound is returned by API methods when the server responds with HTTP 404.
// Use errors.Is to check for this condition; callers should not rely on the
// formatted error text.
var ErrNotFound = errors.New("not found")
