package api

import "errors"

// ErrConflict is returned by API methods when the server responds with HTTP 409.
// Use errors.Is to check for this condition.
var ErrConflict = errors.New("conflict")
