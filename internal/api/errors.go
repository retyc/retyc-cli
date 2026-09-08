package api

import "errors"

// ErrConflict is returned by API methods when the server responds with HTTP 409.
// Use errors.Is to check for this condition.
var ErrConflict = errors.New("conflict")

// ErrNotFound is returned by API methods when the server responds with HTTP 404.
// Use errors.Is to check for this condition. The sentinel is wrapped at the end
// of the message, so the text a user sees still starts with the usual
// "API error 404: ..." and only gains a ": not found" suffix.
var ErrNotFound = errors.New("not found")
