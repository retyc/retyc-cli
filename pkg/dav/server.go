// Package dav is the WebDAV adapter over package vfs: it presents the
// datarooms of an API client as a WebDAV tree (x/net/webdav), with the
// custom COPY, the mirroring of WebDAV locks onto the API's node locks, the
// executable property and the 429 answer to a rate-limited request.
// `retyc fs webdav serve` (cmd/webdav.go) wraps it in a cobra command; a
// program that imports the core builds the same handler with New.
//
// Dependency rule (deps_test.go): no cobra, viper, core/config nor cmd.
// Settings arrive in Options; messages that no request can be told go to
// vfs.Options.Logf, or to the diag output.
package dav

import (
	"context"
	"net/http"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/vfs"
)

// Options are the settings of a Server.
type Options struct {
	// VFS are the settings of the tree (caches, store, identity,
	// concurrency). HideSymlinks and the pacing of COPY are set by New; a nil
	// Logf writes to the diag output, prefixed with "webdav: ".
	VFS vfs.Options
	// LogRequest, when set, is called once per request handled by the WebDAV
	// handler, with the error it ended with or nil. Beware that the request
	// path is a file name in clear.
	LogRequest func(r *http.Request, err error)
}

// Server is the WebDAV view of the datarooms of one API client. It is an
// http.Handler, without authentication: wrap it (BasicAuth) unless it is
// reachable by its user alone.
type Server struct {
	fs      *webdavFS
	mirror  *lockMirror
	handler http.Handler
}

// New returns the Server of client. The client should carry the transport
// of an auth.Watch (auth.Watch.RoundTripper), so that a 401 has the login
// checked at once. Call RunLocks in background while serving, and Close once
// the HTTP server has stopped.
func New(client *api.Client, opts Options) *Server {
	fs := newWebdavFS(client, opts.VFS)
	lockSystem := webdav.NewMemLS()
	fs.locks = lockSystem
	// A request the API rate limit defeated is answered 429 instead of the
	// status x/net/webdav picks (see rateLimitStatus).
	logf := opts.LogRequest
	if logf == nil {
		logf = func(*http.Request, error) {}
	}
	handler := newWebdavHandler(fs, lockSystem, logf)

	// WebDAV locks on files are mirrored onto the API's node locks, so other
	// RETYC clients see them and theirs are honoured here (see lockMirror).
	mirror := newLockMirror(fs, lockSystem)
	davHandler := markReadRequests(mirror.middleware(handler))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "COPY" {
			// Server-side copy: the storage duplicates the chunks, nothing
			// transits through this process (see handleCopy).
			fs.handleCopy(w, r)

			return
		}
		if r.Method == http.MethodPut {
			rctx := withIsPut(r.Context())
			if r.ContentLength >= 0 {
				rctx = withContentLength(rctx, r.ContentLength)
			}
			r = r.WithContext(rctx)
		}
		// Pre-set Content-Type to skip http.ServeContent's 512-byte sniff read,
		// which would otherwise trigger a full buffered download before the
		// streaming path engages. We use the node's decrypted MIME type when
		// available (cached Stat), falling back to the filename extension.
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Content-Type", fs.contentTypeForPath(r.Context(), r.URL.Path))
		}
		davHandler.ServeHTTP(w, r)
	})

	return &Server{fs: fs, mirror: mirror, handler: mux}
}

// ServeHTTP serves a WebDAV request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// RunLocks renews the mirrored server locks while the WebDAV locks stand,
// until ctx ends, then releases them. It returns once they are released: a
// caller waits for it before exiting (see ServeUntilDrained).
func (s *Server) RunLocks(ctx context.Context) { s.mirror.run(ctx) }

// Close releases the tree (caches, store, spools). Call it once the HTTP
// server has stopped accepting requests.
func (s *Server) Close() error { return s.fs.tree.Close() }
