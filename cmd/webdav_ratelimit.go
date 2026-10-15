package cmd

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/retyc/retyc-cli/internal/api"
	"golang.org/x/net/webdav"
)

// — API rate limit (429) ————————————————————————————————————————————————————————
//
// The API client retries a 429 itself; what reaches the WebDAV server is a
// request still refused once api.retry.max_wait is spent
// (api.ErrRateLimited). x/net/webdav builds its statuses from the error of
// the FileSystem with no hook to change them (404, 405, 409 or 500 depending
// on the method), and only then hands the error to Handler.Logger. So the
// error response is held back until the handler returns: when the error the
// handler logged is a rate limit, a 429 with Retry-After (RFC 6585) is sent
// in its place.
//
// A PROPFIND with Depth: 1 needs more: x/net/webdav writes the 207 and the
// entry of the folder itself before it lists the children, so a listing that
// fails leaves a well-formed, truncated answer, i.e. an empty folder. Its
// whole response is held back instead; it is one folder, whose listing
// already sits in memory, in the cache. Depth: 0 lists nothing (a failed Stat
// comes before the 207), and Depth: infinity, which is also what a missing
// header means, walks a whole subtree: it stays streamed, unbounded as it is,
// and a listing refused in the middle of it leaves the truncated 207.

// rateLimitCtxKey is the context key of the error slot of a request.
type rateLimitCtxKey struct{}

// handlerError is where the Logger of the webdav.Handler leaves the error of
// the request for rateLimitStatus. Both run on the request's goroutine.
type handlerError struct{ err error }

// noteHandlerError records err as the error of r; called from the Logger of
// the webdav.Handler wrapped by rateLimitStatus.
func noteHandlerError(r *http.Request, err error) {
	if slot, ok := r.Context().Value(rateLimitCtxKey{}).(*handlerError); ok {
		slot.err = err
	}
}

// retryAfterSeconds is the Retry-After of a 429 answered for err: the pause
// the API asked for, rounded up, 1 s when it gave none.
func retryAfterSeconds(err error) string {
	secs := int(math.Ceil(api.RetryAfter(err).Seconds()))

	return strconv.Itoa(max(secs, 1))
}

// writeRateLimited answers 429 with the Retry-After of err.
func writeRateLimited(w http.ResponseWriter, err error) {
	w.Header().Set("Retry-After", retryAfterSeconds(err))
	http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

// rateLimitStatus wraps a webdav.Handler whose Logger calls noteHandlerError:
// a response whose handler error is api.ErrRateLimited becomes a 429. Success
// responses are written through untouched, streaming included; only the
// status line and the few bytes of an error response are held back, and the
// whole response of a PROPFIND with Depth: 1.
//
// Not covered: a response already started, i.e. a GET whose download is
// refused after the headers left (cut short, as any failed download) and a
// PROPFIND with Depth: infinity refused past its first entry.
func rateLimitStatus(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slot := &handlerError{}
		dw := &deferredErrorWriter{
			ResponseWriter: w,
			holdAll:        r.Method == "PROPFIND" && r.Header.Get("Depth") == "1",
		}
		next.ServeHTTP(dw, r.WithContext(context.WithValue(r.Context(), rateLimitCtxKey{}, slot)))
		if dw.held == 0 {
			return
		}
		if errors.Is(slot.err, api.ErrRateLimited) {
			// http.Error replaces the Content-Type the handler had set.
			writeRateLimited(w, slot.err)

			return
		}
		w.WriteHeader(dw.held)
		_, _ = w.Write(dw.body.Bytes())
	})
}

// newWebdavHandler builds the x/net/webdav handler of `webdav serve`: logf
// receives every request with its error, and a request the API rate limit
// defeated is answered 429 (see rateLimitStatus).
func newWebdavHandler(fs webdav.FileSystem, ls webdav.LockSystem, logf func(*http.Request, error)) http.Handler {
	return rateLimitStatus(&webdav.Handler{
		FileSystem: fs,
		LockSystem: ls,
		Logger: func(r *http.Request, err error) {
			noteHandlerError(r, err)
			if logf != nil {
				logf(r, err)
			}
		},
	})
}

// deferredErrorWriter holds back the status and body of an error response
// (status >= 400), or of any response when holdAll is set, so rateLimitStatus
// can replace it. Anything else goes straight to the underlying writer.
type deferredErrorWriter struct {
	http.ResponseWriter
	// holdAll holds back every response, not only the error ones.
	holdAll bool
	// started is set once a response that is not held back has begun.
	started bool
	// held is the status held back, 0 when none.
	held int
	body bytes.Buffer
}

func (w *deferredErrorWriter) WriteHeader(code int) {
	if w.started || w.held != 0 {
		return
	}
	if w.holdAll || code >= http.StatusBadRequest {
		w.held = code

		return
	}
	w.started = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *deferredErrorWriter) Write(p []byte) (int, error) {
	// A Write with no WriteHeader before it is a 200, as in net/http, where a
	// WriteHeader coming after the first Write is ignored too: holding that
	// 200 hides no later status.
	if w.held == 0 && w.holdAll {
		w.held = http.StatusOK
	}
	if w.held != 0 {
		return w.body.Write(p)
	}
	w.started = true

	return w.ResponseWriter.Write(p)
}

func (w *deferredErrorWriter) Flush() {
	if w.held != 0 {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap gives http.ResponseController the underlying writer, as
// statusRecorder does.
func (w *deferredErrorWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
