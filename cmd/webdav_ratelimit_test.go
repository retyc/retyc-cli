package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// newStatusFS is newLot2FS over an API answering every request with status
// (and a Retry-After of 7 s). The client sends each request once and its
// gate never closes for more than a millisecond, so no test waits: a WebDAV
// request can make several API calls, each one held at the gate the previous
// refusal closed.
func newStatusFS(t *testing.T, status int) *webdavFS {
	t.Helper()
	fs := newLot2FS(t, &lot2API{t: t})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "No more requests allowed", status)
	}))
	t.Cleanup(srv.Close)
	root := cachedNodes(fs, "retyc://dr1/")
	sess, err := fs.tree.Session(context.Background(), "dr1")
	if err != nil {
		t.Fatal(err)
	}
	setClient(fs, api.New(srv.URL, "retyc-test/1.0", oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}), false, false, api.WithMissingChunkRetries(), api.WithRetry(time.Millisecond, 1)))
	// The session and the root listing are carried over. The listing of /sub
	// is not cached: reading it goes to the API.
	fs.tree.SeedSession("dr1", sess)
	_ = nodeStore(fs).PutListing(context.Background(), listingKey("retyc://dr1/"),
		&vfs.Listing{Nodes: root, FetchedAt: time.Now()})

	return fs
}

// A request the API rate limit defeated is answered 429 with the Retry-After
// of the API, whatever status x/net/webdav would have picked for the error.
func TestWebdav_APIRateLimitBecomes429(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
		depth  string
	}{
		// x/net/webdav answers 405 to a failed RemoveAll.
		{"delete", "DELETE", "/dataroom/DR/old.txt", ""},
		// A name looked up in a folder that has to be listed: 404 otherwise.
		{"get in unlisted folder", "GET", "/dataroom/DR/sub/report.txt", ""},
		{"propfind in unlisted folder", "PROPFIND", "/dataroom/DR/sub/report.txt", "0"},
		// x/net/webdav has written the 207 and the folder's own entry by the
		// time the listing fails: without the hold, an empty folder.
		{"propfind listing a folder", "PROPFIND", "/dataroom/DR/sub", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newStatusFS(t, http.StatusTooManyRequests)
			var logged error
			h := newWebdavHandler(fs, webdav.NewMemLS(), func(_ *http.Request, err error) { logged = err })

			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.depth != "" {
				r.Header.Set("Depth", tc.depth)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d (%s), want 429; handler error: %v", w.Code, w.Body.String(), logged)
			}
			if got := w.Header().Get("Retry-After"); got != "7" {
				t.Errorf("Retry-After = %q, want 7", got)
			}
			if logged == nil {
				t.Error("the request error must still reach the logger")
			}
		})
	}
}

// COPY bypasses x/net/webdav (handleCopy): same answer.
func TestHandleCopy_APIRateLimitBecomes429(t *testing.T) {
	fs := newStatusFS(t, http.StatusTooManyRequests)
	w := httptest.NewRecorder()

	fs.handleCopy(w, copyRequest("/dataroom/DR/doc.txt", "/dataroom/DR/copy.txt", ""))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d (%s), want 429", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != "7" {
		t.Errorf("Retry-After = %q, want 7", got)
	}
}

// Any other failure keeps the status and body x/net/webdav gives it, and a
// success is written through.
func TestWebdav_OtherResponsesAreUntouched(t *testing.T) {
	fs := newStatusFS(t, http.StatusInternalServerError)
	h := newWebdavHandler(fs, webdav.NewMemLS(), nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("DELETE", "/dataroom/DR/old.txt", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Body.String() != http.StatusText(http.StatusMethodNotAllowed) {
		t.Errorf("failed DELETE = %d %q, want the 405 of x/net/webdav", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on an error that is not a rate limit", got)
	}

	// Served from the cached listing: no API call.
	r := httptest.NewRequest("PROPFIND", "/dataroom/DR/doc.txt", nil)
	r.Header.Set("Depth", "0")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMultiStatus || w.Body.Len() == 0 {
		t.Errorf("PROPFIND = %d with %d bytes, want a 207 with its body", w.Code, w.Body.Len())
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for _, tc := range []struct {
		retryAfter time.Duration
		want       string
	}{
		{0, "1"}, // none given by the API
		{time.Second, "1"},
		{1500 * time.Millisecond, "2"},
		{7 * time.Second, "7"},
	} {
		err := &api.HTTPError{Status: http.StatusTooManyRequests, RetryAfter: tc.retryAfter}
		if got := retryAfterSeconds(err); got != tc.want {
			t.Errorf("retryAfterSeconds(%s) = %q, want %q", tc.retryAfter, got, tc.want)
		}
	}
}

// Only a PROPFIND with Depth: 1 is held back whole. Without the header
// (Depth: infinity, a whole subtree), with Depth: 0 or for another method,
// the bytes of a success leave as the handler writes them.
func TestRateLimitStatus_HoldsOnlyPropfindDepth1(t *testing.T) {
	for _, tc := range []struct {
		method, depth string
		wantHeld      bool
	}{
		{"PROPFIND", "1", true},
		{"PROPFIND", "", false},
		{"PROPFIND", "infinity", false},
		{"PROPFIND", "0", false},
		{"GET", "1", false},
	} {
		t.Run(tc.method+" depth="+tc.depth, func(t *testing.T) {
			rec := httptest.NewRecorder()
			var midway int
			h := rateLimitStatus(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/xml; charset=utf-8")
				w.WriteHeader(http.StatusMultiStatus)
				_, _ = w.Write([]byte("<first-entry/>"))
				// What has reached the client before the handler is done.
				midway = rec.Body.Len()
				_, _ = w.Write([]byte("<second-entry/>"))
			}))
			r := httptest.NewRequest(tc.method, "/dataroom/DR/sub", nil)
			if tc.depth != "" {
				r.Header.Set("Depth", tc.depth)
			}
			h.ServeHTTP(rec, r)

			if held := midway == 0; held != tc.wantHeld {
				t.Errorf("%d bytes sent before the handler returned; held = %v, want %v", midway, held, tc.wantHeld)
			}
			// Held or not, the client gets the same response in the end.
			if rec.Code != http.StatusMultiStatus || rec.Body.String() != "<first-entry/><second-entry/>" ||
				rec.Header().Get("Content-Type") != "text/xml; charset=utf-8" {
				t.Errorf("response = %d %q (%s)", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
			}
		})
	}
}

// A streamed PROPFIND refused past its first entry cannot be turned into a
// 429 any more: the 207 has left.
func TestRateLimitStatus_StreamedPropfindKeepsItsStatus(t *testing.T) {
	refusal := &api.HTTPError{Status: http.StatusTooManyRequests, RetryAfter: time.Second}
	h := rateLimitStatus(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte("<first-entry/>"))
		noteHandlerError(r, refusal)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("PROPFIND", "/dataroom/DR", nil))
	if rec.Code != http.StatusMultiStatus || rec.Header().Get("Retry-After") != "" {
		t.Errorf("response = %d, Retry-After %q; want the 207 already sent", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// A Depth: 1 listing that fails on anything but a rate limit keeps what
// x/net/webdav answered before this wrapper existed: the 207 it had started,
// holding the entry of the folder alone.
func TestWebdav_PropfindDepth1OtherFailureIsUnchanged(t *testing.T) {
	fs := newStatusFS(t, http.StatusInternalServerError)
	var logged error
	h := newWebdavHandler(fs, webdav.NewMemLS(), func(_ *http.Request, err error) { logged = err })

	r := httptest.NewRequest("PROPFIND", "/dataroom/DR/sub", nil)
	r.Header.Set("Depth", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if logged == nil {
		t.Fatal("the listing was expected to fail")
	}
	if w.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d (%s), want the 207 x/net/webdav had started", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if got := strings.Count(body, "<D:response>"); got != 1 || !strings.Contains(body, "/dataroom/DR/sub") {
		t.Errorf("%d entries in %q, want the folder alone", got, body)
	}
	if got := w.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on a failure that is not a rate limit", got)
	}
}
