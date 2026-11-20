package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

// The size of a chunk is the Content-Length of a HEAD on its route: one
// request, no body.
func TestDataroomChunkEncryptedSize(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Method + " " + r.URL.Path)
		w.Header().Set("Content-Length", "8392299")
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	}))
	defer srv.Close()

	size, err := newTestClient(srv).DataroomChunkEncryptedSize(context.Background(), "v1", 3)
	if err != nil {
		t.Fatalf("DataroomChunkEncryptedSize: %v", err)
	}
	if size != 8392299 {
		t.Errorf("size = %d, want 8392299", size)
	}
	if want := "HEAD /dataroom/node/version/v1/chunk/3"; got.Load() != want {
		t.Errorf("request = %v, want %s", got.Load(), want)
	}
}

// What the route answers when it does not tell: only a 405 or a 501, and a
// success without a length, say the API has no size to give. A 404 is asked
// once, not retried as a download is.
func TestDataroomChunkEncryptedSize_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		noLength bool
		noSize   bool
		is       error
	}{
		"405":                    {status: http.StatusMethodNotAllowed, noSize: true},
		"501":                    {status: http.StatusNotImplemented, noSize: true},
		"200 without a length":   {status: http.StatusOK, noLength: true, noSize: true},
		"404":                    {status: http.StatusNotFound, is: ErrNotFound},
		"410":                    {status: http.StatusGone, is: ErrGone},
		"403":                    {status: http.StatusForbidden},
		"422":                    {status: http.StatusUnprocessableEntity},
		"429 after the retries":  {status: http.StatusTooManyRequests, is: ErrRateLimited},
		"500":                    {status: http.StatusInternalServerError},
		"200 with a zero length": {status: http.StatusOK, noSize: true},
	} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				if tc.noLength {
					// A handler that flushes sends no Content-Length.
					w.WriteHeader(tc.status)
					w.(http.Flusher).Flush()

					return
				}
				w.Header().Set("Content-Length", "0")
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			client := New(srv.URL, "retyc-test/1.0",
				oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}),
				false, false, WithRetry(0, 1))

			_, err := client.DataroomChunkEncryptedSize(context.Background(), "v1", 0)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.Is(err, ErrNoChunkSize); got != tc.noSize {
				t.Errorf("errors.Is(ErrNoChunkSize) = %v, want %v (%v)", got, tc.noSize, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("error = %v, want it to match %v", err, tc.is)
			}
			if tc.status != http.StatusOK {
				var httpErr *HTTPError
				if !errors.As(err, &httpErr) || httpErr.Status != tc.status {
					t.Errorf("error = %v, want the HTTPError %d", err, tc.status)
				}
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("%d requests, want 1", got)
			}
		})
	}
}

// A chunk download given a limit refuses a larger chunk: on its announced
// length, without reading the body, or once the limit is passed when no
// length is announced.
func TestDownloadDataroomChunkLimit(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 100)
	for name, tc := range map[string]struct {
		limit    int64
		chunked  bool
		tooLarge bool
	}{
		"no limit":                      {limit: 0},
		"under the limit":               {limit: 200},
		"exactly the limit":             {limit: 100},
		"over the limit":                {limit: 99, tooLarge: true},
		"no length, under the limit":    {limit: 200, chunked: true},
		"no length, exactly the limit":  {limit: 100, chunked: true},
		"no length, over the limit":     {limit: 99, chunked: true, tooLarge: true},
		"no length, far over, no limit": {limit: 0, chunked: true},
		"far over the limit":            {limit: 1, tooLarge: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.chunked {
					w.(http.Flusher).Flush()
				} else {
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				}
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			got, err := newTestClient(srv).DownloadDataroomChunkLimit(context.Background(), "v1", 0, tc.limit)
			switch {
			case tc.tooLarge:
				if !errors.Is(err, ErrChunkTooLarge) || got != nil {
					t.Fatalf("got %d bytes, error %v; want ErrChunkTooLarge", len(got), err)
				}
			case err != nil || !bytes.Equal(got, body):
				t.Fatalf("got %d bytes, error %v; want the chunk", len(got), err)
			}
		})
	}
}

// An announced length over the limit is refused without waiting for a body
// the server never sends.
func TestDownloadDataroomChunkLimit_RefusedBeforeTheBody(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	_, err := newTestClient(srv).DownloadDataroomChunkLimit(context.Background(), "v1", 0, 4096)
	if !errors.Is(err, ErrChunkTooLarge) {
		t.Fatalf("error = %v, want ErrChunkTooLarge", err)
	}
}

// A refusal of a bounded download keeps its status and its body.
func TestDownloadDataroomChunkLimit_ErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"version_pending_deletion"}`, http.StatusGone)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).DownloadDataroomChunkLimit(context.Background(), "v1", 0, 8)
	if !errors.Is(err, ErrGone) || ErrorDetail(err) != "version_pending_deletion" {
		t.Fatalf("error = %v, want the 410 with its detail", err)
	}
}
