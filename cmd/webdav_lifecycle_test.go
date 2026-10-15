package cmd

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// Shutting the server down while a request is in flight: the lifecycle does
// not return before that request has finished and the API locks are released.
// http.Server.Serve returns as soon as Shutdown closes the listener; returning
// then let the process exit under both, and the locks stood for their lease.
func TestServeUntilDrained_WaitsForRequestsAndLocks(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	handler, mirror := newLockedHandler(fs)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, lockRequest("/dataroom/DR/locked.txt", ""))
	if mirror.held() != 1 {
		t.Fatalf("held = %d, want the lock taken", mirror.held())
	}

	started, finish := make(chan struct{}), make(chan struct{})
	var completed atomic.Bool
	srv := &http.Server{ //nolint:gosec // G112: a test server on loopback
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-finish
			completed.Store(true)
			_, _ = io.WriteString(w, "done")
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	shutdown := newWebdavShutdown(srv, cancel, 5*time.Second)
	locksDone := make(chan struct{})
	var released atomic.Bool
	go func() {
		defer close(locksDone)
		mirror.run(ctx)
		released.Store(true)
	}()
	returned := make(chan error, 1)
	go func() { returned <- serveUntilDrained(srv, ln, shutdown, locksDone) }()

	body := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			body <- "error: " + err.Error()

			return
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		body <- string(raw)
	}()
	<-started

	go shutdown() // SIGTERM
	select {
	case err := <-returned:
		t.Fatalf("the server lifecycle returned (%v) while a request was in flight", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(finish)
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("serveUntilDrained = %v, want nil for a server shut down", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server lifecycle never returned")
	}
	if got := <-body; got != "done" || !completed.Load() {
		t.Errorf("the request in flight got %q, want it answered in full", got)
	}
	if !released.Load() || mirror.held() != 0 || fake.count("DELETE /dataroom/node/lock/l-1") != 1 {
		t.Errorf("on return: lock loop over = %v, held = %d, calls = %v; want the API lock released",
			released.Load(), mirror.held(), fake.calls)
	}
}

// A server that stops on its own (its listener fails) still goes through the
// shutdown path: its error is returned once the locks are released.
func TestServeUntilDrained_ServerFailure(t *testing.T) {
	srv := &http.Server{Handler: http.NotFoundHandler()} //nolint:gosec // G112: a test server on loopback
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	locksDone := make(chan struct{})
	go func() {
		defer close(locksDone)
		<-ctx.Done() // stands for the lock loop, which ends with the context
	}()

	err = serveUntilDrained(srv, ln, newWebdavShutdown(srv, cancel, time.Second), locksDone)
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		t.Errorf("serveUntilDrained = %v, want the failure of the listener", err)
	}
	if ctx.Err() == nil {
		t.Error("the shutdown path did not run for a server that stopped on its own")
	}
}

// A LOCK granted for zero seconds has lapsed as soon as it is answered: the
// mirror reads that from the response of the LOCK itself, not only from a
// later refresh, and releases the API lock at its next round.
func TestLockMirror_ReleasesALockGrantedLapsed(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	handler, mirror := newLockedHandler(fs)

	r := lockRequest("/dataroom/DR/locked.txt", "")
	r.Header.Set("Timeout", "Second-0")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("LOCK: status = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Second-0") {
		t.Fatalf("LOCK response = %s, want a zero timeout granted", w.Body.String())
	}
	if mirror.held() != 1 || fake.count("POST /dataroom/node/n-doc/lock") != 1 {
		t.Fatalf("held = %d, calls = %v, want the API lock taken", mirror.held(), fake.calls)
	}

	time.Sleep(2 * time.Millisecond)
	mirror.refreshAll(context.Background())
	if mirror.held() != 0 || fake.count("DELETE /dataroom/node/lock/l-1") != 1 ||
		fake.count("PUT /dataroom/node/lock/l-1") != 0 {
		t.Errorf("a lock granted lapsed: held = %d, calls = %v, want it released and never renewed",
			mirror.held(), fake.calls)
	}
}

// A COPY whose destination cannot be looked up copies nothing: the API's
// failure is a 500, a rate limit a 429, where the copy used to be sent as if
// the name were free.
func TestHandleCopy_DestinationLookupFailure(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		fs := newLot2FS(t, &lot2API{t: t})
		var copies atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				copies.Add(1)
			}
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
			AccessToken: "test-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour),
		}), false, false, api.WithRetry(time.Millisecond, 1)))
		// The session and the root listing are carried over; the listing of
		// /sub, where the destination is looked up, is not.
		fs.tree.SeedSession("dr1", sess)
		_ = nodeStore(fs).PutListing(context.Background(), listingKey("retyc://dr1/"),
			&vfs.Listing{Nodes: root, FetchedAt: time.Now()})

		w := httptest.NewRecorder()
		fs.handleCopy(w, copyRequest("/dataroom/DR/doc.txt", "/dataroom/DR/sub/copy.txt", ""))
		if w.Code != status {
			t.Errorf("%d: COPY status = %d (%s)", status, w.Code, strings.TrimSpace(w.Body.String()))
		}
		if status == http.StatusTooManyRequests && w.Header().Get("Retry-After") == "" {
			t.Errorf("429 without Retry-After: %v", w.Header())
		}
		if copies.Load() != 0 {
			t.Errorf("%d: %d copy request(s) sent for a destination that could not be looked up", status, copies.Load())
		}
	}
}
