package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

// The Destination header is not normalized: another spelling of the source
// path must not be taken for a destination to replace, which would delete the
// source.
func TestHandleCopy_DestinationSpelledAsSource(t *testing.T) {
	for _, dst := range []string{"/dataroom/DR/sub/../doc.txt", "/dataroom/DR//doc.txt", "/dataroom/DR/doc.txt/"} {
		fake := &lot2API{t: t}
		w := httptest.NewRecorder()
		newLot2FS(t, fake).handleCopy(w, copyRequest("/dataroom/DR/doc.txt", dst, ""))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d (%s), want 403", dst, w.Code, w.Body.String())
		}
		if fake.count("DELETE") != 0 || fake.count("POST") != 0 {
			t.Errorf("%s: API calls = %v, want none", dst, fake.calls)
		}
	}
}

// COPY honours the WebDAV locks as the handler does for its own methods: a
// destination another client locked is not replaced without its token.
func TestHandleCopy_HonoursDestinationLock(t *testing.T) {
	const dst = "/dataroom/DR/old.txt"
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	fs.locks = webdav.NewMemLS()
	token, err := fs.locks.Create(time.Now(), webdav.LockDetails{Root: dst, Duration: time.Hour, ZeroDepth: true})
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	fs.handleCopy(w, copyRequest("/dataroom/DR/doc.txt", dst, ""))
	if w.Code != webdav.StatusLocked || fake.count("DELETE") != 0 {
		t.Fatalf("without the token: status = %d, calls = %v, want 423 and nothing deleted", w.Code, fake.calls)
	}

	w = httptest.NewRecorder()
	r := copyRequest("/dataroom/DR/doc.txt", dst, "")
	r.Header.Set("If", "(<urn:uuid:not-the-lock>)")
	fs.handleCopy(w, r)
	if w.Code != http.StatusPreconditionFailed || fake.count("DELETE") != 0 {
		t.Fatalf("with another token: status = %d, calls = %v, want 412 and nothing deleted", w.Code, fake.calls)
	}

	w = httptest.NewRecorder()
	r = copyRequest("/dataroom/DR/doc.txt", dst, "")
	r.Header.Set("If", "<http://example.com"+dst+"> (<"+token+">)")
	fs.handleCopy(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("with the token: status = %d (%s), want 204", w.Code, w.Body.String())
	}
	// The hold taken for the request is released: the lock can be confirmed again.
	release, err := fs.locks.Confirm(time.Now(), dst, "", webdav.Condition{Token: token})
	if err != nil {
		t.Fatalf("the lock is still held after the COPY: %v", err)
	}
	release()
}

func TestParseIfHeader(t *testing.T) {
	for _, tc := range []struct {
		hdr   string
		lists int
		ok    bool
	}{
		{"(<urn:uuid:a>)", 1, true},
		{"(<urn:uuid:a> [\"etag\"]) (Not <urn:uuid:b>)", 2, true},
		{"<http://h/p> (<urn:uuid:a>)", 1, true},
		{"", 0, false},
		{"()", 0, false},
		{"(<urn:uuid:a>", 0, false},
		{"(Not)", 0, false},
		{"urn:uuid:a", 0, false},
	} {
		lists, ok := parseIfHeader(tc.hdr)
		if ok != tc.ok || len(lists) != tc.lists {
			t.Errorf("parseIfHeader(%q) = %d list(s), %v; want %d, %v", tc.hdr, len(lists), ok, tc.lists, tc.ok)
		}
	}
	lists, _ := parseIfHeader("<http://h/p> (Not <urn:uuid:a> [W/\"e\"])")
	if l := lists[0]; l.resourceTag != "http://h/p" || len(l.conditions) != 2 ||
		!l.conditions[0].Not || l.conditions[0].Token != "urn:uuid:a" || l.conditions[1].ETag != `W/"e"` {
		t.Errorf("parsed %+v", lists)
	}
}

// A WebDAV lock that lapsed without UNLOCK stops being renewed on the API:
// its server lock is released.
func TestLockMirror_ReleasesLapsedLocks(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	handler, mirror := newLockedHandler(fs)
	handler.ServeHTTP(httptest.NewRecorder(), lockRequest("/dataroom/DR/locked.txt", ""))
	if mirror.held() != 1 {
		t.Fatalf("held = %d", mirror.held())
	}

	mirror.refreshAll(context.Background())
	if mirror.held() != 1 || fake.count("PUT /dataroom/node/lock/l-1") != 1 {
		t.Fatalf("a standing lock: held = %d, calls = %v, want it renewed", mirror.held(), fake.calls)
	}

	mirror.mu.Lock()
	for _, ml := range mirror.locks {
		if ml.expires.IsZero() {
			t.Error("the Second-3600 timeout of the LOCK was not recorded")
		}
		ml.expires = time.Now().Add(-time.Second)
	}
	mirror.mu.Unlock()
	mirror.refreshAll(context.Background())
	if mirror.held() != 0 || fake.count("DELETE /dataroom/node/lock/l-1") != 1 {
		t.Errorf("a lapsed lock: held = %d, calls = %v, want it released", mirror.held(), fake.calls)
	}
}

// The periodic renewal never takes a server lock for a token unlocked since
// it was read.
func TestLockMirror_BackgroundRefreshSkipsReleasedToken(t *testing.T) {
	fake := &lot2API{t: t}
	fs := newLot2FS(t, fake)
	_, mirror := newLockedHandler(fs)

	mirror.refresh(context.Background(), "urn:uuid:gone", "n-doc", "/dataroom/DR/locked.txt", time.Time{}, true)
	if mirror.held() != 0 || fake.count("POST") != 0 {
		t.Errorf("held = %d, calls = %v, want nothing taken", mirror.held(), fake.calls)
	}
}
