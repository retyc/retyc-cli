package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingRT is an injected base transport: it records every request it
// sends and forwards it to base.
type recordingRT struct {
	mu   sync.Mutex
	reqs []*http.Request
	base http.RoundTripper
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()

	return r.base.RoundTrip(req)
}

func TestWithBaseTransport_CarriesEveryLayer(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "No more requests allowed", http.StatusTooManyRequests)

			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	rt := &recordingRT{base: srv.Client().Transport}
	client, clock := newRetryTestClient(srv, WithBaseTransport(rt))
	start := clock.now()

	if err := client.Get(context.Background(), "/x", nil); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	// The 429 is replayed through the injected transport.
	if len(rt.reqs) != 2 {
		t.Fatalf("injected transport saw %d requests, want 2", len(rt.reqs))
	}
	if got := clock.now().Sub(start); got != time.Second {
		t.Errorf("waited %s, want the Retry-After of 1s", got)
	}
	for i, req := range rt.reqs {
		if got := req.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("attempt %d Authorization = %q, want Bearer test-token", i+1, got)
		}
		if got := req.Header.Get("User-Agent"); got != "retyc-test/1.0" {
			t.Errorf("attempt %d User-Agent = %q, want retyc-test/1.0", i+1, got)
		}
	}
}

func TestWithBaseTransport_NilKeepsDefault(t *testing.T) {
	for _, opts := range [][]Option{nil, {WithBaseTransport(nil)}} {
		client := New("https://example.invalid", "retyc-test/1.0", nil, false, false, opts...)
		// Anonymous client: the User-Agent layer sits right on the base.
		ua, ok := client.retry.base.(*UserAgentTransport)
		if !ok {
			t.Fatalf("layer under retry = %T, want *UserAgentTransport", client.retry.base)
		}
		base, ok := ua.Base.(*http.Transport)
		if !ok {
			t.Fatalf("base transport = %T, want *http.Transport", ua.Base)
		}
		if base.ResponseHeaderTimeout != 60*time.Second {
			t.Errorf("ResponseHeaderTimeout = %s, want 60s", base.ResponseHeaderTimeout)
		}
	}
}
