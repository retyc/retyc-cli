package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// countingResolver returns a resolver that records how many times it ran and the
// maximum number of concurrent runs, blocking each run until release is closed.
func countingResolver(release <-chan struct{}) (
	fn func(context.Context, string) (*DataroomSession, error), calls, maxConcurrent *atomic.Int32,
) {
	calls, maxConcurrent = new(atomic.Int32), new(atomic.Int32)
	var running atomic.Int32
	fn = func(_ context.Context, drID string) (*DataroomSession, error) {
		calls.Add(1)
		if n := running.Add(1); n > maxConcurrent.Load() {
			maxConcurrent.Store(n)
		}
		<-release
		running.Add(-1)

		return &DataroomSession{PublicKey: "pub-" + drID}, nil
	}

	return fn, calls, maxConcurrent
}

// The dataroom session keypair never changes (a rekey re-encrypts the same key
// for a new member set), so once resolved it must never be resolved again: each
// resolution costs an scrypt (~256 MiB of working memory) when no keyring helps.
func TestSessionCache_ResolvedOnce(t *testing.T) {
	release := make(chan struct{})
	close(release)
	resolve, calls, _ := countingResolver(release)
	var c SessionCache
	ctx := context.Background()

	first, err := c.Get(ctx, "dr1", resolve)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	second, err := c.Get(ctx, "dr1", resolve)
	if err != nil {
		t.Fatalf("Get (cached): %v", err)
	}
	if first != second {
		t.Error("second Get returned a different session: cache miss")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("resolver ran %d times, want 1", got)
	}
}

// A failed resolution is not cached: the next caller retries.
func TestSessionCache_ErrorNotCached(t *testing.T) {
	var c SessionCache
	boom := errors.New("boom")
	n := 0
	resolve := func(_ context.Context, _ string) (*DataroomSession, error) {
		n++
		if n == 1 {
			return nil, boom
		}

		return &DataroomSession{PublicKey: "ok"}, nil
	}
	if _, err := c.Get(context.Background(), "dr1", resolve); !errors.Is(err, boom) {
		t.Fatalf("first Get error = %v, want boom", err)
	}
	sess, err := c.Get(context.Background(), "dr1", resolve)
	if err != nil || sess.PublicKey != "ok" {
		t.Fatalf("second Get = %v, %v; want retry success", sess, err)
	}
}

// Concurrent misses must not stack scrypts: callers for the same dataroom share
// one resolution, and resolutions for different datarooms run one at a time.
func TestSessionCache_SingleFlightAndSerialized(t *testing.T) {
	release := make(chan struct{})
	resolve, calls, maxConcurrent := countingResolver(release)
	var c SessionCache
	ctx := context.Background()

	var wg sync.WaitGroup
	for _, drID := range []string{"dr1", "dr1", "dr1", "dr2", "dr2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, err := c.Get(ctx, drID, resolve)
			if err != nil {
				t.Errorf("Get(%s): %v", drID, err)
			} else if sess.PublicKey != "pub-"+drID {
				t.Errorf("Get(%s) = %q", drID, sess.PublicKey)
			}
		}()
	}
	// Let every goroutine reach the cache miss before releasing the resolver.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 2 {
		t.Errorf("resolver ran %d times, want 2 (one per dataroom)", got)
	}
	if got := maxConcurrent.Load(); got != 1 {
		t.Errorf("max concurrent resolutions = %d, want 1", got)
	}
}

// A caller waiting on someone else's in-flight resolution must honour its context.
func TestSessionCache_WaiterHonoursContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	resolve, _, _ := countingResolver(release)
	var c SessionCache

	go func() { _, _ = c.Get(context.Background(), "dr1", resolve) }()
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, "dr1", resolve); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Get error = %v, want context.DeadlineExceeded", err)
	}
}

// Once the process-wide cache is enabled (mcp serve), every service function that
// resolves a dataroom session goes through it: the second GetDataroomSession for
// the same dataroom must hit neither the API nor the passphrase reader.
func TestGetDataroomSession_UsesProcessCacheWhenEnabled(t *testing.T) {
	t.Cleanup(disableSessionCacheForTest)

	userKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	userPrivEnc, err := crypto.EncryptWithPassphrase([]byte(userKey.String()), "pw")
	if err != nil {
		t.Fatal(err)
	}
	sessPrivEnc, err := crypto.EncryptStringForKeys(sessKey.String(), []string{userKey.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}

	var apiCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		switch r.URL.Path {
		case "/dataroom/dr1":
			_ = json.NewEncoder(w).Encode(api.Dataroom{
				ID: "dr1", SessionPublicKey: sessKey.Recipient().String(), SessionPrivateKeyEnc: sessPrivEnc,
			})
		case "/user/me/key/active":
			_ = json.NewEncoder(w).Encode(api.UserKey{
				ID: "k1", PublicKey: userKey.Recipient().String(), PrivateKeyEnc: userPrivEnc,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{}
	client := api.New(srv.URL, "retyc-test/1.0", oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "t", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour),
	}), false, false)
	reads := 0
	reader := func() (string, error) {
		reads++

		return "pw", nil
	}
	ctx := context.Background()

	EnableSessionCache()

	first, err := GetDataroomSession(ctx, cfg, client, "dr1", reader)
	if err != nil {
		t.Fatalf("GetDataroomSession: %v", err)
	}
	if first.PublicKey != sessKey.Recipient().String() {
		t.Errorf("PublicKey = %q, want the session public key", first.PublicKey)
	}
	callsAfterFirst := apiCalls.Load()

	second, err := GetDataroomSession(ctx, cfg, client, "dr1", reader)
	if err != nil {
		t.Fatalf("GetDataroomSession (cached): %v", err)
	}
	if second != first {
		t.Error("second GetDataroomSession did not return the cached session")
	}
	if got := apiCalls.Load(); got != callsAfterFirst {
		t.Errorf("API calls after second resolution = %d, want %d (no new call)", got, callsAfterFirst)
	}
	if reads != 1 {
		t.Errorf("passphrase reader ran %d times, want 1", reads)
	}
}

// Logout must drop every cached dataroom session: the process-wide cache is
// keyed by dataroom ID only, so material decrypted with user A's key would
// otherwise be served to user B after a login in the same mcp serve process.
func TestLogout_ResetsProcessSessionCache(t *testing.T) {
	t.Setenv("RETYC_CONFIG_DIR", t.TempDir())
	t.Setenv("RETYC_TOKEN", "")
	EnableSessionCache()
	t.Cleanup(disableSessionCacheForTest)
	processSessions.Load().Store("dr1", &DataroomSession{PublicKey: "user-a"})

	if _, err := Logout(context.Background(), "", http.DefaultClient); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	resolved := false
	sess, err := processSessions.Load().Get(context.Background(), "dr1",
		func(context.Context, string) (*DataroomSession, error) {
			resolved = true

			return &DataroomSession{PublicKey: "user-b"}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !resolved || sess.PublicKey != "user-b" {
		t.Errorf("session after logout = %+v (resolved=%v), want a fresh resolution", sess, resolved)
	}
}

// A resolution in flight when Reset is called completes for its callers but is
// not cached: it was started under the identity being dropped.
func TestSessionCache_ResetDropsInflightResult(t *testing.T) {
	release := make(chan struct{})
	resolve, calls, _ := countingResolver(release)
	var c SessionCache
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := c.Get(ctx, "dr1", resolve); err != nil {
			t.Error(err)
		}
	}()
	waitFor(t, func() bool { return calls.Load() == 1 })
	c.Reset()
	close(release)
	<-done

	if _, err := c.Get(ctx, "dr1", resolve); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("resolver ran %d times, want 2 (in-flight result must not be cached after Reset)", got)
	}
}

// waitFor polls cond until it holds or the test times out.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(time.Millisecond)
	}
}

// The shared resolution must not run under the leader's request context: a
// leader whose request is aborted (client disconnect, MCP cancellation) would
// otherwise fail every waiter with context.Canceled for a resolution never
// attempted on their behalf.
func TestSessionCache_LeaderCancellationDoesNotFailWaiters(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int32
	resolve := func(ctx context.Context, drID string) (*DataroomSession, error) {
		started.Add(1)
		<-release
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		return &DataroomSession{PublicKey: "pub-" + drID}, nil
	}
	var c SessionCache

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = c.Get(leaderCtx, "dr1", resolve)
	}()
	waitFor(t, func() bool { return started.Load() == 1 })

	waiterErr := make(chan error, 1)
	go func() {
		_, err := c.Get(context.Background(), "dr1", resolve)
		waiterErr <- err
	}()
	waitFor(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()

		return c.inflight["dr1"] != nil
	})

	cancelLeader()
	close(release)
	<-leaderDone

	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter error = %v, want the resolved session", err)
	}
}
