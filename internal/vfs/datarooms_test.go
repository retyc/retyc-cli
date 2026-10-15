package vfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
)

const sentinel = "SENTINEL-do-not-export"

// swrOptions are the settings webdav serve runs with by default: an expired
// list is served for five minutes past its one-minute TTL.
var swrOptions = Options{TTL: time.Minute, MaxStale: 5 * time.Minute}

// newTestCache returns a cache over list with swrOptions.
func newTestCache(list ListDataroomsFunc) *DataroomCache {
	return NewDataroomCache(list, swrOptions)
}

// ageDataroomCache makes the cached list expired.
func ageDataroomCache(c *DataroomCache) {
	ageDataroomCacheBy(c, 2*c.opts.ttl())
}

// ageDataroomCacheBy makes the cached list one fetched age ago.
func ageDataroomCacheBy(c *DataroomCache, age time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list, _ := c.store.datarooms(context.Background())
	aged := *list
	aged.FetchedAt = time.Now().Add(-age)
	c.store.putDatarooms(&aged)
}

// waitDataroomFetchDone returns once c has no fetch in flight.
func waitDataroomFetchDone(t *testing.T, c *DataroomCache) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		idle := c.incoming == nil
		c.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the dataroom fetch never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

// spanAttr returns the value of the attribute key on s, "" when absent.
func spanAttr(s *tracetest.SpanStub, key string) string {
	for _, kv := range s.Attributes {
		if string(kv.Key) == key {
			return kv.Value.String()
		}
	}

	return ""
}

// waitRefreshSpan returns the first cache.refresh span exported.
func waitRefreshSpan(t *testing.T, exp *tracetest.InMemoryExporter) *tracetest.SpanStub {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, s := range exp.GetSpans() {
			if s.Name == "cache.refresh" {
				return &s
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no cache.refresh span exported")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDataroomCache_BasicResolution(t *testing.T) {
	calls := 0
	cache := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		calls++

		return []Dataroom{
			{ID: "id-1", Title: "Alpha"},
			{ID: "id-2", Title: "Beta"},
		}, nil
	})

	id, err := cache.IDForName(context.Background(), "Alpha")
	if err != nil || id != "id-1" {
		t.Fatalf("IDForName(\"Alpha\") = (%q, %v), want (\"id-1\", nil)", id, err)
	}
	if calls != 1 {
		t.Errorf("fetch called %d times, want 1", calls)
	}
}

func TestDataroomCache_CacheHit(t *testing.T) {
	calls := 0
	cache := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		calls++

		return []Dataroom{{ID: "id-1", Title: "Alpha"}}, nil
	})

	_, _ = cache.IDForName(context.Background(), "Alpha")
	_, _ = cache.IDForName(context.Background(), "Alpha")
	if calls != 1 {
		t.Errorf("fetch called %d times, want 1 (second call should hit cache)", calls)
	}
}

func TestDataroomCache_NotFound(t *testing.T) {
	cache := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		return []Dataroom{{ID: "id-1", Title: "Alpha"}}, nil
	})

	_, err := cache.IDForName(context.Background(), "Unknown")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("IDForName(\"Unknown\") error = %v, want os.ErrNotExist", err)
	}
}

func TestDataroomCache_TitleCollision(t *testing.T) {
	cache := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		return []Dataroom{
			{ID: "id-1", Title: "Docs"},
			{ID: "id-2", Title: "Docs"},
			{ID: "id-3", Title: "Docs"},
		}, nil
	})

	id1, err := cache.IDForName(context.Background(), "Docs")
	if err != nil || id1 != "id-1" {
		t.Fatalf("first collision: got (%q, %v), want (\"id-1\", nil)", id1, err)
	}
	id2, err := cache.IDForName(context.Background(), "Docs (2)")
	if err != nil || id2 != "id-2" {
		t.Fatalf("second collision: got (%q, %v), want (\"id-2\", nil)", id2, err)
	}
	id3, err := cache.IDForName(context.Background(), "Docs (3)")
	if err != nil || id3 != "id-3" {
		t.Fatalf("third collision: got (%q, %v), want (\"id-3\", nil)", id3, err)
	}
}

// TestDataroomCache_CollisionStableAcrossOrder verifies that the collision suffix
// for two same-titled datarooms is assigned by ID, so the name→ID mapping is
// identical regardless of the order the API returns the items in.
func TestDataroomCache_CollisionStableAcrossOrder(t *testing.T) {
	forward := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		return []Dataroom{
			{ID: "id-aaa", Title: "Docs"},
			{ID: "id-bbb", Title: "Docs"},
		}, nil
	})
	reversed := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		return []Dataroom{
			{ID: "id-bbb", Title: "Docs"},
			{ID: "id-aaa", Title: "Docs"},
		}, nil
	})

	ctx := context.Background()
	for _, name := range []string{"Docs", "Docs (2)"} {
		idF, errF := forward.IDForName(ctx, name)
		idR, errR := reversed.IDForName(ctx, name)
		if errF != nil || errR != nil {
			t.Fatalf("IDForName(%q): forward=%v reversed=%v", name, errF, errR)
		}
		if idF != idR {
			t.Errorf("name %q maps to %q (forward) vs %q (reversed); should be stable", name, idF, idR)
		}
	}
	// Lowest ID gets the unsuffixed name.
	if id, _ := forward.IDForName(ctx, "Docs"); id != "id-aaa" {
		t.Errorf("Docs = %q, want id-aaa (lowest ID)", id)
	}
}

// An expired list is served at once while a single background refresh
// replaces it: the refresh used to hold the cache lock, so every request of
// the server waited for the /dataroom round trip once a minute.
func TestDataroomCache_StaleEntryServedWhileRefreshing(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	cache := newTestCache(func(context.Context) ([]Dataroom, error) {
		if calls.Add(1) == 1 {
			return []Dataroom{{ID: "id-1", Title: "Alpha"}}, nil
		}
		<-gate

		return []Dataroom{{ID: "id-9", Title: "Alpha"}}, nil
	})
	ctx := context.Background()
	if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)

	for range 10 {
		id, err := cache.IDForName(ctx, "Alpha")
		if err != nil || id != "id-1" {
			t.Fatalf("IDForName during the refresh = (%q, %v), want the stale id-1", id, err)
		}
	}
	close(gate)
	deadline := time.Now().Add(time.Second)
	for {
		if id, _ := cache.IDForName(ctx, "Alpha"); id == "id-9" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background refresh never replaced the stale entry")
		}
		time.Sleep(time.Millisecond)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("fetch called %d times, want 2 (initial + one shared refresh)", got)
	}
}

// A name missing from an expired list may be a dataroom created since: the
// lookup waits for the refresh instead of answering 404 from the old list.
func TestDataroomCache_MissOnStaleEntryWaitsForRefresh(t *testing.T) {
	var calls atomic.Int32
	cache := newTestCache(func(context.Context) ([]Dataroom, error) {
		items := []Dataroom{{ID: "id-1", Title: "Alpha"}}
		if calls.Add(1) > 1 {
			items = append(items, Dataroom{ID: "id-2", Title: "Beta"})
		}

		return items, nil
	})
	ctx := context.Background()
	if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)

	if id, err := cache.IDForName(ctx, "Beta"); err != nil || id != "id-2" {
		t.Errorf("IDForName(Beta) = (%q, %v), want id-2 from the refreshed list", id, err)
	}
}

// A failed refresh keeps the stale list: the API being briefly unreachable
// must not turn every dataroom into a 404.
func TestDataroomCache_RefreshErrorKeepsStaleEntry(t *testing.T) {
	var calls atomic.Int32
	cache := newTestCache(func(context.Context) ([]Dataroom, error) {
		if calls.Add(1) == 1 {
			return []Dataroom{{ID: "id-1", Title: "Alpha"}}, nil
		}

		return nil, errors.New("API down")
	})
	ctx := context.Background()
	if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)

	// The miss waits for the refresh, which fails: the error is reported.
	if _, err := cache.IDForName(ctx, "Beta"); err == nil {
		t.Error("IDForName(Beta) succeeded although the refresh failed")
	}
	if id, err := cache.IDForName(ctx, "Alpha"); err != nil || id != "id-1" {
		t.Errorf("IDForName(Alpha) after a failed refresh = (%q, %v), want the stale id-1", id, err)
	}
	// That last lookup started a background refresh: it must be over before
	// the test returns, or it would count in another test's refresh metric.
	waitDataroomFetchDone(t, cache)
}

// A fetch that never completes (an API that sends its headers then stalls)
// must time out: otherwise it stays in flight forever and no later lookup can
// start another refresh.
func TestDataroomCache_StalledFetchTimesOut(t *testing.T) {
	var calls atomic.Int32
	opts := swrOptions
	opts.FetchTimeout = 20 * time.Millisecond
	cache := NewDataroomCache(func(ctx context.Context) ([]Dataroom, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()

			return nil, ctx.Err()
		}

		return []Dataroom{{ID: "id-1", Title: "Alpha"}}, nil
	}, opts)
	ctx := context.Background()

	if _, err := cache.IDForName(ctx, "Alpha"); err == nil {
		t.Fatal("the stalled fetch succeeded")
	}
	if id, err := cache.IDForName(ctx, "Alpha"); err != nil || id != "id-1" {
		t.Errorf("IDForName after a timed-out fetch = (%q, %v), want id-1 from a new fetch", id, err)
	}
}

func TestDataroomCache_Names(t *testing.T) {
	cache := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		return []Dataroom{
			{ID: "id-2", Title: "Zebra"},
			{ID: "id-1", Title: "Alpha"},
		}, nil
	})

	names, err := cache.Names(context.Background())
	if err != nil {
		t.Fatalf("Names() error = %v", err)
	}
	if len(names) != 2 || names[0] != "Alpha" || names[1] != "Zebra" {
		t.Errorf("Names() = %v, want [Alpha Zebra]", names)
	}
}

// The names belong to the caller: changing them must not reach the cache, nor
// the next caller.
func TestDataroomCache_NamesAreACopy(t *testing.T) {
	cache := newTestCache(func(_ context.Context) ([]Dataroom, error) {
		return []Dataroom{{ID: "id-1", Title: "Alpha"}, {ID: "id-2", Title: "Zebra"}}, nil
	})
	ctx := context.Background()

	names, err := cache.Names(ctx)
	if err != nil {
		t.Fatalf("Names() error = %v", err)
	}
	names[0] = "X"

	again, err := cache.Names(ctx)
	if err != nil {
		t.Fatalf("Names() error = %v", err)
	}
	if len(again) != 2 || again[0] != "Alpha" || again[1] != "Zebra" {
		t.Errorf("Names() after a caller changed its slice = %v, want [Alpha Zebra]", again)
	}
	if id, err := cache.IDForName(ctx, "Alpha"); err != nil || id != "id-1" {
		t.Errorf("IDForName(Alpha) = (%q, %v), want id-1", id, err)
	}
}

// The slice a ListDataroomsFunc returns stays its own: the cache sorts a copy.
func TestDataroomCache_DoesNotSortTheListedSlice(t *testing.T) {
	items := []Dataroom{{ID: "id-2", Title: "Zebra"}, {ID: "id-1", Title: "Alpha"}}
	cache := newTestCache(func(_ context.Context) ([]Dataroom, error) { return items, nil })

	if _, err := cache.Names(context.Background()); err != nil {
		t.Fatalf("Names() error = %v", err)
	}
	if items[0].ID != "id-2" || items[1].ID != "id-1" {
		t.Errorf("the listed slice was reordered: %+v", items)
	}
}

// The dataroom list honours max stale too: past TTL + max stale, a lookup
// waits for the refresh instead of trusting a list that old.
func TestDataroomCache_PastMaxStaleWaits(t *testing.T) {
	var calls atomic.Int32
	cache := NewDataroomCache(func(context.Context) ([]Dataroom, error) {
		n := calls.Add(1)

		return []Dataroom{{ID: fmt.Sprintf("id-%d", n), Title: "Alpha"}}, nil
	}, Options{TTL: time.Minute, MaxStale: 5 * time.Minute})
	ctx := context.Background()
	if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCacheBy(cache, 7*time.Minute)

	if id, err := cache.IDForName(ctx, "Alpha"); err != nil || id != "id-2" {
		t.Errorf("IDForName = (%q, %v), want the fresh id-2", id, err)
	}
}

// With max stale 0 the dataroom list is not served expired either.
func TestDataroomCache_MaxStaleZeroWaits(t *testing.T) {
	var calls atomic.Int32
	cache := NewDataroomCache(func(context.Context) ([]Dataroom, error) {
		n := calls.Add(1)

		return []Dataroom{{ID: fmt.Sprintf("id-%d", n), Title: "Alpha"}}, nil
	}, Options{TTL: time.Minute})
	ctx := context.Background()
	if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)

	if id, err := cache.IDForName(ctx, "Alpha"); err != nil || id != "id-2" {
		t.Errorf("IDForName = (%q, %v), want the fresh id-2", id, err)
	}
}

// A zero Options is usable: the TTL falls back to DefaultCacheTTL, so the
// second lookup is a cache hit rather than a fetch per call.
func TestDataroomCache_ZeroOptionsUseDefaultTTL(t *testing.T) {
	var calls atomic.Int32
	cache := NewDataroomCache(func(context.Context) ([]Dataroom, error) {
		calls.Add(1)

		return []Dataroom{{ID: "id-1", Title: "Alpha"}}, nil
	}, Options{})
	ctx := context.Background()
	for range 2 {
		if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("fetch called %d times, want 1", got)
	}
}

func TestDataroomCache_CountsRefreshes(t *testing.T) {
	refreshes := metrics.VFSDataroomCacheRefreshes.WithLabelValues("ok")
	before := testutil.ToFloat64(refreshes)
	c := newTestCache(func(context.Context) ([]Dataroom, error) {
		return []Dataroom{{ID: "dr1", Title: "A"}}, nil
	})
	ctx := context.Background()
	if _, err := c.resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(refreshes) - before; got != 1 {
		t.Errorf("refresh delta = %v, want 1 (second resolve is a cache hit)", got)
	}
}

// A refresh that fails is counted apart, so a dashboard tells an API that
// refuses the listing from a list that is merely refreshed often.
func TestDataroomCache_CountsFailedRefreshes(t *testing.T) {
	failed := metrics.VFSDataroomCacheRefreshes.WithLabelValues("error")
	before := testutil.ToFloat64(failed)
	c := newTestCache(func(context.Context) ([]Dataroom, error) {
		return nil, errors.New("boom")
	})
	if _, err := c.resolve(context.Background()); err == nil {
		t.Fatal("resolve() succeeded on a failed fetch")
	}
	if got := testutil.ToFloat64(failed) - before; got != 1 {
		t.Errorf("failed refresh delta = %v, want 1", got)
	}
}

// Resolving a dataroom from its title tags the current span with its ID: the
// title never leaves the process, the UUID is what a trace needs.
func TestDataroomCache_IDForNameTagsSpan(t *testing.T) {
	exp := telemetrytest.Install(t)
	cache := newTestCache(func(context.Context) ([]Dataroom, error) {
		return []Dataroom{{ID: "019d7cba-c700-73c2-8eac-f3dc311d1b25", Title: "SENTINEL"}}, nil
	})
	ctx, span := telemetry.Tracer().Start(context.Background(), "parent")
	if _, err := cache.IDForName(ctx, "SENTINEL"); err != nil {
		t.Fatal(err)
	}
	span.End()

	var got string
	for _, kv := range exp.GetSpans()[0].Attributes {
		if kv.Key == "retyc.dataroom.id" {
			got = kv.Value.AsString()
		}
		if strings.Contains(kv.Value.String(), "SENTINEL") {
			t.Errorf("attribute %s leaks the title", kv.Key)
		}
	}
	if got != "019d7cba-c700-73c2-8eac-f3dc311d1b25" {
		t.Errorf("retyc.dataroom.id = %q", got)
	}
}

// The dataroom list's background refresh gets its own trace; the first
// fetch, which the request waits for, stays in the request's trace.
func TestDataroomCache_BackgroundRefreshHasItsOwnTrace(t *testing.T) {
	exp := telemetrytest.Install(t)
	fetchSpans := make(chan trace.SpanContext, 4)
	cache := newTestCache(func(ctx context.Context) ([]Dataroom, error) {
		fetchSpans <- trace.SpanFromContext(ctx).SpanContext()

		return []Dataroom{{ID: "id-1", Title: sentinel}}, nil
	})

	reqCtx, reqSpan := telemetry.Tracer().Start(context.Background(), "WEBDAV PROPFIND")
	if _, err := cache.IDForName(reqCtx, sentinel); err != nil {
		t.Fatal(err)
	}
	if got := <-fetchSpans; got.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("the first fetch must run in the request span, got %v", got)
	}
	ageDataroomCache(cache)
	if _, err := cache.IDForName(reqCtx, sentinel); err != nil {
		t.Fatal(err)
	}
	reqSpan.End()
	refreshCtx := <-fetchSpans

	refresh := waitRefreshSpan(t, exp)
	if refresh.Parent.IsValid() || refreshCtx.SpanID() != refresh.SpanContext.SpanID() {
		t.Errorf("cache.refresh: parent %v, fetch span %v, want a root span running the fetch", refresh.Parent, refreshCtx)
	}
	if len(refresh.Links) != 1 || refresh.Links[0].SpanContext.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("cache.refresh links = %+v, want one link to the request span", refresh.Links)
	}
	if name := spanAttr(refresh, "retyc.cache.name"); name != "datarooms" {
		t.Errorf("retyc.cache.name = %q, want datarooms", name)
	}
	telemetrytest.AssertNoLeak(t, exp.GetSpans(), sentinel)
}

// The dataroom list's failed refresh is recorded as an error by type only:
// its message never reaches the span.
func TestDataroomCache_FailedRefreshSpanCarriesNoMessage(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	cache := newTestCache(func(context.Context) ([]Dataroom, error) {
		if calls.Add(1) > 1 {
			return nil, errors.New("listing " + sentinel)
		}

		return []Dataroom{{ID: "id-1", Title: "Alpha"}}, nil
	})
	ctx := context.Background()
	if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)
	if _, err := cache.IDForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}

	refresh := waitRefreshSpan(t, exp)
	if refresh.Status.Code != codes.Error || spanAttr(refresh, "error.type") == "" {
		t.Errorf("status = %+v, error.type = %q, want Error with a type", refresh.Status, spanAttr(refresh, "error.type"))
	}
	telemetrytest.AssertNoLeak(t, exp.GetSpans(), sentinel)
}

// Waiting on a dataroom list fetch links the request to it only when the
// fetch ran as a background refresh.
func TestDataroomFetch_WaitLinksBackgroundRefresh(t *testing.T) {
	exp := telemetrytest.Install(t)
	_, refreshSpan := telemetry.Tracer().Start(context.Background(), "cache.refresh")
	refreshSpan.End()

	done := make(chan struct{})
	close(done)
	ctx, span := telemetry.Tracer().Start(context.Background(), "WEBDAV PROPFIND")
	if _, err := (&dataroomFetch{done: done, refresh: refreshSpan.SpanContext()}).wait(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := (&dataroomFetch{done: done}).wait(ctx); err != nil { // foreground: no link
		t.Fatal(err)
	}
	span.End()

	for _, s := range exp.GetSpans() {
		if s.Name != "WEBDAV PROPFIND" {
			continue
		}
		if len(s.Links) != 1 || s.Links[0].SpanContext.SpanID() != refreshSpan.SpanContext().SpanID() {
			t.Errorf("links = %+v, want one link to the refresh", s.Links)
		}
	}
}

func TestOptions_FetchTimeout(t *testing.T) {
	if got := (Options{}).fetchTimeout(); got != detachedFetchTimeout {
		t.Errorf("fetchTimeout() of zero Options = %v, want %v", got, detachedFetchTimeout)
	}
	if got := (Options{FetchTimeout: time.Second}).fetchTimeout(); got != time.Second {
		t.Errorf("fetchTimeout() = %v, want 1s", got)
	}
}
