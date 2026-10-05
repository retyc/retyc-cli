package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

const sentinel = "SENTINEL-do-not-export"

// assertNoSentinel walks every exported field of every span.
func assertNoSentinel(t *testing.T, spans tracetest.SpanStubs) {
	t.Helper()
	check := func(where, s string) {
		if strings.Contains(s, sentinel) {
			t.Errorf("%s leaks the sentinel: %s", where, s)
		}
	}
	for _, s := range spans {
		check("span name", s.Name)
		check("status description", s.Status.Description)
		for _, kv := range s.Attributes {
			check("attribute "+string(kv.Key), kv.Value.String())
		}
		for _, ev := range s.Events {
			check("event name", ev.Name)
			for _, kv := range ev.Attributes {
				check("event attribute "+string(kv.Key), kv.Value.String())
			}
		}
		if s.Resource != nil {
			for _, kv := range s.Resource.Attributes() {
				check("resource "+string(kv.Key), kv.Value.String())
			}
		}
	}
}

func TestTracing_NeverExportsNames(t *testing.T) {
	isolateConfig(t)
	exp := telemetrytest.Install(t)

	// 1. A WebDAV request whose path, body and listing all carry the sentinel.
	fs := &webdavFS{listFn: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return []service.DataroomNodeInfo{{ID: "n1", Name: sentinel + ".pdf", Type: "file"}}, nil
	}}
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.listNodes(r.Context(), "dr1", "/"+sentinel); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusMultiStatus)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PROPFIND", "/dataroom/"+sentinel+"/"+sentinel+".pdf",
		strings.NewReader("<propfind>"+sentinel+"</propfind>")))

	// 2. An API call whose query, header and body carry the sentinel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := &http.Client{Transport: telemetry.RoundTripper(http.DefaultTransport)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/dataroom/019d3de3-cba2-76d0-962d-7817e9858661/nodes?name="+sentinel, strings.NewReader(sentinel))
	req.Header.Set("X-Title", sentinel)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	// 3. A command whose argument and error message carry the sentinel.
	probe := &cobra.Command{
		Use:  "privacy-probe",
		Args: cobra.ArbitraryArgs,
		RunE: func(*cobra.Command, []string) error { return errors.New("stat " + sentinel + ": no such file") },
	}
	withTestCommand(t, probe)
	_ = run(context.Background(), []string{"privacy-probe", "/tmp/" + sentinel + ".pdf"})

	spans := exp.GetSpans()
	if len(spans) < 3 {
		t.Fatalf("expected at least 3 spans (webdav, api, command), got %d", len(spans))
	}
	assertNoSentinel(t, spans)
}

// The OIDC client (discovery, token refresh, device flow) runs before the API
// client exists: webdav serve init spent seconds there with no span at all.
func TestNewHTTPClient_TracesRoundTrips(t *testing.T) {
	isolateConfig(t)
	exp := telemetrytest.Install(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/realms/"+sentinel+"/protocol/openid-connect/token", strings.NewReader(sentinel))
	resp, err := newHTTPClient(false, false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if want := "/realms/{id}/protocol/openid-connect/token"; spans[0].Name != want {
		t.Errorf("span name = %q, want %q", spans[0].Name, want)
	}
	assertNoSentinel(t, spans)
}

// A background refresh of an expired listing runs after the request answered:
// it gets a root span of its own, linked to that request, with the API work as
// its children. A miss the request waits for stays in the request's trace.
func TestListNodes_BackgroundRefreshHasItsOwnTrace(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	fetchSpans := make(chan trace.SpanContext, 4)
	fs := &webdavFS{
		listFn: func(ctx context.Context, _, _ string) ([]service.DataroomNodeInfo, error) {
			calls.Add(1)
			fetchSpans <- trace.SpanFromContext(ctx).SpanContext()

			return []service.DataroomNodeInfo{{ID: "n1", Name: sentinel, Type: "file"}}, nil
		},
		cacheTTL: time.Minute, cacheMaxStale: 5 * time.Minute,
	}

	reqCtx, reqSpan := telemetry.Tracer().Start(context.Background(), "WEBDAV PROPFIND")
	if _, err := fs.listNodes(reqCtx, "dr1", "/"+sentinel); err != nil { // miss: waited for
		t.Fatal(err)
	}
	if got := <-fetchSpans; got.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("a miss the request waits for must run in the request span, got %v", got)
	}
	ageNodeCache(fs, dataroomURI("dr1", "/"+sentinel), 2*time.Minute)
	if _, err := fs.listNodes(reqCtx, "dr1", "/"+sentinel); err != nil { // stale: background refresh
		t.Fatal(err)
	}
	reqSpan.End()
	refreshCtx := <-fetchSpans
	waitNodeID(t, fs, "/"+sentinel, "n1")
	for calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}

	var refresh *tracetest.SpanStub
	deadline := time.Now().Add(2 * time.Second)
	for refresh == nil {
		for _, s := range exp.GetSpans() {
			if s.Name == "cache.refresh" {
				refresh = &s

				break
			}
		}
		if refresh == nil && time.Now().After(deadline) {
			t.Fatal("no cache.refresh span exported")
		}
		time.Sleep(time.Millisecond)
	}
	if refresh.Parent.IsValid() {
		t.Errorf("cache.refresh has parent %v, want a root span", refresh.Parent)
	}
	if refresh.SpanContext.TraceID() == reqSpan.SpanContext().TraceID() {
		t.Error("cache.refresh shares the request's trace")
	}
	if refreshCtx.SpanID() != refresh.SpanContext.SpanID() {
		t.Error("the refresh's API work does not run under the cache.refresh span")
	}
	if len(refresh.Links) != 1 || refresh.Links[0].SpanContext.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("cache.refresh links = %+v, want one link to the request span", refresh.Links)
	}
	attrs := map[string]string{}
	for _, kv := range refresh.Attributes {
		attrs[string(kv.Key)] = kv.Value.String()
	}
	if attrs["retyc.cache.name"] != "nodes" || attrs["retyc.dataroom.id"] != "dr1" {
		t.Errorf("cache.refresh attributes = %v", attrs)
	}
	assertNoSentinel(t, exp.GetSpans())
}

// The dataroom list's background refresh gets its own trace too; the first
// fetch, which the request waits for, stays in the request's trace.
func TestDataroomCache_BackgroundRefreshHasItsOwnTrace(t *testing.T) {
	exp := telemetrytest.Install(t)
	fetchSpans := make(chan trace.SpanContext, 4)
	cache := newDataroomCache(func(ctx context.Context) ([]dataroomCacheItem, error) {
		fetchSpans <- trace.SpanFromContext(ctx).SpanContext()

		return []dataroomCacheItem{{id: "id-1", title: sentinel}}, nil
	})

	reqCtx, reqSpan := telemetry.Tracer().Start(context.Background(), "WEBDAV PROPFIND")
	if _, err := cache.idForName(reqCtx, sentinel); err != nil {
		t.Fatal(err)
	}
	if got := <-fetchSpans; got.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("the first fetch must run in the request span, got %v", got)
	}
	ageDataroomCache(cache)
	if _, err := cache.idForName(reqCtx, sentinel); err != nil {
		t.Fatal(err)
	}
	reqSpan.End()
	refreshCtx := <-fetchSpans

	var refresh *tracetest.SpanStub
	deadline := time.Now().Add(2 * time.Second)
	for refresh == nil {
		for _, s := range exp.GetSpans() {
			if s.Name == "cache.refresh" {
				refresh = &s

				break
			}
		}
		if refresh == nil && time.Now().After(deadline) {
			t.Fatal("no cache.refresh span exported")
		}
		time.Sleep(time.Millisecond)
	}
	if refresh.Parent.IsValid() || refreshCtx.SpanID() != refresh.SpanContext.SpanID() {
		t.Errorf("cache.refresh: parent %v, fetch span %v, want a root span running the fetch", refresh.Parent, refreshCtx)
	}
	if len(refresh.Links) != 1 || refresh.Links[0].SpanContext.SpanID() != reqSpan.SpanContext().SpanID() {
		t.Errorf("cache.refresh links = %+v, want one link to the request span", refresh.Links)
	}
	if name := spanAttr(refresh, "retyc.cache.name"); name != "datarooms" {
		t.Errorf("retyc.cache.name = %q, want datarooms", name)
	}
	assertNoSentinel(t, exp.GetSpans())
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

// A failed background refresh is recorded as an error by type only: its
// message (a name, a path) never reaches the span.
func TestListNodes_FailedRefreshSpanCarriesNoMessage(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	fs := &webdavFS{
		listFn: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			if calls.Add(1) > 1 {
				return nil, fmt.Errorf("listing %s: %w", sentinel, os.ErrNotExist)
			}

			return []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}}, nil
		},
		cacheTTL: time.Minute, cacheMaxStale: 5 * time.Minute,
	}
	ctx := context.Background()
	if _, err := fs.listNodes(ctx, "dr1", "/"+sentinel); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, dataroomURI("dr1", "/"+sentinel), 2*time.Minute)
	if _, err := fs.listNodes(ctx, "dr1", "/"+sentinel); err != nil {
		t.Fatal(err)
	}

	refresh := waitRefreshSpan(t, exp)
	if refresh.Status.Code != codes.Error || refresh.Status.Description != "" {
		t.Errorf("status = %+v, want Error with no description", refresh.Status)
	}
	if spanAttr(refresh, "error.type") == "" {
		t.Error("error.type not set on the failed refresh")
	}
	assertNoSentinel(t, exp.GetSpans())
}

// The dataroom list's failed refresh carries no message either.
func TestDataroomCache_FailedRefreshSpanCarriesNoMessage(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	cache := newDataroomCache(func(context.Context) ([]dataroomCacheItem, error) {
		if calls.Add(1) > 1 {
			return nil, errors.New("listing " + sentinel)
		}

		return []dataroomCacheItem{{id: "id-1", title: "Alpha"}}, nil
	})
	ctx := context.Background()
	if _, err := cache.idForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}
	ageDataroomCache(cache)
	if _, err := cache.idForName(ctx, "Alpha"); err != nil {
		t.Fatal(err)
	}

	refresh := waitRefreshSpan(t, exp)
	if refresh.Status.Code != codes.Error || spanAttr(refresh, "error.type") == "" {
		t.Errorf("status = %+v, error.type = %q, want Error with a type", refresh.Status, spanAttr(refresh, "error.type"))
	}
	assertNoSentinel(t, exp.GetSpans())
}

// A request that joins a background refresh and waits for it (a name missing
// from the expired listing) gets a link to the refresh's trace: the API work
// it waited for is there, not in its own trace.
func TestFindListedNode_JoinedRefreshIsLinked(t *testing.T) {
	exp := telemetrytest.Install(t)
	var calls atomic.Int32
	fs := &webdavFS{
		listFn: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			nodes := []service.DataroomNodeInfo{{ID: "old", Name: "a", Type: "file"}}
			if calls.Add(1) > 1 {
				nodes = append(nodes, service.DataroomNodeInfo{ID: "new", Name: "b", Type: "file"})
			}

			return nodes, nil
		},
		cacheTTL: time.Minute, cacheMaxStale: 5 * time.Minute,
	}
	// Every slot taken: the background refresh stays queued until request B
	// joins it, so B is certain to wait for it.
	fs.refreshSlots = make(chan struct{}, 1)
	fs.refreshSlots <- struct{}{}
	ctx := context.Background()
	if _, err := fs.listNodes(ctx, "dr1", "/"); err != nil {
		t.Fatal(err)
	}
	ageNodeCache(fs, "retyc://dr1/", 2*time.Minute)

	ctxA, spanA := telemetry.Tracer().Start(ctx, "WEBDAV PROPFIND")
	if _, err := fs.listNodes(ctxA, "dr1", "/"); err != nil { // queues the refresh
		t.Fatal(err)
	}
	spanA.End()
	ctxB, spanB := telemetry.Tracer().Start(ctx, "WEBDAV GET")
	if n, err := fs.findListedNode(ctxB, "dr1", "/", "b"); err != nil || n.ID != "new" {
		t.Fatalf("findListedNode(b) = (%+v, %v)", n, err)
	}
	spanB.End()

	refresh := waitRefreshSpan(t, exp)
	var b *tracetest.SpanStub
	for _, s := range exp.GetSpans() {
		if s.Name == "WEBDAV GET" {
			b = &s
		}
	}
	if b == nil {
		t.Fatal("request B span not exported")
	}
	if len(b.Links) != 1 || b.Links[0].SpanContext.SpanID() != refresh.SpanContext.SpanID() {
		t.Errorf("request B links = %+v, want one link to cache.refresh", b.Links)
	}
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
