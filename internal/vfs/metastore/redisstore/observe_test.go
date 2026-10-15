package redisstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// observed is the number of observations the histogram holds for op and
// result.
func observed(t *testing.T, op, result string) uint64 {
	t.Helper()
	h, ok := metrics.VFSStoreOpDuration.WithLabelValues(op, result).(prometheus.Histogram)
	if !ok {
		t.Fatal("not a histogram")
	}
	var m dto.Metric
	must(t, h.Write(&m))

	return m.GetHistogram().GetSampleCount()
}

// spansNamed returns the exported spans called name.
func spansNamed(spans tracetest.SpanStubs, name string) tracetest.SpanStubs {
	var out tracetest.SpanStubs
	for _, s := range spans {
		if s.Name == name {
			out = append(out, s)
		}
	}

	return out
}

func attrOf(s tracetest.SpanStub, key attribute.Key) (attribute.Value, bool) {
	for _, kv := range s.Attributes {
		if kv.Key == key {
			return kv.Value, true
		}
	}

	return attribute.Value{}, false
}

// traced returns a context that carries a span, and that span.
func traced(t *testing.T) (context.Context, trace.Span) {
	t.Helper()

	return telemetry.Tracer().Start(context.Background(), "parent")
}

// An operation made under a span is a CLIENT child of it that says which
// operation, on which dataroom, and how many nodes a listing held.
func TestSpans_ChildOfTheCallersSpan(t *testing.T) {
	e := newEnv(t)
	exp := telemetrytest.Install(t)
	s := e.store(false)
	ctx, parent := traced(t)
	before := observed(t, opGetNode, "ok")

	l := &metastore.Listing{Nodes: []metastore.Node{file("x"), file("y")}, FetchedAt: time.Now()}
	must(t, s.PutListing(ctx, lk("/a"), l))
	n, _, ok, err := s.GetNode(ctx, lk("/a"), "x")
	must(t, err)
	if !ok || n == nil || n.Name != "x" {
		t.Fatalf("GetNode = %v, %v", n, ok)
	}
	if _, ok, err := s.GetListing(ctx, lk("/a")); err != nil || !ok {
		t.Fatalf("GetListing = %v, %v", ok, err)
	}
	parent.End()

	if got := observed(t, opGetNode, "ok") - before; got != 1 {
		t.Errorf("get_node observations = %d, want 1", got)
	}
	spans := exp.GetSpans()
	got := spansNamed(spans, "redis get_node")
	if len(got) != 1 {
		t.Fatalf("%d redis get_node spans, want 1", len(got))
	}
	span := got[0]
	psc := parent.SpanContext()
	if span.Parent.SpanID() != psc.SpanID() || span.SpanContext.TraceID() != psc.TraceID() {
		t.Error("the span is not a child of the caller's")
	}
	if span.SpanKind != trace.SpanKindClient {
		t.Errorf("kind = %v, want client", span.SpanKind)
	}
	if span.Status.Code == codes.Error {
		t.Error("a read that succeeded is marked failed")
	}
	want := map[attribute.Key]string{
		telemetry.AttrDBSystem: "redis", telemetry.AttrDBOperation: opGetNode, telemetry.AttrDataroomID: dr,
	}
	if len(span.Attributes) != len(want) {
		t.Errorf("attributes = %v, want exactly %v", span.Attributes, want)
	}
	for key, v := range want {
		if got, _ := attrOf(span, key); got.AsString() != v {
			t.Errorf("%s = %q, want %q", key, got.AsString(), v)
		}
	}
	for _, name := range []string{"redis put_listing", "redis get_listing"} {
		l := spansNamed(spans, name)
		if len(l) != 1 {
			t.Fatalf("%d %s spans, want 1", len(l), name)
		}
		if count, ok := attrOf(l[0], telemetry.AttrNodeCount); !ok || count.AsInt64() != 2 {
			t.Errorf("%s: node count = %v (%v), want 2", name, count.AsInt64(), ok)
		}
	}
}

// Every method that talks to Redis has its span and its series, under the
// name of its operation.
func TestSpans_EveryOperation(t *testing.T) {
	e := newEnv(t)
	exp := telemetrytest.Install(t)
	s := e.store(false)
	ctx, parent := traced(t)
	ops := []string{
		opGetListing, opGetNode, opGetNamed, opListingMeta, opGeneration, opPutListing, opRenewListing,
		opUpsertNode, opRemoveNode, opDeleteListing, opDeleteSubtree, opGetEntry, opPutEntry, opDeleteEntries,
		opDeleteEntriesBelow,
	}
	before := map[string]uint64{}
	for _, op := range ops {
		before[op] = observed(t, op, "ok")
	}
	x := file("x")
	l := &metastore.Listing{Nodes: []metastore.Node{x}, FetchedAt: time.Now()}
	entry := &metastore.Entry{Node: &x, FetchedAt: time.Now()}

	must(t, s.PutListing(ctx, lk("/a"), l))
	g, err := s.Generation(ctx, lk("/a"))
	must(t, err)
	_, err = s.PutListingIf(ctx, lk("/a"), l, g)
	must(t, err)
	_, _, err = s.GetListing(ctx, lk("/a"))
	must(t, err)
	_, _, err = s.ListingMeta(ctx, lk("/a"))
	must(t, err)
	_, _, _, err = s.GetNode(ctx, lk("/a"), "x")
	must(t, err)
	// A node and an entry in one round trip: one span, not the two of its halves.
	_, _, _, _, _, err = s.GetNamed(ctx, lk("/a"), "x")
	must(t, err)
	_, err = s.RenewListingIf(ctx, lk("/a"), "e", time.Now(), g+1)
	must(t, err)
	_, err = s.UpsertNode(ctx, lk("/a"), file("y"))
	must(t, err)
	_, err = s.RemoveNode(ctx, lk("/a"), "y")
	must(t, err)
	must(t, s.PutEntry(ctx, ek("/a", "x"), entry))
	_, err = s.PutEntryIf(ctx, ek("/a", "x"), entry, g)
	must(t, err)
	_, _, err = s.GetEntry(ctx, ek("/a", "x"))
	must(t, err)
	_, _, err = s.GetEntry(ctx, ek("/a", "absent")) // no such field is not a failure
	must(t, err)
	must(t, s.DeleteEntries(ctx, dr, "/a"))
	must(t, s.DeleteEntriesBelow(ctx, dr, "/"))
	must(t, s.DeleteListing(ctx, lk("/a")))
	must(t, s.DeleteSubtree(ctx, dr, "/"))
	// What does not reach Redis opens nothing.
	must(t, s.PutDatarooms(ctx, &metastore.DataroomList{}))
	_, _, err = s.GetDatarooms(ctx)
	must(t, err)
	parent.End()

	spans := exp.GetSpans()
	calls := map[string]int{opPutListing: 2, opPutEntry: 2, opGetEntry: 2}
	total := 1 // the parent
	for _, op := range ops {
		want := max(calls[op], 1)
		total += want
		if got := len(spansNamed(spans, "redis "+op)); got != want {
			t.Errorf("%d redis %s spans, want %d", got, op, want)
		}
		if got := observed(t, op, "ok") - before[op]; got != uint64(want) {
			t.Errorf("%s: %d observations, want %d", op, got, want)
		}
	}
	if len(spans) != total {
		t.Errorf("%d spans, want %d", len(spans), total)
	}
	for _, sp := range spans {
		if sp.Status.Code == codes.Error {
			t.Errorf("%s is marked failed", sp.Name)
		}
	}
}

// A call that carries no span opens none: what vfs writes after a mutation
// comes with a background context and must not become a trace of its own. A
// call that never reaches Redis opens none either, and is not measured.
func TestSpans_NoneWithoutAParent(t *testing.T) {
	e := newEnv(t)
	exp := telemetrytest.Install(t)
	s := e.store(false)
	before := observed(t, opGetNode, "ok")

	put(t, s, "/a", file("x"))
	_, _, ok, err := s.GetNode(context.Background(), lk("/a"), "x")
	must(t, err)
	if !ok {
		t.Fatal("the node is not held")
	}
	if got := observed(t, opGetNode, "ok") - before; got != 1 {
		t.Errorf("get_node observations = %d, want 1: the histogram needs no span", got)
	}

	// The keys cannot be named: nothing is asked of Redis.
	ctx, parent := traced(t)
	e.codec.unresolved.Store(true)
	_, _, _, err = s.GetNode(ctx, lk("/a"), "x")
	must(t, err)
	must(t, s.PutListing(ctx, lk("/a"), &metastore.Listing{FetchedAt: time.Now()}))
	e.codec.unresolved.Store(false)
	if got := observed(t, opGetNode, "ok") - before; got != 1 {
		t.Errorf("get_node observations = %d, want 1: an early return is not measured", got)
	}
	parent.End()

	if spans := exp.GetSpans(); len(spans) != 1 || spans[0].Name != "parent" {
		t.Errorf("spans = %d, want the parent alone", len(spans))
	}
}

// A failure marks the span with the type of the error and nothing else: the
// message of a Redis error may quote a key, that of the client an address.
func TestSpans_ErrorTypeOnly(t *testing.T) {
	e := newEnv(t)
	exp := telemetrytest.Install(t)
	s := e.store(false)
	f, ok := s.listingOf(lk("/a"))
	if !ok {
		t.Fatal("no keys")
	}
	// A key of another type than the store's: Redis refuses the read.
	must(t, e.raw.Set(context.Background(), f.ls, "not a hash", time.Minute).Err())
	before := observed(t, opGetNode, "error")

	ctx, parent := traced(t)
	_, _, _, wrongType := s.GetNode(ctx, lk("/a"), "x")
	if wrongType == nil {
		t.Fatal("reading a key of the wrong type did not fail")
	}
	must(t, s.Close())
	_, closed := s.Generation(ctx, lk("/a"))
	if closed == nil {
		t.Fatal("a closed store answered")
	}
	parent.End()

	if got := observed(t, opGetNode, "error") - before; got != 1 {
		t.Errorf("get_node error observations = %d, want 1", got)
	}
	spans := exp.GetSpans()
	for name, cause := range map[string]error{"redis get_node": wrongType, "redis generation": closed} {
		got := spansNamed(spans, name)
		if len(got) != 1 {
			t.Fatalf("%d %s spans, want 1", len(got), name)
		}
		if got[0].Status.Code != codes.Error || got[0].Status.Description != "" {
			t.Errorf("%s: status = %v %q, want Error without description", name, got[0].Status.Code, got[0].Status.Description)
		}
		// The type of the client's error, not of the wrapper every failure
		// of the store shares.
		typ, _ := attrOf(got[0], telemetry.AttrErrorType)
		if typ.AsString() == "" || strings.Contains(typ.AsString(), "storeError") || strings.Contains(typ.AsString(), " ") {
			t.Errorf("%s: error.type = %q", name, typ.AsString())
		}
		if len(got[0].Events) != 0 {
			t.Errorf("%s: %d events, want none", name, len(got[0].Events))
		}
		telemetrytest.AssertNoLeak(t, got, cause.Error())
	}
	telemetrytest.AssertNoLeak(t, spans, "WRONGTYPE")
	telemetrytest.AssertNoLeak(t, spans, e.prefix)
}

// The privacy rule: no span of the store carries a name, a path, a target, a
// MIME type, a key, a field, a hash or the URL, whether the store writes the
// names decrypted or sealed.
func TestSpans_NoLeak(t *testing.T) {
	const sentinel = "zzleakzz"
	for _, high := range []bool{false, true} {
		name := "clear"
		if high {
			name = "high confidentiality"
		}
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			exp := telemetrytest.Install(t)
			s := e.store(high)
			ctx, parent := traced(t)
			dir := "/" + sentinel + "-dir/" + sentinel + "-sub"
			doc := seal(file(sentinel + "-report.pdf"))
			link := seal(metastore.Node{
				ID: "id-link", Name: sentinel + "-link", Type: metastore.TypeSymlink, Target: "/" + sentinel + "-target",
			})
			l := &metastore.Listing{Nodes: []metastore.Node{doc}, FetchedAt: time.Now(), ETag: sentinel + "-etag"}

			must(t, s.PutListing(ctx, lk(dir), l))
			g, err := s.Generation(ctx, lk(dir))
			must(t, err)
			_, err = s.PutListingIf(ctx, lk(dir), l, g)
			must(t, err)
			_, err = s.UpsertNode(ctx, lk(dir), link)
			must(t, err)
			got, ok, err := s.GetListing(ctx, lk(dir))
			must(t, err)
			if !ok || names(got.Nodes) != names([]metastore.Node{link, doc}) {
				t.Fatalf("GetListing = %v, %v", got, ok)
			}
			n, _, ok, err := s.GetNode(ctx, lk(dir), doc.Name)
			must(t, err)
			if !ok || n == nil || n.Name != doc.Name {
				t.Fatalf("GetNode = %v, %v", n, ok)
			}
			_, _, err = s.ListingMeta(ctx, lk(dir))
			must(t, err)
			must(t, s.PutEntry(ctx, ek(dir, doc.Name), &metastore.Entry{Node: &doc, FetchedAt: time.Now()}))
			_, err = s.PutEntryIf(ctx, ek(dir, sentinel+"-missing"), &metastore.Entry{FetchedAt: time.Now()}, g)
			must(t, err)
			entry, ok, err := s.GetEntry(ctx, ek(dir, doc.Name))
			must(t, err)
			if !ok || entry.Node == nil || entry.Node.Name != doc.Name {
				t.Fatalf("GetEntry = %v, %v", entry, ok)
			}
			_, err = s.RemoveNode(ctx, lk(dir), link.Name)
			must(t, err)
			must(t, s.DeleteEntries(ctx, dr, dir))
			must(t, s.DeleteEntriesBelow(ctx, dr, "/"+sentinel+"-dir"))
			must(t, s.DeleteListing(ctx, lk(dir)))
			must(t, s.DeleteSubtree(ctx, dr, "/"+sentinel+"-dir"))
			// A failure, whose message go-redis builds.
			must(t, s.Close())
			if _, _, _, err := s.GetNode(ctx, lk(dir), doc.Name); err == nil {
				t.Fatal("a closed store answered")
			}
			parent.End()

			spans := exp.GetSpans()
			if len(spans) < 14 {
				t.Fatalf("%d spans: the scenario was not traced", len(spans))
			}
			f, _ := s.listingOf(lk(dir))
			nh, _ := f.hash(doc.Name)
			for _, needle := range []string{
				sentinel, sealPrefix, e.prefix, e.url, f.h, nh, "text/x-", "id-", "v-", schema + ":",
			} {
				telemetrytest.AssertNoLeak(t, spans, needle)
			}
		})
	}
}
