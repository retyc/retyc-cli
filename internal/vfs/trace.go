package vfs

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/telemetry"
)

// detachedFetchTimeout bounds a fetch shared by several requests, which is
// detached from the request that started it so that one client giving up
// cannot fail the others. The API client has no overall timeout (an upload
// can take as long as it needs): without this bound, an API that sends its
// headers then stalls would keep the fetch in flight forever, and every later
// request needing it would wait on it. Tests shorten it per instance
// (Options.FetchTimeout), never globally: a background fetch of another test
// may still be reading it.
const detachedFetchTimeout = 2 * time.Minute

// fetchTimeout returns FetchTimeout, or the default bound of a detached fetch
// (two minutes) when it is zero.
func (o Options) fetchTimeout() time.Duration {
	if o.FetchTimeout > 0 {
		return o.FetchTimeout
	}

	return detachedFetchTimeout
}

// linkRefresh links the request span of ctx to the cache.refresh trace of a
// background refresh it waited for (a lookup that joined it: a name missing
// from the expired listing, an entry past max stale): the API work the request
// waited for lives in that other trace. An invalid refresh (the fetch was not
// a background one) adds nothing.
func linkRefresh(ctx context.Context, refresh trace.SpanContext) {
	if refresh.IsValid() {
		trace.SpanFromContext(ctx).AddLink(trace.Link{SpanContext: refresh})
	}
}

// startRefreshSpan opens the root span of a background cache refresh, named
// "cache.refresh", linked to the request whose lookup triggered it.
//
// The refresh runs after that request has answered from the expired entry: as
// a child of the request span it would outlive its parent, and read as if the
// request had waited for it. A trace of its own keeps the request's duration
// honest, and the link still leads from one to the other. cache is the
// retyc.cache.name of the entry (nodes, datarooms), never a path or a title.
func startRefreshSpan(ctx context.Context, link trace.Link, cache string) (context.Context, trace.Span) {
	return telemetry.Tracer().Start(ctx, "cache.refresh",
		trace.WithNewRoot(),
		trace.WithLinks(link),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(telemetry.AttrCacheName.String(cache)))
}
