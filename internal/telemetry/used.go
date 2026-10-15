package telemetry

import (
	"context"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// UsedSpan is a root span that is exported only when something happened under
// it: it is kept when a child span was started (an API round trip, a
// decryption, a session unlock) and dropped otherwise.
//
// It is for an operation that is answered from a cache most of the time and
// reaches the API now and then, when nothing tells the two apart beforehand
// (a FUSE lookup, an open, a read): one span per operation would bury the
// trace under spans that carry nothing, no span at all would leave the API
// calls of the others as unrelated roots.
//
// A dropped span is one that is never ended: the SDK exports a span when it
// ends, and holds no reference to it before.
type UsedSpan struct {
	span trace.Span
}

// StartUsedRoot opens a root span named name (WithNewRoot: the caller serves
// requests that belong to no trace of its own) and returns the context that
// carries it. End must be called.
func StartUsedRoot(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, UsedSpan) {
	ctx, span := Tracer().Start(ctx, name, append([]trace.SpanStartOption{trace.WithNewRoot()}, opts...)...)

	return ctx, UsedSpan{span: span}
}

// Span returns the span, to set attributes on. They are lost with a span
// that is dropped.
func (u UsedSpan) Span() trace.Span { return u.span }

// End ends the span when it has children, recording err on it (its type
// only, see RecordError), and drops it otherwise.
func (u UsedSpan) End(err error) {
	if ro, ok := u.span.(sdktrace.ReadOnlySpan); ok && ro.ChildSpanCount() == 0 {
		return
	}
	RecordError(u.span, err)
	u.span.End()
}
