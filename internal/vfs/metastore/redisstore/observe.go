package redisstore

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
)

// The operations of the store, as the "op" label of
// retycfs_store_op_duration_seconds and the name of a "redis <op>"
// span: one fixed name per method that talks to Redis (PutListingIf and
// PutEntryIf are put_listing and put_entry; GetNamed, one round trip for a
// node and an entry, is get_named).
const (
	opGetListing         = "get_listing"
	opGetNode            = "get_node"
	opGetNamed           = "get_named"
	opListingMeta        = "listing_meta"
	opGeneration         = "generation"
	opPutListing         = "put_listing"
	opRenewListing       = "renew_listing"
	opUpsertNode         = "upsert_node"
	opRemoveNode         = "remove_node"
	opDeleteListing      = "delete_listing"
	opDeleteSubtree      = "delete_subtree"
	opGetEntry           = "get_entry"
	opPutEntry           = "put_entry"
	opDeleteEntries      = "delete_entries"
	opDeleteEntriesBelow = "delete_entries_below"
)

// dbSystem is the db.system.name of every span of the store.
const dbSystem = "redis"

// operation is one round trip to Redis being measured: always by the
// histogram, and by a span when the caller is traced.
type operation struct {
	name  string
	start time.Time
	span  trace.Span // nil when the context carries no span
}

// begin starts the measure of an operation, right before its round trip: a
// call that returns early because its keys cannot be named measures nothing.
//
// The span is a child of the one ctx carries and is not opened without one:
// much of what vfs writes follows a mutation already made and comes with a
// background context, which must not become a trace of its own. It carries
// the operation and the dataroom ID, never a key, a field, a value or a path;
// the context it would return is not used, what the codec decrypts after the
// round trip is not under it.
func begin(ctx context.Context, name, dataroomID string) operation {
	o := operation{name: name, start: time.Now()}
	if trace.SpanContextFromContext(ctx).IsValid() {
		_, o.span = telemetry.Tracer().Start(ctx, "redis "+name,
			trace.WithSpanKind(trace.SpanKindClient),
			trace.WithAttributes(
				telemetry.AttrDBSystem.String(dbSystem),
				telemetry.AttrDBOperation.String(name),
				telemetry.AttrDataroomID.String(dataroomID),
			))
	}

	return o
}

// nodes records the number of nodes of the listing read or written.
func (o operation) nodes(n int) {
	if o.span != nil {
		o.span.SetAttributes(telemetry.AttrNodeCount.Int(n))
	}
}

// end closes the measure with the outcome of the round trip. Of an error the
// span keeps the type alone (see telemetry.RecordError), the one of the
// client's error and not of the storeError around it.
func (o operation) end(err error) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.StoreOpDuration.WithLabelValues(o.name, result).Observe(time.Since(o.start).Seconds())
	if o.span == nil {
		return
	}
	var se *storeError
	if errors.As(err, &se) {
		err = se.err
	}
	telemetry.RecordError(o.span, err)
	o.span.End()
}
