package telemetry_test

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
)

func TestUsedSpan_ExportedOnlyWithChildren(t *testing.T) {
	exporter := telemetrytest.Install(t)

	// Nothing happened under it: dropped, error or not.
	_, idle := telemetry.StartUsedRoot(context.Background(), "FUSE lookup")
	idle.End(nil)
	_, failed := telemetry.StartUsedRoot(context.Background(), "FUSE open")
	failed.End(errors.New("secret-name.txt: no such file"))
	if spans := exporter.GetSpans(); len(spans) != 0 {
		t.Fatalf("%d spans exported for operations that started no child", len(spans))
	}

	// A child was started: kept, as a root, with the type of the error only.
	parent, outer := telemetry.Tracer().Start(context.Background(), "caller")
	ctx, used := telemetry.StartUsedRoot(parent, "FUSE readdir",
		trace.WithAttributes(telemetry.AttrFuseOp.String("readdir")))
	_, child := telemetry.Tracer().Start(ctx, "GET /dataroom/{id}/nodes")
	child.End()
	used.End(errors.New("secret-name.txt: no such file"))
	outer.End()

	spans := exporter.GetSpans()
	telemetrytest.AssertNoLeak(t, spans, "secret-name")
	var found bool
	for _, s := range spans {
		if s.Name != "FUSE readdir" {
			continue
		}
		found = true
		if s.Parent.IsValid() {
			t.Error("the span is a child of its caller, want a root")
		}
		if s.ChildSpanCount != 1 {
			t.Errorf("ChildSpanCount = %d, want 1", s.ChildSpanCount)
		}
		var errType string
		for _, kv := range s.Attributes {
			if kv.Key == telemetry.AttrErrorType {
				errType = kv.Value.AsString()
			}
		}
		if errType != "errors.errorString" {
			t.Errorf("error.type = %q", errType)
		}
	}
	if !found {
		t.Errorf("the span with a child was not exported (%d spans)", len(spans))
	}
}

// Without a tracer provider the span is a no-op: End must not panic.
func TestUsedSpan_TracingOff(t *testing.T) {
	_, span := telemetry.StartUsedRoot(context.Background(), "FUSE read")
	span.Span().SetAttributes(telemetry.AttrFuseOp.String("read"))
	span.End(nil)
}
