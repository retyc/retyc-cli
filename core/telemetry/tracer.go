// Package telemetry is the tracing instrumentation of the core: Tracer(), the
// attribute keys (attrs.go), RecordError, the RoundTripper of the API client,
// the root spans of the FUSE operations (used.go). It uses the OpenTelemetry
// API only; `retyc fs mount` installs the SDK and the OTLP exporter
// (pkg/otelexport). Without them every span is a no-op.
package telemetry

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/retyc/retyc-cli"

// Tracer returns the CLI tracer from the global provider (no-op when off).
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}
