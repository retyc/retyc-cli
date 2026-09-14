// Package telemetry sets up OpenTelemetry tracing for the CLI.
//
// Tracing is off unless an OTLP endpoint is configured in the environment;
// then spans go to that collector over HTTP/protobuf or gRPC. Instrumentation
// sites use Tracer() and pay a no-op span when tracing is off.
package telemetry

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName      = "github.com/retyc/retyc-cli"
	shutdownTimeout = 2 * time.Second
)

// Options configures Init.
type Options struct {
	// Version is exported as service.version.
	Version string
	// Debug prints exporter failures on stderr; otherwise a collector that is
	// down stays silent for the user.
	Debug bool
}

// Telemetry holds the tracer provider to flush at exit. The zero value is a
// disabled instance whose Shutdown does nothing.
type Telemetry struct {
	tp  *sdktrace.TracerProvider
	res *resource.Resource // kept for tests; sdktrace.TracerProvider does not expose it
}

// Enabled reports whether the environment asks for tracing: an OTLP endpoint
// is set and OTEL_SDK_DISABLED is not true.
func Enabled() bool {
	return endpointConfigured() && !sdkDisabled()
}

// Init installs the global tracer provider when Enabled. It returns a
// disabled Telemetry and an error when the environment is unusable (unknown
// protocol); the caller reports it under --debug and runs untraced.
func Init(ctx context.Context, opts Options) (*Telemetry, error) {
	if !Enabled() {
		return &Telemetry{}, nil
	}
	// Installed before the exporter is built: the exporters parse their
	// OTEL_EXPORTER_OTLP_* settings at construction and report a malformed
	// value (headers included, so possibly a token) through this logger.
	debug := opts.Debug
	if !debug {
		otel.SetLogger(logr.Discard())
	}
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		if debug {
			fmt.Fprintln(os.Stderr, "opentelemetry:", err)
		}
	}))
	exp, proto, err := newExporter(ctx, protocol())
	if err != nil {
		return &Telemetry{}, err
	}
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "Tracing: OTLP %s exporter\n", proto)
	}
	// Defaults first, then the environment (OTEL_SERVICE_NAME,
	// OTEL_RESOURCE_ATTRIBUTES) so the operator wins. No process or host
	// detector: process.command_args would export cleartext file names.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", "retyc-cli"),
			attribute.String("service.version", opts.Version),
		),
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
	)
	if err != nil && res == nil {
		return &Telemetry{}, fmt.Errorf("building resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	return &Telemetry{tp: tp, res: res}, nil
}

// Shutdown flushes pending spans, bounded by shutdownTimeout. Export failures
// are swallowed: tracing never changes a command's outcome.
func (t *Telemetry) Shutdown(ctx context.Context) {
	if t == nil || t.tp == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()
	_ = t.tp.Shutdown(ctx)
}

// Tracer returns the CLI tracer from the global provider (no-op when off).
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// ParentFromEnv returns ctx carrying the remote span context described by
// TRACEPARENT / TRACESTATE (W3C trace context), or ctx unchanged when the
// variables are unset or invalid.
func ParentFromEnv(ctx context.Context) context.Context {
	tp := traceParent()
	if tp == "" {
		return ctx
	}
	carrier := propagation.MapCarrier{"traceparent": tp}
	if ts := traceState(); ts != "" {
		carrier["tracestate"] = ts
	}

	return propagation.TraceContext{}.Extract(ctx, carrier)
}
