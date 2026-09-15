// Package telemetrytest installs an in-memory span exporter as the global
// tracer provider for the duration of a test.
package telemetrytest

import (
	"context"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

// OTelEnvNames lists every environment variable the OTel SDK or its OTLP
// exporters read. Tests clear all of them so a developer's shell (a real
// collector endpoint, a non-default sampler, exporter headers/TLS/timeout
// tuning...) can never leak into an assertion.
var OTelEnvNames = []string{
	"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
	"OTEL_SDK_DISABLED", "TRACEPARENT", "TRACESTATE", "OTEL_SERVICE_NAME",
	"OTEL_TRACES_SAMPLER", "OTEL_TRACES_SAMPLER_ARG",
	"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
	"OTEL_EXPORTER_OTLP_CERTIFICATE", "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
	"OTEL_EXPORTER_OTLP_COMPRESSION", "OTEL_EXPORTER_OTLP_TRACES_COMPRESSION",
	"OTEL_EXPORTER_OTLP_TIMEOUT", "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
	"OTEL_EXPORTER_OTLP_INSECURE", "OTEL_EXPORTER_OTLP_TRACES_INSECURE",
	"OTEL_BSP_SCHEDULE_DELAY", "OTEL_BSP_EXPORT_TIMEOUT",
	"OTEL_BSP_MAX_QUEUE_SIZE", "OTEL_BSP_MAX_EXPORT_BATCH_SIZE",
	"OTEL_RESOURCE_ATTRIBUTES",
	"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE",
	"OTEL_EXPORTER_OTLP_CLIENT_KEY", "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
	"OTEL_ATTRIBUTE_COUNT_LIMIT", "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT",
	"OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", "OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT",
	"OTEL_SPAN_EVENT_COUNT_LIMIT", "OTEL_SPAN_LINK_COUNT_LIMIT",
	"OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT", "OTEL_LINK_ATTRIBUTE_COUNT_LIMIT",
}

// Install makes every span started through otel.Tracer land in the returned
// exporter, synchronously, until the test ends. It also installs the same
// W3C propagator (trace context + baggage) that Init installs in production,
// so instrumentation that injects/extracts traceparent is exercised the same
// way under test regardless of test order. Both globals are reset on
// cleanup (the SDK refuses to re-install its delegating tracer-provider
// default, so that one goes back to a no-op provider instead).
//
// The sampler is pinned to AlwaysSample so an ambient OTEL_TRACES_SAMPLER in
// the developer's shell (e.g. always_off) can never make a test silently see
// zero spans — the point of Install is a deterministic in-memory exporter.
func Install(t testing.TB) *tracetest.InMemoryExporter {
	t.Helper()
	ClearEnv(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
		_ = tp.Shutdown(context.Background())
	})

	return exp
}

// ClearEnv unsets every variable of OTelEnvNames for the test: t.Setenv
// registers the restore, os.Unsetenv makes the SDK see it as absent (an empty
// OTEL_TRACES_SAMPLER would be "unsupported sampler", not "unset").
func ClearEnv(t testing.TB) {
	t.Helper()
	for _, name := range OTelEnvNames {
		t.Setenv(name, "")
		_ = os.Unsetenv(name)
	}
}
