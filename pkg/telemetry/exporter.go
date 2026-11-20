package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// newExporter builds the OTLP exporter for protocol and returns the
// canonical protocol name. Both exporters read their endpoint, headers, TLS
// and timeout settings from OTEL_EXPORTER_OTLP_* themselves and connect
// lazily, so this never touches the network.
func newExporter(ctx context.Context, protocol string) (sdktrace.SpanExporter, string, error) {
	switch protocol {
	case "", "http/protobuf":
		exp, err := otlptracehttp.New(ctx)

		return exp, "http/protobuf", err
	case "grpc":
		exp, err := otlptracegrpc.New(ctx)

		return exp, "grpc", err
	default:
		return nil, "", fmt.Errorf("unsupported OTLP protocol %q (use http/protobuf or grpc)", protocol)
	}
}
