package telemetry

import (
	"os"
	"strings"
)

// Environment variables read by the CLI itself. The OTel SDK and the OTLP
// exporters read the rest of OTEL_* on their own; this file exists because
// otel-go implements neither the "no endpoint means disabled" rule the CLI
// wants, nor OTEL_SDK_DISABLED, nor the protocol selection, nor TRACEPARENT.
// Nothing outside this file calls os.Getenv for OTEL_* or TRACEPARENT.
const (
	envEndpoint       = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envTracesEndpoint = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
	envProtocol       = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envTracesProtocol = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	envSDKDisabled    = "OTEL_SDK_DISABLED"
	envTraceParent    = "TRACEPARENT"
	envTraceState     = "TRACESTATE"
)

// endpointConfigured reports whether an OTLP endpoint is set. The value is
// never parsed here: the exporter interprets it (scheme, /v1/traces suffix).
func endpointConfigured() bool {
	return strings.TrimSpace(os.Getenv(envTracesEndpoint)) != "" ||
		strings.TrimSpace(os.Getenv(envEndpoint)) != ""
}

func sdkDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(envSDKDisabled)), "true")
}

// protocol returns the requested OTLP transport, "" when unset.
func protocol() string {
	if v := strings.TrimSpace(os.Getenv(envTracesProtocol)); v != "" {
		return v
	}

	return strings.TrimSpace(os.Getenv(envProtocol))
}

func traceParent() string { return strings.TrimSpace(os.Getenv(envTraceParent)) }
func traceState() string  { return strings.TrimSpace(os.Getenv(envTraceState)) }
