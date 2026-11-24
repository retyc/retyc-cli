package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/retyc/retyc-cli/core/telemetry/telemetrytest"
)

func TestErrorType(t *testing.T) {
	if got := ErrorType(context.Canceled); got != "errors.errorString" {
		t.Errorf("ErrorType = %q", got)
	}
	if got := ErrorType(&net.OpError{}); got != "net.OpError" {
		t.Errorf("ErrorType = %q", got)
	}
}

// error.type must name the error, not the fmt wrapper every call site adds.
func TestErrorType_UnwrapsFmtWrappers(t *testing.T) {
	err := fmt.Errorf("listing nodes: %w", fmt.Errorf("api: %w", &net.OpError{Op: "dial"}))
	if got := ErrorType(err); got != "net.OpError" {
		t.Errorf("ErrorType = %q, want net.OpError", got)
	}
	if got := ErrorType(fmt.Errorf("plain: %w", errors.New("x"))); got != "errors.errorString" {
		t.Errorf("ErrorType = %q, want errors.errorString", got)
	}
}

// Install must isolate the tests that use it without clearOTelEnv: service
// and cmd tests build spans through it and count attributes.
func TestInstall_UnsetsOTelEnv(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "host.name=leak")
	t.Setenv("OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", "1")
	telemetrytest.Install(t)
	for _, name := range []string{
		"OTEL_RESOURCE_ATTRIBUTES", "OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT",
		"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
	} {
		if _, ok := os.LookupEnv(name); ok {
			t.Errorf("%s still set after Install", name)
		}
	}
}
