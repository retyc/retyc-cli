package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"errors"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// clearOTelEnv unsets every variable the package or the SDK reads, so the
// developer's shell cannot leak into the assertions.
func clearOTelEnv(t *testing.T) {
	t.Helper()
	telemetrytest.ClearEnv(t)
	t.Cleanup(func() { otel.SetTracerProvider(noop.NewTracerProvider()) })
}

func TestInit_WithoutEndpointIsOff(t *testing.T) {
	clearOTelEnv(t)
	tel, err := Init(context.Background(), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if Enabled() {
		t.Error("Enabled() = true without endpoint")
	}
	if tel.tp != nil {
		t.Error("a tracer provider was built without endpoint")
	}
	tel.Shutdown(context.Background()) // must be a no-op, not a panic
}

func TestInit_SDKDisabledWins(t *testing.T) {
	clearOTelEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	if Enabled() {
		t.Error("Enabled() = true with OTEL_SDK_DISABLED=true")
	}
}

func TestInit_HTTPExportsASpan(t *testing.T) {
	clearOTelEnv(t)
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/traces" {
			posts.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)

	tel, err := Init(context.Background(), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, span := Tracer().Start(context.Background(), "probe")
	span.End()
	tel.Shutdown(context.Background())

	if posts.Load() == 0 {
		t.Error("no OTLP/HTTP POST on /v1/traces reached the collector")
	}
}

// Both OTLP exporters are the same Go type (*otlptrace.Exporter) with a
// different client inside, so the resolved protocol name is what is checked.
func TestNewExporter_Protocols(t *testing.T) {
	clearOTelEnv(t)
	ctx := context.Background()
	for in, want := range map[string]string{"": "http/protobuf", "http/protobuf": "http/protobuf", "grpc": "grpc"} {
		exp, got, err := newExporter(ctx, in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if exp == nil || got != want {
			t.Errorf("newExporter(%q) = (%v, %q), want protocol %q", in, exp, got, want)
		}
		_ = exp.Shutdown(ctx)
	}
	if _, _, err := newExporter(ctx, "http/json"); err == nil {
		t.Error("http/json: expected an error")
	}
}

func TestInit_BadProtocolLeavesTracingOff(t *testing.T) {
	clearOTelEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")
	tel, err := Init(context.Background(), Options{Version: "test"})
	if err == nil {
		t.Fatal("expected an error for an unsupported protocol")
	}
	if tel == nil || tel.tp != nil {
		t.Error("Init must return a usable, disabled Telemetry on error")
	}
}

func TestParentFromEnv(t *testing.T) {
	clearOTelEnv(t)
	t.Setenv("TRACEPARENT", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	sc := traceSpanContext(ParentFromEnv(context.Background()))
	if !sc.IsValid() || !sc.IsRemote() {
		t.Fatal("expected a valid remote span context")
	}
	if got := sc.TraceID().String(); got != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace id = %s", got)
	}
	if !sc.IsSampled() {
		t.Error("sampled flag lost")
	}

	t.Setenv("TRACEPARENT", "garbage")
	if traceSpanContext(ParentFromEnv(context.Background())).IsValid() {
		t.Error("invalid TRACEPARENT must yield no parent")
	}
}

func TestShutdown_IsBounded(t *testing.T) {
	clearOTelEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // net/http only signals disconnects after a body read
		time.Sleep(5 * time.Second)        // longer than the shutdown bound, short enough for teardown
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)

	tel, err := Init(context.Background(), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, span := Tracer().Start(context.Background(), "probe")
	span.End()

	start := time.Now()
	tel.Shutdown(context.Background())
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Shutdown took %s, want < 3s", d)
	}
}

func TestErrorType(t *testing.T) {
	if got := ErrorType(context.Canceled); got != "errors.errorString" {
		t.Errorf("ErrorType = %q", got)
	}
	if got := ErrorType(&net.OpError{}); got != "net.OpError" {
		t.Errorf("ErrorType = %q", got)
	}
}

func TestInit_ResourceHasNoProcessOrHostAttributes(t *testing.T) {
	clearOTelEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	tel, err := Init(context.Background(), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer tel.Shutdown(context.Background())
	for _, kv := range tel.res.Attributes() {
		if k := string(kv.Key); strings.HasPrefix(k, "process.") || strings.HasPrefix(k, "host.") {
			t.Errorf("resource carries %s: process and host detectors must stay off", k)
		}
	}
}

func traceSpanContext(ctx context.Context) trace.SpanContext {
	return trace.SpanContextFromContext(ctx)
}

// Blanking a variable is not unsetting it: the SDK's sampler parser uses
// os.LookupEnv and logs "unsupported sampler" for an empty value.
func TestClearOTelEnv_UnsetsVariables(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	clearOTelEnv(t)
	if _, ok := os.LookupEnv("OTEL_TRACES_SAMPLER"); ok {
		t.Error("OTEL_TRACES_SAMPLER is still set (empty) after clearOTelEnv; it must be unset")
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
	for _, name := range []string{"OTEL_RESOURCE_ATTRIBUTES", "OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT",
		"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY"} {
		if _, ok := os.LookupEnv(name); ok {
			t.Errorf("%s still set after Install", name)
		}
	}
}

// The exporters parse OTEL_EXPORTER_OTLP_* when they are built and log a
// malformed header through the OTel global logger, so the discard logger
// must be installed before the exporter, or a token could reach stderr
// without --debug.
func TestInit_SilencesTheSDKLoggerBeforeBuildingTheExporter(t *testing.T) {
	clearOTelEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "SENTINEL-token-without-equals")
	var logged []string
	otel.SetLogger(funcr.New(func(prefix, args string) { logged = append(logged, prefix+" "+args) }, funcr.Options{}))
	t.Cleanup(func() { otel.SetLogger(logr.Discard()) })

	tel, err := Init(context.Background(), Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	tel.Shutdown(context.Background())
	for _, line := range logged {
		t.Errorf("the SDK logged before the discard logger was installed: %s", line)
	}
}
