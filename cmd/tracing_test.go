package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// withTestCommand registers a throwaway subcommand on rootCmd for one test.
func withTestCommand(t *testing.T, c *cobra.Command) {
	t.Helper()
	isolateOTel(t)
	rootCmd.AddCommand(c)
	t.Cleanup(func() {
		rootCmd.RemoveCommand(c)
		rootCmd.SetArgs(nil)
		commandSpan = nil
		activeTelemetry = nil
	})
}

// isolateOTel keeps the tracing tests hermetic: telemetry.Init runs in
// PersistentPreRunE and would install a real exporter over the in-memory one
// if the developer's shell carried an OTLP endpoint.
func isolateOTel(t *testing.T) {
	t.Helper()
	telemetrytest.ClearEnv(t)
}

func spanNamed(spans tracetest.SpanStubs, name string) (tracetest.SpanStub, bool) {
	for _, s := range spans {
		if s.Name == name {
			return s, true
		}
	}

	return tracetest.SpanStub{}, false
}

func TestRun_CommandSpanNamedAndParented(t *testing.T) {
	isolateConfig(t)
	withTestCommand(t, &cobra.Command{
		Use:  "tracing-probe",
		RunE: func(*cobra.Command, []string) error { return nil },
	})
	// withTestCommand clears TRACEPARENT via isolateOTel; set it after, so
	// this test's own value survives: Install clears the OTel variables, so
	// the parent is set after it.
	exp := telemetrytest.Install(t)
	t.Setenv("TRACEPARENT", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")

	if err := run(context.Background(), []string{"tracing-probe"}); err != nil {
		t.Fatal(err)
	}
	s, ok := spanNamed(exp.GetSpans(), "retyc tracing-probe")
	if !ok {
		t.Fatalf("no command span, got %v", exp.GetSpans())
	}
	if got := s.SpanContext.TraceID().String(); got != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace id = %s, want the TRACEPARENT one", got)
	}
	if s.Parent.SpanID().String() != "b7ad6b7169203331" {
		t.Errorf("parent = %s, want the TRACEPARENT span", s.Parent.SpanID())
	}
	if s.Status.Code != codes.Unset {
		t.Errorf("status = %v, want Unset on success", s.Status.Code)
	}
	if len(s.Attributes) != 2 {
		t.Errorf("attributes = %v, want exactly retyc.command and retyc.cli.version", s.Attributes)
	}
	for _, kv := range s.Attributes {
		if kv.Key != "retyc.command" && kv.Key != "retyc.cli.version" {
			t.Errorf("unexpected attribute %s", kv.Key)
		}
	}
}

func TestRun_ErrorRecordsTypeNotMessage(t *testing.T) {
	isolateConfig(t)
	exp := telemetrytest.Install(t)
	withTestCommand(t, &cobra.Command{
		Use:  "tracing-fail",
		RunE: func(*cobra.Command, []string) error { return errors.New("stat SENTINEL.pdf: no such file") },
	})

	if err := run(context.Background(), []string{"tracing-fail"}); err == nil {
		t.Fatal("expected the command error")
	}
	s, ok := spanNamed(exp.GetSpans(), "retyc tracing-fail")
	if !ok {
		t.Fatal("no command span")
	}
	if s.Status.Code != codes.Error || s.Status.Description != "" {
		t.Errorf("status = %+v, want Error with empty description", s.Status)
	}
	var errType string
	for _, kv := range s.Attributes {
		if kv.Key == "error.type" {
			errType = kv.Value.AsString()
		}
	}
	if errType != "errors.errorString" {
		t.Errorf("error.type = %q", errType)
	}
}

func TestRun_LongRunningHasNoCommandSpan(t *testing.T) {
	isolateConfig(t)
	exp := telemetrytest.Install(t)
	withTestCommand(t, &cobra.Command{
		Use:         "tracing-server",
		Annotations: map[string]string{annotationLongRunning: "true"},
		RunE:        func(*cobra.Command, []string) error { return nil },
	})

	if err := run(context.Background(), []string{"tracing-server"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := spanNamed(exp.GetSpans(), "retyc tracing-server"); ok {
		t.Error("a long-running command must not get a command span")
	}
}
