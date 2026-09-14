package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// TestMCPPassphraseReader_EnvSet verifies that mcpPassphraseReader returns the env value.
func TestMCPPassphraseReader_EnvSet(t *testing.T) {
	t.Setenv("RETYC_KEY_PASSPHRASE", "test-passphrase")

	got, err := mcpPassphraseReader()
	if err != nil {
		t.Fatalf("mcpPassphraseReader() error = %v", err)
	}
	if got != "test-passphrase" {
		t.Errorf("got %q, want %q", got, "test-passphrase")
	}
}

// TestMCPPassphraseReader_EnvUnset verifies that mcpPassphraseReader errors when env is unset.
func TestMCPPassphraseReader_EnvUnset(t *testing.T) {
	_ = os.Unsetenv("RETYC_KEY_PASSPHRASE")

	_, err := mcpPassphraseReader()
	if err == nil {
		t.Fatal("expected error when RETYC_KEY_PASSPHRASE is unset, got nil")
	}
}

// TestToolErr_StructuredJSON verifies that toolErr returns valid JSON with error_code and message.
func TestToolErr_StructuredJSON(t *testing.T) {
	result, handlerErr := toolErr(context.Background(), fmt.Errorf("something went wrong"))
	if handlerErr != nil {
		t.Fatalf("toolErr returned unexpected handler error: %v", handlerErr)
	}
	if result == nil {
		t.Fatal("toolErr returned nil result")
	}
	if len(result.Content) == 0 {
		t.Fatal("toolErr result has no content")
	}

	// Extract the JSON text from the first content item.
	raw, err := json.Marshal(result.Content[0])
	if err != nil {
		t.Fatalf("marshalling content: %v", err)
	}
	var wrapper struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatalf("unmarshalling content wrapper: %v", err)
	}

	var payload mcpToolError
	if err := json.Unmarshal([]byte(wrapper.Text), &payload); err != nil {
		t.Fatalf("unmarshalling error payload %q: %v", wrapper.Text, err)
	}
	if payload.ErrorCode == "" {
		t.Error("error_code is empty")
	}
	if payload.Message == "" {
		t.Error("message is empty")
	}
}

// TestToolErr_NotAuthenticated verifies that auth errors map to not_authenticated code.
func TestToolErr_NotAuthenticated(t *testing.T) {
	result, _ := toolErr(context.Background(), fmt.Errorf("wrapped: %w", auth.ErrNoToken))
	if result == nil {
		t.Fatal("toolErr returned nil result")
	}

	raw, _ := json.Marshal(result.Content[0])
	var wrapper struct{ Text string }
	_ = json.Unmarshal(raw, &wrapper)

	var payload mcpToolError
	_ = json.Unmarshal([]byte(wrapper.Text), &payload)

	if payload.ErrorCode != "not_authenticated" {
		t.Errorf("error_code = %q, want %q", payload.ErrorCode, "not_authenticated")
	}
}

// TestToolErr_GenericError verifies that generic errors use the "error" code.
func TestToolErr_GenericError(t *testing.T) {
	result, _ := toolErr(context.Background(), errors.New("random failure"))
	raw, _ := json.Marshal(result.Content[0])
	var wrapper struct{ Text string }
	_ = json.Unmarshal(raw, &wrapper)
	var payload mcpToolError
	_ = json.Unmarshal([]byte(wrapper.Text), &payload)

	if payload.ErrorCode != "error" {
		t.Errorf("error_code = %q, want %q", payload.ErrorCode, "error")
	}
}

// TestMCPToolSpanMiddleware_RootSpanPerCall verifies that the middleware opens
// a root SERVER span named "MCP <tool>", propagates it to the handler, marks
// it failed on a handler error, and never records tool arguments.
func TestMCPToolSpanMiddleware_RootSpanPerCall(t *testing.T) {
	exp := telemetrytest.Install(t)
	next := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !oteltrace.SpanFromContext(ctx).SpanContext().IsValid() {
			t.Error("tool handler did not receive the span context")
		}

		return nil, errors.New("open SENTINEL.pdf: permission denied")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "dataroom_upload"
	req.Params.Arguments = map[string]any{"path": "/tmp/SENTINEL.pdf"}
	if _, err := mcpToolSpanMiddleware(next)(context.Background(), req); err == nil {
		t.Fatal("expected the handler error")
	}

	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Name != "MCP dataroom_upload" {
		t.Fatalf("spans = %v", spans)
	}
	s := spans[0]
	if s.SpanKind != oteltrace.SpanKindServer || s.Status.Code != codes.Error || s.Status.Description != "" {
		t.Errorf("kind=%v status=%+v", s.SpanKind, s.Status)
	}
	for _, kv := range s.Attributes {
		if strings.Contains(kv.Value.String(), "SENTINEL") {
			t.Errorf("attribute %s leaks an argument: %s", kv.Key, kv.Value.String())
		}
	}
}

// TestMCPServe_IsLongRunning verifies that mcp serve carries the annotation
// that keeps it out of the one-command-one-root-span tracing scheme.
func TestMCPServe_IsLongRunning(t *testing.T) {
	if mcpServeCmd.Annotations[annotationLongRunning] != "true" {
		t.Error("mcp serve must carry the long-running annotation")
	}
}

// TestMCPToolSpanMiddleware_ToolErrIsRecorded verifies that a tool handler
// reporting a failure through toolErr (JSON text result, nil Go error) still
// marks the call's span as failed, since the middleware cannot see the error
// through the nil return value.
func TestMCPToolSpanMiddleware_ToolErrIsRecorded(t *testing.T) {
	exp := telemetrytest.Install(t)
	next := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return toolErr(ctx, errors.New("open SENTINEL.pdf: permission denied"))
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "dataroom_upload"
	res, err := mcpToolSpanMiddleware(next)(context.Background(), req)
	if err != nil || res == nil {
		t.Fatalf("toolErr must keep answering a result with a nil error, got (%v, %v)", res, err)
	}
	s := exp.GetSpans()[0]
	if s.Status.Code != codes.Error || s.Status.Description != "" {
		t.Errorf("status = %+v, want Error with empty description", s.Status)
	}
	var errType string
	for _, kv := range s.Attributes {
		if kv.Key == "error.type" {
			errType = kv.Value.AsString()
		}
		if strings.Contains(kv.Value.String(), "SENTINEL") {
			t.Errorf("attribute %s leaks the message: %s", kv.Key, kv.Value.String())
		}
	}
	if errType != "errors.errorString" {
		t.Errorf("error.type = %q", errType)
	}
}

// TestMCPToolSpanMiddleware_SuccessLeavesStatusUnset verifies that a handler
// returning a successful result leaves the call's span status untouched.
func TestMCPToolSpanMiddleware_SuccessLeavesStatusUnset(t *testing.T) {
	exp := telemetrytest.Install(t)
	next := func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("ok"), nil
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "user_info"
	if _, err := mcpToolSpanMiddleware(next)(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := exp.GetSpans()[0]
	if s.Status.Code != codes.Unset {
		t.Errorf("status = %+v, want Unset", s.Status)
	}
}
