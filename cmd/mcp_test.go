package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/retyc/retyc-cli/internal/auth"
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
	result, handlerErr := toolErr(fmt.Errorf("something went wrong"))
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
	result, _ := toolErr(fmt.Errorf("wrapped: %w", auth.ErrNoToken))
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
	result, _ := toolErr(errors.New("random failure"))
	raw, _ := json.Marshal(result.Content[0])
	var wrapper struct{ Text string }
	_ = json.Unmarshal(raw, &wrapper)
	var payload mcpToolError
	_ = json.Unmarshal([]byte(wrapper.Text), &payload)

	if payload.ErrorCode != "error" {
		t.Errorf("error_code = %q, want %q", payload.ErrorCode, "error")
	}
}
