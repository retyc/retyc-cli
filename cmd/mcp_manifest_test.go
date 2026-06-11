package cmd

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

// TestBuildMCPBManifest_VersionAndTools verifies version injection (leading "v"
// stripped) and that the tools array mirrors the live tool registry.
func TestBuildMCPBManifest_VersionAndTools(t *testing.T) {
	manifest, err := buildMCPBManifest("v1.2.3")
	if err != nil {
		t.Fatalf("buildMCPBManifest() error = %v", err)
	}

	if got := manifest["version"]; got != "1.2.3" {
		t.Errorf("version = %v, want %q", got, "1.2.3")
	}

	tools, ok := manifest["tools"].([]mcpbTool)
	if !ok {
		t.Fatalf("tools has type %T, want []mcpbTool", manifest["tools"])
	}
	// Exact count so that adding or removing a tool is a conscious decision
	// (the manifest tools array is reviewed during directory submission).
	const wantToolCount = 24
	if len(tools) != wantToolCount {
		t.Errorf("tools length = %d, want %d (update wantToolCount if the tool set changed on purpose)",
			len(tools), wantToolCount)
	}
	for _, tool := range tools {
		if tool.Name == "" {
			t.Error("tool with empty name in manifest")
		}
		if tool.Description == "" {
			t.Errorf("tool %q has no description", tool.Name)
		}
	}
}

// TestBuildMCPBManifest_RequiredFields verifies the fields required by the MCPB
// manifest schema (v0.3) and by the Anthropic directory submission rules.
func TestBuildMCPBManifest_RequiredFields(t *testing.T) {
	manifest, err := buildMCPBManifest("1.0.0")
	if err != nil {
		t.Fatalf("buildMCPBManifest() error = %v", err)
	}

	// Schema-required fields.
	for _, key := range []string{"manifest_version", "name", "version", "description", "author", "server"} {
		if _, ok := manifest[key]; !ok {
			t.Errorf("required field %q missing", key)
		}
	}

	// Directory-required: privacy policy URLs.
	policies, ok := manifest["privacy_policies"].([]any)
	if !ok || len(policies) == 0 {
		t.Error("privacy_policies must be a non-empty array (directory submission requirement)")
	}

	srv, ok := manifest["server"].(map[string]any)
	if !ok {
		t.Fatalf("server has type %T, want object", manifest["server"])
	}
	if srv["type"] != "binary" {
		t.Errorf("server.type = %v, want %q", srv["type"], "binary")
	}
}

// TestMCPToolAnnotations verifies that every registered tool carries a title and
// either a read-only or destructive hint, as required by the Anthropic directory
// review criteria.
func TestMCPToolAnnotations(t *testing.T) {
	srv := server.NewMCPServer("retyc", "test", server.WithToolCapabilities(false))
	registerMCPTools(srv)

	for _, st := range srv.ListTools() {
		ann := st.Tool.Annotations
		if ann.Title == "" {
			t.Errorf("tool %q has no title annotation", st.Tool.Name)
		}
		if ann.ReadOnlyHint == nil && ann.DestructiveHint == nil {
			t.Errorf("tool %q has neither readOnlyHint nor destructiveHint", st.Tool.Name)
		}
	}
}
