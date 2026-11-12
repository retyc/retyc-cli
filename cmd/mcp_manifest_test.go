package cmd

import (
	"encoding/json"
	"os"
	"strings"
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

// TestMCPBManifestDeclaresOnlyPassphrase: the Claude Desktop form asks for the
// key passphrase only; the login happens from the chat (no token field).
func TestMCPBManifestDeclaresOnlyPassphrase(t *testing.T) {
	manifest, err := buildMCPBManifest("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	userConfig, _ := manifest["user_config"].(map[string]any)
	if len(userConfig) != 1 || userConfig["key_passphrase"] == nil {
		t.Errorf("user_config = %v, want key_passphrase only", userConfig)
	}
	env := manifest["server"].(map[string]any)["mcp_config"].(map[string]any)["env"].(map[string]any)
	if len(env) != 1 || env["RETYC_KEY_PASSPHRASE"] != "${user_config.key_passphrase}" {
		t.Errorf("mcp_config.env = %v", env)
	}
}

// TestServerJSONMatchesMCPBManifest keeps the MCP Registry entry
// (packaging/mcp/server.json) consistent with the MCPB manifest: every
// variable of the bundle is declared by every package with the same
// required/secret flags, and RETYC_TOKEN is an optional secret.
func TestServerJSONMatchesMCPBManifest(t *testing.T) {
	raw, err := os.ReadFile("../packaging/mcp/server.json")
	if err != nil {
		t.Fatal(err)
	}
	var serverJSON struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Packages    []struct {
			RegistryType         string `json:"registryType"`
			EnvironmentVariables []struct {
				Name       string `json:"name"`
				IsRequired bool   `json:"isRequired"`
				IsSecret   bool   `json:"isSecret"`
			} `json:"environmentVariables"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &serverJSON); err != nil {
		t.Fatal(err)
	}
	if serverJSON.Name != "com.retyc/mcp" {
		t.Errorf("name = %q", serverJSON.Name)
	}
	if n := len(serverJSON.Description); n == 0 || n > 100 {
		t.Errorf("description length %d, the registry allows 1-100", n)
	}

	manifest, err := buildMCPBManifest("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	userConfig := manifest["user_config"].(map[string]any)
	env := manifest["server"].(map[string]any)["mcp_config"].(map[string]any)["env"].(map[string]any)

	if len(serverJSON.Packages) != 2 {
		t.Fatalf("packages = %d, want npm + mcpb", len(serverJSON.Packages))
	}
	for _, pkg := range serverJSON.Packages {
		declared := map[string][2]bool{}
		for _, v := range pkg.EnvironmentVariables {
			declared[v.Name] = [2]bool{v.IsRequired, v.IsSecret}
		}
		for name, ref := range env {
			key := strings.TrimSuffix(strings.TrimPrefix(ref.(string), "${user_config."), "}")
			uc := userConfig[key].(map[string]any)
			want := [2]bool{uc["required"] == true, uc["sensitive"] == true}
			if got, ok := declared[name]; !ok || got != want {
				t.Errorf("%s: %s declared %v (present %v), want required/secret %v", pkg.RegistryType, name, got, ok, want)
			}
		}
		if got, ok := declared["RETYC_TOKEN"]; !ok || got != [2]bool{false, true} {
			t.Errorf("%s: RETYC_TOKEN = %v (present %v), want optional secret", pkg.RegistryType, got, ok)
		}
	}
}
