package cmd

import (
	_ "embed"
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

// mcpbManifestBase holds the static part of the MCPB manifest (metadata, server
// config, user_config). The "version" and "tools" fields are injected at runtime
// so the Go code stays the single source of truth.
//
//go:embed mcpb_manifest_base.json
var mcpbManifestBase []byte

// mcpbTool matches the "tools" item schema of the MCPB manifest (v0.3).
type mcpbTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// mcpbToolList returns the registered MCP tools sorted by name, in the format
// expected by the MCPB manifest "tools" field.
func mcpbToolList() []mcpbTool {
	srv := server.NewMCPServer("retyc", Version, server.WithToolCapabilities(false))
	registerMCPTools(srv)

	registered := srv.ListTools()
	tools := make([]mcpbTool, 0, len(registered))
	for _, st := range registered {
		tools = append(tools, mcpbTool{
			Name:        st.Tool.Name,
			Description: st.Tool.Description,
		})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	return tools
}

// buildMCPBManifest merges the embedded base manifest with the injected
// version and the live tool registry.
func buildMCPBManifest(version string) (map[string]any, error) {
	var manifest map[string]any
	if err := json.Unmarshal(mcpbManifestBase, &manifest); err != nil {
		return nil, err
	}
	manifest["version"] = strings.TrimPrefix(version, "v")
	manifest["tools"] = mcpbToolList()

	return manifest, nil
}

var mcpManifestCmd = &cobra.Command{
	Use:   "manifest",
	Short: "Print the complete MCPB manifest.json",
	Long: `Print the complete manifest.json for the MCPB (MCP Bundle) package.

The static metadata is embedded in the binary; the "version" field (from the
build-time version, leading "v" stripped) and the "tools" array (from the live
MCP tool registry) are injected, so the manifest can never drift from the code.

Example:
  retyc mcp manifest > manifest.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		manifest, err := buildMCPBManifest(Version)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(manifest)
	},
}
