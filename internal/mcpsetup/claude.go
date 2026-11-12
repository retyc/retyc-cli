package mcpsetup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
)

// claudeDesktop writes mcpServers.retyc into claude_desktop_config.json, with
// the secrets in its env block (the format Claude Desktop documents).
type claudeDesktop struct{}

func (claudeDesktop) Name() string { return "Claude Desktop" }

func (claudeDesktop) path(e Env) string {
	return filepath.Join(e.ConfigDir, "Claude", "claude_desktop_config.json")
}

func (c claudeDesktop) Detected(e Env) bool { return isDir(filepath.Dir(c.path(e))) }

func (c claudeDesktop) Configure(e Env, s Server) ([]string, error) {
	path := c.path(e)
	old, err := readOptional(path)
	if err != nil {
		return nil, err
	}

	doc := map[string]any{}
	if len(bytes.TrimSpace(old)) > 0 {
		if err := json.Unmarshal(old, &doc); err != nil {
			return nil, fmt.Errorf("%s is not valid JSON, left untouched: %w", path, err)
		}
	}
	servers := map[string]any{}
	if raw, ok := doc["mcpServers"]; ok && raw != nil {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: mcpServers is not an object, left untouched", path)
		}
		servers = m
	}
	servers[ServerName] = map[string]any{
		"command": s.Command,
		"args":    ServeArgs,
		"env": map[string]string{
			EnvToken:      s.Token,
			EnvPassphrase: s.Passphrase,
		},
	}
	doc["mcpServers"] = servers

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, append(out, '\n'), 0o600); err != nil {
		return nil, err
	}

	return []string{path}, nil
}
