package mcpsetup

import (
	"bytes"
	"fmt"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// hermes writes mcp_servers.retyc into $HERMES_HOME/config.yaml (~/.hermes)
// and the secrets into the .env next to it.
//
// Hermes passes a stdio server only its explicit env block, and resolves
// ${VAR} in it from ~/.hermes/.env (hermes-agent.nousresearch.com,
// reference/mcp-config-reference): config.yaml carries references only.
type hermes struct{}

func (hermes) Name() string { return "Hermes" }

func (hermes) dir(e Env) string {
	if d := e.Getenv("HERMES_HOME"); d != "" {
		return d
	}

	return filepath.Join(e.Home, ".hermes")
}

func (h hermes) Detected(e Env) bool { return isDir(h.dir(e)) }

type hermesEntry struct {
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`
}

func (h hermes) Configure(e Env, s Server) ([]string, error) {
	cfgPath := filepath.Join(h.dir(e), "config.yaml")
	envPath := filepath.Join(h.dir(e), ".env")

	old, err := readOptional(cfgPath)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if len(bytes.TrimSpace(old)) > 0 {
		if err := yaml.Unmarshal(old, &doc); err != nil {
			return nil, fmt.Errorf("%s is not valid YAML, left untouched: %w", cfgPath, err)
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: top level is not a mapping, left untouched", cfgPath)
	}

	var entry yaml.Node
	if err := entry.Encode(hermesEntry{
		Command: s.Command,
		Args:    ServeArgs,
		Env: map[string]string{
			EnvToken:      "${" + EnvToken + "}",
			EnvPassphrase: "${" + EnvPassphrase + "}",
		},
	}); err != nil {
		return nil, err
	}

	servers := mappingValue(root, "mcp_servers")
	if servers.Kind != yaml.MappingNode { // absent, or `mcp_servers:` with no value
		if servers.Kind != 0 && (servers.Kind != yaml.ScalarNode || servers.Tag != "!!null") {
			return nil, fmt.Errorf("%s: mcp_servers is not a mapping, left untouched", cfgPath)
		}
		*servers = yaml.Node{Kind: yaml.MappingNode}
	}
	*mappingValue(servers, ServerName) = entry

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	// Secrets once config.yaml is known to be editable, and before it: a
	// refused value (checked before any write) leaves both files untouched.
	if err := upsertDotEnv(envPath, []string{EnvToken, EnvPassphrase},
		map[string]string{EnvToken: s.Token, EnvPassphrase: s.Passphrase}); err != nil {
		return nil, fmt.Errorf("%s: %w", envPath, err)
	}
	if err := writeFileAtomic(cfgPath, out.Bytes(), 0o600); err != nil {
		return nil, err
	}

	return []string{cfgPath, envPath}, nil
}

// mappingValue returns the value node of key in mapping m, appending an empty
// one when the key is absent.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	v := &yaml.Node{}
	m.Content = append(m.Content, k, v)

	return v
}
