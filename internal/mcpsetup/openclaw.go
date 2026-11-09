package mcpsetup

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// openClaw puts the secrets into the .env of OpenClaw's state directory and
// registers the entry with the OpenClaw CLI: openclaw.json is JSON5 under a
// strict schema, and its writes belong to the Gateway (docs.openclaw.ai,
// cli/config). The entry references the secrets as ${VAR}, resolved from
// that .env.
//
// `config set` is used rather than `mcp set`, which needs the Gateway stopped;
// `config set` routes the write through a running Gateway.
type openClaw struct{}

func (openClaw) Name() string { return "OpenClaw" }

// stateDir resolves the directory OpenClaw reads its global .env from, as
// OpenClaw does: OPENCLAW_STATE_DIR, else the directory of
// OPENCLAW_CONFIG_PATH, else ~/.openclaw.
func (openClaw) stateDir(e Env) string {
	if d := e.Getenv("OPENCLAW_STATE_DIR"); d != "" {
		return expandHome(e, d)
	}
	if p := e.Getenv("OPENCLAW_CONFIG_PATH"); p != "" {
		return filepath.Dir(expandHome(e, p))
	}

	return filepath.Join(e.Home, ".openclaw")
}

func (o openClaw) Detected(e Env) bool { return isDir(o.stateDir(e)) }

func (o openClaw) Configure(e Env, s Server) ([]string, error) {
	envPath := filepath.Join(o.stateDir(e), ".env")
	if err := upsertDotEnv(envPath, []string{EnvToken, EnvPassphrase},
		map[string]string{EnvToken: s.Token, EnvPassphrase: s.Passphrase}); err != nil {
		return nil, fmt.Errorf("%s: %w", envPath, err)
	}
	changed := []string{envPath}

	entry, err := json.Marshal(map[string]any{
		"command": s.Command,
		"args":    ServeArgs,
		"env": map[string]string{
			EnvToken:      "${" + EnvToken + "}",
			EnvPassphrase: "${" + EnvPassphrase + "}",
		},
	})
	if err != nil {
		return changed, err
	}
	args := []string{"config", "set", "mcp.servers." + ServerName, string(entry), "--strict-json"}

	bin, err := e.LookPath("openclaw")
	if err != nil {
		return changed, &ManualStepError{Client: o.Name(), Command: shellJoin("openclaw", args)}
	}
	if err := e.Run(bin, args...); err != nil {
		return changed, fmt.Errorf("%s: %w", o.Name(), err)
	}

	return changed, nil
}

// shellJoin renders a command line a user can paste into a POSIX shell.
func shellJoin(name string, args []string) string {
	parts := []string{name}
	for _, a := range args {
		if a != "" && !strings.ContainsAny(a, " \t\n'\"\\$`{}[]*?;&|<>()#~!") {
			parts = append(parts, a)

			continue
		}
		parts = append(parts, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}

	return strings.Join(parts, " ")
}
