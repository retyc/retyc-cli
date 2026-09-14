//go:build prod

package cmd

import (
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
)

// A prod binary always verifies TLS: `config show` must report the value it
// acts on, and say that the configuration asked for something else.
func TestConfigEntries_InsecureIgnoredInProd(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_INSECURE", "true")
	config.SetDefaults()

	e := entryFor(t, "insecure")
	if e.Value != "false" {
		t.Errorf("insecure value = %q, want \"false\": a prod build ignores the setting", e.Value)
	}
	if e.Note == "" {
		t.Error("insecure note is empty, want an explanation that the setting is ignored")
	}
}

func TestConfigEntries_InsecureNoNoteWhenUnsetInProd(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()

	if e := entryFor(t, "insecure"); e.Value != "false" || e.Note != "" {
		t.Errorf("insecure entry = %+v, want value \"false\" and no note when nothing asks for it", e)
	}
}
