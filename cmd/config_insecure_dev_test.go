//go:build !prod

package cmd

import (
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
)

// `config show` promises flag > env > config > default, but viper cannot see
// the -k flag: the effective value lives in the insecure variable, which
// setInsecureFromConfig has already merged.
func TestConfigEntries_InsecureReflectsFlag(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	prev := insecure
	t.Cleanup(func() { insecure = prev })
	insecure = true // what -k leaves behind after initConfig

	if e := entryFor(t, "insecure"); e.Value != "true" || e.Note != "" {
		t.Errorf("insecure entry = %+v, want value \"true\" and no note", e)
	}
}
