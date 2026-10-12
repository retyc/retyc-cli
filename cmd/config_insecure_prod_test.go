//go:build prod

package cmd

import (
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/viper"
)

// insecure is not a setting of a prod binary: `config show` must not list it,
// whether nothing asks for it, the environment does, or a config file does.
func TestConfigEntries_NoInsecureInProd(t *testing.T) {
	hasInsecure := func() bool {
		for _, e := range configEntries() {
			if e.Key == "insecure" {
				return true
			}
		}

		return false
	}

	t.Run("unset", func(t *testing.T) {
		isolateConfig(t)
		config.SetDefaults()
		if hasInsecure() {
			t.Error("configEntries() lists insecure, want it absent from a prod build")
		}
	})

	t.Run("environment", func(t *testing.T) {
		isolateConfig(t)
		t.Setenv("RETYC_INSECURE", "true")
		config.SetDefaults()
		if hasInsecure() {
			t.Error("configEntries() lists insecure set from RETYC_INSECURE, want it absent")
		}
	})

	t.Run("config file", func(t *testing.T) {
		isolateConfig(t)
		config.SetDefaults()
		viper.Set("insecure", true) // listed by AllKeys(), like a key read from config.yaml
		if hasInsecure() {
			t.Error("configEntries() lists insecure set in the configuration, want it absent")
		}
	})
}
