package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// secretKeys lists the configuration keys whose value must never be printed.
var secretKeys = map[string]bool{
	"admin.api_key": true,
}

// maskedValue is what a set secret is displayed as.
const maskedValue = "••••••••"

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect the effective configuration",
}

var configPathCmd = &cobra.Command{
	Annotations: map[string]string{annotationOffline: "true"},
	Use:         "path",
	Short:       "Print the configuration file locations",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := config.ConfigDir()
		if err != nil {
			return fmt.Errorf("resolving config directory: %w", err)
		}
		tokenFile, err := config.TokenPath()
		if err != nil {
			return fmt.Errorf("resolving token path: %w", err)
		}

		// configFileLoaded, not viper.ConfigFileUsed(): the latter reports the
		// path requested with --config even when reading it failed, and this
		// command is precisely what someone runs to find that out.
		configFile := configFileLoaded

		if jsonOutput {
			return printJSON(configPathJSON{ConfigDir: dir, ConfigFile: configFile, TokenFile: tokenFile})
		}

		if configFile == "" {
			configFile = "(none loaded)"
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "config dir\t%s\n", dir)
		fmt.Fprintf(w, "config file\t%s\n", configFile)
		fmt.Fprintf(w, "token file\t%s\n", tokenFile)

		return w.Flush()
	},
}

var configShowCmd = &cobra.Command{
	Annotations: map[string]string{annotationOffline: "true"},
	Use:         "show",
	Short:       "Print the effective configuration values",
	Long: `Print the effective value of every configuration key.

Values come from the config file, the environment (RETYC_<KEY_WITH_UNDERSCORES>)
or the built-in defaults; viper does not report which one won, so only the
effective value is shown. Secrets are masked.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// A value that viper can print but not unmarshal (keyring.ttl: abc)
		// breaks every other command with an opaque error. Surface it here,
		// on stderr, without hiding the listing someone came for.
		if _, err := config.Load(); err != nil {
			fmt.Fprintln(os.Stderr, "warning: the configuration does not load:", err)
		}

		entries := configEntries()

		if jsonOutput {
			return printJSON(newItemsJSON(entries))
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, e := range entries {
			note := ""
			if e.Note != "" {
				note = "  (" + e.Note + ")"
			}
			fmt.Fprintf(w, "%s\t%s%s\n", e.Key, e.Value, note)
		}

		return w.Flush()
	},
}

// configEntries returns every configuration key with its effective value,
// sorted by key, secrets masked.
func configEntries() []configEntryJSON {
	keys := viper.AllKeys()
	sort.Strings(keys)

	entries := make([]configEntryJSON, 0, len(keys))
	for _, k := range keys {
		value := viper.GetString(k)
		secret := secretKeys[k]
		if secret && value != "" {
			value = maskedValue
		}
		entries = append(entries, configEntryJSON{
			Key: k, Value: value, Secret: secret, Note: entryNote(k),
		})
	}

	return entries
}

// entryNote returns a warning for a key the running binary ignores, so that
// `config show` never reports a value the build does not act on. A prod binary
// has no --insecure flag: cmd/insecure_prod.go defines it as a const false.
func entryNote(key string) string {
	if key == "insecure" && config.BuildMode == "prod" {
		return "ignored: prod build always verifies TLS"
	}

	return ""
}

func init() {
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)
}
