// Package cmd contains all CLI command definitions.
package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	debug   bool
)

// annotationOffline marks commands that make no network call. They skip the
// root CA loading, so an invalid SSL_CERT_FILE inherited from another tool
// cannot break them — the release CI runs `retyc mcp manifest`.
const annotationOffline = "retyc:offline"

// rootCmd is the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:           "retyc",
	Short:         "RETYC CLI",
	Long:          `RETYC command-line interface for interacting with the RETYC platform.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	// Load the custom root CAs before any command runs, so an unreadable or
	// invalid SSL_CERT_FILE / SSL_CERT_DIR fails immediately with a clear
	// message instead of surfacing as a TLS error mid-transfer.
	//
	// Commands annotated with annotationOffline open no connection, so a CA
	// bundle they never use must not stop them.
	//
	// cobra only runs the closest PersistentPreRunE unless
	// cobra.EnableTraverseRunHooks is set: defining one on a subcommand would
	// silently skip this.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Annotations[annotationOffline] == "true" {
			return nil
		}

		source, err := api.InitTLSRoots()
		if err != nil {
			return fmt.Errorf("loading root CAs: %w", err)
		}

		if debug {
			fmt.Fprintln(os.Stderr, "TLS roots:", source)
		}

		return nil
	},
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		printError(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Build the default config path hint from the active build mode so the
	// help text always reflects the real default location.
	defaultCfgHint := "auto"
	if dir, err := config.ConfigDir(); err == nil {
		defaultCfgHint = dir + "/config.yaml"
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: "+defaultCfgHint+")")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "print raw API responses to stderr")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false,
		"print results as JSON on stdout (errors as JSON on stderr)")
}

// cliUserAgent returns the User-Agent string used for all outgoing HTTP requests.
func cliUserAgent() string {
	return fmt.Sprintf("retyc-cli/%s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
}

// initConfig reads the configuration file and environment variables.
func initConfig() {
	config.SetDefaults()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		dir, err := config.ConfigDir()
		if err != nil {
			// Flags are already parsed here (cobra.OnInitialize), so --json is honoured.
			printError(fmt.Errorf("could not determine config directory: %w", err))
			os.Exit(1)
		}

		viper.AddConfigPath(dir)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if debug {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}

	setInsecureFromConfig()
}
