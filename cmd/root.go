// Package cmd contains all CLI command definitions.
package cmd

import (
	"fmt"
	"os"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


var (
	cfgFile  string
	insecure bool
	debug    bool
)

// rootCmd is the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:           "retyc",
	Short:         "RETYC CLI",
	Long:          `RETYC command-line interface for interacting with the RETYC platform.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
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
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "k", false, "skip TLS certificate verification (useful for self-signed certificates)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "print raw API responses to stderr")
}

// initConfig reads the configuration file and environment variables.
func initConfig() {
	config.SetDefaults()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		dir, err := config.ConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not determine config directory:", err)
			os.Exit(1)
		}

		viper.AddConfigPath(dir)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
