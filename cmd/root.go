// Package cmd contains all CLI command definitions.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel/trace"
)

var (
	cfgFile string
	debug   bool

	// configFileLoaded is the config file that was actually read, or "" when
	// none was. It is not viper.ConfigFileUsed(): with --config, viper records
	// the requested path before reading it and keeps it even when the read
	// fails, so ConfigFileUsed() would report a file no value ever came from.
	configFileLoaded string

	// configFileErr is why a config file exists but was not loaded (unreadable
	// --config path, YAML syntax error). It stays nil when there is simply no
	// config file, which is the normal case. Commands still run on defaults
	// and environment; `config path` and --debug report it.
	configFileErr error
)

// annotationOffline marks commands that make no network call. They skip the
// root CA loading, so an invalid SSL_CERT_FILE inherited from another tool
// cannot break them — the release CI runs `retyc mcp manifest`.
const annotationOffline = "retyc:offline"

// annotationLongRunning marks the servers (webdav serve, mcp serve). They get
// no command span: one span spanning days would parent every request under a
// single trace that never closes. They open their own per-request roots.
const annotationLongRunning = "retyc:long-running"

var (
	// activeTelemetry is flushed by run once the command returns.
	activeTelemetry *telemetry.Telemetry
	// commandSpan wraps a one-shot command; opened in PersistentPreRunE,
	// closed by run (cobra skips the PersistentPostRun hooks when RunE
	// fails, so a post-run hook would leak it on every error).
	commandSpan trace.Span
)

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

		applyServiceConfig()

		// Tracing is decided by the environment only; a bad OTEL_* value is
		// reported under --debug and the command runs untraced.
		tel, err := telemetry.Init(cmd.Context(), telemetry.Options{Version: Version, Debug: debug})
		if err != nil && debug {
			fmt.Fprintln(os.Stderr, "Tracing disabled:", err)
		}
		activeTelemetry = tel

		if cmd.Annotations[annotationLongRunning] != "true" {
			ctx, span := telemetry.Tracer().Start(cmd.Context(), cmd.CommandPath(),
				trace.WithAttributes(
					telemetry.AttrCommand.String(cmd.CommandPath()),
					telemetry.AttrCLIVersion.String(Version),
				))
			commandSpan = span
			cmd.SetContext(ctx)
		}

		return nil
	},
}

// exitAuthRequired is the exit code of a command stopped by a login that
// cannot recover without a new token: none stored, or a refresh token the
// identity provider rejected (expired or revoked, invalid_grant). It is
// sysexits.h EX_NOPERM and a stable contract: a supervisor restarting
// `retyc webdav serve` stops on it instead of hammering the API and the
// identity provider. A transient failure (network, 5xx) keeps exit code 1.
const exitAuthRequired = 77

// exitConfig is the exit code of a command stopped by a key passphrase that
// is missing (RETYC_KEY_PASSPHRASE unset, no TTY to prompt) or wrong. It is
// sysexits.h EX_CONFIG and, like exitAuthRequired, tells a supervisor that a
// restart with the same environment will fail again.
const exitConfig = 78

// exitCode maps the error a command returned to the process exit code.
func exitCode(err error) int {
	switch {
	case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
		return exitAuthRequired
	case errors.Is(err, config.ErrNoKeyPassphrase), errors.Is(err, service.ErrWrongKeyPassphrase):
		return exitConfig
	}

	return 1
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		printError(err)
		os.Exit(exitCode(err))
	}
}

// run executes args against rootCmd with the TRACEPARENT parent in the
// context, closes the command span with the outcome and flushes the traces.
// Execute and the tests share it.
func run(ctx context.Context, args []string) error {
	rootCmd.SetArgs(args)
	err := rootCmd.ExecuteContext(telemetry.ParentFromEnv(ctx))
	if commandSpan != nil {
		telemetry.RecordError(commandSpan, err)
		commandSpan.End()
		commandSpan = nil
	}
	activeTelemetry.Shutdown(context.Background())

	return err
}

func init() {
	cobra.OnInitialize(initConfig)

	// Build the default config path hint from the active build mode so the
	// help text always reflects the real default location.
	defaultCfgHint := "auto"
	if dir, err := config.ConfigDir(); err == nil {
		defaultCfgHint = dir + "/config.yaml"
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default: "+defaultCfgHint+"); does not move token.json")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false,
		"print every HTTP request and raw response to stderr")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false,
		"print results as JSON on stdout (errors as JSON on stderr)")
}

// cliUserAgent returns the User-Agent string used for all outgoing HTTP requests.
func cliUserAgent() string {
	return fmt.Sprintf("retyc-cli/%s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
}

// applyServiceConfig hands the settings the service reads process-wide
// (api.concurrency.*) to it, once, before the command runs.
//
// A configuration that does not load is left for the command to report through
// its own config.Load; some commands deliberately tolerate it (auth logout), so
// failing here would break them. The service then keeps its defaults.
func applyServiceConfig() {
	cfg, err := config.Load()
	if err != nil {
		return
	}
	service.SetConcurrency(cfg.API.Concurrency)
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

	var notFound viper.ConfigFileNotFoundError
	switch err := viper.ReadInConfig(); {
	case err == nil:
		configFileLoaded = viper.ConfigFileUsed()
		if debug {
			fmt.Fprintln(os.Stderr, "Using config file:", configFileLoaded)
		}
	case errors.As(err, &notFound):
		// No config file in the search path: defaults and environment apply.
	default:
		configFileErr = err
		if debug {
			fmt.Fprintln(os.Stderr, "Config file not loaded:", err)
		}
	}

	setInsecureFromConfig()
}
