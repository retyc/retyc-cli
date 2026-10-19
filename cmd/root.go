// Package cmd contains all CLI command definitions.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	debug   bool

	// envFileFlag is --env-file; RETYC_ENV_FILE applies when it is empty.
	envFileFlag string

	// envFileLoaded describes the environment file whose variables were
	// applied, nil when none was designated or when it failed to load.
	envFileLoaded *config.EnvFile

	// envFileErr is why the designated environment file was not loaded. It is
	// fatal for every command but the offline ones (PersistentPreRunE).
	envFileErr error

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
			// An offline command needs no secret, and `config path` is what
			// someone runs to find out why the file does not load.
			if envFileErr != nil {
				fmt.Fprintln(os.Stderr, "warning:", envFileErr)
			}

			return nil
		}

		// A designated environment file that does not load is fatal: running
		// without the secrets it was meant to bring would fail later, less
		// clearly, or prompt on a terminal nobody watches.
		if envFileErr != nil {
			return envFileErr
		}

		source, err := api.InitTLSRoots()
		if err != nil {
			return fmt.Errorf("loading root CAs: %w", err)
		}

		if debug {
			fmt.Fprintln(os.Stderr, "TLS roots:", source)
		}

		applyServiceConfig()

		return nil
	},
}

// exitAuthRequired is the exit code of a command stopped by a login that
// cannot recover without a new token: none stored, or a refresh token the
// identity provider rejected (expired or revoked, invalid_grant). It is
// sysexits.h EX_NOPERM and a stable contract: a supervisor restarting
// `retyc fs webdav serve` stops on it instead of hammering the API and the
// identity provider. A transient failure (network, 5xx) keeps exit code 1.
const exitAuthRequired = 77

// exitConfig is the exit code of a command stopped by a key passphrase that
// is missing (RETYC_KEY_PASSPHRASE unset, no TTY to prompt) or wrong, or by an
// environment file (--env-file) that does not load. It is
// sysexits.h EX_CONFIG and, like exitAuthRequired, tells a supervisor that a
// restart with the same environment will fail again.
const exitConfig = 78

// exitLostWrites is the exit code of `retyc fs mount` when files being
// written, or removed in the background, did not reach the API before the
// filesystem went away. It is sysexits.h EX_TEMPFAIL: the mount itself
// worked, data written through it is lost, and a supervisor can tell it apart
// from a failure to start (1). A login lost at the same time keeps 77.
const exitLostWrites = 75

// lostWritesError marks the error of a mount that lost writes (see
// exitLostWrites) without changing its message. It is declared here, built
// everywhere, while the driver's own error exists on Linux only.
type lostWritesError struct{ error }

func (e lostWritesError) Unwrap() error { return e.error }

// machineUnauthorized reports whether err carries a 401 of the API while the
// process authenticates as a machine account: its token is refused, which
// no login can fix, so it is a lost login (77) like a revoked account.
func machineUnauthorized(err error) bool {
	var httpErr *api.HTTPError

	return config.MachineMode() && errors.As(err, &httpErr) && httpErr.Status == http.StatusUnauthorized
}

// exitCode maps the error a command returned to the process exit code.
func exitCode(err error) int {
	var lost lostWritesError
	switch {
	case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken),
		errors.Is(err, auth.ErrMachineRevoked), machineUnauthorized(err):
		return exitAuthRequired
	case errors.Is(err, config.ErrNoKeyPassphrase), errors.Is(err, service.ErrWrongKeyPassphrase),
		errors.Is(err, config.ErrEnvFile), errors.Is(err, config.ErrMachineConfig),
		errors.Is(err, service.ErrEnrollmentDenied):
		return exitConfig
	case errors.As(err, &lost):
		return exitLostWrites
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

// run executes args against rootCmd. Execute and the tests share it.
func run(ctx context.Context, args []string) error {
	rootCmd.SetArgs(args)

	return rootCmd.ExecuteContext(ctx)
}

func init() {
	// The environment file comes first: its variables must be in the
	// environment before viper, or anything else, reads a RETYC_ variable.
	cobra.OnInitialize(loadEnvFile, initConfig)

	// Build the default config path hint from the active build mode so the
	// help text always reflects the real default location.
	defaultCfgHint := "auto"
	if dir, err := config.ConfigDir(); err == nil {
		defaultCfgHint = dir + "/config.yaml"
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default: "+defaultCfgHint+"); does not move token.json")
	rootCmd.PersistentFlags().StringVar(&envFileFlag, "env-file", "",
		"file of RETYC_* variables (NAME=value lines), applied unless already set in the\n"+
			"environment; must be mode 0600 (default: $"+config.EnvFileName+")")
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

// loadEnvFile applies the environment file designated by --env-file or
// RETYC_ENV_FILE. The outcome is kept for PersistentPreRunE, which decides
// whether a failure stops the command: cobra.OnInitialize cannot return one.
//
// --debug names the file and the variables, never a value.
func loadEnvFile() {
	envFileLoaded, envFileErr = config.LoadEnvFile(envFileFlag)
	if !debug || envFileLoaded == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "Using environment file:", envFileLoaded.Path)
	if len(envFileLoaded.Applied) > 0 {
		fmt.Fprintln(os.Stderr, "  applied:", strings.Join(envFileLoaded.Applied, " "))
	}
	if len(envFileLoaded.Kept) > 0 {
		fmt.Fprintln(os.Stderr, "  already in the environment, kept:", strings.Join(envFileLoaded.Kept, " "))
	}
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
