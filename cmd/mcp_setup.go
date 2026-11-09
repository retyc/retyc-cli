package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/term"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/mcpsetup"
	"github.com/retyc/retyc-cli/internal/service"
)

// setupPassphraseAttempts bounds the passphrase prompts of `mcp setup`.
const setupPassphraseAttempts = 3

var mcpSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Connect Retyc to your AI clients (Claude Desktop, Hermes, OpenClaw)",
	Long: `Interactive setup of the MCP server for the AI clients found on this machine.

It signs you in (browser, OIDC device flow, long-lived offline token), checks
your key passphrase by unlocking your key, copies this binary to a stable
location and writes the retyc entry, with both secrets, into the configuration
of the clients you choose. Run it again to update the binary or the secrets.

Usually run as: npx -y @retyc/mcp setup`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := refuseInMachineMode(); err != nil {
			return err
		}
		if jsonOutput {
			return errors.New("mcp setup is interactive: --json is not supported")
		}
		if !stdinIsTerminal() {
			return errors.New("mcp setup is interactive: run it in a terminal")
		}
		deps, err := realSetupDeps(cmd.Context())
		if err != nil {
			return err
		}

		return runMCPSetup(cmd.Context(), deps)
	},
}

// setupDeps are the side effects of runMCPSetup, replaced in tests.
type setupDeps struct {
	// login runs the device flow and returns a token carrying an offline
	// refresh token.
	login func(ctx context.Context) (*oauth2.Token, error)
	// verify unlocks the user key with passphrase; a wrong one wraps
	// service.ErrWrongKeyPassphrase.
	verify     func(ctx context.Context, tok *oauth2.Token, passphrase string) error
	readSecret func(prompt string) (string, error)
	readLine   func(prompt string) (string, error)
	env        mcpsetup.Env
	exe        string // this binary, copied by install
	install    func(e mcpsetup.Env, src string) (string, error)
	out        io.Writer // every message; stdout is never used
}

// runMCPSetup chooses the clients, then logs in, checks the passphrase,
// installs the binary and writes the configurations. Nothing is written
// before every check passed.
func runMCPSetup(ctx context.Context, d setupDeps) error {
	out := d.out
	fmt.Fprintln(out, "Retyc MCP setup")
	fmt.Fprintln(out)

	var detected []mcpsetup.Client
	for _, c := range mcpsetup.Clients() {
		if c.Detected(d.env) {
			detected = append(detected, c)
		}
	}
	if len(detected) == 0 {
		return printManualSetup(out)
	}
	chosen, err := chooseClients(d, detected)
	if err != nil {
		return err
	}

	fmt.Fprintln(out, "Step 1/3: sign in to Retyc in your browser.")
	tok, err := d.login(ctx)
	if err != nil {
		return fmt.Errorf("sign-in: %w", err)
	}
	if tok.RefreshToken == "" {
		return errors.New("sign-in: the server returned no offline token")
	}
	fmt.Fprintln(out, "Signed in.")
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Step 2/3: your key passphrase (the one that protects your Retyc encryption key).")
	passphrase, err := askPassphrase(ctx, d, tok)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Passphrase checked.")
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Step 3/3: configuring your clients.")
	bin, err := d.install(d.env, d.exe)
	if errors.Is(err, mcpsetup.ErrBinaryInUse) {
		return fmt.Errorf("%w: Quit your AI clients (%s) and run the setup again", err, clientNames(chosen))
	}
	if err != nil {
		return fmt.Errorf("installing the retyc binary: %w", err)
	}

	server := mcpsetup.Server{Command: bin, Token: tok.RefreshToken, Passphrase: passphrase}
	var failed []string
	manualPending := false
	for _, c := range chosen {
		_, err := c.Configure(d.env, server)
		var manual *mcpsetup.ManualStepError
		switch {
		case errors.As(err, &manual):
			fmt.Fprintf(out, "  ! %s: the %s command was not found. Run this to finish:\n\n    %s\n\n",
				c.Name(), strings.ToLower(c.Name()), manual.Command)
			manualPending = true
		case err != nil:
			fmt.Fprintf(out, "  x %s: %v\n", c.Name(), err)
			failed = append(failed, c.Name())
		default:
			fmt.Fprintf(out, "  ok %s configured. Restart %s.\n", c.Name(), c.Name())
		}
	}
	fmt.Fprintln(out)
	if len(failed) > 0 {
		return fmt.Errorf("could not configure %s", strings.Join(failed, ", "))
	}
	if manualPending {
		fmt.Fprintln(out, `Run the command above, then ask your agent, for example: "list my Retyc transfers".`)

		return nil
	}
	fmt.Fprintln(out, `Done. Then ask your agent, for example: "list my Retyc transfers".`)

	return nil
}

// chooseClients lists the detected clients and reads a selection: Enter for
// all, or numbers separated by commas.
func chooseClients(d setupDeps, detected []mcpsetup.Client) ([]mcpsetup.Client, error) {
	fmt.Fprintln(d.out, "AI clients found on this machine:")
	for i, c := range detected {
		fmt.Fprintf(d.out, "  %d) %s\n", i+1, c.Name())
	}
	for range 3 {
		line, err := d.readLine("Configure which? [Enter = all, or e.g. 1,2]: ")
		if err != nil {
			return nil, err
		}
		if chosen, ok := parseSelection(line, detected); ok {
			fmt.Fprintln(d.out)

			return chosen, nil
		}
		fmt.Fprintln(d.out, "Please answer with numbers from the list, separated by commas.")
	}

	return nil, errors.New("no valid client selection")
}

func parseSelection(line string, detected []mcpsetup.Client) ([]mcpsetup.Client, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return detected, true
	}
	var chosen []mcpsetup.Client
	seen := map[int]bool{}
	for f := range strings.SplitSeq(line, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 || n > len(detected) {
			return nil, false
		}
		if !seen[n] {
			seen[n] = true
			chosen = append(chosen, detected[n-1])
		}
	}

	return chosen, true
}

// askPassphrase prompts until the passphrase unlocks the key, at most
// setupPassphraseAttempts times; the last error keeps ErrWrongKeyPassphrase.
func askPassphrase(ctx context.Context, d setupDeps, tok *oauth2.Token) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= setupPassphraseAttempts; attempt++ {
		pass, err := d.readSecret("Key passphrase: ")
		if err != nil {
			return "", fmt.Errorf("reading key passphrase: %w", err)
		}
		err = d.verify(ctx, tok, pass)
		if err == nil {
			return pass, nil
		}
		if !errors.Is(err, service.ErrWrongKeyPassphrase) {
			return "", err
		}
		lastErr = err
		if left := setupPassphraseAttempts - attempt; left > 0 {
			fmt.Fprintf(d.out, "Wrong passphrase, try again (%d left).\n", left)
		}
	}

	return "", lastErr
}

func clientNames(cs []mcpsetup.Client) string {
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = c.Name()
	}

	return strings.Join(names, ", ")
}

// printManualSetup explains what to do when no supported client is found. The
// snippet carries placeholders, never secrets.
func printManualSetup(out io.Writer) error {
	snippet, err := json.MarshalIndent(map[string]any{
		"mcpServers": map[string]any{
			mcpsetup.ServerName: map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@retyc/mcp"},
				"env":     map[string]string{mcpsetup.EnvPassphrase: "<your key passphrase>"},
			},
		},
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "No supported AI client found (Claude Desktop, Hermes, OpenClaw).")
	fmt.Fprintln(out, "For another MCP client, add this server to its configuration:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, string(snippet))
	fmt.Fprintln(out)
	fmt.Fprintln(out, `Then ask your agent to "log me into Retyc".`)

	return nil
}

// realSetupDeps wires runMCPSetup to the API, the terminal and the host.
func realSetupDeps(ctx context.Context) (setupDeps, error) {
	cfg, err := config.Load()
	if err != nil {
		return setupDeps{}, fmt.Errorf("loading config: %w", err)
	}
	env, err := mcpsetup.DefaultEnv(ctx)
	if err != nil {
		return setupDeps{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return setupDeps{}, err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	httpClient := newHTTPClient(insecure, debug)
	stdin := bufio.NewReader(os.Stdin)

	return setupDeps{
		login: func(ctx context.Context) (*oauth2.Token, error) {
			oidcCfg, err := api.FetchOIDCConfig(ctx, cfg.API.BaseURL, httpClient)
			if err != nil {
				return nil, fmt.Errorf("fetching OIDC config: %w", err)
			}
			oidcCfg.Scopes = append(oidcCfg.Scopes, "offline_access")

			return auth.DeviceFlowNotify(ctx, *oidcCfg, httpClient, func(url string) { openBrowser(ctx, url) })
		},
		verify: func(ctx context.Context, tok *oauth2.Token, passphrase string) error {
			client := api.New(cfg.API.BaseURL, cliUserAgent(), oauth2.StaticTokenSource(tok), insecure, debug,
				apiRetry(cfg), api.WithUnsafeWrite(cfg.API.UnsafeWrite))
			_, err := service.UnlockUserIdentity(ctx, client, func() (string, error) { return passphrase, nil })

			return err
		},
		readSecret: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)

			return string(b), err
		},
		readLine: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			line, err := stdin.ReadString('\n')
			if errors.Is(err, io.EOF) && line != "" {
				err = nil
			}

			return strings.TrimRight(line, "\r\n"), err
		},
		env:     env,
		exe:     exe,
		install: mcpsetup.InstallBinary,
		out:     os.Stderr,
	}, nil
}

// openBrowser opens url in the user's browser, best effort: over SSH or
// without a desktop the URL printed by the device flow is enough. The opener
// is never killed with ctx: the browser it starts must outlive the command.
func openBrowser(ctx context.Context, url string) {
	if os.Getenv("SSH_CONNECTION") != "" {
		return
	}
	ctx = context.WithoutCancel(ctx)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", url) //nolint:gosec // G204: verification URI from the OIDC server
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec // G204: same
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", url) //nolint:gosec // G204: same
	}
	if err := cmd.Start(); err == nil {
		go func() { _ = cmd.Wait() }()
	}
}
