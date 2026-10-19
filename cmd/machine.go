// Package cmd — machine command group (machine accounts).
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/ui"
)

// maxMachineNameLen bounds --name and --cluster-uid, in characters.
const maxMachineNameLen = 63

// uuidRE matches the textual form of a UUID.
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// machineCmd groups the machine account commands. It must not carry a
// PersistentPreRun(E): cobra runs only the closest one, so it would mask the
// root hook (CA loading, tracing, concurrency).
var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Machine accounts (servers, CI, clusters)",
}

// Flags of machine enroll. They are arguments of a one-shot command, not
// viper keys.
var (
	enrollOrg        string
	enrollOutputDir  string
	enrollName       string
	enrollClusterUID string
)

var machineEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll this machine in an organization",
	Long: `Generate the keys of a machine account in --output-dir, ask to join the
organization and wait until an administrator approves the request in
Organization > Machines, after comparing the fingerprint shown here.

No login is needed. Existing keys in the directory are reused, never
regenerated. With --json, one JSON event per line is written on stdout
(pending, then approved, denied or expired); everything else goes to stderr.
Exit codes: 0 approved, 1 expired (run it again), 78 denied or misconfigured.`,
	Args: cobra.NoArgs,
	RunE: runMachineEnroll,
}

func init() {
	machineEnrollCmd.Flags().StringVar(&enrollOrg, "org", "", "organization ID (UUID)")
	machineEnrollCmd.Flags().StringVar(&enrollOutputDir, "output-dir", "",
		"directory receiving the keys and the machine configuration")
	machineEnrollCmd.Flags().StringVar(&enrollName, "name", "",
		"name shown to the administrators (default: the host name)")
	machineEnrollCmd.Flags().StringVar(&enrollClusterUID, "cluster-uid", "",
		"Kubernetes cluster identifier (UID of the kube-system namespace)")
	machineCmd.AddCommand(machineEnrollCmd)
	rootCmd.AddCommand(machineCmd)
}

// enrollParams validates the flags before any network call.
func enrollParams(cmd *cobra.Command) (service.EnrollParams, error) {
	var p service.EnrollParams
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", config.ErrMachineConfig, fmt.Sprintf(format, a...))
	}
	if !uuidRE.MatchString(enrollOrg) {
		return p, bad("--org must be an organization UUID")
	}
	if enrollOutputDir == "" {
		return p, bad("--output-dir is required")
	}
	name := enrollName
	if !cmd.Flags().Changed("name") {
		host, err := os.Hostname()
		if err != nil {
			return p, bad("cannot read the host name, pass --name: %v", err)
		}
		if r := []rune(host); len(r) > maxMachineNameLen {
			host = string(r[:maxMachineNameLen])
		}
		name = host
	}
	if n := utf8.RuneCountInString(name); n < 1 || n > maxMachineNameLen || strings.ContainsRune(name, 0) {
		return p, bad("--name must be 1 to %d characters, without NUL", maxMachineNameLen)
	}
	// The API answers UUIDs in lower case: send it so, the answers compare equal.
	p = service.EnrollParams{OrganizationID: strings.ToLower(enrollOrg), Dir: enrollOutputDir, DisplayName: name}
	if enrollClusterUID != "" {
		if utf8.RuneCountInString(enrollClusterUID) > maxMachineNameLen {
			return p, bad("--cluster-uid must be at most %d characters", maxMachineNameLen)
		}
		uid := enrollClusterUID
		p.ClusterUID = &uid
	}

	return p, nil
}

func runMachineEnroll(cmd *cobra.Command, _ []string) error {
	p, err := enrollParams(cmd)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	// Anonymous: the machine has no token yet.
	client := api.New(cfg.API.BaseURL, cliUserAgent(), nil, insecure, debug, apiRetry(cfg))

	return service.Enroll(cmd.Context(), client, p, emitEnrollEvent)
}

// emitEnrollEvent writes one event: a JSON line on stdout with --json, text
// on stderr otherwise.
func emitEnrollEvent(ev service.EnrollEvent) {
	if jsonOutput {
		if b, err := json.Marshal(newEnrollEventJSON(ev)); err == nil {
			fmt.Fprintln(os.Stdout, string(b))
		}

		return
	}
	switch ev.Kind {
	case service.EnrollPending:
		if ev.Fingerprint != "" {
			fmt.Fprintf(os.Stderr, "Fingerprint: %s\n", ev.Fingerprint)
		}
		if ev.ApprovalURI != "" {
			fmt.Fprintf(os.Stderr, "Approval: %s\n", ui.Escape(ev.ApprovalURI))
		}
		fmt.Fprintf(os.Stderr, "Waiting for approval in Organization > Machines (request expires %s)\n",
			ev.ExpiresAt.Local().Format("2006-01-02 15:04:05"))
	case service.EnrollApproved:
		fmt.Fprintf(os.Stderr, "Machine %s approved\n", ui.Escape(ev.MachineID))
	}
}
