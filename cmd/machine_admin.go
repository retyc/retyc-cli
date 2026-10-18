// Package cmd — management of the organization's machine accounts by an
// organization admin, with the admin's login (not an organization API key:
// these routes are not on /v1).
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/ui"
)

// errMachineAdminInMachineMode refuses the management commands in machine
// mode: they need the login of an organization admin.
var errMachineAdminInMachineMode = fmt.Errorf(
	"%w: managing machine accounts needs the login of an organization admin, not a machine account",
	config.ErrMachineConfig)

// deref returns *s, or "" when s is nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

// newMachineAdminClient is newAPIClient for the management commands.
func newMachineAdminClient(ctx context.Context) (*api.Client, error) {
	if config.MachineMode() {
		return nil, errMachineAdminInMachineMode
	}
	_, client, err := newAPIClient(ctx)

	return client, err
}

// normalizeFingerprint makes a typed fingerprint comparable with the API's:
// upper case, spaces removed.
func normalizeFingerprint(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
}

var machineListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the machine accounts of your organization (admins)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := newMachineAdminClient(cmd.Context())
		if err != nil {
			return err
		}
		machines, err := client.ListMachines(cmd.Context())
		if err != nil {
			return fmt.Errorf("listing machine accounts: %w", err)
		}
		if jsonOutput {
			return printJSON(newItemsJSON(machines))
		}
		if len(machines) == 0 {
			fmt.Println("No machine accounts.")

			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "MACHINE ID\tNAME\tSTATUS\tFINGERPRINT\tCLUSTER UID\tCREATED")
		for _, m := range machines {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", m.ID, ui.Escape(m.DisplayName), m.Status,
				m.Fingerprint, ui.Escape(deref(m.ClusterUID)), m.CreatedAt.Format("2006-01-02"))
		}
		_ = w.Flush()

		return nil
	},
}

var machineRequestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "List the enrollments waiting for an approval (admins)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := newMachineAdminClient(cmd.Context())
		if err != nil {
			return err
		}
		reqs, err := client.ListMachineEnrollments(cmd.Context())
		if err != nil {
			return fmt.Errorf("listing enrollments: %w", err)
		}
		if jsonOutput {
			return printJSON(newItemsJSON(reqs))
		}
		if len(reqs) == 0 {
			fmt.Println("No pending enrollments.")

			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ENROLLMENT ID\tNAME\tFINGERPRINT\tFROM\tEXPIRES\tREPLACES")
		for _, e := range reqs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, ui.Escape(e.DisplayName), e.Fingerprint,
				deref(e.CreatedIP), e.ExpiresAt.Local().Format("15:04:05"), deref(e.ReplacesMachineID))
		}
		_ = w.Flush()

		return nil
	},
}

// findEnrollment returns the pending enrollment id of the organization.
func findEnrollment(ctx context.Context, client *api.Client, id string) (*api.MachineEnrollment, error) {
	reqs, err := client.ListMachineEnrollments(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing enrollments: %w", err)
	}
	for i := range reqs {
		if strings.EqualFold(reqs[i].ID, id) {
			return &reqs[i], nil
		}
	}

	return nil, fmt.Errorf("no pending enrollment %s in your organization (expired or already decided?): %w",
		id, api.ErrNotFound)
}

// describeEnrollment prints what the admin must check before deciding.
func describeEnrollment(e *api.MachineEnrollment) {
	fmt.Fprintf(os.Stderr, "Enrollment %s\n  name:        %s\n  fingerprint: %s\n", e.ID, ui.Escape(e.DisplayName),
		e.Fingerprint)
	if e.ClusterUID != nil {
		fmt.Fprintf(os.Stderr, "  cluster UID: %s\n", ui.Escape(*e.ClusterUID))
	}
	if e.CreatedIP != nil {
		fmt.Fprintf(os.Stderr, "  from:        %s\n", *e.CreatedIP)
	}
	if e.ReplacesMachineID != nil {
		fmt.Fprintf(os.Stderr, "  replaces:    machine %s (same cluster)\n", *e.ReplacesMachineID)
	}
}

var machineApproveCmd = &cobra.Command{
	Use:   "approve <enrollment-id>",
	Short: "Approve an enrollment, after checking its fingerprint (admins)",
	Long: `Approve a pending enrollment: the machine account is created and takes a
seat in the organization.

Compare the fingerprint with the one printed by ` + "`retyc machine enroll`" + ` on the
machine before approving; --fingerprint makes the command check it.
In an organization with no organization key, the command asks again: only
the members the machine adds to its datarooms can then read them once the
machine is lost (--yes accepts it).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		name, _ := cmd.Flags().GetString("name")
		want, _ := cmd.Flags().GetString("fingerprint")
		yes, _ := cmd.Flags().GetBool("yes")
		if cmd.Flags().Changed("name") && (name == "" || len([]rune(name)) > maxMachineNameLen) {
			return fmt.Errorf("--name must be 1 to %d characters", maxMachineNameLen)
		}

		client, err := newMachineAdminClient(ctx)
		if err != nil {
			return err
		}
		e, err := findEnrollment(ctx, client, args[0])
		if err != nil {
			return err
		}
		describeEnrollment(e)
		if want != "" && normalizeFingerprint(want) != normalizeFingerprint(e.Fingerprint) {
			return fmt.Errorf("fingerprint mismatch: the enrollment shows %s, not %s: do not approve it",
				e.Fingerprint, want)
		}
		if want == "" {
			ok, err := confirm("Approve it? The fingerprint must be the one the machine printed.", yes)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("aborted")
			}
		}
		if name == "" {
			name = e.DisplayName
		}

		m, err := client.ApproveMachineEnrollment(ctx, e.ID, name, false)
		if errors.Is(err, api.ErrNoOrganizationKeyAck) {
			// The API wants an explicit acknowledgement: ask, then approve again.
			fmt.Fprintln(os.Stderr, "Warning: the organization has no organization key: only the members the "+
				"machine adds to its datarooms can read them once the machine is lost.")
			ok, cerr := confirm("Approve anyway?", yes)
			if cerr != nil {
				return cerr
			}
			if !ok {
				return errors.New("aborted")
			}
			m, err = client.ApproveMachineEnrollment(ctx, e.ID, name, true)
		}
		if err != nil {
			return fmt.Errorf("approving enrollment: %w", err)
		}
		if jsonOutput {
			return printJSON(m)
		}
		fmt.Printf("Machine %s approved (machine id %s).\n", ui.Escape(m.DisplayName), m.ID)

		return nil
	},
}

var machineDenyCmd = &cobra.Command{
	Use:   "deny <enrollment-id>",
	Short: "Refuse an enrollment (admins)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		yes, _ := cmd.Flags().GetBool("yes")
		client, err := newMachineAdminClient(ctx)
		if err != nil {
			return err
		}
		e, err := findEnrollment(ctx, client, args[0])
		if err != nil {
			return err
		}
		describeEnrollment(e)
		ok, err := confirm("Refuse it?", yes)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
		if err := client.DenyMachineEnrollment(ctx, e.ID); err != nil {
			return fmt.Errorf("refusing enrollment: %w", err)
		}
		if jsonOutput {
			return printJSON(machineActionJSON{ID: e.ID, Result: "denied"})
		}
		fmt.Printf("Enrollment %s refused.\n", e.ID)

		return nil
	},
}

var machineRmCmd = &cobra.Command{
	Use:   "rm <machine-id>",
	Short: "Delete a machine account that owns no dataroom (admins)",
	Long: `Delete a machine account: its seat is freed and it must enroll again to
come back. The API refuses it while the machine owns datarooms, deleted ones
not purged yet included; disable it instead to cut its access.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if !uuidRE.MatchString(args[0]) {
			return fmt.Errorf("invalid machine id %q: see `retyc machine ls`", args[0])
		}
		client, err := newMachineAdminClient(ctx)
		if err != nil {
			return err
		}
		yes, _ := cmd.Flags().GetBool("yes")
		ok, err := confirm(fmt.Sprintf("Delete machine %s? It will have to enroll again.", args[0]), yes)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
		err = client.DeleteMachine(ctx, args[0])
		if errors.Is(err, api.ErrConflict) {
			return fmt.Errorf("deleting machine account: it still owns datarooms (deleted ones not purged yet "+
				"included): transfer their ownership (`retyc admin dataroom chown`), delete them "+
				"or disable the machine instead: %w", err)
		}
		if err != nil {
			return fmt.Errorf("deleting machine account: %w", err)
		}
		if jsonOutput {
			return printJSON(machineActionJSON{ID: args[0], Result: "deleted"})
		}
		fmt.Printf("Machine %s deleted.\n", args[0])

		return nil
	},
}

// newMachineToggleCmd builds `machine enable` / `machine disable`.
func newMachineToggleCmd(enable bool) *cobra.Command {
	verb, done, short := "disable", "disabled",
		"Disable a machine account: it is refused at once, keeps its keys and can be enabled again (admins)"
	if enable {
		verb, done, short = "enable", "enabled", "Enable a disabled machine account again (admins)"
	}
	c := &cobra.Command{
		Use:   verb + " <machine-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if !uuidRE.MatchString(args[0]) {
				return fmt.Errorf("invalid machine id %q: see `retyc machine ls`", args[0])
			}
			client, err := newMachineAdminClient(ctx)
			if err != nil {
				return err
			}
			if !enable {
				yes, _ := cmd.Flags().GetBool("yes")
				ok, err := confirm(fmt.Sprintf("Disable machine %s? Its servers stop with exit code 77.", args[0]), yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}
			if err := client.SetMachineEnabled(ctx, args[0], enable); err != nil {
				return fmt.Errorf("%s machine account: %w", strings.TrimSuffix(verb, "e")+"ing", err)
			}
			if jsonOutput {
				return printJSON(machineActionJSON{ID: args[0], Result: done})
			}
			fmt.Printf("Machine %s %s.\n", args[0], done)

			return nil
		},
	}
	// enable asks nothing: -y is accepted so that scripts can pass it to
	// every machine command.
	c.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	return c
}

func init() {
	machineApproveCmd.Flags().String("name", "", "name of the machine account (default: the name it asked for)")
	machineApproveCmd.Flags().String("fingerprint", "",
		"fingerprint printed by the machine: approve only if it matches (no prompt then)")
	machineApproveCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	machineDenyCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	machineRmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	machineCmd.AddCommand(machineListCmd, machineRequestsCmd, machineApproveCmd, machineDenyCmd,
		newMachineToggleCmd(true), newMachineToggleCmd(false), machineRmCmd)
}
