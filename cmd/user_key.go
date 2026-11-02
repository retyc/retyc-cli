package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/ui"
)

// userKeyCmd groups the commands on the user's encryption key. No hook: the
// root's PersistentPreRunE must run.
var userKeyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage your encryption key",
}

var userKeyRotateYes bool

var userKeyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace your encryption key and rekey what is bound to the old one",
	Long: `Generate a new encryption key, rekey the datarooms and the sent transfers
still bound to the previous key, then revoke it. Run it again to resume an
interrupted or incomplete rotation: the previous key is revoked only once
everything was rekeyed. With a machine account, age.key is replaced in place.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ok, err := confirm("Rotate your encryption key? Items you received stay unreadable "+
			"with the new key until their owner's client rekeys them.", userKeyRotateYes)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "Aborted.")

			return nil
		}

		// The result is printed even with ErrKeyRotationIncomplete. A 403
		// refused to a machine account is explained by printError
		// (explainMachineForbidden): wrapping it here would say it twice.
		res, err := runKeyRotation(cmd.Context())
		if res != nil {
			if pErr := printKeyRotation(res); pErr != nil {
				return pErr
			}
		}

		return err
	},
}

// runKeyRotation rotates the key of the machine account or of the logged-in
// user. Progress goes to stderr.
func runKeyRotation(ctx context.Context) (*service.KeyRotationResult, error) {
	progress := func(msg string) { fmt.Fprintln(os.Stderr, msg) }

	if !config.MachineMode() {
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return nil, err
		}

		return service.RotateUserKey(ctx, client, readKeyPassphrase, progress)
	}

	// A swap interrupted between its renames leaves no age.key, which the
	// machine configuration requires: finish it before loading anything.
	path, err := config.MachineAgeKeyPath()
	if err != nil {
		return nil, err
	}
	if err := service.FinishMachineKeySwap(path); err != nil {
		return nil, err
	}
	_, client, err := newAPIClient(ctx)
	if err != nil {
		return nil, err
	}
	m, err := config.LoadMachine()
	if err != nil {
		return nil, err
	}

	return service.RotateMachineKey(ctx, client, m, time.Now, progress)
}

// printKeyRotation writes the result on stdout, as JSON with --json.
func printKeyRotation(r *service.KeyRotationResult) error {
	if jsonOutput {
		return printJSON(newKeyRotationJSON(r))
	}

	if r.Resumed {
		fmt.Println("Resumed a rotation in progress.")
	}
	if r.Machine {
		fmt.Printf("Fingerprint:  %s (shown on the organization's Machines page)\n", r.Fingerprint)
	} else {
		fmt.Printf("Key ID:       %s\n", r.KeyID)
	}
	fmt.Printf("Public key:   %s\n", r.PublicKey)
	printRekeyOutcome("Datarooms", r.Datarooms)
	if !r.Machine {
		printRekeyOutcome("Transfers", r.Transfers)
	}
	switch {
	case r.OldKeyKept:
		fmt.Println("The previous key is kept: run the command again once the failures are fixed.")
	case len(r.Revoked) > 0:
		fmt.Printf("Revoked:      %d previous key(s)\n", len(r.Revoked))
	}

	return nil
}

func printRekeyOutcome(label string, o service.RekeyOutcome) {
	fmt.Printf("%-13s %d rekeyed, %d skipped, %d failed\n", label+":", o.Rekeyed, len(o.Skipped), len(o.Failed))
	for _, s := range o.Skipped {
		fmt.Printf("  skipped: %s\n", ui.Escape(s))
	}
	for _, f := range o.Failed {
		fmt.Printf("  failed:  %s\n", ui.Escape(f))
	}
}

func init() {
	userKeyRotateCmd.Flags().BoolVarP(&userKeyRotateYes, "yes", "y", false, "Skip the confirmation prompt")
	userKeyCmd.AddCommand(userKeyRotateCmd)
}
