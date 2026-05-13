package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var dataroomCmd = &cobra.Command{
	Use:   "dataroom",
	Short: "Manage datarooms",
}

var dataroomUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage dataroom users",
}

// — dataroom ls ——————————————————————————————————————————————————————————————

var dataroomLsCmd = &cobra.Command{
	Use:   "ls [retyc://dataroom_id[/path]]",
	Short: "List datarooms, or list files in a dataroom path",
	Args:  cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		if len(args) == 0 {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return err
			}
			s := ui.NewSpinner()
			s.Start()
			result, err := service.ListDatarooms(ctx, client)
			s.Stop()
			if err != nil {
				return err
			}
			if len(result.Items) == 0 {
				fmt.Println("No datarooms found.")

				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "DATAROOM ID\tTITLE\tCREATED")
			for _, dr := range result.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\n",
					dr.ID,
					dr.Title,
					dr.CreatedAt.Format("2006-01-02 15:04"),
				)
			}
			_ = w.Flush()
			if result.Pages > 1 {
				fmt.Printf("\nPage 1/%d · %d dataroom(s) total\n", result.Pages, result.Total)
			}

			return nil
		}

		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		nodes, err := service.ListNodes(ctx, cfg, client, args[0], spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		if len(nodes) == 0 {
			fmt.Println("No matching nodes.")

			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tNAME\tSIZE")
		for _, n := range nodes {
			if n.Type == "dir" {
				fmt.Fprintf(w, "DIR\t%s\t\n", n.Name)
			} else {
				fmt.Fprintf(w, "FILE\t%s\t%s\n", n.Name, ui.FormatSize(n.Size))
			}
		}
		_ = w.Flush()

		return nil
	},
}

// — dataroom create ——————————————————————————————————————————————————————————

var dataroomCreateCmd = &cobra.Command{
	Use:   "create --title <title>",
	Short: "Create a new dataroom",
	RunE: func(cmd *cobra.Command, args []string) error {
		title, _ := cmd.Flags().GetString("title")

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		result, err := service.CreateDataroom(ctx, cfg, client, title, spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("Dataroom %s created.\n", result.ID)
		if result.Title != "" {
			fmt.Printf("Title: %s\n", result.Title)
		}

		return nil
	},
}

// — dataroom info ————————————————————————————————————————————————————————————

var dataroomInfoCmd = &cobra.Command{
	Use:   "info <dataroom_id>",
	Short: "Show dataroom details, stats and members",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		info, err := service.GetDataroomInfo(ctx, client, args[0])
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("ID:      %s\n", info.Dataroom.ID)
		fmt.Printf("Title:   %s\n", info.Dataroom.Title)
		fmt.Printf("Created: %s\n", info.Dataroom.CreatedAt.Format("2006-01-02 15:04"))

		if info.Stats != nil {
			fmt.Printf("\nFiles:   %d · %s (encrypted)\n", info.Stats.FilesCount, ui.FormatSize(info.Stats.FilesEncryptedSize))
		}

		if len(info.Users) > 0 {
			fmt.Println("\nUsers:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  EMAIL\tROLE\tUSER ID")
			for _, u := range info.Users {
				fmt.Fprintf(w, "  %s\t%s\t%s\n", u.UserEmail, u.Role, u.UserID)
			}
			_ = w.Flush()
		}

		return nil
	},
}

// — dataroom user add ————————————————————————————————————————————————————————

var dataroomUserAddCmd = &cobra.Command{
	Use:   "add <dataroom_id> <email>",
	Short: "Add a user to a dataroom",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		drID := args[0]
		email := args[1]
		role, _ := cmd.Flags().GetString("role")

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		err = service.AddDataroomUser(ctx, cfg, client, drID, email, role, spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("Added %s with role %s.\n", email, role)

		return nil
	},
}

// — dataroom user rm —————————————————————————————————————————————————————————

var dataroomUserRmCmd = &cobra.Command{
	Use:   "rm <dataroom_id> <user_id>",
	Short: "Remove a user from a dataroom",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		drID := args[0]
		userID := args[1]

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		err = service.RemoveDataroomUser(ctx, cfg, client, drID, userID, spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("User %s removed.\n", userID)

		return nil
	},
}

// — dataroom cp ——————————————————————————————————————————————————————————————

var dataroomCpCmd = &cobra.Command{
	Use:   "cp <src...> <dst>",
	Short: "Copy files to or from a dataroom  (local→retyc:// uploads, retyc://→local downloads)",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")

		dst := args[len(args)-1]
		srcs := args[:len(args)-1]

		_, dstErr := service.ParseRetycURI(dst)
		_, srcErr := service.ParseRetycURI(srcs[0])

		switch {
		case dstErr == nil && srcErr == nil:
			return fmt.Errorf("remote-to-remote copy is not supported")
		case dstErr != nil && srcErr != nil:
			return fmt.Errorf("either source or destination must be a retyc:// URI")
		case dstErr == nil:
			return dataroomUpload(cmd.Context(), srcs, dst, yes)
		default:
			if len(srcs) > 1 {
				return fmt.Errorf("only one remote source is supported for download")
			}

			return dataroomDownload(cmd.Context(), srcs[0], dst)
		}
	},
}

func dataroomUpload(ctx context.Context, localPaths []string, dstURI string, yes bool) error {
	type statEntry struct {
		path  string
		name  string
		size  int64
		isDir bool
	}

	var entries []statEntry
	var totalSize int64
	for _, p := range localPaths {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		size := info.Size()
		if info.IsDir() {
			size = 0
			if walkErr := filepath.WalkDir(p, func(_ string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				fi, err := d.Info()
				if err != nil {
					return err
				}
				size += fi.Size()

				return nil
			}); walkErr != nil {
				return fmt.Errorf("scanning %s: %w", p, walkErr)
			}
		}
		entries = append(entries, statEntry{path: p, name: info.Name(), size: size, isDir: info.IsDir()})
		totalSize += size
	}

	if !yes {
		const lineWidth = 44
		fmt.Fprintln(os.Stderr)
		for _, e := range entries {
			displayName := e.name
			if e.isDir {
				displayName = e.name + "/"
			}
			runes := []rune(displayName)
			if len(runes) > lineWidth-10 {
				displayName = string(runes[:lineWidth-13]) + "…"
			}
			fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, displayName, ui.FormatSize(e.size))
		}
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("─", lineWidth))
		var dirCount, fileCount int
		for _, e := range entries {
			if e.isDir {
				dirCount++
			} else {
				fileCount++
			}
		}
		var labelParts []string
		if dirCount == 1 {
			labelParts = append(labelParts, "1 folder")
		} else if dirCount > 1 {
			labelParts = append(labelParts, fmt.Sprintf("%d folders", dirCount))
		}
		if fileCount == 1 {
			labelParts = append(labelParts, "1 file")
		} else if fileCount > 1 {
			labelParts = append(labelParts, fmt.Sprintf("%d files", fileCount))
		}
		fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, strings.Join(labelParts, ", "), ui.FormatSize(totalSize))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  Destination:  %s\n", dstURI)
		fmt.Fprintln(os.Stderr)
		fmt.Fprint(os.Stderr, "Proceed? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Fprintln(os.Stderr)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Fprintln(os.Stderr, "Aborted.")

			return nil
		}
	}

	cfg, client, err := newAPIClient(ctx)
	if err != nil {
		return err
	}

	uploadCtx, cancelUpload := context.WithCancel(ctx)
	defer cancelUpload()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "\nUpload interrupted.")
			cancelUpload()
		case <-uploadCtx.Done():
		}
	}()

	bars := make(map[string]*progressbar.ProgressBar)

	return service.UploadToDataroom(uploadCtx, cfg, client, localPaths, dstURI, readKeyPassphrase, cliProgressFn(bars))
}

func dataroomDownload(ctx context.Context, srcURI, localDst string) error {
	cfg, client, err := newAPIClient(ctx)
	if err != nil {
		return err
	}

	bars := make(map[string]*progressbar.ProgressBar)

	files, err := service.DownloadFromDataroom(
		ctx, cfg, client, srcURI, localDst, readKeyPassphrase, cliProgressFn(bars),
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nDownloaded %d file(s) to %s/\n", len(files), localDst)

	return nil
}

// — dataroom mv ——————————————————————————————————————————————————————————————

var dataroomMvCmd = &cobra.Command{
	Use:   "mv <retyc://src_path> <retyc://dst_path>",
	Short: "Move or rename a node within a dataroom",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		err = service.MoveDataroomNode(ctx, cfg, client, args[0], args[1], spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("Moved %s → %s\n", args[0], args[1])

		return nil
	},
}

// — dataroom rm ——————————————————————————————————————————————————————————————

var dataroomRmCmd = &cobra.Command{
	Use:   "rm <retyc://path>",
	Short: "Delete a node, or the whole dataroom when path is omitted (retyc://id)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")
		uri := args[0]

		ctx := cmd.Context()

		// Parse URI to decide confirmation message.
		parsed, err := service.ParseRetycURI(uri)
		if err != nil {
			return err
		}

		if !yes {
			if parsed.IsRoot() {
				fmt.Fprintf(os.Stderr, "Delete dataroom %s and all its contents? [y/N] ", parsed.DataroomID)
			} else {
				fmt.Fprintf(os.Stderr, "Delete %s? [y/N] ", uri)
			}
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stderr, "Aborted.")

				return nil
			}
		}

		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		count, err := service.DeleteDataroomNode(ctx, cfg, client, uri, spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		if parsed.IsRoot() {
			fmt.Printf("Dataroom %s deleted.\n", parsed.DataroomID)
		} else if count > 1 {
			fmt.Printf("Deleted %d node(s).\n", count)
		} else {
			fmt.Printf("Deleted %s\n", uri)
		}

		return nil
	},
}

// — dataroom mkdir ———————————————————————————————————————————————————————————

var dataroomMkdirCmd = &cobra.Command{
	Use:   "mkdir <retyc://path>",
	Short: "Create a folder in a dataroom",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		nodeID, err := service.MkdirDataroom(ctx, cfg, client, args[0], spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("Created %s (id: %s)\n", args[0], nodeID)

		return nil
	},
}

// — init ——————————————————————————————————————————————————————————————————————

func init() {
	dataroomCreateCmd.Flags().String("title", "", "Title of the dataroom")
	_ = dataroomCreateCmd.MarkFlagRequired("title")

	dataroomUserAddCmd.Flags().String("role", "viewer", "Role: viewer, editor, or admin")

	dataroomCpCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	dataroomRmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	dataroomUserCmd.AddCommand(dataroomUserAddCmd)
	dataroomUserCmd.AddCommand(dataroomUserRmCmd)

	dataroomCmd.AddCommand(dataroomLsCmd)
	dataroomCmd.AddCommand(dataroomCreateCmd)
	dataroomCmd.AddCommand(dataroomInfoCmd)
	dataroomCmd.AddCommand(dataroomCpCmd)
	dataroomCmd.AddCommand(dataroomMvCmd)
	dataroomCmd.AddCommand(dataroomRmCmd)
	dataroomCmd.AddCommand(dataroomMkdirCmd)
	dataroomCmd.AddCommand(dataroomUserCmd)

	rootCmd.AddCommand(dataroomCmd)
}
