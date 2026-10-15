// Package cmd — fs mount command (FUSE driver, Linux only).
package cmd

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
)

// mountTarget is what `retyc fs mount` was asked to mount, and where.
type mountTarget struct {
	// all mounts every dataroom, one folder each; otherwise dataroomID is the
	// dataroom mounted as the root.
	all        bool
	dataroomID string
	mountpoint string
	// readOnly mounts the filesystem read only (--read-only, mount.read_only).
	readOnly bool
}

// parseMountArgs reads the two forms of the command:
//
//	retyc fs mount retyc://<dataroom-id> <mountpoint>
//	retyc fs mount --all <mountpoint>
func parseMountArgs(all bool, args []string) (mountTarget, error) {
	if all {
		if len(args) != 1 {
			return mountTarget{}, errors.New("with --all, expected one argument: the mount point")
		}
		if strings.HasPrefix(args[0], "retyc://") {
			return mountTarget{}, errors.New("--all mounts every dataroom: give the mount point only")
		}

		return mountTarget{all: true, mountpoint: args[0]}, nil
	}
	if len(args) != 2 {
		return mountTarget{}, errors.New(
			"expected a dataroom and a mount point (retyc://<dataroom-id> <mountpoint>), or --all <mountpoint>")
	}
	uri, err := service.ParseRetycURI(args[0])
	if err != nil {
		return mountTarget{}, err
	}
	if strings.Trim(uri.Path, "/") != "" {
		return mountTarget{}, fmt.Errorf("%q names a folder: only a whole dataroom can be mounted (retyc://%s)",
			args[0], uri.DataroomID)
	}

	return mountTarget{dataroomID: uri.DataroomID, mountpoint: args[1]}, nil
}

var fsMountCmd = &cobra.Command{
	Use:         "mount {retyc://<dataroom-id> | --all} <mountpoint>",
	Annotations: map[string]string{annotationLongRunning: "true"},
	Short:       "Mount your datarooms as a filesystem (Linux)",
	Long: `Mount a dataroom, or all of them, as a local folder (RetycFS). Files are decrypted
locally as they are read. A file being written is kept in a temporary file
(mode 0600, removed when the file is closed) and sent, encrypted, as a new
version when it is closed or fsync'ed.

  retyc fs mount retyc://<dataroom-id> <mountpoint>   the dataroom is the root
  retyc fs mount --all <mountpoint>                   one folder per dataroom

The swap and backup files of an editor (.name.swp, name~: see --local-file)
are kept on this machine for as long as the mount lasts and never sent: no
other client sees them, and they are gone once the filesystem is unmounted.

The mount is read-write; --read-only refuses every change. Linux only: it
needs /dev/fuse and, unless run as root, the fusermount3 helper (package fuse3).

The command stays in the foreground until the filesystem is unmounted: Ctrl-C,
SIGTERM, or "fusermount3 -u <mountpoint>" from another terminal. When it is
stopped, the files being sent have --drain-timeout to reach the API; a second
Ctrl-C does not wait for them.

--mirror-locks takes a lock at the API on a file for as long as it is open
for writing, so that other RETYC clients see it locked. --metrics-addr serves
Prometheus metrics and health probes (/metrics, /healthz, /readyz).

--background-delete makes the removal of a file answer at once: the file is
deleted at the API afterwards, a few at a time. Removing many files is much
faster, but a removal that succeeded no longer proves the API deleted the
file: one it refuses, or that is not sent before the mount stops, is reported
in the log and the file is listed again.

Every flag has a configuration key (mount.*) and an environment variable
(RETYC_MOUNT_*): see the configuration reference.

Key passphrase: set RETYC_KEY_PASSPHRASE (env var).

While it is mounted, "cat <mountpoint>/.retycfs/accesslog" shows the
operations as they happen (by inode number, never by name).

Example:
  mkdir -p ~/dr
  RETYC_KEY_PASSPHRASE=your-passphrase retyc fs mount retyc://<dataroom-id> ~/dr`,
	// Arguments are checked in RunE, where both forms are told apart.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		all, _ := cmd.Flags().GetBool("all")
		target, err := parseMountArgs(all, args)
		if err != nil {
			return err
		}

		return runMount(cmd, target)
	},
}

// mountFlags binds each flag of `fs mount` that has one to its configuration
// key. --all has none: it is an argument of the command, not a setting.
// --unsafe-write is the one that is not a mount.* setting: api.unsafe_write is
// what every command that uploads reads, `fs webdav serve` has the same flag.
var mountFlags = [][2]string{
	{"read-only", "mount.read_only"},
	{"entry-ttl", "mount.entry_ttl"},
	{"attr-ttl", "mount.attr_ttl"},
	{"kernel-cache", "mount.kernel_cache"},
	{"spool-dir", "mount.spool_dir"},
	{"allow-other", "mount.allow_other"},
	{"uid", "mount.uid"},
	{"gid", "mount.gid"},
	{"file-mode", "mount.file_mode"},
	{"dir-mode", "mount.dir_mode"},
	{"drain-timeout", "mount.drain_timeout"},
	{"mirror-locks", "mount.mirror_locks"},
	{"background-delete", "mount.background_delete"},
	{"local-file", "mount.local_files"},
	{"unsafe-write", "api.unsafe_write"},
	{"metrics-addr", "mount.metrics.addr"},
	{"metrics-runtime", "mount.metrics.runtime"},
	{"metrics-label", "mount.metrics.labels"},
}

// resolveMountFlags binds the flags of `fs mount` to their viper keys, so
// that config.Load reads them with the usual precedence (flag > env > config
// file > default) and validates them like any other source. From RunE, never
// from init(), like resolveCacheFlags.
func resolveMountFlags(flags *pflag.FlagSet) {
	resolveCacheFlags(flags)
	for _, f := range mountFlags {
		if flag := flags.Lookup(f[0]); flag != nil {
			_ = viper.BindPFlag(f[1], flag)
		}
	}
}

// mountSettings is the mount.* section as the mount takes it: validated by
// config.Load, the modes parsed, the owner and the spool directory resolved.
type mountSettings struct {
	entryTTL, attrTTL time.Duration
	kernelCache       bool
	spoolDir          string
	allowOther        bool
	// uid and gid are nil for the user and the group of the process.
	uid, gid          *uint32
	fileMode, dirMode os.FileMode
	readOnly          bool
	drainTimeout      time.Duration
	// mirrorLocks takes an API lock on a file while it is open for writing.
	mirrorLocks bool
	// backgroundDelete makes unlink answer before the API deleted the file.
	backgroundDelete bool
	// localFiles are the patterns of the names kept local, none when empty.
	localFiles []string
	// metrics is the observability listener, off while its address is empty.
	metrics metricsSettings
}

// newMountSettings reads the mount settings of cfg. The spool directory is
// made absolute, and checked: a file written through the mount is kept there
// until it is sent, so a directory that is missing or cannot be written to
// is refused before the mount is made rather than at the first write.
func newMountSettings(cfg *config.Config) (mountSettings, error) {
	m := cfg.Mount
	s := mountSettings{
		kernelCache:      m.KernelCache,
		allowOther:       m.AllowOther,
		readOnly:         m.ReadOnly,
		drainTimeout:     m.DrainTimeout,
		mirrorLocks:      m.MirrorLocks,
		backgroundDelete: m.BackgroundDelete,
		localFiles:       m.LocalFiles,
		metrics:          metricsSettings{addr: m.Metrics.Addr, runtime: m.Metrics.Runtime, labels: m.Metrics.Labels},
		uid:              mountID(m.UID),
		gid:              mountID(m.GID),
	}
	s.entryTTL, s.attrTTL = cfg.KernelTTLs()
	var err error
	if s.fileMode, err = config.ParseMountMode(m.FileMode); err != nil {
		return mountSettings{}, fmt.Errorf("mount.file_mode: %w", err)
	}
	if s.dirMode, err = config.ParseMountMode(m.DirMode); err != nil {
		return mountSettings{}, fmt.Errorf("mount.dir_mode: %w", err)
	}
	if s.spoolDir, err = checkSpoolDir(m.SpoolDir); err != nil {
		return mountSettings{}, err
	}

	return s, nil
}

// mountID turns mount.uid / mount.gid into the owner presented: nil, the
// process's own, for config.MountProcessID.
func mountID(id int64) *uint32 {
	if id < 0 || id > math.MaxUint32 {
		return nil
	}
	v := uint32(id)

	return &v
}

// checkSpoolDir returns the absolute path of the spool directory, the
// temporary directory of the system when dir is empty, after checking that a
// file can be created in it. A read-only mount has a spool directory too: it
// is checked all the same, the setting being wrong either way.
func checkSpoolDir(dir string) (string, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("spool directory %s: %w", dir, err)
	}
	info, err := os.Stat(abs)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("spool directory %s does not exist: create it, or set --spool-dir (mount.spool_dir)", abs)
	case err != nil:
		return "", fmt.Errorf("spool directory: %w", err)
	case !info.IsDir():
		return "", fmt.Errorf("spool directory %s is not a directory", abs)
	}
	probe, err := os.CreateTemp(abs, ".retyc-spool-check-*")
	if err != nil {
		return "", fmt.Errorf("spool directory %s is not writable: %w", abs, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())

	return abs, nil
}

// addMountFlags declares the flags of `fs mount` on cmd.
func addMountFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.Bool("all", false, "mount every dataroom, one folder each")
	flags.Bool("read-only", false, "mount read-only: every change is refused")
	addCacheFlags(cmd, false)
	flags.Duration("entry-ttl", 0, "how long the kernel keeps a name without asking again (0: --cache-ttl)")
	flags.Duration("attr-ttl", 0,
		"how long the kernel keeps the attributes of a file without asking again (0: --cache-ttl)")
	flags.Bool("kernel-cache", true, "let the kernel keep what it read of a file between two opens")
	flags.String("spool-dir", "",
		"directory holding the files being written until they are sent (default: the system's temporary directory)")
	flags.Bool("allow-other", false, "let the other users of the machine into the mount (-o allow_other)")
	flags.Int64("uid", config.MountProcessID,
		"user every file is presented as owned by (-1: the user running the command)")
	flags.Int64("gid", config.MountProcessID,
		"group every file is presented as owned by (-1: the group running the command)")
	flags.String("file-mode", config.DefaultMountFileMode, "permissions, in octal, of a file that has none stored")
	flags.String("dir-mode", config.DefaultMountDirMode, "permissions, in octal, of a folder that has none stored")
	flags.Duration("drain-timeout", config.DefaultMountDrainTimeout,
		"how long the files being sent are waited for when the mount is stopped (0: not at all)")
	flags.Bool("mirror-locks", false,
		"take an API lock on a file while it is open for writing (a file locked by another client: EBUSY)")
	flags.Bool("background-delete", false,
		"answer the removal of a file at once and delete it at the API in the background "+
			"(faster rm; a delete that fails is only logged, and the file comes back)")
	flags.StringArray("local-file", nil,
		"name pattern of the files kept on this machine and never sent, e.g. '*.tmp' (repeatable; "+
			"'"+config.MountLocalFilesNone+"' alone: no such file; default: "+
			strings.Join(config.DefaultMountLocalFiles(), " ")+")")
	flags.Bool("unsafe-write", false,
		"let the API acknowledge uploads before they are stored (faster; a failed background store is not reported)")
	flags.String("metrics-addr", "",
		"address for Prometheus metrics and health probes (e.g. 127.0.0.1:9090)")
	flags.Bool("metrics-runtime", true,
		"include Go runtime and process metrics on /metrics")
	flags.StringArray("metrics-label", nil,
		"constant label key=value added to every metric (repeatable)")
}

func init() {
	addMountFlags(fsMountCmd)
	fsCmd.AddCommand(fsMountCmd)
}
