package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/retyc/retyc-cli/internal/config"
)

func TestParseMountArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		all  bool
		args []string
		want mountTarget
		err  string
	}{
		{
			name: "one dataroom", args: []string{"retyc://dr-1", "/mnt/dr"},
			want: mountTarget{dataroomID: "dr-1", mountpoint: "/mnt/dr"},
		},
		{
			name: "trailing slash", args: []string{"retyc://dr-1/", "mnt"},
			want: mountTarget{dataroomID: "dr-1", mountpoint: "mnt"},
		},
		{name: "all", all: true, args: []string{"/mnt/all"}, want: mountTarget{all: true, mountpoint: "/mnt/all"}},
		{name: "no argument", err: "expected a dataroom and a mount point"},
		{name: "mount point only", args: []string{"/mnt/dr"}, err: "expected a dataroom and a mount point"},
		{name: "three arguments", args: []string{"retyc://dr-1", "/mnt", "x"}, err: "expected a dataroom and a mount point"},
		{name: "not a URI", args: []string{"dr-1", "/mnt/dr"}, err: "not a retyc URI"},
		{name: "no dataroom", args: []string{"retyc://", "/mnt/dr"}, err: "missing dataroom ID"},
		{name: "a folder", args: []string{"retyc://dr-1/docs", "/mnt/dr"}, err: "only a whole dataroom"},
		{name: "all without mount point", all: true, err: "one argument"},
		{name: "all with a dataroom", all: true, args: []string{"retyc://dr-1", "/mnt"}, err: "one argument"},
		{name: "all with a URI", all: true, args: []string{"retyc://dr-1"}, err: "mount point only"},
	} {
		got, err := parseMountArgs(tc.all, tc.args)
		switch {
		case tc.err == "" && (err != nil || got != tc.want):
			t.Errorf("%s: %+v, %v; want %+v", tc.name, got, err, tc.want)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: error %v, want one holding %q", tc.name, err, tc.err)
		}
	}
}

// `retyc fs mount` hangs from the fs group, and nothing between it and the
// root defines a PersistentPreRun(E): cobra runs only the closest one, which
// would mask the root hook (CA loading, tracing, concurrency).
func TestCommandTree_MountUnderFS(t *testing.T) {
	found, rest, err := rootCmd.Find([]string{"fs", "mount"})
	if err != nil || found != fsMountCmd || len(rest) != 0 {
		t.Fatalf("fs mount resolved to %v (rest %v, err %v)", found, rest, err)
	}
	if got := fsMountCmd.CommandPath(); got != "retyc fs mount" {
		t.Errorf("command path = %q", got)
	}
	for c := fsMountCmd; c != rootCmd; c = c.Parent() {
		if c.PersistentPreRun != nil || c.PersistentPreRunE != nil {
			t.Errorf("%q defines a PersistentPreRun(E) that masks the root one", c.CommandPath())
		}
	}
	// A filesystem served for days gets no command span.
	if fsMountCmd.Annotations[annotationLongRunning] != "true" {
		t.Error("fs mount is not annotated long-running")
	}
	// What is mounted, the two cache durations that apply to a mount (it
	// never serves an expired listing, so it has no --cache-max-stale), where
	// the cache is kept, and one flag per mount.* key.
	want := []string{
		"all", "cache-ttl", "cache-negative-ttl",
		"cache-store", "cache-redis-url", "cache-redis-high-confidentiality",
	}
	for _, f := range mountFlags {
		want = append(want, f[0])
	}
	flags := 0
	fsMountCmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "help" {
			flags++
		}
	})
	for _, name := range want {
		if fsMountCmd.Flags().Lookup(name) == nil {
			t.Errorf("fs mount has no --%s", name)
		}
	}
	if flags != len(want) || fsMountCmd.Flags().Lookup("cache-max-stale") != nil {
		t.Errorf("fs mount has %d flags, want %v", flags, want)
	}
	// Not a setting yet.
	for _, name := range []string{"open-cache"} {
		if fsMountCmd.Flags().Lookup(name) != nil {
			t.Errorf("fs mount has a --%s", name)
		}
	}
}

// Every mount.* key has its flag, and the reverse: a key without a flag, or a
// flag bound to a key that does not exist, fails here.
func TestMountFlags_OnePerKey(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	bound := make(map[string]bool)
	for _, f := range mountFlags {
		bound[f[1]] = true
		if !viper.IsSet(f[1]) {
			t.Errorf("--%s is bound to %s, which has no default", f[0], f[1])
		}
	}
	for _, key := range viper.AllKeys() {
		if strings.HasPrefix(key, "mount.") && !bound[key] {
			t.Errorf("%s has no flag", key)
		}
	}
}

func TestResolveMountFlags(t *testing.T) {
	spool := t.TempDir()
	uid := func(v uint32) *uint32 { return &v }
	cases := map[string]struct {
		env, flags map[string]string
		want       mountSettings
		wantErr    string
	}{
		"defaults": {
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute,
			},
		},
		"the kernel timeouts follow cache.ttl": {
			flags: map[string]string{"cache-ttl": "10s", "attr-ttl": "2s"},
			want: mountSettings{
				entryTTL: 10 * time.Second, attrTTL: 2 * time.Second, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute,
			},
		},
		"env without flags": {
			env: map[string]string{
				"RETYC_MOUNT_ENTRY_TTL": "5s", "RETYC_MOUNT_KERNEL_CACHE": "false", "RETYC_MOUNT_SPOOL_DIR": spool,
				"RETYC_MOUNT_ALLOW_OTHER": "true", "RETYC_MOUNT_UID": "0", "RETYC_MOUNT_GID": "100",
				"RETYC_MOUNT_FILE_MODE": "0600", "RETYC_MOUNT_DIR_MODE": "700", "RETYC_MOUNT_READ_ONLY": "true",
				"RETYC_MOUNT_DRAIN_TIMEOUT": "0",
			},
			want: mountSettings{
				entryTTL: 5 * time.Second, attrTTL: time.Minute, spoolDir: spool, allowOther: true,
				uid: uid(0), gid: uid(100), fileMode: 0o600, dirMode: 0o700, readOnly: true,
			},
		},
		"flags override env": {
			env: map[string]string{
				"RETYC_MOUNT_UID": "1", "RETYC_MOUNT_FILE_MODE": "0600", "RETYC_MOUNT_DRAIN_TIMEOUT": "5s",
				"RETYC_MOUNT_KERNEL_CACHE": "false",
			},
			flags: map[string]string{
				"uid": "4242", "gid": "4343", "file-mode": "0640", "dir-mode": "0750", "drain-timeout": "1m",
				"kernel-cache": "true", "entry-ttl": "3s", "attr-ttl": "4s", "spool-dir": spool,
				"allow-other": "true", "read-only": "true", "mirror-locks": "true",
				"metrics-addr": "127.0.0.1:9191", "metrics-runtime": "false",
			},
			want: mountSettings{
				entryTTL: 3 * time.Second, attrTTL: 4 * time.Second, kernelCache: true, spoolDir: spool,
				allowOther: true, uid: uid(4242), gid: uid(4343), fileMode: 0o640, dirMode: 0o750, readOnly: true,
				drainTimeout: time.Minute, mirrorLocks: true,
				metrics: metricsSettings{addr: "127.0.0.1:9191", labels: []string{}},
			},
		},
		"the metrics listener from the environment": {
			env: map[string]string{
				"RETYC_MOUNT_METRICS_ADDR": "127.0.0.1:9192", "RETYC_MOUNT_METRICS_LABELS": "pod=a volume=b",
				"RETYC_MOUNT_MIRROR_LOCKS": "true",
			},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute, mirrorLocks: true,
				metrics: metricsSettings{addr: "127.0.0.1:9192", runtime: true, labels: []string{"pod=a", "volume=b"}},
			},
		},
		"background delete from the environment": {
			env: map[string]string{"RETYC_MOUNT_BACKGROUND_DELETE": "true"},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute, backgroundDelete: true,
			},
		},
		"background delete: the flag overrides the environment": {
			env:   map[string]string{"RETYC_MOUNT_BACKGROUND_DELETE": "true"},
			flags: map[string]string{"background-delete": "false"},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute,
			},
		},
		"background delete from the flag": {
			flags: map[string]string{"background-delete": "true"},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute, backgroundDelete: true,
			},
		},
		"local files from the environment": {
			env: map[string]string{"RETYC_MOUNT_LOCAL_FILES": "*.tmp .*.swp"},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute,
				localFiles: []string{"*.tmp", ".*.swp"},
			},
		},
		"no local file, from the environment": {
			env: map[string]string{"RETYC_MOUNT_LOCAL_FILES": "none"},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute,
				localFiles: []string{},
			},
		},
		"no local file, from the flag over the environment": {
			env:   map[string]string{"RETYC_MOUNT_LOCAL_FILES": "*.tmp"},
			flags: map[string]string{"local-file": "none"},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute,
				localFiles: []string{},
			},
		},
		"no local file, from an empty flag": {
			flags: map[string]string{"local-file": ""},
			want: mountSettings{
				entryTTL: time.Minute, attrTTL: time.Minute, kernelCache: true, spoolDir: os.TempDir(),
				fileMode: 0o644, dirMode: 0o755, drainTimeout: 5 * time.Minute,
				localFiles: []string{},
			},
		},
		"a local file pattern that is malformed": {
			flags: map[string]string{"local-file": "[a-"}, wantErr: "mount.local_files",
		},
		"a mode that is not octal": {flags: map[string]string{"file-mode": "rw-r--r--"}, wantErr: "mount.file_mode"},
		"a mode with setuid":       {flags: map[string]string{"dir-mode": "4755"}, wantErr: "mount.dir_mode"},
		"an owner below -1":        {flags: map[string]string{"uid": "-2"}, wantErr: "mount.uid"},
		"a group past 32 bits":     {env: map[string]string{"RETYC_MOUNT_GID": "4294967296"}, wantErr: "mount.gid"},
		"a drain without a unit": {
			env: map[string]string{"RETYC_MOUNT_DRAIN_TIMEOUT": "30"}, wantErr: "mount.drain_timeout",
		},
		"a kernel timeout without a unit": {
			env: map[string]string{"RETYC_MOUNT_ATTR_TTL": "60"}, wantErr: "mount.attr_ttl",
		},
		"a spool directory that is missing": {
			flags: map[string]string{"spool-dir": filepath.Join(spool, "missing")}, wantErr: "does not exist",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			isolateConfig(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			config.SetDefaults()
			cmd := &cobra.Command{Use: "mount"}
			addMountFlags(cmd)
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			resolveMountFlags(cmd.Flags())
			var got mountSettings
			cfg, err := config.Load()
			if err == nil {
				got, err = newMountSettings(cfg)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want one naming %q", err, tc.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.want.metrics.labels == nil {
				// The cases that say nothing of the listener: off, with the
				// runtime collectors it would carry.
				tc.want.metrics = metricsSettings{runtime: true, labels: []string{}}
			}
			if tc.want.localFiles == nil {
				// The cases that say nothing of the local files: the default.
				tc.want.localFiles = config.DefaultMountLocalFiles()
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("settings = %s, want %s", describeSettings(got), describeSettings(tc.want))
			}
		})
	}
}

// describeSettings prints mount settings with the owner dereferenced.
func describeSettings(s mountSettings) string {
	id := func(p *uint32) string {
		if p == nil {
			return "process"
		}

		return strconv.FormatUint(uint64(*p), 10)
	}
	owner := id(s.uid) + ":" + id(s.gid)
	s.uid, s.gid = nil, nil

	return fmt.Sprintf("%+v owner %s", s, owner)
}

// The spool directory is where a file being written lives until it is sent:
// one that cannot hold a file is refused before the mount is made.
func TestCheckSpoolDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := checkSpoolDir(dir); err != nil || got != dir {
		t.Errorf("checkSpoolDir(dir) = %q, %v", got, err)
	}
	if got, err := checkSpoolDir(""); err != nil || got != os.TempDir() {
		t.Errorf("checkSpoolDir(\"\") = %q, %v, want the temporary directory", got, err)
	}
	// Nothing is left behind by the check.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the check left %d entries in the directory", len(entries))
	}
	for path, want := range map[string]string{
		filepath.Join(dir, "missing"): "does not exist",
		file:                          "not a directory",
	} {
		if _, err := checkSpoolDir(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("checkSpoolDir(%s) = %v, want an error holding %q", filepath.Base(path), err, want)
		}
	}
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(locked, 0o500); err != nil {
			t.Fatal(err)
		}
		if _, err := checkSpoolDir(locked); err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Errorf("checkSpoolDir(read-only directory) = %v, want it refused", err)
		}
	}
}

// --unsafe-write lands in api.unsafe_write, the key the API client of the mount
// is built from, with the usual precedence over the environment.
func TestMountFlags_UnsafeWrite(t *testing.T) {
	cases := map[string]struct {
		env, flag string
		want      bool
	}{
		"default":            {want: false},
		"flag":               {flag: "true", want: true},
		"env":                {env: "true", want: true},
		"flag over the env":  {env: "true", flag: "false", want: false},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			isolateConfig(t)
			if tc.env != "" {
				t.Setenv("RETYC_API_UNSAFE_WRITE", tc.env)
			}
			config.SetDefaults()
			cmd := &cobra.Command{Use: "mount"}
			addMountFlags(cmd)
			if tc.flag != "" {
				if err := cmd.Flags().Set("unsafe-write", tc.flag); err != nil {
					t.Fatal(err)
				}
			}
			resolveMountFlags(cmd.Flags())
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.API.UnsafeWrite != tc.want {
				t.Errorf("API.UnsafeWrite = %v, want %v", cfg.API.UnsafeWrite, tc.want)
			}
		})
	}
}

// --local-file is repeatable, and replaces the list of the other sources.
func TestMountSettings_LocalFileFlagRepeats(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_MOUNT_LOCAL_FILES", "*.env")
	config.SetDefaults()
	cmd := &cobra.Command{Use: "mount"}
	addMountFlags(cmd)
	for _, pattern := range []string{"*.tmp", "[a-c]*~"} {
		if err := cmd.Flags().Set("local-file", pattern); err != nil {
			t.Fatal(err)
		}
	}
	resolveMountFlags(cmd.Flags())
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	settings, err := newMountSettings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"*.tmp", "[a-c]*~"}; !reflect.DeepEqual(settings.localFiles, want) {
		t.Errorf("localFiles = %q, want %q", settings.localFiles, want)
	}
}
