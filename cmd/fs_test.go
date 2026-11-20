package cmd

import "testing"

// The WebDAV server lives under the fs group: `retyc fs webdav serve`. The
// former `retyc webdav` path was removed without an alias.
func TestCommandTree_WebdavUnderFS(t *testing.T) {
	found, rest, err := rootCmd.Find([]string{"fs", "webdav", "serve"})
	if err != nil {
		t.Fatalf("Find(fs webdav serve): %v", err)
	}
	if found != webdavServeCmd || len(rest) != 0 {
		t.Fatalf("fs webdav serve resolved to %q (rest %v)", found.CommandPath(), rest)
	}
	if got := webdavServeCmd.CommandPath(); got != "retyc fs webdav serve" {
		t.Errorf("command path = %q, want %q", got, "retyc fs webdav serve")
	}

	for _, c := range rootCmd.Commands() {
		if c.Name() == "webdav" || c.HasAlias("webdav") {
			t.Errorf("root still exposes %q as webdav", c.CommandPath())
		}
	}
	if found, _, err := rootCmd.Find([]string{"webdav", "serve"}); err == nil && found != rootCmd {
		t.Errorf("retyc webdav serve still resolves to %q", found.CommandPath())
	}
}

// cobra runs only the closest PersistentPreRun(E): one on the fs group or on
// webdav would mask the root hook (CA loading, tracing, concurrency).
func TestFSGroup_KeepsRootPreRun(t *testing.T) {
	for c := webdavServeCmd; c != rootCmd; c = c.Parent() {
		if c.PersistentPreRun != nil || c.PersistentPreRunE != nil {
			t.Errorf("%q defines a PersistentPreRun(E) that masks the root one", c.CommandPath())
		}
	}
}

// The dataroom commands are named after the user-facing "space"; "dataroom"
// stays an alias so that existing scripts keep working.
func TestSpaceCommandsKeepDataroomAlias(t *testing.T) {
	for _, path := range [][]string{
		{"space", "ls"},
		{"dataroom", "ls"},
		{"admin", "space", "ls"},
		{"admin", "dataroom", "ls"},
	} {
		found, _, err := rootCmd.Find(path)
		if err != nil || found.Name() != "ls" || found.Parent().Name() != "space" {
			t.Errorf("Find(%v) = %v, %v; want the ls of a space command", path, found.CommandPath(), err)
		}
	}
}
