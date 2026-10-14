package cmd

import (
	"testing"

	"github.com/spf13/pflag"
)

func newDataroomOptionFlags(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addDataroomOptionFlags(flags)
	if err := flags.Parse(args); err != nil {
		t.Fatalf("Parse(%v) error = %v", args, err)
	}

	return flags
}

func TestDataroomOptionsFromFlags_OnlySetFlags(t *testing.T) {
	opts, err := dataroomOptionsFromFlags(newDataroomOptionFlags(t))
	if err != nil {
		t.Fatal(err)
	}
	if opts.VersioningEnabled != nil || opts.StorageCapacity != nil {
		t.Errorf("opts = %+v, want nothing set", opts)
	}
}

func TestDataroomOptionsFromFlags(t *testing.T) {
	opts, err := dataroomOptionsFromFlags(newDataroomOptionFlags(t, "--versioning=false", "--storage-capacity", "2G"))
	if err != nil {
		t.Fatal(err)
	}
	if opts.VersioningEnabled == nil || *opts.VersioningEnabled {
		t.Errorf("VersioningEnabled = %v, want false", opts.VersioningEnabled)
	}
	if opts.StorageCapacity == nil || *opts.StorageCapacity != 2<<30 {
		t.Errorf("StorageCapacity = %v, want %d", opts.StorageCapacity, 2<<30)
	}
}

func TestDataroomOptionsFromFlags_BadSize(t *testing.T) {
	if _, err := dataroomOptionsFromFlags(newDataroomOptionFlags(t, "--storage-capacity", "2GB")); err == nil {
		t.Error("want an error for a decimal unit")
	}
}

func TestDataroomIDArg(t *testing.T) {
	for in, want := range map[string]string{"dr-1": "dr-1", "retyc://dr-1": "dr-1", "retyc://dr-1/": "dr-1"} {
		got, err := dataroomIDArg(in)
		if err != nil || got != want {
			t.Errorf("dataroomIDArg(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"retyc://dr-1/folder", "retyc://"} {
		if _, err := dataroomIDArg(in); err == nil {
			t.Errorf("dataroomIDArg(%q) want an error", in)
		}
	}
}
