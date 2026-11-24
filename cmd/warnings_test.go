package cmd

import (
	"bytes"
	"testing"

	"github.com/retyc/retyc-cli/core/diag"
)

// The warnings of a service result are printed as the core used to print
// them: one "warning: " line each, on diag (stderr).
func TestPrintWarnings(t *testing.T) {
	var buf bytes.Buffer
	diag.SetOutput(&buf)
	t.Cleanup(func() { diag.SetOutput(nil) })

	printWarnings(nil)
	printWarnings([]string{"first", "second"})
	if want := "warning: first\nwarning: second\n"; buf.String() != want {
		t.Errorf("output = %q, want %q", buf.String(), want)
	}
}
