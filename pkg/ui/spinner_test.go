package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/pkg/diag"
)

// A spinner whose stderr is not a terminal draws nothing: no goroutine, no
// escape sequence left before an error object a script reads.
func TestSpinner_SilentWithoutTerminal(t *testing.T) {
	orig := stderrIsTerminal
	stderrIsTerminal = func() bool { return false }
	defer func() { stderrIsTerminal = orig }()

	s := NewSpinner("working")
	s.Start()
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if running {
		t.Fatal("the spinner started without a terminal")
	}
	s.Stop()
}

// The frames go to the diag output captured by Start, never to os.Stderr.
func TestSpinner_WritesToDiag(t *testing.T) {
	orig := stderrIsTerminal
	stderrIsTerminal = func() bool { return true }
	defer func() { stderrIsTerminal = orig }()
	var buf bytes.Buffer
	diag.SetOutput(&buf)
	t.Cleanup(func() { diag.SetOutput(nil) })

	s := NewSpinner("working")
	s.Start()
	s.Stop()
	// Stop waited for the goroutine, whose last write clears the line.
	if got := buf.String(); !strings.HasSuffix(got, clearLine+ansiReset) {
		t.Errorf("diag output = %q, want the line cleared", got)
	}
}
