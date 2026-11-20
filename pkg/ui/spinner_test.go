package ui

import "testing"

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
