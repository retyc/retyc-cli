// Package ui provides terminal UI helpers for the retyc CLI.
package ui

import (
	"fmt"
	"os"
	"time"
)

// frames uses Unicode dot marks (U+22C5, U+2058, U+2059, U+205A, U+205B) that
// create a visual dot-pulse effect — single dot expands to five then contracts back.
var frames = []string{"⁘", "⁙", "⁛", "⁙", "⁘"}

// spinColors cycles through ANSI foreground color codes for each frame.
var spinColors = []string{
	"\033[96m", // bright cyan
	"\033[34m", // blue
	"\033[35m", // magenta
	"\033[33m", // yellow
	"\033[32m", // green
	"\033[36m", // cyan
}

const (
	ansiReset = "\033[0m"
	clearLine = "\r\033[K"
)

// Spinner displays an animated dot indicator on stderr while a blocking
// operation is running. The label is shown to the right of the rotating frame.
type Spinner struct {
	label string
	stop  chan struct{}
	done  chan struct{}
}

// New creates a Spinner with the given label. Call Start to begin animating.
func New(label string) *Spinner {
	return &Spinner{
		label: label,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
}

// Start begins animating the spinner in a background goroutine.
// Call Stop to halt the animation and clear the line.
func (s *Spinner) Start() {
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Fprint(os.Stderr, clearLine+ansiReset)
				return
			case <-ticker.C:
				color := spinColors[i%len(spinColors)]
				frame := frames[i%len(frames)]
				fmt.Fprintf(os.Stderr, "\r%s%s %s %s", color, frame, s.label, ansiReset)
				i++
			}
		}
	}()
}

// Stop halts the spinner and erases the spinner line from the terminal.
// It blocks until the background goroutine has exited.
func (s *Spinner) Stop() {
	close(s.stop)
	<-s.done
}
