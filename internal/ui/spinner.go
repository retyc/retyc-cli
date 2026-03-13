// Package ui provides terminal UI helpers for the retyc CLI.
package ui

import (
	"fmt"
	"os"
	"time"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	spinColor = "\033[36m" // cyan
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
		ticker := time.NewTicker(75 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Fprint(os.Stderr, clearLine+ansiReset)

				return
			case <-ticker.C:
				frame := frames[i%len(frames)]
				fmt.Fprintf(os.Stderr, "\r%s%s %s%s", spinColor, frame, s.label, ansiReset)
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
