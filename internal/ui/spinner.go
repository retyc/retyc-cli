// Package ui provides terminal UI helpers for the retyc CLI.
package ui

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	spinColor = "\033[36m" // cyan
	ansiReset = "\033[0m"
	clearLine = "\r\033[K"
)

// Spinner displays an animated dot indicator on stderr while a blocking
// operation is running. If a label is provided, it is shown to the right of
// the rotating frame; otherwise only the frame is displayed.
type Spinner struct {
	mu    sync.Mutex
	label string
	stop  chan struct{}
	done  chan struct{}
}

// NewSpinner creates a Spinner with an optional label. Call Start to begin animating.
func NewSpinner(label ...string) *Spinner {
	s := &Spinner{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if len(label) > 0 {
		s.label = label[0]
	}

	return s
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
				s.mu.Lock()
				label := s.label
				s.mu.Unlock()
				if label != "" {
					fmt.Fprintf(os.Stderr, "\r%s%s %s%s", spinColor, frame, label, ansiReset)
				} else {
					fmt.Fprintf(os.Stderr, "\r%s%s%s", spinColor, frame, ansiReset)
				}
				i++
			}
		}
	}()
}

// SetLabel updates the label shown next to the spinning frame.
// Safe to call while the spinner is running.
func (s *Spinner) SetLabel(label string) {
	s.mu.Lock()
	s.label = label
	s.mu.Unlock()
}

// Stop halts the spinner and erases the spinner line from the terminal.
// It blocks until the background goroutine has exited.
func (s *Spinner) Stop() {
	close(s.stop)
	<-s.done
}
