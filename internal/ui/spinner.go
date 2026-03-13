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
//
// Start and Stop may be called multiple times in sequence.
// Stop is idempotent: calling it on an already-stopped spinner is a no-op.
type Spinner struct {
	mu      sync.Mutex
	label   string
	stop    chan struct{}
	done    chan struct{}
	running bool
}

// NewSpinner creates a Spinner with an optional label. Call Start to begin animating.
func NewSpinner(label ...string) *Spinner {
	s := &Spinner{}
	if len(label) > 0 {
		s.label = label[0]
	}

	return s
}

// Start begins animating the spinner in a background goroutine.
// If the spinner is already running it is a no-op.
// Start may be called again after Stop to resume animation.
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()

		return
	}
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.running = true
	stop := s.stop
	done := s.done
	s.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(75 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-stop:
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
// Calling Stop on an already-stopped spinner is a no-op.
// Start may be called again after Stop to resume animation.
func (s *Spinner) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()

		return
	}
	s.running = false
	stop := s.stop
	done := s.done
	s.mu.Unlock()

	close(stop)
	<-done
}
