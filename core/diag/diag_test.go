package diag

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestSetOutputConcurrentWrites writes to a bytes.Buffer from many goroutines,
// as the core does; run with -race.
func TestSetOutputConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	t.Cleanup(func() { SetOutput(nil) })

	const writers, lines = 16, 100
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range lines {
				Printf("line\n")
				_, _ = Writer().Write([]byte("raw\n"))
			}
		})
	}
	wg.Wait()

	if got, want := strings.Count(buf.String(), "line\n"), writers*lines; got != want {
		t.Errorf("Printf lines = %d, want %d", got, want)
	}
	if got, want := strings.Count(buf.String(), "raw\n"), writers*lines; got != want {
		t.Errorf("Write lines = %d, want %d", got, want)
	}
}

func TestIsStderr(t *testing.T) {
	t.Cleanup(func() { SetOutput(nil) })

	SetOutput(nil)
	if !IsStderr() {
		t.Error("default output: IsStderr() = false")
	}
	SetOutput(os.Stderr)
	if !IsStderr() {
		t.Error("SetOutput(os.Stderr): IsStderr() = false")
	}
	SetOutput(&bytes.Buffer{})
	if IsStderr() {
		t.Error("SetOutput(buffer): IsStderr() = true")
	}
}
