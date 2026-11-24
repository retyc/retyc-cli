// Package diag is where the core packages (api, auth, service, telemetry,
// dav) write what they tell the operator rather than the caller: warnings,
// progress notes and the --debug trace of the API client. The CLI leaves it
// on stderr; a program that imports the core redirects it with SetOutput.
//
// It imports the standard library only.
package diag

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	mu  sync.RWMutex
	out *lockedWriter
)

// lockedWriter serializes the writes to a writer given to SetOutput: the core
// writes from many goroutines, and a writer such as a bytes.Buffer or a log
// file is not safe for concurrent use.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.w.Write(p)
}

// SetOutput sends the messages of the core to w from now on; nil restores
// the default, stderr. Use io.Discard to drop them. Writes to w are
// serialized: w need not be safe for concurrent use.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if w == nil {
		out = nil

		return
	}
	out = &lockedWriter{w: w}
}

// Writer returns the current output. The default is read from os.Stderr at
// each call, so that a test replacing os.Stderr still captures it.
func Writer() io.Writer {
	mu.RLock()
	defer mu.RUnlock()
	if out == nil {
		return os.Stderr
	}

	return out
}

// IsStderr reports whether the output is the process's stderr: the default,
// or os.Stderr given to SetOutput.
func IsStderr() bool {
	mu.RLock()
	defer mu.RUnlock()

	return out == nil || out.w == io.Writer(os.Stderr)
}

// Printf formats according to format and writes the result to Writer.
func Printf(format string, args ...any) {
	_, _ = fmt.Fprintf(Writer(), format, args...)
}
