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
	out io.Writer
)

// SetOutput sends the messages of the core to w from now on; nil restores
// the default, stderr. Use io.Discard to drop them.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
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

// Printf formats according to format and writes the result to Writer.
func Printf(format string, args ...any) {
	_, _ = fmt.Fprintf(Writer(), format, args...)
}
