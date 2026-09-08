// Package trace provides opt-in timing instrumentation for performance
// diagnostics. It is enabled by setting RETYC_TRACE to a non-empty value and
// writes one line per traced operation to stderr.
//
// Log and Span return immediately when tracing is off, but their variadic
// arguments are boxed into an []any at the call site before that, costing
// ~28ns and two allocations whether or not tracing is on. Call sites therefore
// guard themselves with Enabled(), which compiles down to a single flag test
// and keeps the disabled path genuinely free.
package trace

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	enabled = os.Getenv("RETYC_TRACE") != ""
	start   = time.Now()
	mu      sync.Mutex
)

// Enabled reports whether timing instrumentation is active.
func Enabled() bool { return enabled }

// Log writes a single trace line, prefixed with the time elapsed since process start.
func Log(format string, args ...any) {
	if !enabled {
		return
	}
	msg := fmt.Sprintf(format, args...)
	now := time.Now()
	mu.Lock()
	// Absolute wall-clock timestamp so server-side spans can be correlated
	// line-by-line with a client-side strace capture.
	fmt.Fprintf(os.Stderr, "trace %s (%7.3fs) %s\n",
		now.Format("15:04:05.000000"), now.Sub(start).Seconds(), msg)
	mu.Unlock()
}

// Span returns a function that logs the elapsed time under label when called,
// typically via defer. It is a no-op when tracing is disabled.
func Span(format string, args ...any) func() {
	if !enabled {
		return func() {}
	}
	label := fmt.Sprintf(format, args...)
	began := time.Now()

	return func() {
		Log("%-58s %8.1fms", label, float64(time.Since(began).Microseconds())/1000)
	}
}
