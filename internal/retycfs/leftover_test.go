//go:build linux

package retycfs

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The test binary serves its own mounts. If it exits while one of them still
// has a request in flight (Ctrl-C, the timeout of go test, a test that left
// its mount behind), the thread that made the request waits in the kernel
// for an answer only the exiting process could give: it stays in state D,
// unkillable, and go test hangs on it. Aborting the FUSE connection fails
// those requests, so the process can exit. The abort file of a connection
// belongs to the user who mounted it: no root needed.

// testMounts holds the mount points mountFS made, the only ones swept.
var testMounts sync.Map

func registerTestMount(dir string) { testMounts.Store(dir, struct{}{}) }

// sweepTestMounts aborts the FUSE connection of every test mount still
// attached, then detaches its mount point. It returns the mount points swept.
func sweepTestMounts() []string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var swept []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "36 35 0:98 / /mnt rw - fuse.retycfs …": device third, mount point fifth.
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		dir := unescapeMount(fields[4])
		if _, ok := testMounts.Load(dir); !ok {
			continue
		}
		// A FUSE connection is named by the minor of its device (major 0).
		if _, minor, ok := strings.Cut(fields[2], ":"); ok {
			_ = os.WriteFile("/sys/fs/fuse/connections/"+minor+"/abort", []byte("1"), 0)
		}
		_ = detach(dir)
		swept = append(swept, dir)
	}

	return swept
}

// guardTestMounts sweeps the test mounts when the binary is interrupted or
// about to reach the timeout of go test, with the stacks of every goroutine
// first: they show what the test was waiting for.
func guardTestMounts() {
	abort := func(why string) {
		buf := make([]byte, 1<<20)
		buf = buf[:runtime.Stack(buf, true)]
		fmt.Fprintf(os.Stderr, "retycfs tests: %s, aborting the test mounts\n%s\n", why, buf)
		for _, dir := range sweepTestMounts() {
			fmt.Fprintf(os.Stderr, "retycfs tests: aborted %s\n", dir)
		}
		os.Exit(2)
	}

	sigs := make(chan os.Signal, 1)
	// SIGQUIT is what go test sends a binary that outlives its timeout.
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() { abort(fmt.Sprintf("%v received", <-sigs)) }()

	// Before the panic of -test.timeout, which would exit with the requests
	// in flight.
	if f := flag.Lookup("test.timeout"); f != nil {
		if timeout, ok := f.Value.(flag.Getter).Get().(time.Duration); ok && timeout > 0 {
			margin := min(timeout/10, 15*time.Second)
			time.AfterFunc(timeout-margin, func() {
				abort(fmt.Sprintf("test timeout (%s) in %s", timeout, margin))
			})
		}
	}
}
