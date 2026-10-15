//go:build linux

package retycfs

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// The kernel sends an INTERRUPT for a request as soon as the thread that
// waits for it receives a signal, whatever the signal: the SIGURG the Go
// runtime preempts its goroutines with, SIGCHLD, SIGALRM, SIGPROF, a handled
// SIGUSR1. go-fuse then ends the context of the request. Answering EINTR to
// those would fail the close(2) of any program that receives signals, and its
// reads with EIO (the page cache does not restart an interrupted read).
//
// The driver therefore honours an interruption only when the caller is being
// killed, and lets every other one go to its end, like libfuse does unless
// asked otherwise. The handlers never give vfs the context go-fuse ends: they
// give the one driver.guard derives from it.

// interruptProbeInterval is how often the caller of an interrupted request is
// looked at again while the request lasts: an interruption the driver ignored
// (a harmless signal) may be followed by a kill, for which the kernel sends
// nothing more.
const interruptProbeInterval = 100 * time.Millisecond

// sigKillPending is the bit of SIGKILL (signal 9) in the SigPnd and ShdPnd
// masks of /proc/<pid>/status.
const sigKillPending = 1 << (uint(syscall.SIGKILL) - 1)

// errProcUnusable is what the default reader of /proc answers when /proc
// cannot tell anything of the caller.
var errProcUnusable = errors.New("/proc does not describe the callers of the mount")

// procStatusReader reads /proc/<pid>/status. pid is what the kernel gave as
// the caller of a request: a thread ID.
type procStatusReader func(pid uint32) ([]byte, error)

// procUsable reports, once, whether /proc is the one of this process's PID
// namespace: /proc/self then names this process. The PIDs the kernel gives
// are those of the namespace the filesystem was mounted from; a /proc of
// another namespace would describe other processes under the same numbers.
var procUsable = sync.OnceValue(func() bool {
	self, err := os.Readlink("/proc/self")

	return err == nil && self == strconv.Itoa(os.Getpid())
})

// procShowsAll reports, once, whether /proc shows the processes this one has
// no right over, which is what makes a missing /proc/<pid> mean "no such
// process" (see procStatusIn).
//
// procUsable cannot tell: a process always sees itself. What tells is a
// process of another user being listed: mounted with hidepid=2 (or
// "invisible", "ptraceable"), /proc lists to an unprivileged reader the
// processes it may ptrace only, never those of another user. When none is
// listed (hidden, or there is none: a container whose processes all run as
// this user) nothing is known, and a missing entry proves nothing.
var procShowsAll = sync.OnceValue(func() bool {
	return procListsOthers("/proc", uint32(os.Geteuid())) //nolint:gosec // G115: IDs are 32 bits on Linux
})

// procListsOthers reports whether root, a /proc, lists a process that does
// not belong to the user euid.
func procListsOthers(root string, euid uint32) bool {
	dir, err := os.Open(root) //nolint:gosec // G304: /proc
	if err != nil {
		return false
	}
	defer func() { _ = dir.Close() }()
	for {
		entries, err := dir.ReadDir(64)
		for _, entry := range entries {
			if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if owner, ok := info.Sys().(*syscall.Stat_t); ok && owner.Uid != euid {
				return true
			}
		}
		if err != nil {
			return false
		}
	}
}

// readProcStatus is the procStatusReader of a mount.
func readProcStatus(pid uint32) ([]byte, error) {
	if !procUsable() {
		return nil, errProcUnusable
	}

	return procStatusIn("/proc", pid, procShowsAll)
}

// procStatusIn reads the status of pid in root, a /proc. A missing entry is
// reported as such only when showsAll says this /proc hides no process:
// under hidepid=2 the entry of a process this one may not ptrace (another
// user's, when the mount is shared with allow_other; a non-dumpable one)
// answers ENOENT while the process is alive and well, and taking it for gone
// would cancel its operations at the first harmless signal. Hidden or gone,
// such a caller is one the driver cannot see: errProcUnusable.
func procStatusIn(root string, pid uint32, showsAll func() bool) ([]byte, error) {
	// /proc/<tid> exists for every thread, although only the thread group
	// leaders are listed in /proc.
	status, err := os.ReadFile(root + "/" + strconv.FormatUint(uint64(pid), 10) + "/status") //nolint:gosec // G304: /proc
	if errors.Is(err, fs.ErrNotExist) && !showsAll() {
		return nil, errProcUnusable
	}

	return status, err
}

// callerDying reports whether the caller of a request is being killed, which
// is when its interruption is honoured.
//
// A process that dies of a signal (SIGKILL, or any signal whose action is to
// terminate: SIGTERM, the SIGINT of Ctrl-C without a handler...) has SIGKILL
// made pending on every one of its threads by the kernel (group exit), and it
// stays pending on a thread blocked in a FUSE request. So do the threads of a
// process one of whose threads called exit_group or execve.
//
//   - a caller that no longer exists is dying, when /proc can be trusted to
//     say so (procStatusIn);
//   - a caller the driver cannot see is not: PID 0 (the kernel gives it for a
//     process of another PID namespace), a /proc that is missing, unreadable
//     or of another namespace, or one that hides processes (hidepid) and
//     has no entry for the caller. Its interruptions are all ignored, so such a
//     process, once killed, only goes when the operation ends (bounded by
//     api.retry.max_wait for a request the API holds back) or the filesystem
//     is unmounted.
func callerDying(pid uint32, read procStatusReader) bool {
	if pid == 0 {
		return false
	}
	status, err := read(pid)
	if err != nil {
		// ESRCH is what reading the file of a task that exited meanwhile
		// answers.
		return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
	}

	return killPending(status)
}

// killPending reports whether SIGKILL is pending in a /proc/<pid>/status:
// for the thread (SigPnd) or for its process (ShdPnd).
func killPending(status []byte) bool {
	for line := range bytes.Lines(status) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || (string(name) != "SigPnd" && string(name) != "ShdPnd") {
			continue
		}
		mask, err := strconv.ParseUint(string(bytes.TrimSpace(value)), 16, 64)
		if err == nil && mask&sigKillPending != 0 {
			return true
		}
	}

	return false
}

// opContext is the context a handler works with: the values of the request's
// (the caller, and through startSpan the trace), and an end that comes only
//
//   - when the request is interrupted and its caller is being killed
//     (callerDying), looked at when the interruption arrives and then every
//     interruptProbeInterval for as long as the operation lasts;
//   - when the drain of a shutdown is over (driver.stopped).
//
// Nothing watches the request until something waits on the context (Done):
// an operation answered from memory starts no goroutine, one that reaches the
// API starts one, which ends with the operation (release).
type opContext struct {
	// Context is the request's, as go-fuse gives it. Done and Err are
	// overridden; a deadline it has none.
	context.Context

	drv *driver

	mu sync.Mutex
	// done is what Done returns, made at its first call; ended stops the
	// goroutine that watches the request.
	done     chan struct{}
	ended    chan struct{}
	released bool
	err      error
}

// guard returns the context a handler passes on in place of ctx, the one of
// its request, and what releases it when the handler returns. The context
// never ends once released.
func (d *driver) guard(ctx context.Context) (context.Context, func()) {
	c := &opContext{Context: ctx, drv: d}

	return c, c.release
}

// guard is driver.guard for a handler that has a call: its end releases the
// context.
func (c *call) guard(ctx context.Context) context.Context {
	ctx, c.release = c.drv.guard(ctx)

	return ctx
}

// Deadline reports none: an operation lasts as long as the API takes.
func (c *opContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done starts watching the request at its first call.
func (c *opContext) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done == nil {
		c.done = make(chan struct{})
		if !c.released {
			c.ended = make(chan struct{})
			go c.watch(c.ended)
		}
	}

	return c.done
}

// Err reports context.Canceled once the context has ended. An interruption
// nothing was waiting for is looked at from here.
func (c *opContext) Err() error {
	if c.Context.Err() != nil || c.drv.stopped.Err() != nil {
		c.Done()
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.err
}

// release ends the watch: the handler returned.
func (c *opContext) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return
	}
	c.released = true
	if c.ended != nil {
		close(c.ended)
	}
}

// cancel ends the context.
func (c *opContext) cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = context.Canceled
		close(c.done)
	}
}

// watch ends the context when the operation must stop (see opContext), and
// returns when the handler does.
func (c *opContext) watch(ended <-chan struct{}) {
	stopped := c.drv.stopped.Done()
	select {
	case <-c.Context.Done():
	case <-stopped:
		c.cancel()

		return
	case <-ended:
		return
	}

	// Interrupted. The kernel sends one INTERRUPT per request, for the first
	// signal: a kill that follows a harmless signal is only seen by looking
	// again.
	var pid uint32
	if caller, ok := fuse.FromContext(c.Context); ok {
		pid = caller.Pid
	}
	tick := time.NewTicker(interruptProbeInterval)
	defer tick.Stop()
	for {
		if callerDying(pid, c.drv.procStatus) {
			c.cancel()

			return
		}
		select {
		case <-tick.C:
		case <-stopped:
			c.cancel()

			return
		case <-ended:
			return
		}
	}
}
