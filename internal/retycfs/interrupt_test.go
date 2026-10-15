//go:build linux

package retycfs

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// helperReadEnv names, for the test binary started as a helper, the file it
// reads: a process of its own, with a handler for SIGUSR1, to interrupt and
// to kill.
const helperReadEnv = "RETYCFS_TEST_HELPER_READ"

// TestMain runs the tests, or the helper of TestInterrupt_KilledReader.
func TestMain(m *testing.M) {
	if path := os.Getenv(helperReadEnv); path != "" {
		handled := make(chan os.Signal, 16)
		signal.Notify(handled, syscall.SIGUSR1)
		data, err := os.ReadFile(path) //nolint:gosec // G304: the file the test names
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(3)
		}
		fmt.Printf("read %d bytes\n", len(data))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func status(sigPnd, shdPnd string) []byte {
	return []byte("Name:\tcat\nState:\tS (sleeping)\nTgid:\t42\nPid:\t43\n" +
		"SigQ:\t1/62000\nSigPnd:\t" + sigPnd + "\nShdPnd:\t" + shdPnd + "\nSigBlk:\t0000000000000100\n" +
		"SigIgn:\t0000000000000100\nSigCgt:\t0000000000000100\n")
}

func TestCallerDying(t *testing.T) {
	const none = "0000000000000000"
	cases := []struct {
		name   string
		pid    uint32
		status []byte
		err    error
		want   bool
	}{
		{"nothing pending", 43, status(none, none), nil, false},
		{"harmless signals pending", 43, status("0000000000410200", "0000000000010000"), nil, false},
		{"SIGKILL pending on the thread", 43, status("0000000000000100", none), nil, true},
		{"SIGKILL pending on the process", 43, status(none, "0000000000000100"), nil, true},
		{"SIGKILL among others", 43, status("0000000000804100", none), nil, true},
		// SigBlk, SigIgn and SigCgt carry the bit in every status above.
		{"no pending line", 43, []byte("Name:\tcat\nSigBlk:\t0000000000000100\n"), nil, false},
		{"unreadable mask", 43, []byte("SigPnd:\tzz\nShdPnd:\n"), nil, false},
		{"process gone", 43, nil, &os.PathError{Op: "open", Path: "/proc/43/status", Err: syscall.ENOENT}, true},
		{"process gone while read", 43, nil, &os.PathError{Op: "read", Path: "/proc/43/status", Err: syscall.ESRCH}, true},
		{"status hidden", 43, nil, &os.PathError{Op: "open", Path: "/proc/43/status", Err: syscall.EACCES}, false},
		{"no usable /proc", 43, nil, errProcUnusable, false},
		{"caller of another PID namespace", 0, status("0000000000000100", none), nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			read := func(pid uint32) ([]byte, error) {
				if pid != tc.pid {
					t.Errorf("read the status of %d, want %d", pid, tc.pid)
				}

				return tc.status, tc.err
			}
			if got := callerDying(tc.pid, read); got != tc.want {
				t.Errorf("callerDying = %v, want %v", got, tc.want)
			}
		})
	}

	// The reader of a mount, on this very process: alive, nothing fatal.
	if !procUsable() {
		t.Skip("/proc is not the one of this PID namespace")
	}
	if callerDying(uint32(os.Getpid()), readProcStatus) { //nolint:gosec // G115: a PID
		t.Error("this process is reported dying")
	}
	if callerDying(uint32(unix.Gettid()), readProcStatus) { //nolint:gosec // G115: a thread ID
		t.Error("this thread is reported dying")
	}
}

// probes records what the driver asked of /proc.
type probes struct {
	mu    sync.Mutex
	pids  map[uint32]int
	dying map[uint32]bool
}

func (p *probes) read(pid uint32) ([]byte, error) {
	status, err := readProcStatus(pid)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pids == nil {
		p.pids, p.dying = make(map[uint32]int), make(map[uint32]bool)
	}
	p.pids[pid]++
	if callerDying(pid, func(uint32) ([]byte, error) { return status, err }) {
		p.dying[pid] = true
	}

	return status, err
}

func (p *probes) count(pid uint32) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.pids[pid]
}

func (p *probes) sawDying() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.dying) > 0
}

// underSignals runs fn on a thread of its own that receives, for as long as
// fn lasts, signals that kill nothing: SIGUSR1, which the test handles, and
// SIGURG, which the Go runtime does. It returns the ID of that thread.
func underSignals(t *testing.T, fn func()) int {
	t.Helper()
	handled := make(chan os.Signal, 64)
	signal.Notify(handled, syscall.SIGUSR1)
	defer signal.Stop(handled)

	var tid atomic.Int64
	stop, sender, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid.Store(int64(unix.Gettid()))
		fn()
	}()
	go func() {
		defer close(sender)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-handled:
			case <-time.After(time.Millisecond):
			}
			if id := int(tid.Load()); id != 0 {
				sig := syscall.SIGUSR1
				if i%2 == 1 {
					sig = syscall.SIGURG
				}
				_ = unix.Tgkill(os.Getpid(), id, sig)
			}
		}
	}()
	<-done
	close(stop)
	<-sender

	return int(tid.Load())
}

// slowAPI makes the fake API take its time for the requests match selects.
func slowAPI(a *fakeAPI, delay time.Duration, match func(r *http.Request) bool) {
	slow := func(r *http.Request) {
		if match(r) {
			time.Sleep(delay)
		}
	}
	a.mu.Lock()
	a.before, a.beforeRead = slow, slow
	a.mu.Unlock()
}

func isChunkRead(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/chunk/")
}

// A reader that keeps receiving signals it handles reads the whole file: the
// interruptions the kernel sends for them are looked at (the caller is the
// thread, and it is not dying) and ignored. The read(2) calls are made
// directly: os.File would hide an EINTR by calling again.
func TestInterrupt_HarmlessSignalsDoNotFailReads(t *testing.T) {
	a := newFakeAPI(t)
	_, big := sampleTree(a)
	slowAPI(a, 40*time.Millisecond, isChunkRead)
	seen := &probes{}
	opts := single("dr1")
	opts.driver.procStatus = seen.read
	m := mountFS(t, a, opts)

	var got []byte
	var failure error
	tid := underSignals(t, func() {
		fd, err := unix.Open(filepath.Join(m.dir, "big.bin"), unix.O_RDONLY, 0)
		if err != nil {
			failure = fmt.Errorf("open: %w", err)

			return
		}
		buf := make([]byte, 32<<10)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				failure = fmt.Errorf("read at %d: %w", len(got), err)

				break
			}
			if n == 0 {
				break
			}
			got = append(got, buf[:n]...)
		}
		if err := unix.Close(fd); err != nil && failure == nil {
			failure = fmt.Errorf("close: %w", err)
		}
	})
	if failure != nil {
		t.Fatal(failure)
	}
	if !bytes.Equal(got, big) {
		t.Errorf("read %d bytes that differ from the %d of the file", len(got), len(big))
	}
	// The caller the kernel names is the thread, not its process (which this
	// run only tells apart when the reader was not on the main thread).
	if tid != os.Getpid() && seen.count(uint32(os.Getpid())) != 0 { //nolint:gosec // G115: a PID
		t.Errorf("the process was looked at, the caller was thread %d (asked: %v)", tid, seen.pids)
	}
	if seen.count(uint32(tid)) == 0 { //nolint:gosec // G115: a thread ID
		t.Errorf("no interruption was looked at for thread %d (asked: %v): the signals interrupted nothing", tid, seen.pids)
	}
	if seen.sawDying() {
		t.Errorf("a caller was taken for dying: %v", seen.dying)
	}
	if journal := m.journal(1 << 20); strings.Contains(journal, "EINTR") {
		t.Errorf("an operation answered EINTR:\n%s", journal)
	}
}

// close(2) under the same signals sends the file and never answers EINTR,
// however long the upload takes.
func TestInterrupt_HarmlessSignalsDoNotFailClose(t *testing.T) {
	a := newFakeAPI(t)
	dr, _ := sampleTree(a)
	slowAPI(a, 60*time.Millisecond, func(r *http.Request) bool { return r.Method != http.MethodGet })
	seen := &probes{}
	opts := single("dr1")
	opts.driver.procStatus = seen.read
	m := mountFS(t, a, opts)

	const files = 8
	var failure error
	tid := underSignals(t, func() {
		for i := range files {
			name := fmt.Sprintf("signalled-%d.txt", i)
			fd, err := unix.Open(filepath.Join(m.dir, name), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644)
			if err != nil {
				failure = fmt.Errorf("%s: open: %w", name, err)

				return
			}
			if _, err := unix.Write(fd, []byte(name)); err != nil {
				failure = errors.Join(failure, fmt.Errorf("%s: write: %w", name, err))
			}
			if err := unix.Close(fd); err != nil {
				failure = errors.Join(failure, fmt.Errorf("%s: close: %w", name, err))
			}
		}
	})
	if failure != nil {
		t.Fatal(failure)
	}
	for i := range files {
		name := fmt.Sprintf("signalled-%d.txt", i)
		if got := stored(t, a, dr, "", name); string(got) != name {
			t.Errorf("%s: the API holds %q", name, got)
		}
	}
	if seen.count(uint32(tid)) == 0 { //nolint:gosec // G115: a thread ID
		t.Errorf("no interruption was looked at for thread %d (asked: %v)", tid, seen.pids)
	}
	if journal := m.journal(1 << 20); strings.Contains(journal, "EINTR") {
		t.Errorf("an operation answered EINTR:\n%s", journal)
	}
}

// holdChunks holds back the chunk downloads until release, and tells when the
// first arrives and when one is abandoned by the client.
func holdChunks(a *fakeAPI) (arrived, abandoned <-chan struct{}, release func()) {
	here, gone, gate := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var first, left, open sync.Once
	a.mu.Lock()
	a.beforeRead = func(r *http.Request) {
		if !isChunkRead(r) {
			return
		}
		first.Do(func() { close(here) })
		select {
		case <-gate:
		case <-r.Context().Done():
			left.Do(func() { close(gone) })
		}
	}
	a.mu.Unlock()

	return here, gone, func() { open.Do(func() { close(gate) }) }
}

// A process blocked in a read the API holds back dies when it is killed, at
// once or after signals it handled, without waiting for the download: the
// interruption of a dying caller is honoured, and the download is abandoned
// when its file is closed.
func TestInterrupt_KilledReader(t *testing.T) {
	for _, tc := range []struct {
		name     string
		harmless int
	}{
		{"killed at once", 0},
		{"killed after signals it handled", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newFakeAPI(t)
			sampleTree(a)
			arrived, abandoned, release := holdChunks(a)
			seen := &probes{}
			opts := single("dr1")
			opts.driver.procStatus = seen.read
			m := mountFS(t, a, opts)
			// Whatever happens, the API answers before its server is closed.
			t.Cleanup(release)

			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe) //nolint:gosec // G204: the test binary itself
			cmd.Env = append(os.Environ(), helperReadEnv+"="+filepath.Join(m.dir, "big.bin"))
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			select {
			case <-arrived:
			case err := <-exited:
				t.Fatalf("the reader ended before its download reached the API: %v\n%s", err, output.String())
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatal("the download never reached the API")
			}

			for range tc.harmless {
				if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
					t.Fatal(err)
				}
				time.Sleep(50 * time.Millisecond)
			}
			select {
			case err := <-exited:
				t.Fatalf("the reader did not survive the signals it handles: %v\n%s", err, output.String())
			case <-time.After(150 * time.Millisecond):
			}
			if seen.sawDying() {
				t.Fatalf("a caller was taken for dying before the kill: %v", seen.dying)
			}

			killed := time.Now()
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				release()
				<-exited
				t.Fatal("the killed reader waited for the download the API holds")
			}
			took := time.Since(killed)
			t.Logf("the reader was gone %s after its kill", took.Round(time.Millisecond))
			if took > time.Second {
				t.Errorf("the reader took %s to die", took)
			}
			if !seen.sawDying() {
				t.Errorf("no caller was found dying (asked: %v)", seen.pids)
			}
			select {
			case <-abandoned:
			case <-time.After(5 * time.Second):
				t.Error("the download of the dead reader was not abandoned")
			}
		})
	}
}
