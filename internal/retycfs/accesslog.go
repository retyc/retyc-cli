//go:build linux

package retycfs

import (
	"context"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// defaultAccessLogSize is the number of operations the access log keeps.
const defaultAccessLogSize = 4096

// accessRecord is one operation of the access log. It holds numbers only: an
// operation is named by its inode, never by a name or a path, which are what
// the platform encrypts (the rule of the traces, see internal/telemetry).
type accessRecord struct {
	at       time.Time
	op       string
	ino      uint64
	off      int64
	size     int
	ranged   bool // off and size are meaningful (read)
	duration time.Duration
	errno    syscall.Errno
}

// appendTo formats the record as one line:
//
//	<RFC 3339 time, microseconds> <op> ino=<n> [off=<n> len=<n>] <duration> <result>
//
// The result is "ok" or the name of the errno (ENOENT, EIO, …).
func (r accessRecord) appendTo(b []byte) []byte {
	b = r.at.UTC().AppendFormat(b, "2006-01-02T15:04:05.000000Z")
	b = append(b, ' ')
	b = append(b, r.op...)
	b = append(b, " ino="...)
	b = strconv.AppendUint(b, r.ino, 10)
	if r.ranged {
		b = append(b, " off="...)
		b = strconv.AppendInt(b, r.off, 10)
		b = append(b, " len="...)
		b = strconv.AppendInt(b, int64(r.size), 10)
	}
	b = append(b, ' ')
	b = append(b, r.duration.Round(time.Microsecond).String()...)
	b = append(b, ' ')
	b = append(b, errnoName(r.errno)...)

	return append(b, '\n')
}

// errnoNames are the errnos the driver answers.
var errnoNames = map[syscall.Errno]string{
	syscall.EACCES:    "EACCES",
	syscall.EBADF:     "EBADF",
	syscall.EBUSY:     "EBUSY",
	syscall.EXDEV:     "EXDEV",
	syscall.EEXIST:    "EEXIST",
	syscall.EINTR:     "EINTR",
	syscall.EINVAL:    "EINVAL",
	syscall.EIO:       "EIO",
	syscall.EISDIR:    "EISDIR",
	syscall.ENAMETOOLONG: "ENAMETOOLONG",
	syscall.ENODATA:   "ENODATA",
	syscall.ENOENT:    "ENOENT",
	syscall.ENOSPC:    "ENOSPC",
	syscall.ENOTDIR:   "ENOTDIR",
	syscall.ENOTEMPTY: "ENOTEMPTY",
	syscall.ENOTSUP:   "ENOTSUP",
	syscall.EPERM:     "EPERM",
	syscall.ERANGE:    "ERANGE",
	syscall.EROFS:     "EROFS",
	syscall.ESTALE:    "ESTALE",
}

// errnoName returns the name of errno, "ok" for none.
func errnoName(errno syscall.Errno) string {
	if errno == 0 {
		return "ok"
	}
	if name, ok := errnoNames[errno]; ok {
		return name
	}

	return "errno=" + strconv.FormatUint(uint64(errno), 10)
}

// resultLabel returns the value of the result label of the FUSE metrics for
// errno: its name, or "other" for one the driver has no name for, so that the
// label set stays bounded.
func resultLabel(errno syscall.Errno) string {
	if errno == 0 {
		return "ok"
	}
	if name, ok := errnoNames[errno]; ok {
		return name
	}

	return "other"
}

// accessLog keeps the last operations of the mount in a ring, and feeds the
// readers of .retycfs/accesslog, which block for the next one like tail -f.
//
// The ring is bounded: recording an operation never allocates nor waits for a
// reader. A reader that falls behind by more than the ring loses the oldest
// records and is told how many.
type accessLog struct {
	mu   sync.Mutex
	ring []accessRecord
	// next is the sequence number of the next record; the ring holds the
	// records next-len(ring) (at most) to next-1, record n at index n%len.
	next uint64
	// wake is closed and replaced when a record arrives.
	wake chan struct{}
	// done is closed by close: readers then meet the end of the file.
	done   chan struct{}
	closed bool
}

func newAccessLog(size int) *accessLog {
	if size <= 0 {
		size = defaultAccessLogSize
	}

	return &accessLog{
		ring: make([]accessRecord, size),
		wake: make(chan struct{}),
		done: make(chan struct{}),
	}
}

// record appends r to the log and wakes the readers.
func (l *accessLog) record(r accessRecord) {
	l.mu.Lock()
	l.ring[l.next%uint64(len(l.ring))] = r
	l.next++
	wake := l.wake
	l.wake = make(chan struct{})
	l.mu.Unlock()
	close(wake)
}

// close ends the log: every read, blocked or to come, returns the end of the
// file once it has drained what it was given. A reader blocked on the log
// holds the mount busy, so this must come before the unmount.
func (l *accessLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.done)
	}
}

// oldestLocked returns the sequence number of the oldest record held. The caller
// holds mu.
func (l *accessLog) oldestLocked() uint64 {
	if l.next > uint64(len(l.ring)) {
		return l.next - uint64(len(l.ring))
	}

	return 0
}

// accessReader is one open of the access log: a position in it, and the end
// of a line that did not fit the last read.
type accessReader struct {
	log *accessLog

	mu      sync.Mutex
	started bool
	seq     uint64 // next record to format
	pending []byte
}

// reader returns a reader that starts at the oldest record held: opening the
// log after reproducing a problem still shows it.
func (l *accessLog) reader() *accessReader {
	return &accessReader{log: l}
}

// read fills dest with whole lines, as many as fit, waiting for a record when
// there is none. It returns 0 bytes at the end of the log (close), and
// context.Canceled when ctx ends first.
func (r *accessReader) read(ctx context.Context, dest []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if len(r.pending) == 0 {
			r.fill(len(dest))
		}
		if len(r.pending) > 0 {
			n := copy(dest, r.pending)
			r.pending = r.pending[n:]

			return n, nil
		}

		r.log.mu.Lock()
		wake, behind := r.log.wake, r.seq < r.log.next
		r.log.mu.Unlock()
		if behind {
			continue
		}
		select {
		case <-wake:
		case <-r.log.done:
			return 0, nil
		case <-ctx.Done():
			return 0, context.Canceled
		}
	}
}

// fill formats into pending the records the reader has not seen, up to about
// limit bytes (at least one line). The caller holds r.mu.
func (r *accessReader) fill(limit int) {
	l := r.log
	l.mu.Lock()
	defer l.mu.Unlock()
	oldest := l.oldestLocked()
	if !r.started {
		r.started, r.seq = true, oldest
	}
	r.pending = r.pending[:0]
	if r.seq < oldest {
		r.pending = append(r.pending, "# "...)
		r.pending = strconv.AppendUint(r.pending, oldest-r.seq, 10)
		r.pending = append(r.pending, " operations dropped\n"...)
		r.seq = oldest
	}
	for r.seq < l.next && len(r.pending) < limit {
		r.pending = l.ring[r.seq%uint64(len(l.ring))].appendTo(r.pending)
		r.seq++
	}
}
