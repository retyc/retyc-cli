package service

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// setConcurrency applies c for the duration of the test and restores the
// defaults afterwards: the setting is process-wide.
func setConcurrency(t *testing.T, c config.ConcurrencyConfig) {
	t.Helper()
	SetConcurrency(c)
	t.Cleanup(func() { SetConcurrency(defaultConcurrency) })
}

// barrier holds every call until want of them run at once, then lets them all
// through, and records the highest number of calls running at once. A
// peak-concurrency test built on it does not depend on timing: when the code
// under test allows want concurrent calls, the peak reaches want exactly;
// when it allows fewer, the calls wait for the timeout and the test fails.
type barrier struct {
	want     int32
	inFlight atomic.Int32
	peak     atomic.Int32
	full     chan struct{}
	once     sync.Once
}

func newBarrier(want int) *barrier {
	return &barrier{want: int32(want), full: make(chan struct{})} //nolint:gosec // small test bounds
}

// enter runs one call through the barrier; it is safe from any goroutine.
func (b *barrier) enter(t *testing.T) {
	n := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	for {
		cur := b.peak.Load()
		if n <= cur || b.peak.CompareAndSwap(cur, n) {
			break
		}
	}
	if n >= b.want {
		b.once.Do(func() { close(b.full) })
	}
	select {
	case <-b.full:
	case <-time.After(5 * time.Second):
		t.Errorf("no more than %d of %d expected calls ran at once", b.peak.Load(), b.want)
		b.once.Do(func() { close(b.full) })
	}
}

// Without SetConcurrency, every bound is the documented default.
func TestConcurrency_DefaultsWithoutSet(t *testing.T) {
	want := config.ConcurrencyConfig{
		List: config.DefaultConcurrency, Upload: config.DefaultConcurrency, Download: config.DefaultConcurrency,
	}
	if got := Concurrency(); got != want {
		t.Errorf("Concurrency() = %+v, want %+v", got, want)
	}
}

func TestConcurrency_ListFollowsSetting(t *testing.T) {
	for _, limit := range []int{1, 2, 7} {
		setConcurrency(t, config.ConcurrencyConfig{List: limit, Upload: 1, Download: 1})
		gate := newBarrier(limit)
		fetch := func(_ context.Context, page int) (int, int, error) {
			if page > 1 { // page 1 is fetched alone, before the concurrent ones
				gate.enter(t)
			}

			return page, 16, nil
		}
		if _, err := fetchAllPages(context.Background(), fetch, keepPage); err != nil {
			t.Fatalf("fetchAllPages: %v", err)
		}
		if got := int(gate.peak.Load()); got != limit {
			t.Errorf("list concurrency %d: peak = %d, want %d", limit, got, limit)
		}
	}
}

func TestConcurrency_UploadFollowsSetting(t *testing.T) {
	setConcurrency(t, config.ConcurrencyConfig{List: 1, Upload: 2, Download: 1})
	data := make([]byte, UploadChunkSize*5+1)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	gate := newBarrier(2)
	uploadFn := func(_ context.Context, _ int, _ []byte) error {
		gate.enter(t)

		return nil
	}
	if err := UploadChunks(context.Background(), bytes.NewReader(data), int64(len(data)), "f.bin",
		identity.Recipient().String(), nil, uploadFn); err != nil {
		t.Fatalf("UploadChunks: %v", err)
	}
	if got := gate.peak.Load(); got != 2 {
		t.Errorf("peak uploads = %d, want 2", got)
	}
}

func TestConcurrency_DownloadFollowsSetting(t *testing.T) {
	setConcurrency(t, config.ConcurrencyConfig{List: 1, Upload: 1, Download: 3})
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	chunk, err := crypto.EncryptBinaryForKey(make([]byte, 16), identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}

	const chunks = 12
	gate := newBarrier(3)
	downloadFn := func(_ context.Context, _ int) ([]byte, error) {
		gate.enter(t)

		return chunk, nil
	}
	if err := StreamDownloadChunks(context.Background(), io.Discard, 16*chunks, chunks, identity, nil,
		downloadFn); err != nil {
		t.Fatalf("StreamDownloadChunks: %v", err)
	}
	if got := gate.peak.Load(); got != 3 {
		t.Errorf("peak downloads = %d, want 3", got)
	}
}
