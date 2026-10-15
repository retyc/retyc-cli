package vfs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// A payload is decrypted once: the second read of it is answered by the memo.
// Two datarooms share nothing, even for one payload.
func TestSealedMemo_DecryptsAPayloadOnce(t *testing.T) {
	var m sealedMemo
	calls := 0
	decrypt := func(enc string) (string, error) {
		calls++

		return "plain of " + enc, nil
	}
	for range 3 {
		got, err := m.open("dr1", "payload", decrypt)
		if err != nil || got != "plain of payload" {
			t.Fatalf("open = (%q, %v)", got, err)
		}
	}
	if calls != 1 {
		t.Errorf("%d decryptions of one payload, want 1", calls)
	}
	if _, err := m.open("dr2", "payload", decrypt); err != nil || calls != 2 {
		t.Errorf("another dataroom: %d decryptions (err %v), want 2: datarooms share nothing", calls, err)
	}
	// The digest tells where the dataroom ID ends.
	if _, err := m.open("dr", "1payload", decrypt); err != nil || calls != 3 {
		t.Errorf("(dr, 1payload) after (dr1, payload): %d decryptions (err %v), want 3", calls, err)
	}
	if m.len() != 3 {
		t.Errorf("len = %d, want 3", m.len())
	}
	m.reset()
	if _, err := m.open("dr1", "payload", decrypt); err != nil || calls != 4 || m.len() != 1 {
		t.Errorf("after reset: %d decryptions, len %d (err %v), want 4 and 1", calls, m.len(), err)
	}
}

// A failure is never remembered: the next read decrypts again.
func TestSealedMemo_FailureIsNotRecorded(t *testing.T) {
	var m sealedMemo
	boom := errors.New("boom")
	calls := 0
	decrypt := func(string) (string, error) {
		calls++
		if calls == 1 {
			return "", boom
		}

		return "plain", nil
	}
	if _, err := m.open("dr1", "payload", decrypt); !errors.Is(err, boom) {
		t.Fatalf("first open: %v, want the failure", err)
	}
	if m.len() != 0 {
		t.Errorf("len = %d after a failure, want 0", m.len())
	}
	if got, err := m.open("dr1", "payload", decrypt); err != nil || got != "plain" || calls != 2 {
		t.Errorf("second open = (%q, %v) after %d decryptions, want plain after 2", got, err, calls)
	}
}

// The memo holds its bound: the oldest recorded leaves first.
func TestSealedMemo_Bounded(t *testing.T) {
	m := sealedMemo{max: 4}
	calls := 0
	decrypt := func(enc string) (string, error) {
		calls++

		return enc, nil
	}
	for i := range 10 {
		if _, err := m.open("dr1", fmt.Sprint("p", i), decrypt); err != nil {
			t.Fatal(err)
		}
		if m.len() > 4 {
			t.Fatalf("len = %d after %d payloads, want at most 4", m.len(), i+1)
		}
	}
	if m.len() != 4 || len(m.ring) != 4 {
		t.Errorf("len = %d, ring %d, want 4 and 4", m.len(), len(m.ring))
	}
	calls = 0
	for _, i := range []int{6, 7, 8, 9} {
		_, _ = m.open("dr1", fmt.Sprint("p", i), decrypt)
	}
	if calls != 0 {
		t.Errorf("%d decryptions of the four latest payloads, want 0", calls)
	}
	if _, _ = m.open("dr1", "p0", decrypt); calls != 1 {
		t.Errorf("the oldest payload was still held")
	}
}

// The memo is safe for the concurrent readers of a store (run with -race).
func TestSealedMemo_Concurrent(t *testing.T) {
	m := sealedMemo{max: 8}
	var calls atomic.Int64
	decrypt := func(enc string) (string, error) {
		calls.Add(1)

		return "plain of " + enc, nil
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 500 {
				enc := fmt.Sprint("p", (g+i)%16)
				if got, err := m.open("dr1", enc, decrypt); err != nil || got != "plain of "+enc {
					t.Errorf("open(%s) = (%q, %v)", enc, got, err)

					return
				}
			}
		})
	}
	wg.Wait()
	if m.len() > 8 {
		t.Errorf("len = %d, want at most 8", m.len())
	}
}

// The codec opens a sealed node through the memo: once a payload was opened,
// it is not decrypted again. The proof is a session that could not decrypt
// it: the name it once opened is still answered, where a payload never seen
// fails, and that failure leaves nothing behind. FS.Close empties the memo.
func TestCodec_OpenRemembersWhatItDecrypted(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	seal := func(s string) string {
		t.Helper()
		enc, err := crypto.EncryptStringForKeys(s, []string{pub})
		if err != nil {
			t.Fatal(err)
		}

		return enc
	}
	fs := New(nil, Options{})
	fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	c := codec{fs: fs}
	ctx := context.Background()
	link := metastore.Sealed{Name: seal("link"), Target: seal("../target")}

	n := Node{ID: "n1", Type: TypeSymlink, Sealed: link}
	if err := c.Open(ctx, "dr1", &n); err != nil || n.Name != "link" || n.Target != "../target" {
		t.Fatalf("Open = %v, node %+v", err, n)
	}
	if fs.sealed.len() != 2 {
		t.Fatalf("memo holds %d plaintexts, want the name and the target", fs.sealed.len())
	}

	// Another key: nothing sealed for the first one decrypts any more.
	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fs.SeedSession("dr1", &service.DataroomSession{Identity: other, PublicKey: other.Recipient().String()})
	again := Node{ID: "n1", Type: TypeSymlink, Sealed: link}
	if err := c.Open(ctx, "dr1", &again); err != nil || again.Name != "link" || again.Target != "../target" {
		t.Errorf("second Open = %v, node %+v: it decrypted again", err, again)
	}
	unseen := Node{ID: "n2", Sealed: metastore.Sealed{Name: seal("unseen")}}
	if err := c.Open(ctx, "dr1", &unseen); err == nil || unseen.Name != "" {
		t.Errorf("Open of a payload never seen = %v, name %q: want a failure", err, unseen.Name)
	}
	if fs.sealed.len() != 2 {
		t.Errorf("memo holds %d plaintexts after a failure, want 2", fs.sealed.len())
	}
	// The memo is per dataroom: the same payload under another one is decrypted.
	fs.SeedSession("dr2", &service.DataroomSession{Identity: other, PublicKey: other.Recipient().String()})
	elsewhere := Node{ID: "n1", Sealed: link}
	if err := c.Open(ctx, "dr2", &elsewhere); err == nil {
		t.Error("dr2 opened a payload from the memo of dr1")
	}
	// A dataroom without a session opens nothing, memo or not.
	fs.sessions.Store("dr1", nil)
	if err := c.Open(ctx, "dr1", &Node{Sealed: link}); err == nil {
		t.Error("Open without a session succeeded")
	}

	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	if fs.sealed.len() != 0 {
		t.Errorf("memo holds %d plaintexts after Close, want 0", fs.sealed.len())
	}
}
