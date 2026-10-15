package vfs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// codec is the metastore.Codec an FS hands to a store that asks for one
// (metastore.Binder): the name hash and the decryption of a dataroom, from the
// sessions the FS holds.
//
// The store calls it from its own methods, which the FS calls with mu held:
// nothing here takes mu, and neither method resolves a session nor makes a
// request. A dataroom
// whose session is not held yet has no hash and opens nothing, which a store
// reports as a miss or an error; the fetch from the API that follows resolves
// the session (see fetchNodes), outside mu.
type codec struct{ fs *FS }

var _ metastore.Codec = codec{}

// Hash implements metastore.Codec: the name hash of the dataroom (see
// service.DataroomSession.NameHash), ok being false while its session is not
// resolved.
func (c codec) Hash(dataroomID, s string) (string, bool) {
	sess, ok := c.fs.sessions.Peek(dataroomID)
	if !ok || sess == nil {
		return "", false
	}

	return sess.NameHash(s), true
}

// Open implements metastore.Codec with the decryptions a listing makes (see
// service.DataroomSession.OpenSealed). It makes no request, whatever the
// interface allows. The FS reads the store with FS.mu held and a context
// that leaves the sealed nodes unopened (see leaveSealed): it calls Open
// itself, once mu is let go (openNode, openListing), so that no decryption,
// nor the digest of the memo, holds the filesystem. A MIME type whose row
// the session does not hold yet is left empty.
//
// The name and the target are asked of the FS's memo first (see sealedMemo):
// a store that keeps sealed nodes hands the same ciphertexts over at every
// read, and each costs one post-quantum AGE decryption. The MIME type is
// resolved by the session's table each time, which is a map lookup.
func (c codec) Open(_ context.Context, dataroomID string, n *Node) error {
	if c.fs.openHook != nil {
		if err := c.fs.openHook(); err != nil {
			return err
		}
	}
	sess, ok := c.fs.sessions.Peek(dataroomID)
	if !ok || sess == nil {
		return fmt.Errorf("opening a sealed node: the session of dataroom %s is not resolved", dataroomID)
	}
	if n.Sealed == nil || n.Sealed.Name == "" {
		return fmt.Errorf("opening a sealed node: node %s has no sealed name", n.ID)
	}
	memo := &c.fs.sealed
	name, err := memo.open(dataroomID, n.Sealed.Name, sess.OpenSealedName)
	if err != nil {
		return err
	}
	var target string
	if n.Sealed.Target != "" {
		if target, err = memo.open(dataroomID, n.Sealed.Target, sess.OpenSealedTarget); err != nil {
			return err
		}
	}
	n.Name, n.Target = name, target
	n.MIMEType = sess.SealedMIMEType(n.Sealed.MIMETypeID, n.Sealed.MIMEType)

	return nil
}

// sealedMemoMax bounds the plaintexts an FS remembers: a digest and a name
// each, some twenty megabytes at the limit.
const sealedMemoMax = 100_000

// decryptSlots bounds the sealed payloads the process decrypts at once to
// half its CPUs, whatever the number of listings opened together. Each
// decryption is some 200 µs of CPU (ML-KEM + X25519): a listing walk of
// several folders at once, each opening its nodes GOMAXPROCS at a time, took
// every CPU, and the goroutine holding FS.mu for its read of the store waited
// for one, which held every other operation of the FS. Measured on 24 CPUs,
// twenty-odd find in parallel over 10,000 sealed names: about 500 ms without
// a bound, 210 ms at half the CPUs, 250 ms at a third, 280 ms when the
// decryption was done under FS.mu.
var decryptSlots = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))

// sealedMemo remembers what the sealed fields of the nodes read from the
// store decrypt to: digest of the ciphertext → plaintext.
//
// An AGE payload always decrypts to the same string, so an entry never
// expires; a node renamed gets another payload from the API, hence another
// entry. The payload is digested as it comes: one seen armored (from the API)
// and binary (from a store that keeps it without its armor, see
// metastore.Sealed) is two entries, which costs less than decoding an armor
// at every read to make them one. The key is the SHA-256 of the dataroom ID and of the payload, not
// the payload (2.5 kB for a post-quantum recipient): one dataroom never
// answers for another, whatever they hold. The memo is bounded all the same,
// sealedMemoMax entries, the oldest recorded leaving first (see chunkSizes);
// a payload that left costs its next read one decryption. A failure is never
// recorded. Nothing of it is written to the store nor to disk: it holds the
// names a store of sealed nodes exists to keep out of Redis, in the memory of
// the process that holds the key to them anyway, and FS.Close drops it.
//
// It has its own mutex and never takes FS.mu: the codec is called with FS.mu
// held, and from several goroutines of the store at once (see
// redisstore.hasher.openAll). Two readers that miss one payload together
// both decrypt it.
type sealedMemo struct {
	mu    sync.Mutex
	plain map[[sha256.Size]byte]string
	// ring holds the digests recorded, in the order they were, and next is
	// the place of the one to replace once the ring is full.
	ring [][sha256.Size]byte
	next int
	// max replaces sealedMemoMax when not zero (tests).
	max int
}

// open returns what the payload enc of the dataroom decrypts to, from the
// memo, else from decrypt, whose answer is then recorded.
func (m *sealedMemo) open(dataroomID, enc string, decrypt func(string) (string, error)) (string, error) {
	if enc == "" {
		return decrypt(enc)
	}
	h := sha256.New()
	h.Write([]byte(dataroomID))
	h.Write([]byte{0}) // an ID holds no zero byte: no two (ID, payload) pairs digest alike
	h.Write([]byte(enc))
	var key [sha256.Size]byte
	h.Sum(key[:0])

	m.mu.Lock()
	plain, ok := m.plain[key]
	m.mu.Unlock()
	if ok {
		return plain, nil
	}
	decryptSlots <- struct{}{}
	plain, err := decrypt(enc)
	<-decryptSlots
	if err != nil {
		return "", err
	}
	m.put(key, plain)

	return plain, nil
}

// put records the plaintext of a digest.
func (m *sealedMemo) put(key [sha256.Size]byte, plain string) {
	limit := m.max
	if limit <= 0 {
		limit = sealedMemoMax
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.plain[key]; ok {
		return
	}
	if m.plain == nil {
		m.plain = make(map[[sha256.Size]byte]string)
	}
	if len(m.ring) < limit {
		m.ring = append(m.ring, key)
	} else {
		delete(m.plain, m.ring[m.next])
		m.ring[m.next] = key
		m.next = (m.next + 1) % len(m.ring)
	}
	m.plain[key] = plain
}

// len returns the number of plaintexts recorded.
func (m *sealedMemo) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.plain)
}

// reset forgets everything.
func (m *sealedMemo) reset() {
	m.mu.Lock()
	m.plain, m.ring, m.next = nil, nil, 0
	m.mu.Unlock()
}

// leaveSealed is ctx for a read of the store made with mu held, when the
// nodes read go back to the caller: a store that may hold sealed nodes
// returns them unopened (see metastore.LeaveSealed), and the caller opens
// them with openNode / openListing once it has let mu go. ctx as it is for a
// memstore.
func (fs *FS) leaveSealed(ctx context.Context) context.Context {
	if !fs.openLater {
		return ctx
	}

	return metastore.LeaveSealed(ctx)
}

// openNode opens n when a store returned it sealed (see leaveSealed). false
// tells it does not open: the caller treats it as absent, which is what the
// store answered when it opened its nodes itself. Never with mu held.
func (fs *FS) openNode(ctx context.Context, dataroomID string, n *Node) bool {
	if n == nil || !n.Unopened() {
		return true
	}
	if err := (codec{fs}).Open(ctx, dataroomID, n); err != nil {
		return false
	}

	return n.Name != ""
}

// openListing returns l with the nodes a store returned sealed opened (see
// leaveSealed), sorted by name as a store that opens them sorts them; l
// itself when none is sealed. The nodes of l are not written through: the
// opened ones are a copy. false tells one of them does not open: the listing
// is then absent, as the store answered it when it opened its nodes itself.
// The nodes are opened GOMAXPROCS at a time, each being one AGE decryption
// unless the memo holds it. Never with mu held.
func (fs *FS) openListing(ctx context.Context, dataroomID string, l *Listing) (*Listing, bool) {
	var sealed []int
	for i := range l.Nodes {
		if l.Nodes[i].Unopened() {
			sealed = append(sealed, i)
		}
	}
	if len(sealed) == 0 {
		return l, true
	}
	nodes := slices.Clone(l.Nodes)
	if !fs.openAll(ctx, dataroomID, nodes, sealed) {
		return nil, false
	}
	slices.SortFunc(nodes, func(a, b Node) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}

		return strings.Compare(a.ID, b.ID)
	})

	return &Listing{Nodes: nodes, FetchedAt: l.FetchedAt, ETag: l.ETag}, true
}

// openAll opens nodes[i] for each i of sealed, GOMAXPROCS at a time. It
// answers false when one of them does not open, the others being left as
// they are.
func (fs *FS) openAll(ctx context.Context, dataroomID string, nodes []Node, sealed []int) bool {
	workers := min(runtime.GOMAXPROCS(0), len(sealed))
	if workers <= 1 {
		for _, i := range sealed {
			if !fs.openNode(ctx, dataroomID, &nodes[i]) {
				return false
			}
		}

		return true
	}
	var (
		wg     sync.WaitGroup
		next   = make(chan int)
		failed = make(chan struct{})
		once   sync.Once
	)
	for range workers {
		wg.Go(func() {
			for i := range next {
				if !fs.openNode(ctx, dataroomID, &nodes[i]) {
					once.Do(func() { close(failed) })
				}
			}
		})
	}
feed:
	for _, i := range sealed {
		select {
		case next <- i:
		case <-failed:
			break feed
		}
	}
	close(next)
	wg.Wait()
	select {
	case <-failed:
		return false
	default:
		return true
	}
}
