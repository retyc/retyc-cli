package vfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/redisstore"
)

// redisTestURLEnv names the Redis these tests run against, the variable of
// the redisstore tests: without it they are skipped, except on CI, where they
// fail.
const redisTestURLEnv = "REDISSTORE_TEST_URL"

// sharedRedis is two instances over one fake API and one Redis: what two
// `retyc fs mount` of one dataroom are to each other.
type sharedRedis struct {
	t      *testing.T
	api    *treeAPI
	raw    *redis.Client
	prefix string
	// instance builds one more FS on the shared Redis; high is its
	// cache.redis.high_confidentiality.
	instance func(high bool) *FS
}

// newSharedRedis returns the pair's corner of the Redis: a random prefix,
// removed at the end (never a FLUSHDB: the database may be someone's).
func newSharedRedis(t *testing.T, a *treeAPI) *sharedRedis {
	t.Helper()
	url := os.Getenv(redisTestURLEnv)
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is not set: the shared cache tests need a Redis", redisTestURLEnv)
		}
		t.Skipf("%s is not set", redisTestURLEnv)
	}
	ropts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("%s is not a Redis URL", redisTestURLEnv)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	s := &sharedRedis{t: t, api: a, raw: redis.NewClient(ropts), prefix: "retyc-test-" + hex.EncodeToString(b[:])}
	t.Cleanup(func() {
		if keys := s.keys(); len(keys) > 0 {
			_ = s.raw.Unlink(context.Background(), keys...).Err()
		}
		_ = s.raw.Close()
	})

	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	a.pub, a.salt = identity.Recipient().String(), "salt"
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	s.instance = func(high bool) *FS {
		t.Helper()
		const ttl = 30 * time.Second
		store, err := redisstore.New(context.Background(), redisstore.Options{
			URL: url, HighConfidentiality: high, Prefix: s.prefix,
			ListingLife: ListingRetention(ttl, 0), EntryLife: ttl, NegativeEntryLife: time.Second,
		})
		if err != nil {
			t.Fatalf("redisstore.New: %v", err)
		}
		fs := New(testClient(srv), Options{TTL: ttl, Store: store, KeepSealed: high})
		t.Cleanup(func() { _ = fs.Close() })
		fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: a.pub, NameSalt: a.salt})

		return fs
	}

	return s
}

// keys lists the keys of the test's prefix.
func (s *sharedRedis) keys() []string {
	s.t.Helper()
	var keys []string
	iter := s.raw.Scan(context.Background(), 0, s.prefix+":*", 1000).Iterator()
	for iter.Next(context.Background()) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		s.t.Fatalf("SCAN: %v", err)
	}

	return keys
}

// dump is everything Redis holds under the prefix: key names and contents.
func (s *sharedRedis) dump() string {
	s.t.Helper()
	ctx := context.Background()
	var sb strings.Builder
	for _, k := range s.keys() {
		sb.WriteString(k + "\n")
		switch s.raw.Type(ctx, k).Val() {
		case "hash":
			for f, v := range s.raw.HGetAll(ctx, k).Val() {
				sb.WriteString("  " + f + " = " + v + "\n")
			}
		case "set":
			sb.WriteString("  " + strings.Join(s.raw.SMembers(ctx, k).Val(), " ") + "\n")
		default:
			sb.WriteString("  " + s.raw.Get(ctx, k).Val() + "\n")
		}
	}

	return sb.String()
}

// asked returns the listings and the lookups by name the API received.
func (s *sharedRedis) asked() (listings, lookups int) {
	lookups, listings, _ = s.api.counts()

	return listings, lookups
}

// A listing one instance fetched is served to the other from Redis: the API
// is not asked again, for the listing nor for a name in it.
func TestSharedRedis_ListingOfOneInstanceServesTheOther(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	shared := newSharedRedis(t, a)
	one, two := shared.instance(false), shared.instance(false)
	ctx := context.Background()

	first, err := one.ReadDir(ctx, "dr1", "/")
	if err != nil {
		t.Fatalf("instance 1: ReadDir(/): %v", err)
	}
	if listings, _ := shared.asked(); listings != 1 {
		t.Fatalf("instance 1 made %d listings, want 1", listings)
	}

	second, err := two.ReadDir(ctx, "dr1", "/")
	if err != nil {
		t.Fatalf("instance 2: ReadDir(/): %v", err)
	}
	if got, want := names(second), names(first); !slices.Equal(got, want) || len(got) != 1 || got[0] != "a" {
		t.Errorf("instance 2 lists %v, instance 1 listed %v, want [a]", got, want)
	}
	mustLookup(t, two, "/", "a", "d-a")
	if listings, lookups := shared.asked(); listings != 1 || lookups != 0 {
		t.Errorf("after instance 2 read the folder: %d listings and %d lookups, want 1 and 0", listings, lookups)
	}
}

// What one instance creates or removes is what the other finds, without a
// request: the edit is made to the listing both read.
func TestSharedRedis_MutationOfOneInstanceIsSeenByTheOther(t *testing.T) {
	a := deepTree(newTreeAPI(t))
	shared := newSharedRedis(t, a)
	one, two := shared.instance(false), shared.instance(false)
	ctx := context.Background()

	// Both know /a: instance 1 lists it, instance 2 reads that listing.
	if _, err := one.ReadDir(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("instance 1: ReadDir(/a): %v", err)
	}
	mustLookup(t, two, "/a", "x.txt", "f-x")
	mustMiss(t, two, "/a", "copy.txt")
	listings, lookups := shared.asked()

	// A file created by instance 1 (a server-side copy answers the node).
	if _, _, err := one.Copy(ctx, "dr1", "/a/x.txt", "/a/copy.txt", false); err != nil {
		t.Fatalf("instance 1: Copy: %v", err)
	}
	mustLookup(t, two, "/a", "copy.txt", "f-copy")

	// A file removed by instance 1.
	if err := one.Remove(ctx, "dr1", "/a/x.txt", false); err != nil {
		t.Fatalf("instance 1: Remove: %v", err)
	}
	mustMiss(t, two, "/a", "x.txt")
	nodes, err := two.ReadDir(ctx, "dr1", "/a")
	if err != nil {
		t.Fatalf("instance 2: ReadDir(/a): %v", err)
	}
	if got := names(nodes); !slices.Equal(got, []string{"b", "copy.txt"}) {
		t.Errorf("instance 2 lists %v, want [b copy.txt]", got)
	}

	if l, k := shared.asked(); l != listings || k != lookups {
		t.Errorf("the mutations cost %d listings and %d lookups, want none", l-listings, k-lookups)
	}
}

// With high confidentiality nothing an instance writes to Redis holds a name
// or a link target in clear, and an instance configured otherwise still reads
// it: what is read depends on the value alone.
func TestSharedRedis_HighConfidentialityStoresNoName(t *testing.T) {
	a := newTreeAPI(t)
	a.put("", "contracts-2026", fakeNode{id: "d-contracts", kind: api.NodeTypeFolder})
	a.put("d-contracts", "merger-draft.docx", fakeNode{id: "f-merger", kind: api.NodeTypeFile})
	a.put("d-contracts", "latest-offer",
		fakeNode{id: "l-offer", kind: api.NodeTypeSymlink, target: "offers/final-bid.pdf"})
	shared := newSharedRedis(t, a)
	sealed, clear := shared.instance(true), shared.instance(false)
	ctx := context.Background()

	for _, p := range []string{"/", "/contracts-2026"} {
		if _, err := sealed.ReadDir(ctx, "dr1", p); err != nil {
			t.Fatalf("sealed instance: ReadDir: %v", err)
		}
	}
	// A name looked up on its own is stored too, as an entry.
	if _, err := sealed.Lookup(ctx, "dr1", "/contracts-2026", "absent-memo.txt"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("sealed instance: Lookup of a missing name: %v", err)
	}
	listings, lookups := shared.asked()

	dump := shared.dump()
	if !strings.Contains(dump, ":ls:") {
		t.Fatalf("Redis holds no listing:\n%s", dump)
	}
	for _, secret := range []string{
		"contracts-2026", "merger-draft", "docx", "latest-offer", "final-bid", "offers", "absent-memo",
	} {
		if strings.Contains(dump, secret) {
			t.Errorf("Redis holds %q in clear", secret)
		}
	}

	nodes, err := clear.ReadDir(ctx, "dr1", "/contracts-2026")
	if err != nil {
		t.Fatalf("clear instance: ReadDir: %v", err)
	}
	if got := names(nodes); !slices.Equal(got, []string{"latest-offer", "merger-draft.docx"}) {
		t.Errorf("clear instance lists %v, want [latest-offer merger-draft.docx]", got)
	}
	for _, n := range nodes {
		if n.Type == TypeSymlink && n.Target != "offers/final-bid.pdf" {
			t.Errorf("clear instance reads the target %q", n.Target)
		}
	}
	mustLookup(t, clear, "/", "contracts-2026", "d-contracts")
	if l, k := shared.asked(); l != listings || k != lookups {
		t.Errorf("reading the sealed listings cost %d listings and %d lookups, want none", l-listings, k-lookups)
	}
}

// The sealed nodes read from the store are opened once FS.mu is let go: a
// decryption that takes its time holds the request that waits for it, not
// the other operations of the filesystem.
func TestSharedRedis_SealedNodesAreOpenedOutsideTheMutex(t *testing.T) {
	a := newTreeAPI(t)
	a.put("", "x", fakeNode{id: "d-x", kind: api.NodeTypeFolder})
	a.put("", "y", fakeNode{id: "d-y", kind: api.NodeTypeFolder})
	for _, name := range []string{"c.txt", "a.txt", "b.txt"} {
		a.put("d-x", name, fakeNode{id: "f-x-" + name, kind: api.NodeTypeFile})
		a.put("d-y", name, fakeNode{id: "f-y-" + name, kind: api.NodeTypeFile})
	}
	shared := newSharedRedis(t, a)
	ctx := context.Background()
	writer := shared.instance(true)
	for _, p := range []string{"/", "/x", "/y"} {
		if _, err := writer.ReadDir(ctx, "dr1", p); err != nil {
			t.Fatalf("writer: ReadDir(%s): %v", p, err)
		}
	}

	// A second instance has never decrypted these names: it reads them sealed.
	reader := shared.instance(true)
	listings, lookups := shared.asked()
	blocked, release := make(chan struct{}), make(chan struct{})
	// The first decryption only waits (not sync.Once: the others would wait
	// for it too).
	var first atomic.Bool
	reader.openHook = func() error {
		if first.CompareAndSwap(false, true) {
			close(blocked)
			<-release
		}

		return nil
	}
	done := make(chan []Node, 1)
	go func() {
		nodes, err := reader.ReadDir(ctx, "dr1", "/x")
		if err != nil {
			t.Errorf("reader: ReadDir(/x): %v", err)
		}
		done <- nodes
	}()
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("ReadDir(/x) opened no sealed node")
	}

	// While a name of /x is being decrypted, the other folder is served.
	other := make(chan error, 1)
	go func() {
		nodes, err := reader.ReadDir(ctx, "dr1", "/y")
		if err == nil && !slices.Equal(names(nodes), []string{"a.txt", "b.txt", "c.txt"}) {
			err = errors.New("ReadDir(/y) lists " + strings.Join(names(nodes), ","))
		}
		if err == nil {
			_, err = reader.Lookup(ctx, "dr1", "/y", "b.txt")
		}
		other <- err
	}()
	select {
	case err := <-other:
		if err != nil {
			t.Errorf("reader: /y while /x is opened: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("reader: /y waited for the decryption of a name of /x: FS.mu is held across it")
	}
	close(release)

	select {
	case nodes := <-done:
		if got := names(nodes); !slices.Equal(got, []string{"a.txt", "b.txt", "c.txt"}) {
			t.Errorf("reader: ReadDir(/x) = %v, want [a.txt b.txt c.txt]", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reader: ReadDir(/x) did not return")
	}
	mustLookup(t, reader, "/x", "c.txt", "f-x-c.txt")
	if l, k := shared.asked(); l != listings || k != lookups {
		t.Errorf("the reader cost %d listings and %d lookups, want none: it reads the store", l-listings, k-lookups)
	}
}

// A sealed node that does not open, now opened by the FS rather than by the
// store, still makes what holds it absent: the listing is fetched again, the
// name looked up at the API.
func TestSharedRedis_SealedNodeThatDoesNotOpenIsAbsent(t *testing.T) {
	a := newTreeAPI(t)
	a.put("", "x", fakeNode{id: "d-x", kind: api.NodeTypeFolder})
	a.put("d-x", "a.txt", fakeNode{id: "f-a", kind: api.NodeTypeFile})
	shared := newSharedRedis(t, a)
	ctx := context.Background()
	writer := shared.instance(true)
	for _, p := range []string{"/", "/x"} {
		if _, err := writer.ReadDir(ctx, "dr1", p); err != nil {
			t.Fatalf("writer: ReadDir(%s): %v", p, err)
		}
	}

	reader := shared.instance(true)
	reader.openHook = func() error { return errors.New("does not open") }
	listings, lookups := shared.asked()
	nodes, err := reader.ReadDir(ctx, "dr1", "/x")
	if err != nil || !slices.Equal(names(nodes), []string{"a.txt"}) {
		t.Fatalf("reader: ReadDir(/x) = %v, %v, want [a.txt]", names(nodes), err)
	}
	if l, _ := shared.asked(); l != listings+1 {
		t.Errorf("reader: ReadDir(/x) made %d listings, want 1: the stored one does not open", l-listings)
	}
	mustLookup(t, reader, "/x", "a.txt", "f-a")
	if _, k := shared.asked(); k == lookups {
		t.Error("reader: Lookup made no lookup by name: the stored listing does not open")
	}
}
