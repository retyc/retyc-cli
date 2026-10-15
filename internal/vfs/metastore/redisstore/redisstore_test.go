package redisstore

import (
	"reflect"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// testURLEnv names the Redis the tests run against, e.g.
// redis://localhost:6379/15. They need a real server (per-field expiry,
// scripts): without the variable they are skipped, except on CI, where they
// fail.
const testURLEnv = "REDISSTORE_TEST_URL"

const dr = "11111111-2222-3333-4444-555555555555"

// hsetBatch is the number of fields one HSET of lua/put_listing.lua carries.
const hsetBatch = 512

// fakeCodec hashes with a plain SHA-256 and "decrypts" by removing a prefix
// (see sealed).
type fakeCodec struct {
	unresolved atomic.Bool
	failOpen   atomic.Bool
	opens      atomic.Int64
}

const sealPrefix = "sealed:"

func (c *fakeCodec) Hash(dataroomID, s string) (string, bool) {
	if c.unresolved.Load() {
		return "", false
	}
	sum := sha256.Sum256([]byte(dataroomID + s))

	return hex.EncodeToString(sum[:]), true
}

func (c *fakeCodec) Open(_ context.Context, _ string, n *metastore.Node) error {
	c.opens.Add(1)
	name, ok := unseal(n.Sealed.Name)
	if !ok || c.failOpen.Load() {
		return errors.New("cannot open")
	}
	n.Name = name
	n.Target, _ = unseal(n.Sealed.Target)
	n.MIMEType, _ = unseal(n.Sealed.MIMEType)

	return nil
}

// sealed stands for a ciphertext: the prefix, then the value in hexadecimal
// so that a dump of Redis can be searched for the plaintext.
func sealed(v string) string {
	if v == "" {
		return ""
	}

	return sealPrefix + hex.EncodeToString([]byte(v))
}

func unseal(v string) (string, bool) {
	rest, ok := strings.CutPrefix(v, sealPrefix)
	if !ok {
		return "", false
	}
	raw, err := hex.DecodeString(rest)

	return string(raw), err == nil
}

// seal returns n with the sealed form of its decrypted fields.
func seal(n metastore.Node) metastore.Node {
	var s metastore.Sealed
	if n.Sealed != nil {
		s = *n.Sealed
	}
	s.Name, s.Target, s.MIMEType = sealed(n.Name), sealed(n.Target), sealed(n.MIMEType)
	n.Sealed = &s

	return n
}

// env is one test's corner of the Redis: a random prefix, removed at the end.
type env struct {
	t      *testing.T
	url    string
	prefix string
	raw    *redis.Client
	codec  *fakeCodec
}

func newEnv(t *testing.T) *env {
	t.Helper()
	url := os.Getenv(testURLEnv)
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is not set: the redisstore tests need a Redis", testURLEnv)
		}
		t.Skipf("%s is not set", testURLEnv)
	}
	ropts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("%s is not a Redis URL", testURLEnv)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	e := &env{
		t: t, url: url, prefix: "retyc-test-" + hex.EncodeToString(b[:]),
		raw: redis.NewClient(ropts), codec: &fakeCodec{},
	}
	t.Cleanup(func() {
		if keys := e.keys(); len(keys) > 0 {
			_ = e.raw.Unlink(context.Background(), keys...).Err()
		}
		_ = e.raw.Close()
	})

	return e
}

// keys lists the keys of the test's prefix.
func (e *env) keys() []string {
	e.t.Helper()
	var keys []string
	iter := e.raw.Scan(context.Background(), 0, e.prefix+":*", 1000).Iterator()
	for iter.Next(context.Background()) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		e.t.Fatalf("SCAN: %v", err)
	}

	return keys
}

// dump is everything Redis holds under the prefix: key names and contents.
func (e *env) dump() string {
	e.t.Helper()
	ctx := context.Background()
	var sb strings.Builder
	for _, k := range e.keys() {
		sb.WriteString(k + "\n")
		switch e.raw.Type(ctx, k).Val() {
		case "hash":
			for f, v := range e.raw.HGetAll(ctx, k).Val() {
				sb.WriteString("  " + f + " = " + v + "\n")
			}
		case "set":
			sb.WriteString("  " + strings.Join(e.raw.SMembers(ctx, k).Val(), " ") + "\n")
		default:
			sb.WriteString("  " + e.raw.Get(ctx, k).Val() + "\n")
		}
	}

	return sb.String()
}

// store opens a Store on the test's prefix, bound to its codec.
func (e *env) store(high bool, tune ...func(*Options)) *Store {
	e.t.Helper()
	opts := Options{
		URL: e.url, HighConfidentiality: high, Prefix: e.prefix,
		ListingLife: 30 * time.Second, EntryLife: 30 * time.Second, NegativeEntryLife: 10 * time.Second,
	}
	for _, f := range tune {
		f(&opts)
	}
	s, err := New(context.Background(), opts)
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	e.t.Cleanup(func() { _ = s.Close() })
	s.Bind(e.codec)

	return s
}

func lk(p string) metastore.ListingKey { return metastore.ListingKey{DataroomID: dr, Path: p} }
func ek(p, name string) metastore.EntryKey {
	return metastore.EntryKey{DataroomID: dr, ParentPath: p, Name: name}
}

func file(name string) metastore.Node {
	return metastore.Node{
		ID: "id-" + name, ParentID: "parent", Name: name, Type: metastore.TypeFile, VersionID: "v-" + name,
		ChunkCount: 3, Size: 1234, MIMEType: "text/x-" + name, Mode: 0o640,
		ModTime: time.Unix(1700000000, 123).UTC(), CreatedAt: time.Unix(1600000000, 0).UTC(),
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func put(t *testing.T, s *Store, p string, nodes ...metastore.Node) {
	t.Helper()
	must(t, s.PutListing(context.Background(), lk(p), &metastore.Listing{Nodes: nodes, FetchedAt: time.Now()}))
}

// held reports whether a listing is stored at p, and its nodes.
func held(t *testing.T, s *Store, p string) ([]metastore.Node, bool) {
	t.Helper()
	l, ok, err := s.GetListing(context.Background(), lk(p))
	must(t, err)
	if !ok {
		return nil, false
	}

	return l.Nodes, true
}

func gen(t *testing.T, s *Store, p string) uint64 {
	t.Helper()
	g, err := s.Generation(context.Background(), lk(p))
	must(t, err)

	return g
}

func names(nodes []metastore.Node) string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Name
	}

	return strings.Join(out, ",")
}

func TestListing_Conformance(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()

	// Nothing stored: absent everywhere; the generation is created, never 0.
	if _, ok := held(t, s, "/a"); ok {
		t.Fatal("a listing never put is held")
	}
	if _, ok, err := s.ListingMeta(ctx, lk("/a")); ok || err != nil {
		t.Fatalf("ListingMeta of nothing: ok=%v err=%v", ok, err)
	}
	if n, _, isHeld, err := s.GetNode(ctx, lk("/a"), "x"); n != nil || isHeld || err != nil {
		t.Fatalf("GetNode of nothing: node=%v held=%v err=%v", n, isHeld, err)
	}
	first := gen(t, s, "/a")
	if first == 0 || gen(t, s, "/a") != first {
		t.Fatalf("generation of nothing = %d, then %d", first, gen(t, s, "/a"))
	}

	// An empty listing is a listing.
	put(t, s, "/a")
	nodes, ok := held(t, s, "/a")
	if !ok || nodes == nil || len(nodes) != 0 {
		t.Fatalf("empty listing: nodes=%v ok=%v", nodes, ok)
	}
	if n, _, isHeld, err := s.GetNode(ctx, lk("/a"), "x"); n != nil || !isHeld || err != nil {
		t.Fatalf("GetNode in an empty listing: node=%v held=%v err=%v", n, isHeld, err)
	}
	if g := gen(t, s, "/a"); g != first+1 {
		t.Fatalf("generation after one put = %d", g)
	}

	// Every field of a node comes back, nodes sorted by name.
	dir := metastore.Node{ID: "id-dir", Name: "dir", Type: metastore.TypeDir}
	link := metastore.Node{ID: "id-link", Name: "link", Type: metastore.TypeSymlink, Target: "../elsewhere", Size: 12}
	must(t, s.PutListing(ctx, lk("/a"), &metastore.Listing{
		Nodes: []metastore.Node{link, file("zz"), dir}, FetchedAt: time.Now(), ETag: `W/"etag1"`,
	}))
	l, ok, err := s.GetListing(ctx, lk("/a"))
	must(t, err)
	if !ok || len(l.Nodes) != 3 || !reflect.DeepEqual(l.Nodes, []metastore.Node{dir, link, file("zz")}) {
		t.Fatalf("listing read back: ok=%v %+v", ok, l)
	}
	if l.ETag != `W/"etag1"` {
		t.Fatalf("ETag = %q", l.ETag)
	}
	meta, ok, err := s.ListingMeta(ctx, lk("/a"))
	if err != nil || !ok || meta.ETag != `W/"etag1"` || time.Since(meta.FetchedAt) > 5*time.Second {
		t.Fatalf("ListingMeta: %+v ok=%v err=%v", meta, ok, err)
	}
	n, meta, isHeld, err := s.GetNode(ctx, lk("/a"), "zz")
	if err != nil || !isHeld || n == nil || *n != file("zz") || meta.ETag != `W/"etag1"` {
		t.Fatalf("GetNode: %+v %+v held=%v err=%v", n, meta, isHeld, err)
	}

	// Upsert adds and replaces, empties the ETag, bumps the generation.
	before := gen(t, s, "/a")
	g, err := s.UpsertNode(ctx, lk("/a"), file("new"))
	must(t, err)
	if g != before+1 || gen(t, s, "/a") != g {
		t.Fatalf("generation after upsert = %d, want %d", g, before+1)
	}
	changed := file("zz")
	changed.Size = 99
	_, err = s.UpsertNode(ctx, lk("/a"), changed)
	must(t, err)
	l, _, err = s.GetListing(ctx, lk("/a"))
	must(t, err)
	if names(l.Nodes) != "dir,link,new,zz" || l.Nodes[3].Size != 99 || l.ETag != "" {
		t.Fatalf("after upserts: %s size=%d etag=%q", names(l.Nodes), l.Nodes[3].Size, l.ETag)
	}

	// Remove drops the child, present or not, and bumps either way.
	before = gen(t, s, "/a")
	g, err = s.RemoveNode(ctx, lk("/a"), "link")
	must(t, err)
	g2, err := s.RemoveNode(ctx, lk("/a"), "never-there")
	must(t, err)
	nodes, _ = held(t, s, "/a")
	if names(nodes) != "dir,new,zz" || g != before+1 || g2 != before+2 {
		t.Fatalf("after removes: %s gen %d, %d (from %d)", names(nodes), g, g2, before)
	}

	// Delete removes the listing and bumps.
	must(t, s.DeleteListing(ctx, lk("/a")))
	if _, ok := held(t, s, "/a"); ok || gen(t, s, "/a") != before+3 {
		t.Fatalf("after delete: held=%v gen=%d", ok, gen(t, s, "/a"))
	}

	// An edit without a listing stores nothing, and still bumps.
	g, err = s.UpsertNode(ctx, lk("/a"), file("orphan"))
	must(t, err)
	g2, err = s.RemoveNode(ctx, lk("/a"), "orphan")
	must(t, err)
	if _, ok := held(t, s, "/a"); ok || g != before+4 || g2 != before+5 {
		t.Fatalf("edits without a listing: held=%v gen %d, %d", ok, g, g2)
	}
	f, _ := s.folder(dr, "/a")
	if n := e.raw.Exists(ctx, f.ls).Val(); n != 0 {
		t.Fatal("an upsert without a listing created its hash")
	}
}

func TestListing_Large(t *testing.T) {
	e := newEnv(t)
	high, clear := e.store(true), e.store(false)
	nodes := make([]metastore.Node, 3*hsetBatch+7)
	for i := range nodes {
		nodes[i] = seal(file(fmt.Sprintf("f%05d", i)))
	}
	put(t, high, "/big", nodes...)
	got, ok := held(t, clear, "/big")
	if !ok || len(got) != len(nodes) {
		t.Fatalf("large listing: %d nodes, ok=%v", len(got), ok)
	}
	for i := range got {
		if !reflect.DeepEqual(got[i], nodes[i]) {
			t.Fatalf("node %d: %+v, want %+v", i, got[i], nodes[i])
		}
	}
	if opens := e.codec.opens.Load(); opens != int64(len(nodes)) {
		t.Fatalf("%d nodes opened, want %d", opens, len(nodes))
	}
	// One node that does not open makes the listing absent, not shorter.
	e.codec.failOpen.Store(true)
	if _, ok := held(t, clear, "/big"); ok {
		t.Fatal("a listing with nodes that cannot be opened is served")
	}
}

func TestFetchedAt_ComesFromRedis(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	// A second process, configured with another lifetime, reads the same age.
	other := e.store(false, func(o *Options) { o.ListingLife = time.Hour })
	ctx := context.Background()

	wrote := time.Now()
	put(t, s, "/a", file("x"))
	m1, _, err := s.ListingMeta(ctx, lk("/a"))
	must(t, err)
	time.Sleep(250 * time.Millisecond)
	_, err = s.UpsertNode(ctx, lk("/a"), file("y"))
	must(t, err)

	m2, ok, err := s.ListingMeta(ctx, lk("/a"))
	must(t, err)
	l, _, err := other.GetListing(ctx, lk("/a"))
	must(t, err)
	_, m3, _, err := other.GetNode(ctx, lk("/a"), "x")
	must(t, err)
	for _, at := range []time.Time{m1.FetchedAt, m2.FetchedAt, l.FetchedAt, m3.FetchedAt} {
		if d := at.Sub(wrote); !ok || d < -100*time.Millisecond || d > 100*time.Millisecond {
			t.Fatalf("FetchedAt is %v away from the write (an upsert must not make the listing younger)", d)
		}
	}

	// A listing fetched a while before it is stored is as old as its fetch.
	must(t, s.PutListing(ctx, lk("/old"), &metastore.Listing{FetchedAt: time.Now().Add(-10 * time.Second)}))
	m, ok, err := s.ListingMeta(ctx, lk("/old"))
	must(t, err)
	if age := time.Since(m.FetchedAt); !ok || age < 10*time.Second || age > 11*time.Second {
		t.Fatalf("age of a listing fetched 10 s ago = %v (ok=%v)", age, ok)
	}
	// One fetched longer ago than its lifetime is not kept, and replaces.
	must(t, s.PutListing(ctx, lk("/old"), &metastore.Listing{FetchedAt: time.Now().Add(-time.Minute)}))
	if _, ok := held(t, s, "/old"); ok {
		t.Fatal("a listing older than its lifetime is held")
	}

	// Entries: same rule, per field.
	must(t, s.PutEntry(ctx, ek("/a", "n"), &metastore.Entry{FetchedAt: time.Now().Add(-3 * time.Second)}))
	time.Sleep(200 * time.Millisecond)
	en, ok, err := other.GetEntry(ctx, ek("/a", "n"))
	must(t, err)
	if age := time.Since(en.FetchedAt); !ok || age < 3200*time.Millisecond || age > 4*time.Second {
		t.Fatalf("age of an entry fetched 3.2 s ago = %v (ok=%v)", age, ok)
	}
}

func TestExpiry(t *testing.T) {
	e := newEnv(t)
	s := e.store(false, func(o *Options) {
		o.ListingLife, o.EntryLife, o.NegativeEntryLife = 400*time.Millisecond, 400*time.Millisecond, 150*time.Millisecond
	})
	ctx := context.Background()
	x := file("x")
	put(t, s, "/a", x)
	g := gen(t, s, "/a")
	must(t, s.PutEntry(ctx, ek("/a", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	must(t, s.PutEntry(ctx, ek("/a", "gone"), &metastore.Entry{FetchedAt: time.Now()}))
	has := func(name string) bool {
		_, ok, err := s.GetEntry(ctx, ek("/a", name))
		must(t, err)

		return ok
	}
	if _, ok := held(t, s, "/a"); !ok || !has("x") || !has("gone") {
		t.Fatal("values are not held right after the write")
	}
	time.Sleep(250 * time.Millisecond)
	if _, ok := held(t, s, "/a"); !ok || !has("x") || has("gone") {
		t.Fatal("after 250 ms: want the listing and the positive entry, not the negative one")
	}
	time.Sleep(300 * time.Millisecond)
	if _, ok := held(t, s, "/a"); ok || has("x") {
		t.Fatal("after 550 ms the listing or the positive entry is still held")
	}
	// The generation outlives the listing.
	if gen(t, s, "/a") != g {
		t.Fatal("the generation went with the listing")
	}
}

func TestPutListingIf_TwoInstances(t *testing.T) {
	e := newEnv(t)
	a, b := e.store(false), e.store(false)
	ctx := context.Background()
	fresh := &metastore.Listing{Nodes: []metastore.Node{file("x")}, FetchedAt: time.Now()}

	// The other instance wrote the folder while the listing was fetched.
	g := gen(t, a, "/a")
	_, err := b.UpsertNode(ctx, lk("/a"), file("y"))
	must(t, err)
	stored, err := a.PutListingIf(ctx, lk("/a"), fresh, g)
	if stored || err != nil {
		t.Fatalf("PutListingIf after a foreign write: stored=%v err=%v", stored, err)
	}
	if _, ok := held(t, b, "/a"); ok {
		t.Fatal("a refused listing was stored")
	}

	// Nothing moved: stored, seen by the other instance, generation bumped.
	g = gen(t, a, "/a")
	stored, err = a.PutListingIf(ctx, lk("/a"), fresh, g)
	if !stored || err != nil {
		t.Fatalf("PutListingIf with the current generation: stored=%v err=%v", stored, err)
	}
	nodes, ok := held(t, b, "/a")
	if !ok || names(nodes) != "x" || gen(t, b, "/a") != g+1 {
		t.Fatalf("after the put: %s ok=%v gen=%d", names(nodes), ok, gen(t, b, "/a"))
	}
	// The generation it was stored at is not current any more.
	if stored, _ := a.PutListingIf(ctx, lk("/a"), fresh, g); stored {
		t.Fatal("PutListingIf with a past generation stored")
	}
}

func TestPutListingIf_Race(t *testing.T) {
	e := newEnv(t)
	const n = 24
	stores := []*Store{e.store(false), e.store(false), e.store(true)}
	g := gen(t, stores[0], "/race")
	var (
		wg     sync.WaitGroup
		wins   atomic.Int64
		winner atomic.Value
		start  = make(chan struct{})
	)
	for i := range n {
		wg.Go(func() {
			name := fmt.Sprintf("writer-%02d", i)
			l := &metastore.Listing{Nodes: []metastore.Node{seal(file(name))}, FetchedAt: time.Now()}
			<-start
			stored, err := stores[i%len(stores)].PutListingIf(context.Background(), lk("/race"), l, g)
			if err != nil {
				t.Errorf("PutListingIf: %v", err)
			}
			if stored {
				wins.Add(1)
				winner.Store(name)
			}
		})
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d writers stored their listing, want 1", wins.Load())
	}
	nodes, ok := held(t, stores[0], "/race")
	if !ok || names(nodes) != winner.Load().(string) || gen(t, stores[0], "/race") != g+1 {
		t.Fatalf("listing held: %s ok=%v gen=%d, winner %v", names(nodes), ok, gen(t, stores[0], "/race"), winner.Load())
	}
}

func TestDeleteSubtree(t *testing.T) {
	e := newEnv(t)
	s, other := e.store(false), e.store(true)
	ctx := context.Background()
	all := []string{"/", "/a", "/a/b/c", "/ab", "/z/a"}
	before := map[string]uint64{}
	for _, p := range all {
		put(t, s, p, file("x"))
		before[p] = gen(t, s, p)
	}
	x := file("x")
	must(t, s.PutEntry(ctx, ek("/a/b", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	must(t, other.DeleteSubtree(ctx, dr, "/a"))
	for p, want := range map[string]bool{"/": true, "/a": false, "/a/b/c": false, "/ab": true, "/z/a": true} {
		_, ok := held(t, s, p)
		if moved := gen(t, s, p) != before[p]; ok != want || moved == want {
			t.Errorf("%s: held=%v generation moved=%v, want held=%v", p, ok, moved, want)
		}
	}
	// The entries are not the listings: DeleteSubtree leaves them.
	if _, ok, err := s.GetEntry(ctx, ek("/a/b", "x")); !ok || err != nil {
		t.Errorf("an entry below went with DeleteSubtree: ok=%v err=%v", ok, err)
	}
	// A folder below that holds no listing yet: the subtree is still swept
	// when it gets one later, and a stale member of the index costs nothing.
	put(t, s, "/a/b/c", file("x"))
	must(t, s.DeleteSubtree(ctx, dr, "/a/b"))
	if _, ok := held(t, s, "/a/b/c"); ok {
		t.Error("/a/b/c survived DeleteSubtree(/a/b)")
	}
	must(t, s.DeleteSubtree(ctx, dr, "/"))
	for _, p := range all {
		if _, ok := held(t, s, p); ok {
			t.Errorf("%s survived DeleteSubtree(/)", p)
		}
	}
}

func TestEntries(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	x := file("x")
	get := func(p, name string) (*metastore.Entry, bool) {
		t.Helper()
		en, ok, err := s.GetEntry(ctx, ek(p, name))
		must(t, err)

		return en, ok
	}
	if _, ok := get("/a", "x"); ok {
		t.Fatal("an entry never put is held")
	}
	must(t, s.PutEntry(ctx, ek("/a", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	must(t, s.PutEntry(ctx, ek("/a", "none"), &metastore.Entry{FetchedAt: time.Now()}))
	if en, ok := get("/a", "x"); !ok || en.Node == nil || *en.Node != x || time.Since(en.FetchedAt) > 5*time.Second {
		t.Fatalf("positive entry: %+v ok=%v", en, ok)
	}
	if en, ok := get("/a", "none"); !ok || en.Node != nil {
		t.Fatalf("negative entry: %+v ok=%v", en, ok)
	}
	// An entry replaces the previous one of its name.
	must(t, s.PutEntry(ctx, ek("/a", "x"), &metastore.Entry{FetchedAt: time.Now()}))
	if en, ok := get("/a", "x"); !ok || en.Node != nil {
		t.Fatalf("entry replaced by a negative one: %+v ok=%v", en, ok)
	}

	// DeleteEntries: that folder, no other.
	for _, p := range []string{"/", "/a", "/a/b", "/a/b/c", "/ab"} {
		must(t, s.PutEntry(ctx, ek(p, "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	}
	must(t, s.PutEntry(ctx, ek("/", "a"), &metastore.Entry{FetchedAt: time.Now()}))
	must(t, s.DeleteEntries(ctx, dr, "/a/b"))
	for p, want := range map[string]bool{"/": true, "/a": true, "/a/b": false, "/a/b/c": true, "/ab": true} {
		if _, ok := get(p, "x"); ok != want {
			t.Errorf("after DeleteEntries(/a/b), entry of %s held=%v", p, ok)
		}
	}
	// DeleteEntriesBelow: the folder and below; the entry naming the folder
	// is its parent's.
	must(t, s.DeleteEntriesBelow(ctx, dr, "/a"))
	for p, want := range map[string]bool{"/": true, "/a": false, "/a/b/c": false, "/ab": true} {
		if _, ok := get(p, "x"); ok != want {
			t.Errorf("after DeleteEntriesBelow(/a), entry of %s held=%v", p, ok)
		}
	}
	if _, ok := get("/", "a"); !ok {
		t.Error("DeleteEntriesBelow(/a) removed the entry that names /a")
	}

	// No negative lifetime: a negative entry is not stored, and still
	// replaces what was there.
	none := e.store(false, func(o *Options) { o.NegativeEntryLife = 0 })
	must(t, none.PutEntry(ctx, ek("/", "x"), &metastore.Entry{FetchedAt: time.Now()}))
	if _, ok := get("/", "x"); ok {
		t.Error("a negative entry was stored, or left the positive one, with no negative lifetime")
	}
}

func TestHighConfidentiality(t *testing.T) {
	e := newEnv(t)
	high, clear := e.store(true), e.store(false)
	ctx := context.Background()
	secrets := []string{"confidential-dir", "secret-report", "secret-target", "x-secret-mime", "missing-name"}
	doc := seal(metastore.Node{
		ID: "id-doc", Name: "secret-report.pdf", Type: metastore.TypeFile, MIMEType: "application/x-secret-mime", Size: 7,
	})
	link := seal(metastore.Node{
		ID: "id-link", Name: "secret-report.lnk", Type: metastore.TypeSymlink, Target: "/secret-target",
	})
	const dir = "/confidential-dir/sub"

	put(t, high, dir, doc, link)
	must(t, high.PutEntry(ctx, ek(dir, doc.Name), &metastore.Entry{Node: &doc, FetchedAt: time.Now()}))
	must(t, high.PutEntry(ctx, ek(dir, "missing-name"), &metastore.Entry{FetchedAt: time.Now()}))
	_, err := high.UpsertNode(ctx, lk(dir), link)
	must(t, err)

	// Nothing in Redis, key or value, names a file, a folder, a target or a
	// MIME type.
	dump := e.dump()
	for _, secret := range secrets {
		if strings.Contains(dump, secret) {
			t.Fatalf("%q is readable in Redis:\n%s", secret, dump)
		}
	}
	if !strings.Contains(dump, doc.Sealed.Name) || !strings.Contains(dump, link.Sealed.Target) {
		t.Fatalf("no sealed value in Redis:\n%s", dump)
	}

	// Both configurations read the sealed values.
	for _, s := range []*Store{clear, high} {
		nodes, ok := held(t, s, dir)
		if !ok || len(nodes) != 2 || !reflect.DeepEqual(nodes, []metastore.Node{link, doc}) {
			t.Fatalf("sealed listing read back: %+v ok=%v", nodes, ok)
		}
		n, _, isHeld, err := s.GetNode(ctx, lk(dir), doc.Name)
		if err != nil || !isHeld || n == nil || !reflect.DeepEqual(*n, doc) {
			t.Fatalf("sealed node read back: %+v held=%v err=%v", n, isHeld, err)
		}
		en, ok, err := s.GetEntry(ctx, ek(dir, doc.Name))
		if err != nil || !ok || en.Node == nil || !reflect.DeepEqual(*en.Node, doc) {
			t.Fatalf("sealed entry read back: %+v ok=%v err=%v", en, ok, err)
		}
		if en, ok, _ := s.GetEntry(ctx, ek(dir, "missing-name")); !ok || en.Node != nil {
			t.Fatalf("negative entry read back: %+v ok=%v", en, ok)
		}
	}

	// A clear writer adds to the same hash; the hash now mixes both forms and
	// both configurations read it. The clear value does hold the name.
	plain := file("plain-name")
	_, err = clear.UpsertNode(ctx, lk(dir), plain)
	must(t, err)
	if !strings.Contains(e.dump(), "plain-name") {
		t.Fatal("a clear writer did not store the name")
	}
	for _, s := range []*Store{clear, high} {
		if nodes, ok := held(t, s, dir); !ok || names(nodes) != "plain-name,secret-report.lnk,secret-report.pdf" {
			t.Fatalf("mixed listing: %s ok=%v", names(nodes), ok)
		}
	}

	// A node without sealed form cannot be written sealed: the listing goes,
	// rather than lack a name.
	before := gen(t, high, dir)
	g, err := high.UpsertNode(ctx, lk(dir), file("unsealed"))
	must(t, err)
	if _, ok := held(t, clear, dir); ok || g != before+1 {
		t.Fatalf("upsert of an unsealed node: listing held=%v gen=%d (from %d)", ok, g, before)
	}
	// Same for a whole listing: nothing stored, the previous one removed.
	put(t, high, dir, doc)
	put(t, high, dir, doc, file("unsealed"))
	if _, ok := held(t, clear, dir); ok {
		t.Fatal("a listing with an unsealed node was stored, or the previous one kept")
	}
	put(t, high, dir, doc)
	g = gen(t, high, dir)
	bad := &metastore.Listing{Nodes: []metastore.Node{file("unsealed")}, FetchedAt: time.Now()}
	stored, err := high.PutListingIf(ctx, lk(dir), bad, g)
	if _, ok := held(t, clear, dir); ok || stored || err != nil {
		t.Fatalf("PutListingIf with an unsealed node: stored=%v held=%v err=%v", stored, ok, err)
	}
	// And for a positive entry: the field goes.
	unsealed := file("unsealed")
	must(t, high.PutEntry(ctx, ek(dir, doc.Name), &metastore.Entry{Node: &unsealed, FetchedAt: time.Now()}))
	if _, ok, _ := clear.GetEntry(ctx, ek(dir, doc.Name)); ok {
		t.Fatal("an unsealed positive entry was stored, or the previous one kept")
	}
	if strings.Contains(e.dump(), "unsealed") {
		t.Fatal("an unsealed name reached Redis in high confidentiality")
	}
}

func TestUnresolved_AbsentWithoutError(t *testing.T) {
	e := newEnv(t)
	bound := e.store(false)
	put(t, bound, "/a", file("x"))
	x := file("x")
	must(t, bound.PutEntry(context.Background(), ek("/a", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	keysBefore := len(e.keys())

	unbound := e.store(false)
	unbound.Bind(nil)
	e.codec.unresolved.Store(true)
	for name, s := range map[string]*Store{"unresolved session": bound, "no codec": unbound} {
		ctx := context.Background()
		l, ok, err := s.GetListing(ctx, lk("/a"))
		if l != nil || ok || err != nil {
			t.Errorf("%s: GetListing = %v, %v, %v", name, l, ok, err)
		}
		if _, ok, err := s.ListingMeta(ctx, lk("/a")); ok || err != nil {
			t.Errorf("%s: ListingMeta = %v, %v", name, ok, err)
		}
		if n, _, isHeld, err := s.GetNode(ctx, lk("/a"), "x"); n != nil || isHeld || err != nil {
			t.Errorf("%s: GetNode = %v, %v, %v", name, n, isHeld, err)
		}
		if en, ok, err := s.GetEntry(ctx, ek("/a", "x")); en != nil || ok || err != nil {
			t.Errorf("%s: GetEntry = %v, %v, %v", name, en, ok, err)
		}
		if g, err := s.Generation(ctx, lk("/a")); g != 0 || err != nil {
			t.Errorf("%s: Generation = %d, %v", name, g, err)
		}
		if stored, err := s.PutListingIf(ctx, lk("/b"), &metastore.Listing{}, 0); stored || err != nil {
			t.Errorf("%s: PutListingIf = %v, %v", name, stored, err)
		}
		_, err1 := s.UpsertNode(ctx, lk("/a"), x)
		_, err2 := s.RemoveNode(ctx, lk("/a"), "x")
		for _, err := range []error{
			err1, err2,
			s.PutListing(ctx, lk("/b"), &metastore.Listing{}), s.DeleteListing(ctx, lk("/a")),
			s.DeleteSubtree(ctx, dr, "/"), s.PutEntry(ctx, ek("/b", "x"), &metastore.Entry{}),
			s.DeleteEntries(ctx, dr, "/a"), s.DeleteEntriesBelow(ctx, dr, "/"),
		} {
			if err != nil {
				t.Errorf("%s: a write failed: %v", name, err)
			}
		}
	}
	if got := len(e.keys()); got != keysBefore {
		t.Errorf("writes without a hash changed Redis: %d keys, %d before", got, keysBefore)
	}
	// Once the session is resolved, what was stored is still there.
	e.codec.unresolved.Store(false)
	if nodes, ok := held(t, bound, "/a"); !ok || names(nodes) != "x" {
		t.Errorf("listing after the session resolved: %s ok=%v", names(nodes), ok)
	}
}

func TestUnreadableValues_Absent(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	f, _ := s.folder(dr, "/a")
	xh, _ := f.hash("x")
	reset := func() {
		t.Helper()
		put(t, s, "/a", file("x"), file("y"))
	}
	absent := func(what string) {
		t.Helper()
		if l, ok, err := s.GetListing(ctx, lk("/a")); l != nil || ok || err != nil {
			t.Errorf("%s: GetListing = %v, %v, %v", what, l, ok, err)
		}
		if n, _, isHeld, err := s.GetNode(ctx, lk("/a"), "x"); n != nil || isHeld || err != nil {
			t.Errorf("%s: GetNode = %v, %v, %v", what, n, isHeld, err)
		}
	}

	for what, value := range map[string]string{
		"garbage node":         "\x00not json{",
		"node of a new format": `{"v":99,"id":"i","name":"x"}`,
		"node without a name":  `{"v":1,"id":"i"}`,
		"node of another type": `[1,2,3]`,
	} {
		reset()
		must(t, e.raw.HSet(ctx, f.ls, nodePrefix+xh, value).Err())
		absent(what)
		// The other child is untouched, and still answered.
		if n, _, isHeld, err := s.GetNode(ctx, lk("/a"), "y"); n == nil || !isHeld || err != nil {
			t.Errorf("%s: GetNode of a readable sibling = %v, %v, %v", what, n, isHeld, err)
		}
	}
	for what, value := range map[string]string{
		"garbage meta":         "{{{",
		"meta of a new format": `99:30000`,
		"meta without a life":  `1:`,
		"meta of a zero life":  `1:0`,
		"meta with a sign":     `1:-30000`,
		"meta with a tail":     `1:30000:x`,
		"meta as JSON":         `{"v":1,"life_ms":30000}`,
	} {
		reset()
		must(t, e.raw.HSet(ctx, f.ls, metaField, value).Err())
		absent(what)
		if _, ok, err := s.ListingMeta(ctx, lk("/a")); ok || err != nil {
			t.Errorf("%s: ListingMeta = %v, %v", what, ok, err)
		}
		// An edit cannot keep such a listing: it goes.
		_, err := s.UpsertNode(ctx, lk("/a"), file("z"))
		must(t, err)
		if n := e.raw.Exists(ctx, f.ls).Val(); n != 0 {
			t.Errorf("%s: the listing survived an edit", what)
		}
	}
	// A listing nothing gave a lifetime to has no age.
	reset()
	must(t, e.raw.Persist(ctx, f.ls).Err())
	absent("listing without a lifetime")
	// A generation that is not a number is an error, not a panic.
	must(t, e.raw.Set(ctx, f.gen, "oops", time.Minute).Err())
	if _, err := s.Generation(ctx, lk("/a")); err == nil {
		t.Error("a generation that is not a number was read")
	}
	must(t, e.raw.Del(ctx, f.gen).Err())

	// Entries.
	x := file("x")
	for what, value := range map[string]string{
		"garbage entry":         "nope",
		"entry of a new format": `{"v":2,"life_ms":1000}`,
		"entry of a bad node":   `{"v":1,"life_ms":1000,"node":{"v":1,"id":"i"}}`,
	} {
		must(t, s.PutEntry(ctx, ek("/a", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
		// HSET keeps... nothing of the field's lifetime: it is given again.
		must(t, e.raw.HSet(ctx, f.entries, xh, value).Err())
		must(t, e.raw.HPExpire(ctx, f.entries, time.Minute, xh).Err())
		if en, ok, err := s.GetEntry(ctx, ek("/a", "x")); en != nil || ok || err != nil {
			t.Errorf("%s: GetEntry = %v, %v, %v", what, en, ok, err)
		}
	}
	// An entry without a lifetime has no age either.
	must(t, s.PutEntry(ctx, ek("/a", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	must(t, e.raw.HPersist(ctx, f.entries, xh).Err())
	if _, ok, err := s.GetEntry(ctx, ek("/a", "x")); ok || err != nil {
		t.Errorf("entry without a lifetime: ok=%v err=%v", ok, err)
	}
}

func TestDatarooms_InMemory(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	if l, ok, err := s.GetDatarooms(ctx); l != nil || ok || err != nil {
		t.Fatalf("GetDatarooms of nothing = %v, %v, %v", l, ok, err)
	}
	list := &metastore.DataroomList{
		Items: []metastore.DataroomInfo{{ID: dr, Title: "private-title"}}, FetchedAt: time.Now(),
	}
	must(t, s.PutDatarooms(ctx, list))
	if l, ok, _ := s.GetDatarooms(ctx); !ok || l != list {
		t.Fatalf("GetDatarooms = %v, %v", l, ok)
	}
	// It is this process's alone.
	if _, ok, _ := e.store(false).GetDatarooms(ctx); ok {
		t.Fatal("the dataroom list is shared")
	}
	if strings.Contains(e.dump(), "private-title") {
		t.Fatal("the dataroom list reached Redis")
	}
}

func TestKeys_Schema(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	put(t, s, "/dir/sub", file("x"))
	for _, k := range e.keys() {
		rest, ok := strings.CutPrefix(k, e.prefix+":v2:{"+dr+"}:")
		kind, h, _ := strings.Cut(rest, ":")
		if !ok || len(h) != 64 || (kind != "ls" && kind != "g" && kind != "tl") {
			t.Errorf("unexpected key %q", k)
		}
		if ttl := e.raw.PTTL(context.Background(), k).Val(); ttl <= 0 {
			t.Errorf("key %q has no lifetime", k)
		}
	}
	def, err := New(context.Background(), Options{URL: e.url, ListingLife: time.Second, EntryLife: time.Second})
	must(t, err)
	if def.prefix != DefaultPrefix {
		t.Errorf("default prefix = %q", def.prefix)
	}
	must(t, def.Close())
}

func TestNew_ErrorsNeverHoldTheURL(t *testing.T) {
	lives := Options{ListingLife: time.Second, EntryLife: time.Second}
	for name, url := range map[string]string{ //nolint:gosec // G101: made-up credentials, the point of the test
		"closed port":    "redis://user:s3cr3t-pass@127.0.0.1:1/0",
		"unknown scheme": "http://user:s3cr3t-pass@127.0.0.1:1/0",
		"not a URL":      "redis://user:s3cr3t-pass@127.0.0.1:1/0\x7f%zz",
		"bad database":   "redis://user:s3cr3t-pass@127.0.0.1:1/notadb",
	} {
		opts := lives
		opts.URL = url
		s, err := New(context.Background(), opts)
		if err == nil {
			_ = s.Close()
			t.Fatalf("%s: New succeeded", name)
		}
		if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(fmt.Sprintf("%+v %#v", err, err), "s3cr3t") {
			t.Errorf("%s: the error holds the password: %v", name, err)
		}
		if !strings.HasPrefix(err.Error(), "redisstore: ") {
			t.Errorf("%s: error %q does not say where it comes from", name, err)
		}
	}
	if _, err := New(context.Background(), Options{URL: "redis://127.0.0.1:1"}); err == nil {
		t.Error("New accepted lifetimes of zero")
	}
}

func TestErrors_AreWrapped(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := s.GetListing(ctx, lk("/a"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GetListing with a context that is over = %v", err)
	}
	if _, err := s.PutListingIf(ctx, lk("/a"), &metastore.Listing{}, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("PutListingIf with a context that is over = %v", err)
	}
	must(t, s.Close())
	if err := s.PutListing(context.Background(), lk("/a"), &metastore.Listing{}); err == nil {
		t.Fatal("a write on a closed store succeeded")
	}
	must(t, s.Close())
}

func TestServerVersion(t *testing.T) {
	v, ok := serverVersion("# Server\r\nredis_version:8.10.2\r\nredis_mode:standalone\r\n")
	if !ok || v != "8.10.2" {
		t.Fatalf("serverVersion = %q, %v", v, ok)
	}
	if _, ok := serverVersion("# Server\r\n"); ok {
		t.Fatal("a version was read out of nothing")
	}
	for version, want := range map[string]bool{
		"7.4.0": true, "7.4": true, "8.0.1": true, "8.10.2": true, "10.0.0": true,
		"7.2.5": false, "6.2.14": false, "7": false, "": false, "x.y.z": false,
	} {
		if got := versionAtLeast(version, minVersion); got != want {
			t.Errorf("versionAtLeast(%q) = %v, want %v", version, got, want)
		}
	}
}
