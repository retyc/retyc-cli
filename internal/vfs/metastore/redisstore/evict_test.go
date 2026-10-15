package redisstore

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// The eviction tests: Redis under maxmemory-policy allkeys-lru may evict any
// key at any time. An eviction may cost a miss, never a stale value nor a
// write that should have been refused. Evictions are simulated by UNLINK.

// evict removes keys as Redis would evict them.
func (e *env) evict(keys ...string) {
	e.t.Helper()
	must(e.t, e.raw.Unlink(context.Background(), keys...).Err())
}

// An ancestor's listing token gone: every listing below reads absent, by
// every read; the entries keep theirs. Its entry token gone: the entries
// below read absent, the listings stay.
func TestEviction_AncestorTokens(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	x := file("x")
	a, _ := s.folder(dr, "/a")
	listings := func() bool {
		t.Helper()
		_, inListing := held(t, s, "/a/b/c")
		_, metaHeld, err := s.ListingMeta(ctx, lk("/a/b/c"))
		must(t, err)
		_, _, nodeHeld, err := s.GetNode(ctx, lk("/a/b/c"), "x")
		must(t, err)
		_, _, namedHeld, _, _, err := s.GetNamed(ctx, lk("/a/b/c"), "x")
		must(t, err)
		if inListing != metaHeld || inListing != nodeHeld || inListing != namedHeld {
			t.Fatalf("the reads disagree: GetListing %v, ListingMeta %v, GetNode %v, GetNamed %v",
				inListing, metaHeld, nodeHeld, namedHeld)
		}

		return inListing
	}
	entries := func() bool {
		t.Helper()
		_, ok, err := s.GetEntry(ctx, ek("/a/b/c", "x"))
		must(t, err)
		_, _, _, _, named, err := s.GetNamed(ctx, lk("/a/b/c"), "x")
		must(t, err)
		if ok != named {
			t.Fatalf("GetEntry %v, GetNamed %v", ok, named)
		}

		return ok
	}
	write := func() {
		t.Helper()
		put(t, s, "/a/b/c", x)
		must(t, s.PutEntry(ctx, ek("/a/b/c", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
		if !listings() || !entries() {
			t.Fatal("values not held right after the write")
		}
	}

	write()
	e.evict(a.tl[1]) // the listing token of /a
	if listings() {
		t.Error("a listing below an evicted listing token is served")
	}
	if !entries() {
		t.Error("an evicted listing token took the entries along")
	}
	// The next write settles a new token: written under it, served again.
	write()
	e.evict(a.te[0]) // the entry token of the root
	if entries() {
		t.Error("an entry below an evicted entry token is served")
	}
	if !listings() {
		t.Error("an evicted entry token took the listings along")
	}
	// An entry written now does not bring back the stale ones: the hash is
	// emptied first.
	y := file("y")
	must(t, s.PutEntry(ctx, ek("/a/b/c", "y"), &metastore.Entry{Node: &y, FetchedAt: time.Now()}))
	if entries() {
		t.Error("a stale entry came back with a write of its neighbour")
	}
	if _, ok, err := s.GetEntry(ctx, ek("/a/b/c", "y")); !ok || err != nil {
		t.Errorf("the entry just written is not served: %v", err)
	}
}

// DeleteSubtree sweeps the listings at and below a folder and not the
// entries; DeleteEntriesBelow the reverse. Each is one SET.
func TestDeleteSubtree_ListingsNotEntries(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	x := file("x")
	for _, p := range []string{"/a", "/a/b", "/ab"} {
		put(t, s, p, x)
		must(t, s.PutEntry(ctx, ek(p, "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	}
	state := func() string {
		t.Helper()
		var out []string
		for _, p := range []string{"/a", "/a/b", "/ab"} {
			_, l := held(t, s, p)
			_, en, err := s.GetEntry(ctx, ek(p, "x"))
			must(t, err)
			out = append(out, fmt.Sprintf("%s:%v/%v", p, l, en))
		}

		return strings.Join(out, " ")
	}
	must(t, s.DeleteSubtree(ctx, dr, "/a"))
	if got, want := state(), "/a:false/true /a/b:false/true /ab:true/true"; got != want {
		t.Errorf("after DeleteSubtree(/a): %s, want %s", got, want)
	}
	for _, p := range []string{"/a", "/a/b"} {
		put(t, s, p, x)
	}
	must(t, s.DeleteEntriesBelow(ctx, dr, "/a"))
	if got, want := state(), "/a:true/false /a/b:true/false /ab:true/true"; got != want {
		t.Errorf("after DeleteEntriesBelow(/a): %s, want %s", got, want)
	}
}

// A generation evicted between the read that starts a fetch and the write
// of its answer refuses the write, whatever the write; read again, it is
// another one (no ABA: a counter would have started over at its old value).
func TestEviction_GenerationRefusesTheWrite(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	f, _ := s.folder(dr, "/a")
	x := file("x")
	l := &metastore.Listing{Nodes: []metastore.Node{x}, FetchedAt: time.Now()}

	put(t, s, "/a", x)
	for what, write := range map[string]func(uint64) (bool, error){
		"PutListingIf": func(g uint64) (bool, error) { return s.PutListingIf(ctx, lk("/a"), l, g) },
		"PutEntryIf": func(g uint64) (bool, error) {
			return s.PutEntryIf(ctx, ek("/a", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}, g)
		},
		"RenewListingIf": func(g uint64) (bool, error) { return s.RenewListingIf(ctx, lk("/a"), "e", time.Now(), g) },
	} {
		g := gen(t, s, "/a")
		e.evict(f.gen)
		if done, err := write(g); done || err != nil {
			t.Errorf("%s under an evicted generation: done=%v err=%v", what, done, err)
		}
		if now := gen(t, s, "/a"); now == g || now == 0 {
			t.Errorf("%s: the generation read again after its eviction is %d, was %d", what, now, g)
		}
		// Not refused for another reason: under the generation of now it is
		// accepted.
		if done, err := write(gen(t, s, "/a")); !done || err != nil {
			t.Errorf("%s under the generation of now: done=%v err=%v", what, done, err)
		}
	}
	// The same for a listing token of the folder or of an ancestor.
	for i := range f.tl {
		g := gen(t, s, "/a")
		e.evict(f.tl[i])
		if done, err := s.PutListingIf(ctx, lk("/a"), l, g); done || err != nil {
			t.Errorf("PutListingIf under an evicted token %d: done=%v err=%v", i, done, err)
		}
	}
}

// A fetch in flight under a DeleteSubtree of an ancestor stores nothing, by
// any of its writes, though the folder held nothing when it started.
func TestDeleteSubtree_RefusesAFetchInFlight(t *testing.T) {
	e := newEnv(t)
	a, b := e.store(false), e.store(true)
	ctx := context.Background()
	x := seal(file("x"))
	l := &metastore.Listing{Nodes: []metastore.Node{x}, FetchedAt: time.Now()}

	g := gen(t, a, "/a/b/c")
	must(t, b.DeleteSubtree(ctx, dr, "/a"))
	if stored, err := a.PutListingIf(ctx, lk("/a/b/c"), l, g); stored || err != nil {
		t.Errorf("PutListingIf: stored=%v err=%v", stored, err)
	}
	if stored, err := a.PutEntryIf(ctx, ek("/a/b/c", "x"),
		&metastore.Entry{Node: &x, FetchedAt: time.Now()}, g); stored || err != nil {
		t.Errorf("PutEntryIf: stored=%v err=%v", stored, err)
	}

	// A listing held, renewed after a sweep it predates: refused, and not
	// served either.
	put(t, a, "/a/b/c", x)
	g = gen(t, a, "/a/b/c")
	must(t, b.DeleteSubtree(ctx, dr, "/a/b"))
	if renewed, err := a.RenewListingIf(ctx, lk("/a/b/c"), "e", time.Now(), g); renewed || err != nil {
		t.Errorf("RenewListingIf: renewed=%v err=%v", renewed, err)
	}
	// Even under the generation of now: the listing held predates the sweep.
	if renewed, err := a.RenewListingIf(ctx, lk("/a/b/c"), "e", time.Now(), gen(t, a, "/a/b/c")); renewed || err != nil {
		t.Errorf("RenewListingIf of a swept listing under the generation of now: renewed=%v err=%v", renewed, err)
	}
	if _, ok := held(t, a, "/a/b/c"); ok {
		t.Error("a swept listing is served")
	}
}

// evictionModel is the truth (what the API holds) of a few folders, and
// what a store sharing Redis with another instance does about it, as vfs
// does: every change goes with the edit or the invalidation vfs makes, every
// fetch and lookup is stored conditionally on the generation read before.
// Keys are evicted at random meanwhile. Whatever is served must be the truth.
type evictionModel struct {
	t      *testing.T
	e      *env
	rng    *rand.Rand
	stores []*Store
	truth  map[string][]string
	next   int
	// fetches and lookups in flight.
	fetches []pendingFetch
	lookups []pendingLookup
	// served counts the values read back, to check the test reads some.
	served, stored int
}

type pendingFetch struct {
	p     string
	gen   uint64
	names []string
	renew bool // the store held the truth when it started: a 304 is right
}

type pendingLookup struct {
	p, name string
	gen     uint64
	found   bool
}

var evictionFolders = []string{"/", "/a", "/a/b", "/a/b/c", "/d"}

func (m *evictionModel) store() *Store { return m.stores[m.rng.IntN(len(m.stores))] }

func (m *evictionModel) folder() string { return evictionFolders[m.rng.IntN(len(evictionFolders))] }

func (m *evictionModel) name(p string) string {
	if names := m.truth[p]; len(names) > 0 && m.rng.IntN(3) > 0 {
		return names[m.rng.IntN(len(names))]
	}
	m.next++

	return fmt.Sprintf("n%03d", m.next)
}

func nodesOf(names []string) []metastore.Node {
	nodes := make([]metastore.Node, len(names))
	for i, n := range names {
		nodes[i] = seal(file(n))
	}

	return nodes
}

func below(p, q string) bool {
	return q == p || p == "/" || strings.HasPrefix(q, p+"/")
}

func (m *evictionModel) step() {
	t, ctx := m.t, context.Background()
	s := m.store()
	switch op := m.rng.IntN(11); op {
	case 0, 1: // a file created or removed in a folder
		p := m.folder()
		name := m.name(p)
		var err error
		if i := slices.Index(m.truth[p], name); i >= 0 {
			m.truth[p] = slices.Delete(m.truth[p], i, i+1)
			_, err = s.RemoveNode(ctx, lk(p), name)
		} else {
			m.truth[p] = append(m.truth[p], name)
			slices.Sort(m.truth[p])
			_, err = s.UpsertNode(ctx, lk(p), seal(file(name)))
		}
		must(t, err)
		must(t, s.DeleteEntries(ctx, dr, p))
	case 2: // another folder moved in: everything below is another tree
		p := m.folder()
		for _, q := range evictionFolders {
			if below(p, q) {
				m.next++
				m.truth[q] = []string{fmt.Sprintf("m%03d", m.next)}
			}
		}
		must(t, s.DeleteSubtree(ctx, dr, p))
		must(t, s.DeleteEntriesBelow(ctx, dr, p))
	case 3, 4: // a fetch starts
		p := m.folder()
		g, err := s.Generation(ctx, lk(p))
		must(t, err)
		l, ok, err := s.GetListing(ctx, lk(p))
		must(t, err)
		m.fetches = append(m.fetches, pendingFetch{p: p, gen: g, names: slices.Clone(m.truth[p]),
			renew: ok && names(l.Nodes) == strings.Join(m.truth[p], ",")})
	case 5: // a fetch ends
		if len(m.fetches) == 0 {
			return
		}
		i := m.rng.IntN(len(m.fetches))
		f := m.fetches[i]
		m.fetches = slices.Delete(m.fetches, i, i+1)
		var done bool
		var err error
		if f.renew && m.rng.IntN(2) == 0 {
			done, err = s.RenewListingIf(ctx, lk(f.p), "", time.Now(), f.gen)
		} else {
			done, err = s.PutListingIf(ctx, lk(f.p), &metastore.Listing{Nodes: nodesOf(f.names), FetchedAt: time.Now()}, f.gen)
		}
		must(t, err)
		if done {
			m.stored++
		}
	case 6: // a lookup starts
		p := m.folder()
		name := m.name(p)
		g, err := s.Generation(ctx, lk(p))
		must(t, err)
		m.lookups = append(m.lookups, pendingLookup{p: p, name: name, gen: g, found: slices.Contains(m.truth[p], name)})
	case 7: // a lookup ends
		if len(m.lookups) == 0 {
			return
		}
		i := m.rng.IntN(len(m.lookups))
		l := m.lookups[i]
		m.lookups = slices.Delete(m.lookups, i, i+1)
		entry := &metastore.Entry{FetchedAt: time.Now()}
		if l.found {
			n := seal(file(l.name))
			entry.Node = &n
		}
		done, err := s.PutEntryIf(ctx, ek(l.p, l.name), entry, l.gen)
		must(t, err)
		if done {
			m.stored++
		}
	case 8, 9: // Redis evicts a key
		keys := m.e.keys()
		if len(keys) > 0 {
			m.e.evict(keys[m.rng.IntN(len(keys))])
		}
	default:
		m.check()
	}
}

// check reads everything back: what is served must be the truth.
func (m *evictionModel) check() {
	t, ctx := m.t, context.Background()
	for _, s := range m.stores {
		for _, p := range evictionFolders {
			truth := strings.Join(m.truth[p], ",")
			if nodes, ok := held(t, s, p); ok {
				m.served++
				if got := names(nodes); got != truth {
					t.Fatalf("%s served %q, the truth is %q", p, got, truth)
				}
			}
			for _, name := range append(slices.Clone(m.truth[p]), "n000") {
				node, _, isHeld, entry, hasEntry, err := s.GetNamed(ctx, lk(p), name)
				must(t, err)
				want := slices.Contains(m.truth[p], name)
				if isHeld && (node != nil) != want {
					t.Fatalf("%s/%s: the listing says %v, the truth %v", p, name, node != nil, want)
				}
				if hasEntry {
					m.served++
					if (entry.Node != nil) != want {
						t.Fatalf("%s/%s: the entry says %v, the truth %v", p, name, entry.Node != nil, want)
					}
				}
				if e, ok, err := s.GetEntry(ctx, ek(p, name)); err != nil || ok != hasEntry ||
					(ok && (e.Node != nil) != want) {
					t.Fatalf("%s/%s: GetEntry disagrees with GetNamed (%v, %v)", p, name, ok, err)
				}
			}
		}
	}
}

// Keys evicted at random during a sequence of operations of two instances:
// no stale value is ever served.
func TestEviction_Random(t *testing.T) {
	for seed := range uint64(8) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			e := newEnv(t)
			m := &evictionModel{
				t: t, e: e, rng: rand.New(rand.NewPCG(seed, 0x5eed)), //nolint:gosec // a reproducible sequence, not a secret
				stores: []*Store{e.store(false), e.store(true)},
				truth:  map[string][]string{},
			}
			for range 600 {
				m.step()
			}
			m.check()
			if m.served == 0 || m.stored == 0 {
				t.Fatalf("the test proves nothing: %d values served, %d conditional writes stored", m.served, m.stored)
			}
		})
	}
}
