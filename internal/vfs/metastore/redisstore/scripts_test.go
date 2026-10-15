package redisstore

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// allScripts is every script of the package, by the name of its file.
var allScripts = map[string]*redis.Script{
	"generation":    generationScript,
	"put_listing":   putListingScript,
	"renew_listing": renewListingScript,
	"upsert_node":   upsertNodeScript,
	"remove_node":   removeNodeScript,
	"drop_listing":  dropListingScript,
	"put_entry":     putEntryScript,
}

// A server that lost its scripts (restart, SCRIPT FLUSH, failover) is no
// error: the call that finds out sends the source again.
func TestScripts_SurviveScriptFlush(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	x := file("x")
	// every runs each script once, and checks what it did.
	every := func(round string) {
		t.Helper()
		g := gen(t, s, "/a/b")
		l := &metastore.Listing{Nodes: []metastore.Node{x}, FetchedAt: time.Now()}
		stored, err := s.PutListingIf(ctx, lk("/a/b"), l, g)
		if !stored || err != nil {
			t.Fatalf("%s: PutListingIf: stored=%v err=%v", round, stored, err)
		}
		put(t, s, "/a", file("b"))
		up, err := s.UpsertNode(ctx, lk("/a/b"), file("y"))
		must(t, err)
		down, err := s.RemoveNode(ctx, lk("/a/b"), "x")
		must(t, err)
		if nodes, ok := held(t, s, "/a/b"); !ok || names(nodes) != "y" || up != g+2 || down != g+3 {
			t.Fatalf("%s: after the edits: %s ok=%v gens %d, %d, %d", round, names(nodes), ok, g, up, down)
		}
		stored, err = s.PutEntryIf(ctx, ek("/a/b", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}, down)
		if !stored || err != nil {
			t.Fatalf("%s: PutEntryIf: stored=%v err=%v", round, stored, err)
		}
		must(t, s.DeleteEntriesBelow(ctx, dr, "/a"))
		if _, ok, _ := s.GetEntry(ctx, ek("/a/b", "x")); ok {
			t.Fatalf("%s: the entry survived DeleteEntriesBelow", round)
		}
		must(t, s.DeleteSubtree(ctx, dr, "/a"))
		if _, ok := held(t, s, "/a/b"); ok || gen(t, s, "/a/b") == down {
			t.Fatalf("%s: after DeleteSubtree: held=%v gen=%d", round, ok, gen(t, s, "/a/b"))
		}
		put(t, s, "/a", file("b"))
		renewed, err := s.RenewListingIf(ctx, lk("/a"), "e", time.Now(), gen(t, s, "/a"))
		if !renewed || err != nil {
			t.Fatalf("%s: RenewListingIf: renewed=%v err=%v", round, renewed, err)
		}
		must(t, s.DeleteListing(ctx, lk("/a")))
		if _, ok := held(t, s, "/a"); ok {
			t.Fatalf("%s: the listing survived DeleteListing", round)
		}
	}
	cached := func() map[string]bool {
		t.Helper()
		out := map[string]bool{}
		for name, script := range allScripts {
			exists, err := script.Exists(ctx, e.raw).Result()
			must(t, err)
			out[name] = len(exists) == 1 && exists[0]
		}

		return out
	}

	every("first run")
	for name, ok := range cached() {
		if !ok {
			t.Errorf("%s was not run by the first round", name)
		}
	}
	// SCRIPT FLUSH empties the script cache only, never the data.
	must(t, e.raw.ScriptFlush(ctx).Err())
	for name, ok := range cached() {
		if ok {
			t.Fatalf("%s is still cached after SCRIPT FLUSH", name)
		}
	}
	every("after SCRIPT FLUSH")
	for name, ok := range cached() {
		if !ok {
			t.Errorf("%s was not loaded again", name)
		}
	}
}

// An error of a script, and an answer of a type it should not have, are
// ordinary errors.
func TestScripts_ErrorsAreErrors(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	f, _ := s.folder(dr, "/a")
	// The generation is not a counter: INCR fails inside the script.
	must(t, e.raw.HSet(ctx, f.gen, "not", "a counter").Err())
	x := file("x")
	l := &metastore.Listing{Nodes: []metastore.Node{x}, FetchedAt: time.Now()}
	entry := &metastore.Entry{Node: &x, FetchedAt: time.Now()}
	genErr := func(_ uint64, err error) error { return err }
	flagErr := func(_ bool, err error) error { return err }
	for what, call := range map[string]func() error{
		"Generation":   func() error { return genErr(s.Generation(ctx, lk("/a"))) },
		"PutListing":   func() error { return s.PutListing(ctx, lk("/a"), l) },
		"PutListingIf": func() error { return flagErr(s.PutListingIf(ctx, lk("/a"), l, 0)) },
		"RenewListingIf": func() error {
			return flagErr(s.RenewListingIf(ctx, lk("/a"), "e", time.Now(), 0))
		},
		"UpsertNode":    func() error { return genErr(s.UpsertNode(ctx, lk("/a"), x)) },
		"RemoveNode":    func() error { return genErr(s.RemoveNode(ctx, lk("/a"), "x")) },
		"DeleteListing": func() error { return s.DeleteListing(ctx, lk("/a")) },
		"PutEntryIf":    func() error { return flagErr(s.PutEntryIf(ctx, ek("/a", "x"), entry, 0)) },
	} {
		err := call()
		if err == nil || !strings.HasPrefix(err.Error(), "redisstore: ") {
			t.Errorf("%s on a generation of the wrong type: %v", what, err)
		}
	}
	must(t, e.raw.Del(ctx, f.gen).Err())
	must(t, e.raw.HSet(ctx, f.te[0], "not", "a token").Err())
	if err := s.PutEntry(ctx, ek("/a", "x"), entry); err == nil || !strings.HasPrefix(err.Error(), "redisstore: ") {
		t.Errorf("PutEntry under a token of the wrong type: %v", err)
	}
	must(t, e.raw.Del(ctx, f.te[0]).Err())

	keys := []string{f.gen}
	for what, src := range map[string]string{
		"a number":  "return 7",
		"a string":  "return 'x'",
		"a table":   "return {1, 2}",
		"a nil":     "return nil",
		"a status":  "return redis.status_reply('OK')",
		"a failure": "return redis.error_reply('nope')",
	} {
		if _, err := s.runFlag(ctx, redis.NewScript(src), keys); err == nil {
			t.Errorf("runFlag accepted %s", what)
		}
		if what == "a number" {
			continue
		}
		if _, err := s.runGeneration(ctx, redis.NewScript(src), keys); err == nil {
			t.Errorf("runGeneration accepted %s", what)
		}
	}
	if _, err := s.runGeneration(ctx, redis.NewScript("return 7"), keys); err == nil {
		t.Error("runGeneration accepted a number")
	}
	// A stored number this format never writes (beyond 2^52, where the sum
	// with the fingerprint would no longer be exact, zero, not an integer)
	// is an error, never a generation.
	for _, bad := range []string{"4503599627370496", "18446744073709551614", "0", "-3", "1.5", "x"} {
		must(t, e.raw.Set(ctx, f.gen, bad, time.Minute).Err())
		if _, err := s.Generation(ctx, lk("/a")); err == nil {
			t.Errorf("Generation over a stored %q answered no error", bad)
		}
		// Left to expire: a failing Generation does not keep it alive.
		if ttl := e.raw.PTTL(ctx, f.gen).Val(); ttl > time.Minute {
			t.Errorf("Generation over a stored %q extended it to %v", bad, ttl)
		}
		if _, err := s.PutListingIf(ctx, lk("/a"), l, 1); err == nil {
			t.Errorf("PutListingIf over a stored %q answered no error", bad)
		}
	}
	// The largest start, plus writes, stays exact.
	must(t, e.raw.Set(ctx, f.gen, fmt.Sprint(maxGenerationStart), time.Minute).Err())
	g := gen(t, s, "/a")
	if stored, err := s.PutListingIf(ctx, lk("/a"), l, g-1); stored || err != nil {
		t.Errorf("PutListingIf with a generation one below: stored=%v err=%v", stored, err)
	}
	if stored, err := s.PutListingIf(ctx, lk("/a"), l, g); !stored || err != nil || gen(t, s, "/a") != g+1 {
		t.Errorf("PutListingIf with the exact generation: stored=%v err=%v gen=%d, want %d",
			stored, err, gen(t, s, "/a"), g+1)
	}
}

func TestPutEntryIf(t *testing.T) {
	e := newEnv(t)
	a, b := e.store(false), e.store(false)
	ctx := context.Background()
	x := file("x")
	entry := &metastore.Entry{Node: &x, FetchedAt: time.Now()}

	// Another instance wrote the folder while the name was looked up.
	g := gen(t, a, "/a/b")
	_, err := b.UpsertNode(ctx, lk("/a/b"), file("y"))
	must(t, err)
	stored, err := a.PutEntryIf(ctx, ek("/a/b", "x"), entry, g)
	if stored || err != nil {
		t.Fatalf("PutEntryIf after a foreign write: stored=%v err=%v", stored, err)
	}
	if _, ok, _ := b.GetEntry(ctx, ek("/a/b", "x")); ok {
		t.Fatal("a refused entry was stored")
	}

	// Nothing moved: stored, seen by the other instance, no generation bumped.
	g = gen(t, a, "/a/b")
	stored, err = a.PutEntryIf(ctx, ek("/a/b", "x"), entry, g)
	if !stored || err != nil {
		t.Fatalf("PutEntryIf with the current generation: stored=%v err=%v", stored, err)
	}
	got, ok, err := b.GetEntry(ctx, ek("/a/b", "x"))
	if err != nil || !ok || got.Node == nil || *got.Node != x || time.Since(got.FetchedAt) > 5*time.Second {
		t.Fatalf("GetEntry = %+v, %v, %v", got, ok, err)
	}
	if now := gen(t, b, "/a/b"); now != g {
		t.Fatalf("PutEntryIf moved the generation from %d to %d", g, now)
	}
	// So a second one at the same generation is stored too, negative here.
	stored, err = a.PutEntryIf(ctx, ek("/a/b", "x"), &metastore.Entry{FetchedAt: time.Now()}, g)
	if !stored || err != nil {
		t.Fatalf("second PutEntryIf: stored=%v err=%v", stored, err)
	}
	if got, ok, _ := b.GetEntry(ctx, ek("/a/b", "x")); !ok || got.Node != nil {
		t.Fatalf("the negative entry did not replace the positive one: %+v, %v", got, ok)
	}
	// The field has its own lifetime, and the folder is in its ancestors' index.
	f, _ := a.folder(dr, "/a/b")
	xh, _ := f.hash("x")
	if left := e.raw.HPTTL(ctx, f.entries, xh).Val(); len(left) != 1 || left[0] <= 0 || left[0] > 10_000 {
		t.Fatalf("lifetime of the field = %v", left)
	}
	must(t, b.DeleteEntriesBelow(ctx, dr, "/a"))
	if _, ok, _ := a.GetEntry(ctx, ek("/a/b", "x")); ok {
		t.Fatal("the entry is not reached from its ancestor")
	}

	// An entry that is not stored removes the one held, when the generation
	// matches only.
	must(t, a.PutEntry(ctx, ek("/a/b", "x"), entry))
	old := &metastore.Entry{Node: &x, FetchedAt: time.Now().Add(-time.Hour)}
	if stored, err := a.PutEntryIf(ctx, ek("/a/b", "x"), old, g+1); stored || err != nil {
		t.Fatalf("PutEntryIf of an expired entry, wrong generation: stored=%v err=%v", stored, err)
	}
	if _, ok, _ := a.GetEntry(ctx, ek("/a/b", "x")); !ok {
		t.Fatal("a refused PutEntryIf removed the entry held")
	}
	if stored, err := a.PutEntryIf(ctx, ek("/a/b", "x"), old, g); stored || err != nil {
		t.Fatalf("PutEntryIf of an expired entry: stored=%v err=%v", stored, err)
	}
	if _, ok, _ := a.GetEntry(ctx, ek("/a/b", "x")); ok {
		t.Fatal("an entry too old to be stored left the previous one")
	}
	// Unresolved session: nothing, no error.
	e.codec.unresolved.Store(true)
	if stored, err := a.PutEntryIf(ctx, ek("/a/b", "x"), entry, g); stored || err != nil {
		t.Fatalf("PutEntryIf without a session: stored=%v err=%v", stored, err)
	}
}

func TestUpsertNode_WithoutListing(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	f, _ := s.folder(dr, "/a")
	first, err := s.UpsertNode(ctx, lk("/a"), file("x"))
	must(t, err)
	if first == 0 {
		t.Fatal("UpsertNode answered generation 0")
	}
	for i := range 3 {
		g, err := s.UpsertNode(ctx, lk("/a"), file("x"))
		must(t, err)
		if g != first+uint64(2*i+1) {
			t.Fatalf("UpsertNode %d: generation %d, first %d", i, g, first)
		}
		g, err = s.RemoveNode(ctx, lk("/a"), "x")
		must(t, err)
		if g != first+uint64(2*i+2) {
			t.Fatalf("RemoveNode %d: generation %d, first %d", i, g, first)
		}
	}
	if n := e.raw.Exists(ctx, f.ls).Val(); n != 0 {
		t.Fatalf("an edit created a listing:\n%s", e.dump())
	}
	for _, k := range e.keys() {
		if k != f.gen && k != f.tl[0] && k != f.tl[1] {
			t.Errorf("unexpected key %q", k)
		}
		if ttl := e.raw.PTTL(ctx, k).Val(); ttl <= 0 {
			t.Errorf("%q has no lifetime: %v", k, ttl)
		}
	}
}

func TestEdits_KeepTheLifetime(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	f, _ := s.folder(dr, "/a")
	must(t, s.PutListing(ctx, lk("/a"), &metastore.Listing{
		Nodes: []metastore.Node{file("x")}, FetchedAt: time.Now(), ETag: "etag",
	}))
	// Nine seconds left of thirty: an edit that gave the lifetime again would
	// show.
	must(t, e.raw.PExpire(ctx, f.ls, 9*time.Second).Err())
	before, _, err := s.ListingMeta(ctx, lk("/a"))
	must(t, err)
	_, err = s.UpsertNode(ctx, lk("/a"), file("y"))
	must(t, err)
	_, err = s.RemoveNode(ctx, lk("/a"), "x")
	must(t, err)
	if ttl := e.raw.PTTL(ctx, f.ls).Val(); ttl <= 0 || ttl > 9*time.Second {
		t.Fatalf("lifetime after the edits = %v", ttl)
	}
	after, ok, err := s.ListingMeta(ctx, lk("/a"))
	must(t, err)
	if !ok || after.ETag != "" || before.ETag != "etag" {
		t.Fatalf("ETag before %q, after %q, ok=%v", before.ETag, after.ETag, ok)
	}
	if d := after.FetchedAt.Sub(before.FetchedAt); d < -time.Second || d > time.Second {
		t.Fatalf("FetchedAt moved by %v", d)
	}
	if nodes, _ := held(t, s, "/a"); names(nodes) != "y" {
		t.Fatalf("nodes = %s", names(nodes))
	}
	if e.raw.HExists(ctx, f.ls, etagField).Val() {
		t.Fatal("the ETag field survived an edit")
	}
}

// A fetch of /a/b by A starts (Generation), then B renames /a, which
// replaces the listing token of /a. The answer A gets is of a folder that
// moved: it must be refused, though /a/b never held anything.
func TestGeneration_MovesUnderASweep(t *testing.T) {
	e := newEnv(t)
	a, b := e.store(false), e.store(true)
	ctx := context.Background()
	x := file("x")
	l := &metastore.Listing{Nodes: []metastore.Node{x}, FetchedAt: time.Now()}

	g := gen(t, a, "/a/b")
	lookup := gen(t, a, "/a/c/d")
	neighbour, root := gen(t, a, "/ab"), gen(t, a, "/")
	if g == 0 || lookup == 0 || g == lookup {
		t.Fatalf("generations of folders never written: %d, %d", g, lookup)
	}
	must(t, b.DeleteSubtree(ctx, dr, "/a"))
	stored, err := a.PutListingIf(ctx, lk("/a/b"), l, g)
	if stored || err != nil {
		t.Fatalf("PutListingIf after the subtree was swept: stored=%v err=%v", stored, err)
	}
	if _, ok := held(t, a, "/a/b"); ok {
		t.Fatal("the listing of a folder that moved was stored")
	}
	// The same for a name looked up below, two levels down.
	stored, err = a.PutEntryIf(ctx, ek("/a/c/d", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}, lookup)
	if stored || err != nil {
		t.Fatalf("PutEntryIf after the subtree was swept: stored=%v err=%v", stored, err)
	}
	if now := gen(t, a, "/a/b"); now == g || gen(t, a, "/a/b") != now {
		t.Fatalf("generation of /a/b after the sweep = %d, was %d", now, g)
	}
	// A neighbour is not concerned, nor the root.
	if gen(t, a, "/ab") != neighbour || gen(t, a, "/") != root {
		t.Fatal("a folder outside the subtree moved")
	}
	for _, k := range e.keys() {
		if ttl := e.raw.PTTL(ctx, k).Val(); ttl <= 0 {
			t.Errorf("key %q has no lifetime", k)
		}
	}
}

func TestListing_TooLarge(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	put(t, s, "/a", file("old"))
	s.maxListing = 2000
	nodes := make([]metastore.Node, 50)
	for i := range nodes {
		nodes[i] = file(fmt.Sprintf("f%02d", i))
	}
	l := &metastore.Listing{Nodes: nodes, FetchedAt: time.Now()}
	g := gen(t, s, "/a")
	stored, err := s.PutListingIf(ctx, lk("/a"), l, g)
	if stored || err != nil {
		t.Fatalf("PutListingIf of a listing above the bound: stored=%v err=%v", stored, err)
	}
	if _, ok := held(t, s, "/a"); ok || gen(t, s, "/a") != g+1 {
		t.Fatalf("after the refusal: held=%v gen=%d, want %d", ok, gen(t, s, "/a"), g+1)
	}
	must(t, s.PutListing(ctx, lk("/a"), l))
	if _, ok := held(t, s, "/a"); ok || gen(t, s, "/a") != g+2 {
		t.Fatalf("after PutListing: held=%v gen=%d, want %d", ok, gen(t, s, "/a"), g+2)
	}
	// Under the bound it is stored.
	l.Nodes = nodes[:3]
	stored, err = s.PutListingIf(ctx, lk("/a"), l, g+2)
	if !stored || err != nil {
		t.Fatalf("PutListingIf under the bound: stored=%v err=%v", stored, err)
	}
}

// An instance with shorter lifetimes never cuts short the tokens another one
// set for its longer-lived values (they would be read stale before their
// time), and a new token still gets a lifetime.
func TestScripts_TokenLifetimeOnlyGrows(t *testing.T) {
	e := newEnv(t)
	long := e.store(false, func(o *Options) { o.ListingLife, o.EntryLife = time.Hour, time.Hour })
	short := e.store(false)
	ctx := context.Background()
	put(t, long, "/a/b", file("y"))
	y := file("y")
	must(t, long.PutEntry(ctx, ek("/a/b", "y"), &metastore.Entry{Node: &y, FetchedAt: time.Now()}))
	subs := func() map[string]time.Duration {
		t.Helper()
		out := map[string]time.Duration{}
		for _, k := range e.keys() {
			if strings.Contains(k, ":tl:") || strings.Contains(k, ":te:") {
				out[k] = e.raw.PTTL(ctx, k).Val()
			}
		}

		return out
	}
	before := subs()
	if len(before) != 6 { // three folders, two families
		t.Fatalf("%d tokens written, want 6", len(before))
	}

	// Every way the short instance lengthens a token.
	_ = gen(t, short, "/a/b/c")
	put(t, short, "/a/d", file("y"))
	x := file("x")
	stored, err := short.PutEntryIf(ctx, ek("/a/b", "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()},
		gen(t, short, "/a/b"))
	if !stored || err != nil {
		t.Fatalf("PutEntryIf: stored=%v err=%v", stored, err)
	}
	g := gen(t, short, "/a/d")
	renewed, err := short.RenewListingIf(ctx, lk("/a/d"), "", time.Now(), g)
	if !renewed || err != nil {
		t.Fatalf("RenewListingIf: renewed=%v err=%v", renewed, err)
	}
	_, err = short.UpsertNode(ctx, lk("/a/b"), file("z"))
	must(t, err)
	_, err = short.RemoveNode(ctx, lk("/a/b"), "z")
	must(t, err)
	must(t, short.DeleteListing(ctx, lk("/a/d")))
	must(t, short.PutEntry(ctx, ek("/a/b", "x"), &metastore.Entry{FetchedAt: time.Now()}))
	// What the long instance wrote is still served by it.
	if _, ok := held(t, long, "/a/b"); !ok {
		t.Error("the listing of the long instance is gone")
	}
	if _, ok, err := long.GetEntry(ctx, ek("/a/b", "y")); !ok || err != nil {
		t.Errorf("the entry of the long instance is gone: %v", err)
	}

	for k, ttl := range subs() {
		if ttl <= 0 {
			t.Errorf("%s has no lifetime (%v)", k, ttl)
		}
		if was, ok := before[k]; ok && ttl < was-time.Minute {
			t.Errorf("%s cut short: %v, was %v", k, ttl, was)
		}
	}
}

// A clear node without a name is not written: the read would refuse it and
// drop the whole listing.
func TestPutListing_ClearNodeWithoutNameIsNotStored(t *testing.T) {
	e := newEnv(t)
	s := e.store(false)
	ctx := context.Background()
	g := gen(t, s, "/a")
	l := &metastore.Listing{Nodes: []metastore.Node{file("x"), {ID: "n-anon", Type: metastore.TypeFile}},
		FetchedAt: time.Now()}
	stored, err := s.PutListingIf(ctx, lk("/a"), l, g)
	must(t, err)
	if nodes, ok := held(t, s, "/a"); ok {
		t.Errorf("listing held (stored=%v): %s", stored, names(nodes))
	}
	for _, k := range e.keys() {
		if strings.Contains(k, ":ls:") {
			t.Errorf("listing written: %s", k)
		}
	}
}
