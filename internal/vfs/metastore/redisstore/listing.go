package redisstore

import (
	"context"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

const (
	// metaField is the reserved field of a listing. It is what makes an empty
	// listing exist, and what tells a listing from a hash an edit left behind.
	metaField = "m"
	// etagField holds the ETag of a listing that has one. It is apart from
	// the reserved field so that an edit empties it with one HDEL.
	etagField = "etag"
	// nodePrefix starts the field of a child, followed by the hash of its
	// name: no field of a child is ever the reserved one.
	nodePrefix = "n:"
)

// listingOf builds the keys of a listing.
func (s *Store) listingOf(key metastore.ListingKey) (folder, bool) {
	return s.folder(key.DataroomID, key.Path)
}

// metaOf reads the reserved field, the ETag and the lifetime left of a
// listing; ok is false when there is no listing, or none this version can read. A listing
// without a lifetime is one nothing here wrote: its age is unknown and it is
// not served.
func metaOf(raw, etag string, left time.Duration, asked time.Time) (metastore.ListingMeta, bool) {
	m, ok := decodeMeta(raw)
	if !ok || left < 0 {
		return metastore.ListingMeta{}, false
	}

	return metastore.ListingMeta{FetchedAt: fetchedAt(asked, m.LifeMS, left), ETag: etag}, true
}

// GetListing implements metastore.MetaStore: HGETALL, PTTL and the MGET of
// the listing tokens in one MULTI, so that the lifetime and the tokens read
// are those of the listing read and not of one written in between. A
// listing written under other tokens than those of now is absent. The nodes
// come back sorted by name, a hash having no order. One node
// that cannot be read makes the listing absent: served without it, the
// listing would say the name does not exist.
func (s *Store) GetListing(ctx context.Context, key metastore.ListingKey) (*metastore.Listing, bool, error) {
	f, ok := s.listingOf(key)
	if !ok {
		return nil, false, nil
	}
	asked := time.Now()
	op := begin(ctx, opGetListing, key.DataroomID)
	pipe := s.rdb.TxPipeline()
	all := pipe.HGetAll(ctx, f.ls)
	ttl := pipe.PTTL(ctx, f.ls)
	toks := pipe.MGet(ctx, f.tl...)
	if _, err := pipe.Exec(ctx); err != nil {
		op.end(err)

		return nil, false, s.fail("reading a listing", err)
	}
	fields := all.Val()
	held := 0
	for field := range fields {
		if strings.HasPrefix(field, nodePrefix) {
			held++
		}
	}
	op.nodes(held)
	op.end(nil)
	meta, ok := metaOf(fields[metaField], fields[etagField], ttl.Val(), asked)
	if !ok || !sameTokens(recordedTokens(fields), toks.Val()) {
		return nil, false, nil
	}
	nodes := make([]metastore.Node, 0, len(fields))
	var sealed []int
	for field, raw := range fields {
		if !strings.HasPrefix(field, nodePrefix) {
			continue
		}
		n, isSealed, ok := decodeNode(raw)
		if !ok {
			return nil, false, nil
		}
		if isSealed {
			sealed = append(sealed, len(nodes))
		}
		nodes = append(nodes, n)
	}
	if !f.openAll(ctx, nodes, sealed) {
		return nil, false, nil
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Name != nodes[j].Name {
			return nodes[i].Name < nodes[j].Name
		}

		return nodes[i].ID < nodes[j].ID
	})

	return &metastore.Listing{Nodes: nodes, FetchedAt: meta.FetchedAt, ETag: meta.ETag}, true, nil
}

// openAll opens the sealed nodes of a listing, GOMAXPROCS at a time: each is
// one AGE decryption. It answers false as soon as one cannot be opened. A
// context made by metastore.LeaveSealed opens nothing: the caller will.
func (h hasher) openAll(ctx context.Context, nodes []metastore.Node, sealed []int) bool {
	if len(sealed) > 0 && metastore.SealedLeft(ctx) {
		return h.codec != nil
	}
	workers := min(runtime.GOMAXPROCS(0), len(sealed))
	if workers <= 1 {
		for _, i := range sealed {
			if !h.open(ctx, &nodes[i]) {
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
				if !h.open(ctx, &nodes[i]) {
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

// recordedTokens is the field "t" of a listing read by HGETALL, nil when
// there is none.
func recordedTokens(fields map[string]string) any {
	if t, ok := fields[tokensField]; ok {
		return t
	}

	return nil
}

// ListingMeta implements metastore.MetaStore: HMGET of the reserved fields,
// PTTL and the MGET of the listing tokens, in one MULTI.
func (s *Store) ListingMeta(ctx context.Context, key metastore.ListingKey) (metastore.ListingMeta, bool, error) {
	f, ok := s.listingOf(key)
	if !ok {
		return metastore.ListingMeta{}, false, nil
	}
	asked := time.Now()
	op := begin(ctx, opListingMeta, key.DataroomID)
	pipe := s.rdb.TxPipeline()
	got := pipe.HMGet(ctx, f.ls, metaField, etagField, tokensField)
	ttl := pipe.PTTL(ctx, f.ls)
	toks := pipe.MGet(ctx, f.tl...)
	_, err := pipe.Exec(ctx)
	op.end(err)
	if err != nil {
		return metastore.ListingMeta{}, false, s.fail("reading a listing", err)
	}
	vals := got.Val()
	if len(vals) != 3 || !sameTokens(vals[2], toks.Val()) {
		return metastore.ListingMeta{}, false, nil
	}
	rawMeta, _ := vals[0].(string)
	etag, _ := vals[1].(string)
	meta, ok := metaOf(rawMeta, etag, ttl.Val(), asked)

	return meta, ok, nil
}

// GetNode implements metastore.MetaStore: HMGET of the child and of the
// reserved fields, PTTL and the MGET of the listing tokens, in one MULTI. A child that cannot be read
// is answered as no listing held, never as a name the folder does not have.
func (s *Store) GetNode(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, error) {
	var none metastore.ListingMeta
	f, ok := s.listingOf(key)
	if !ok {
		return nil, none, false, nil
	}
	nh, ok := f.hash(name)
	if !ok {
		return nil, none, false, nil
	}
	asked := time.Now()
	op := begin(ctx, opGetNode, key.DataroomID)
	pipe := s.rdb.TxPipeline()
	got := pipe.HMGet(ctx, f.ls, nodePrefix+nh, metaField, etagField, tokensField)
	ttl := pipe.PTTL(ctx, f.ls)
	toks := pipe.MGet(ctx, f.tl...)
	_, err := pipe.Exec(ctx)
	op.end(err)
	if err != nil {
		return nil, none, false, s.fail("reading a node", err)
	}
	node, meta, held := f.heldNode(ctx, got.Val(), ttl.Val(), toks.Val(), asked)

	return node, meta, held, nil
}

// heldNode reads the answer of the HMGET of a child, of the reserved field,
// of the ETag and of the tokens of a listing, left being the lifetime of its
// key and tokens the listing tokens of now.
func (h hasher) heldNode(
	ctx context.Context, vals []any, left time.Duration, tokens []any, asked time.Time,
) (*metastore.Node, metastore.ListingMeta, bool) {
	var none metastore.ListingMeta
	if len(vals) != 4 || !sameTokens(vals[3], tokens) {
		return nil, none, false
	}
	rawMeta, _ := vals[1].(string)
	etag, _ := vals[2].(string)
	meta, ok := metaOf(rawMeta, etag, left, asked)
	if !ok {
		return nil, none, false
	}
	if vals[0] == nil {
		return nil, meta, true
	}
	rawNode, _ := vals[0].(string)
	n, sealed, ok := decodeNode(rawNode)
	if !ok || (sealed && !h.open(ctx, &n)) {
		return nil, none, false
	}

	return &n, meta, true
}

// GetNamed implements metastore.MetaStore: what GetNode and GetEntry read, in
// one MULTI, so one round trip. Each half is read as its own method reads it.
func (s *Store) GetNamed(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, *metastore.Entry, bool, error) {
	var none metastore.ListingMeta
	f, ok := s.listingOf(key)
	if !ok {
		return nil, none, false, nil, false, nil
	}
	nh, ok := f.hash(name)
	if !ok {
		return nil, none, false, nil, false, nil
	}
	asked := time.Now()
	op := begin(ctx, opGetNamed, key.DataroomID)
	pipe := s.rdb.TxPipeline()
	got := pipe.HMGet(ctx, f.ls, nodePrefix+nh, metaField, etagField, tokensField)
	ttl := pipe.PTTL(ctx, f.ls)
	raw := pipe.HMGet(ctx, f.entries, nh, tokensField)
	left := pipe.HPTTL(ctx, f.entries, nh)
	// Both families of tokens in one MGET: the keys share the slot.
	toks := pipe.MGet(ctx, append(append(make([]string, 0, 2*len(f.tl)), f.tl...), f.te...)...)
	_, err := pipe.Exec(ctx)
	op.end(err)
	if err != nil {
		return nil, none, false, nil, false, s.fail("reading a name", err)
	}
	tokens := toks.Val()
	if len(tokens) != 2*len(f.tl) {
		return nil, none, false, nil, false, nil
	}
	node, meta, held := f.heldNode(ctx, got.Val(), ttl.Val(), tokens[:len(f.tl)], asked)
	entry, hasEntry := f.heldEntry(ctx, raw.Val(), left.Val(), tokens[len(f.tl):], asked)

	return node, meta, held, entry, hasEntry, nil
}

// Generation implements metastore.MetaStore. A dataroom whose keys cannot be
// named yet has generation zero, which no write accepts.
//
// An absent generation is created with a random start, and the listing
// tokens of the folder and of its ancestors are settled in the same step:
// the value answered is made of both (see lua/lib.lua). A generation is read
// to start a fetch, and the folder may never have held anything: a
// DeleteSubtree of an ancestor meanwhile (the folder was moved with it)
// replaces a token, the generation moves, and the answer of the fetch is not
// stored under a path that now names something else. An eviction of either
// key does the same.
func (s *Store) Generation(ctx context.Context, key metastore.ListingKey) (uint64, error) {
	f, ok := s.listingOf(key)
	if !ok {
		return 0, nil
	}
	op := begin(ctx, opGeneration, key.DataroomID)
	gen, err := s.runGeneration(ctx, generationScript, f.withTokens(f.gen),
		newToken(), s.tokenLife.Milliseconds(), newGeneration(), generationLife.Milliseconds())
	op.end(err)
	if err != nil {
		return 0, s.fail("reading a generation", err)
	}

	return gen, nil
}

// listingWrite is what putting a listing comes to.
type listingWrite int

const (
	// writeNothing: the keys or a field cannot be named (see Store.folder).
	writeNothing listingWrite = iota
	// writeDrop: the listing may not or need not be stored, the one held
	// goes: a node without sealed form in high confidentiality, or a listing
	// already older than its lifetime.
	writeDrop
	// writeStore replaces the listing held.
	writeStore
)

// listingFields is the hash of a listing, as the field / value pairs of
// HSET, and the lifetime to give it. A listing above maxListingBytes is not
// stored.
func (s *Store) listingFields(f folder, l *metastore.Listing) ([]any, time.Duration, listingWrite) {
	if l == nil {
		return nil, 0, writeDrop
	}
	ttl := remaining(s.opts.ListingLife, l.FetchedAt)
	if ttl <= 0 {
		return nil, 0, writeDrop
	}
	fields := make([]any, 0, 2*len(l.Nodes)+4)
	size := 0
	for i := range l.Nodes {
		nh, ok := f.hash(l.Nodes[i].Name)
		if !ok {
			return nil, 0, writeNothing
		}
		raw, ok := s.encodeNode(&l.Nodes[i])
		if !ok {
			return nil, 0, writeDrop
		}
		size += len(nodePrefix) + len(nh) + len(raw)
		if size > s.maxListing {
			return nil, 0, writeDrop
		}
		fields = append(fields, nodePrefix+nh, raw)
	}
	fields = append(fields, metaField, encodeMeta(s.opts.ListingLife))
	if l.ETag != "" {
		fields = append(fields, etagField, l.ETag)
	}

	return fields, ttl, writeStore
}

// putListing runs the script that replaces a listing: the old one unlinked,
// the new one written with its lifetime and its tokens, the generation bumped, when the generation is the one expected
// ("" for any). One execution: no reader sees the hash half written or
// without a lifetime. written tells that the generation matched. nodes is the
// number of nodes written, for the span: none when the listing is dropped.
func (s *Store) putListing(
	ctx context.Context, f folder, fields []any, ttl time.Duration, expected string, nodes int,
) (written bool, err error) {
	args := make([]any, 0, 6+len(fields))
	args = append(args, expected, ttl.Milliseconds(), generationLife.Milliseconds(), s.tokenLife.Milliseconds(),
		newToken(), newGeneration())
	args = append(args, fields...)

	op := begin(ctx, opPutListing, f.dataroomID)
	op.nodes(nodes)
	written, err = s.runFlag(ctx, putListingScript, f.withTokens(f.ls, f.gen), args...)
	op.end(err)

	return written, err
}

// storedNodes is the number of nodes a write of listing stores.
func storedNodes(listing *metastore.Listing, what listingWrite) int {
	if listing == nil || what != writeStore {
		return 0
	}

	return len(listing.Nodes)
}

// PutListing implements metastore.MetaStore.
func (s *Store) PutListing(ctx context.Context, key metastore.ListingKey, listing *metastore.Listing) error {
	f, ok := s.listingOf(key)
	if !ok {
		return nil
	}
	fields, ttl, what := s.listingFields(f, listing)
	if what == writeNothing {
		return nil
	}
	if _, err := s.putListing(ctx, f, fields, ttl, "", storedNodes(listing, what)); err != nil {
		return s.fail("writing a listing", err)
	}

	return nil
}

// PutListingIf implements metastore.MetaStore: one script compares the
// generation and, when it is gen, writes the listing and bumps it. A
// generation that moved is stored == false, not an error: the listing is
// older than what was written.
//
// stored is also false, the generation being gen, when the listing could not
// be kept (see writeDrop): the one held is then removed.
func (s *Store) PutListingIf(
	ctx context.Context, key metastore.ListingKey, listing *metastore.Listing, gen uint64,
) (bool, error) {
	f, ok := s.listingOf(key)
	if !ok {
		return false, nil
	}
	fields, ttl, what := s.listingFields(f, listing)
	if what == writeNothing {
		return false, nil
	}
	done, err := s.putListing(ctx, f, fields, ttl, strconv.FormatUint(gen, 10), storedNodes(listing, what))
	if err != nil {
		return false, s.fail("writing a listing", err)
	}

	return done && what == writeStore, nil
}

// RenewListingIf implements metastore.MetaStore: one script compares the
// generation and, when it is gen and the listing is still held, gives it the
// lifetime left to a listing fetched at fetchedAt, the ETag, and bumps the
// generation, as PutListingIf would with the same nodes. Nothing is written
// otherwise, the generation included: a listing that expired meanwhile, or is
// already older than its lifetime, is renewed == false.
func (s *Store) RenewListingIf(
	ctx context.Context, key metastore.ListingKey, etag string, fetchedAt time.Time, gen uint64,
) (bool, error) {
	f, ok := s.listingOf(key)
	if !ok {
		return false, nil
	}
	ttl := remaining(s.opts.ListingLife, fetchedAt)
	if ttl <= 0 {
		return false, nil
	}
	op := begin(ctx, opRenewListing, key.DataroomID)
	renewed, err := s.runFlag(ctx, renewListingScript, f.withTokens(f.ls, f.gen),
		strconv.FormatUint(gen, 10), ttl.Milliseconds(), generationLife.Milliseconds(), s.tokenLife.Milliseconds(),
		newToken(), newGeneration(), wireVersion, encodeMeta(s.opts.ListingLife), etag)
	op.end(err)
	if err != nil {
		return false, s.fail("renewing a listing", err)
	}

	return renewed, nil
}

// editArgs are the first arguments of the scripts that bump a generation
// unconditionally: drop_listing, upsert_node, remove_node.
func (s *Store) editArgs() []any {
	return []any{generationLife.Milliseconds(), s.tokenLife.Milliseconds(), newToken(), newGeneration()}
}

// dropListing removes a listing and bumps its generation.
func (s *Store) dropListing(ctx context.Context, f folder) (uint64, error) {
	gen, err := s.runGeneration(ctx, dropListingScript, f.withTokens(f.ls, f.gen), s.editArgs()...)
	if err != nil {
		return 0, s.fail("deleting a listing", err)
	}

	return gen, nil
}

// UpsertNode implements metastore.MetaStore: one script sets the field of the
// child when the listing is held, empties its ETag, and bumps the generation
// either way. Nothing is created without a listing (HSET alone would leave a
// hash with one child and no lifetime), and the lifetime of the key is not
// touched: the listing keeps its age.
//
// In high confidentiality a node without sealed form cannot be written: the
// listing is dropped, since one that lacks the name would say it does not
// exist.
func (s *Store) UpsertNode(ctx context.Context, key metastore.ListingKey, node metastore.Node) (uint64, error) {
	f, ok := s.listingOf(key)
	if !ok {
		return 0, nil
	}
	nh, ok := f.hash(node.Name)
	if !ok {
		return 0, nil
	}
	op := begin(ctx, opUpsertNode, key.DataroomID)
	raw, ok := s.encodeNode(&node)
	if !ok {
		gen, err := s.dropListing(ctx, f)
		op.end(err)

		return gen, err
	}
	gen, err := s.runGeneration(ctx, upsertNodeScript, f.withTokens(f.ls, f.gen),
		append(s.editArgs(), wireVersion, nodePrefix+nh, raw)...)
	op.end(err)
	if err != nil {
		return 0, s.fail("editing a listing", err)
	}

	return gen, nil
}

// RemoveNode implements metastore.MetaStore, like UpsertNode.
func (s *Store) RemoveNode(ctx context.Context, key metastore.ListingKey, name string) (uint64, error) {
	f, ok := s.listingOf(key)
	if !ok {
		return 0, nil
	}
	nh, ok := f.hash(name)
	if !ok {
		return 0, nil
	}
	op := begin(ctx, opRemoveNode, key.DataroomID)
	gen, err := s.runGeneration(ctx, removeNodeScript, f.withTokens(f.ls, f.gen),
		append(s.editArgs(), wireVersion, nodePrefix+nh)...)
	op.end(err)
	if err != nil {
		return 0, s.fail("editing a listing", err)
	}

	return gen, nil
}

// DeleteListing implements metastore.MetaStore.
func (s *Store) DeleteListing(ctx context.Context, key metastore.ListingKey) error {
	f, ok := s.listingOf(key)
	if !ok {
		return nil
	}
	op := begin(ctx, opDeleteListing, key.DataroomID)
	_, err := s.dropListing(ctx, f)
	op.end(err)

	return err
}

// DeleteSubtree implements metastore.MetaStore: one SET gives the folder a
// new listing token. Every listing at or below it recorded the old one and is
// stale from then on, and the generation of each moves (the tokens are part
// of it), whether it held a listing or not. Nothing is walked, nothing is
// deleted: the stale hashes expire with their lifetime.
func (s *Store) DeleteSubtree(ctx context.Context, dataroomID, p string) error {
	f, ok := s.folder(dataroomID, p)
	if !ok {
		return nil
	}
	op := begin(ctx, opDeleteSubtree, dataroomID)
	err := s.rdb.Set(ctx, f.tl[len(f.tl)-1], newToken(), s.tokenLife).Err()
	op.end(err)
	if err != nil {
		return s.fail("deleting a subtree", err)
	}

	return nil
}
