package redisstore

import (
	"context"
	"strconv"
	"time"


	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// GetEntry implements metastore.MetaStore: HMGET of the field and of the
// tokens of the hash, HPTTL of the field and the MGET of the entry tokens, in
// one MULTI. An entry that cannot be read, that has no lifetime, or whose
// hash recorded other tokens than those of now, is absent.
func (s *Store) GetEntry(ctx context.Context, key metastore.EntryKey) (*metastore.Entry, bool, error) {
	f, ok := s.folder(key.DataroomID, key.ParentPath)
	if !ok {
		return nil, false, nil
	}
	nh, ok := f.hash(key.Name)
	if !ok {
		return nil, false, nil
	}
	asked := time.Now()
	op := begin(ctx, opGetEntry, key.DataroomID)
	pipe := s.rdb.TxPipeline()
	got := pipe.HMGet(ctx, f.entries, nh, tokensField)
	ttl := pipe.HPTTL(ctx, f.entries, nh)
	toks := pipe.MGet(ctx, f.te...)
	_, err := pipe.Exec(ctx)
	op.end(err)
	if err != nil {
		return nil, false, s.fail("reading an entry", err)
	}
	entry, ok := f.heldEntry(ctx, got.Val(), ttl.Val(), toks.Val(), asked)

	return entry, ok, nil
}

// heldEntry reads the answer of the HMGET of an entry and of the tokens of
// its hash, and of the HPTTL of the entry; tokens are the entry tokens of
// now.
func (h hasher) heldEntry(
	ctx context.Context, vals []any, left []int64, tokens []any, asked time.Time,
) (*metastore.Entry, bool) {
	// HPTTL answers -2 for a field that is not there and -1 for one that
	// never expires, which nothing here writes.
	if len(vals) != 2 || len(left) != 1 || left[0] < 0 || !sameTokens(vals[1], tokens) {
		return nil, false
	}
	raw, ok := vals[0].(string)
	if !ok {
		return nil, false
	}
	lifeMS, n, sealed, ok := decodeEntry(raw)
	if !ok || (sealed && !h.open(ctx, n)) {
		return nil, false
	}

	return &metastore.Entry{
		Node:      n,
		FetchedAt: fetchedAt(asked, lifeMS, time.Duration(left[0])*time.Millisecond),
	}, true
}

// entryValue is the stored form of an entry and the lifetime of its field;
// ok is false when it is not stored: a negative entry with no negative
// lifetime, a positive one without sealed form in high confidentiality, an
// entry already older than its lifetime.
func (s *Store) entryValue(entry *metastore.Entry) (string, time.Duration, bool) {
	if entry == nil {
		return "", 0, false
	}
	life := s.opts.EntryLife
	if entry.Node == nil {
		life = s.opts.NegativeEntryLife
	}
	ttl := remaining(life, entry.FetchedAt)
	if ttl <= 0 || life.Milliseconds() <= 0 {
		return "", 0, false
	}
	raw, ok := s.encodeEntry(life, entry.Node)

	return raw, ttl, ok
}

// PutEntry implements metastore.MetaStore: PutEntryIf whatever the
// generation. An entry that is not stored (see entryValue) still replaces
// the previous one: the field is removed.
func (s *Store) PutEntry(ctx context.Context, key metastore.EntryKey, entry *metastore.Entry) error {
	_, err := s.putEntry(ctx, key, entry, "")

	return err
}

// PutEntryIf implements metastore.MetaStore: one script compares the
// generation of the folder's listing and, when it is gen, writes the field
// and its lifetime under the entry tokens of now, emptying first a hash
// written under others. The generation is not bumped. stored is false when it
// moved, and when the entry is not stored (see entryValue): the field is then
// removed.
func (s *Store) PutEntryIf(
	ctx context.Context, key metastore.EntryKey, entry *metastore.Entry, gen uint64,
) (bool, error) {
	return s.putEntry(ctx, key, entry, strconv.FormatUint(gen, 10))
}

// putEntry runs put_entry.lua; expected is "" for any generation.
func (s *Store) putEntry(
	ctx context.Context, key metastore.EntryKey, entry *metastore.Entry, expected string,
) (bool, error) {
	f, ok := s.folder(key.DataroomID, key.ParentPath)
	if !ok {
		return false, nil
	}
	nh, ok := f.hash(key.Name)
	if !ok {
		return false, nil
	}
	raw, ttl, keep := s.entryValue(entry)
	if !keep {
		ttl = 0
	}
	keys := make([]string, 0, 2+2*len(f.tl))
	keys = append(append(append(keys, f.entries, f.gen), f.tl...), f.te...)
	op := begin(ctx, opPutEntry, key.DataroomID)
	written, err := s.runFlag(ctx, putEntryScript, keys,
		expected, nh, raw, ttl.Milliseconds(), s.tokenLife.Milliseconds(), newToken(), len(f.tl))
	op.end(err)
	if err != nil {
		return false, s.fail("writing an entry", err)
	}

	return written && keep, nil
}

// DeleteEntries implements metastore.MetaStore.
func (s *Store) DeleteEntries(ctx context.Context, dataroomID, parentPath string) error {
	f, ok := s.folder(dataroomID, parentPath)
	if !ok {
		return nil
	}
	op := begin(ctx, opDeleteEntries, dataroomID)
	err := s.rdb.Unlink(ctx, f.entries).Err()
	op.end(err)
	if err != nil {
		return s.fail("deleting entries", err)
	}

	return nil
}

// DeleteEntriesBelow implements metastore.MetaStore: one SET gives the
// folder a new entry token. Every entries hash at or below it recorded the
// old one and is stale from then on. The entry that names the folder is a
// field of its parent's hash and is not touched.
func (s *Store) DeleteEntriesBelow(ctx context.Context, dataroomID, p string) error {
	f, ok := s.folder(dataroomID, p)
	if !ok {
		return nil
	}
	op := begin(ctx, opDeleteEntriesBelow, dataroomID)
	err := s.rdb.Set(ctx, f.te[len(f.te)-1], newToken(), s.tokenLife).Err()
	op.end(err)
	if err != nil {
		return s.fail("deleting entries", err)
	}

	return nil
}
