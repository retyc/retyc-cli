// Package redisstore is the metastore.MetaStore kept in Redis: the listings
// and the entries of several processes (FUSE mounts, WebDAV servers) that
// share one Redis are one cache.
//
// Keys are <prefix>:v2:{<dataroom ID>}:<kind>:<h>, h being
// Codec.Hash(dataroomID, path): no file or folder name appears in a key. The
// braces are a hash tag: every key of a dataroom is in one slot. "v2" is the
// schema: another format takes another prefix and never reads these (the v1
// keys, which had a subtree index and counters, are never read).
//
//	ls:<h>   hash    the listing of the folder at path: one field "n:" +
//	                 Hash(name) per child (the node, see below), the field "m"
//	                 ("<value version>:<lifetime in ms>"), the field "t" (the
//	                 listing tokens it was written under) and, when the
//	                 listing has one, the field "etag". PEXPIRE on the key.
//	e:<h>    hash    the entries of the folder at path: one field Hash(name)
//	                 per name looked up, each with its own lifetime (HPEXPIRE),
//	                 and the field "t" (the entry tokens they were written
//	                 under), which lives as long as the longest of them.
//	tl:<h>   string  the listing token of the folder: random, drawn here.
//	te:<h>   string  the entry token of the folder.
//	g:<h>    string  the generation of the listing: a random number when
//	                 created, INCR by every write to the listing.
//
// Eviction. Redis may evict any key at any time (maxmemory-policy
// allkeys-lru): an absent key always means "invalid", never "unchanged".
// A listing is served only while the listing token of every folder from the
// root down to its own is the one its field "t" recorded, an entry likewise
// with the entry tokens; the tokens are read in the same MULTI as the value.
// DeleteSubtree replaces the listing token of a folder, DeleteEntriesBelow its
// entry token: one SET, no walk, and everything below is stale. An evicted
// token is the same as a replaced one. The generation given to vfs is the
// stored number plus a fingerprint of the listing tokens of the folder and its
// ancestors: it moves with every write to the listing, with a DeleteSubtree
// above it, and with the eviction of the generation (a new random number,
// never a counter starting over at 1) or of a token. A conditional write
// whose generation is absent is refused. See lua/lib.lua.
//
// Redis is the only clock. A value is stored with the lifetime it was given
// and read back with what is left of it: FetchedAt is the reader's time minus
// (lifetime - time left), so processes whose clocks disagree read one age.
//
// Every method is one round trip, the caller holding a process-wide mutex
// across it. Reads are a MULTI (the value, what is left of its lifetime and
// the tokens are of one instant); a write is a Lua script (a generation to
// compare, tokens to settle, a listing that must exist), see scripts.go and
// lua/, or a single command. The scripts are sent by EVALSHA with EVAL as the
// fallback: a server that lost them (restart, SCRIPT FLUSH, failover) is given
// the source again by the call that finds out.
//
// Every key a call touches is named here and passed in KEYS: no script
// builds a key. With the hash tag, the store is fit for Redis Cluster, though
// it only connects to a single Redis (or a primary with replicas) today.
//
// What is written depends on Options.HighConfidentiality, what is read on
// the value alone: a node stored with its decrypted name is read as it is,
// one stored sealed (the ciphertexts the API sent, never anything encrypted
// here) goes through Codec.Open. One hash may hold both.
//
// The values are binary, a format of this package (wire.go): a version byte,
// then fields in a fixed order, a block of them carrying its length so that
// a field can be added at its end. A sealed node holds its AGE payloads
// (name, target, MIME type) in binary. The API sends them armored: the armor
// is taken off when the node is written, which makes the value a quarter
// smaller, and is not put back when it is read (metastore.Sealed holds either
// form). Taking an armor off decodes base64: the AGE bytes are those the API
// sent, and this package still encrypts nothing. redis-cli shows such values
// as escaped bytes: Describe (describe.go) decodes one, and
// scripts/redis-cache-dump prints a cache with it.
//
// The list of datarooms is the user's own and stays in memory.
package redisstore

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

const (
	// DefaultPrefix starts every key when Options.Prefix is empty.
	DefaultPrefix = "retyc"
	// schema is the version of the key layout, part of every key.
	schema = "v2"
	// generationLife is how long a generation outlives the last write to its
	// listing. It only has to outlast a fetch of that listing.
	generationLife = 24 * time.Hour
	// tokenSlack is added to the longest lifetime of a value to make that of
	// a token, lengthened by every write below it.
	tokenSlack = time.Minute
	// tokensField is the reserved field of a listing and of an entries hash
	// that records the tokens they were written under.
	tokensField = "t"
	// ioTimeout bounds the dial and each read or write of the connection: the
	// caller holds a process-wide mutex across a call.
	ioTimeout = 2 * time.Second
	// maxListingBytes bounds the fields and values of one listing, which
	// travel as the arguments of a single command: 64 MiB, about 25,000 sealed
	// nodes. A larger listing is not stored (PutListingIf answers false), the
	// one held is removed and the generation bumped, as for any listing the
	// store cannot keep. Redis itself takes 512 MiB an argument and 1 GiB a
	// command by default.
	maxListingBytes = 64 << 20
)

// minVersion is the first Redis with a lifetime per hash field (HPEXPIRE).
var minVersion = [2]int{7, 4}

// Options configure a Store.
type Options struct {
	// URL is a redis:// or rediss:// URL, password included. It is never
	// logged and never part of an error.
	URL string
	// HighConfidentiality makes this process write sealed nodes: no decrypted
	// name, target or MIME type leaves it. It does not change what is read.
	HighConfidentiality bool
	// ListingLife is how long Redis keeps a listing, EntryLife a positive
	// entry, NegativeEntryLife a negative one; a zero NegativeEntryLife
	// stores none.
	ListingLife       time.Duration
	EntryLife         time.Duration
	NegativeEntryLife time.Duration
	// Prefix starts every key, DefaultPrefix when empty.
	Prefix string
}

// Store is a metastore.MetaStore in Redis. Build one with New.
type Store struct {
	rdb    *redis.Client
	opts   Options
	prefix string
	// secrets are replaced in every error message (see fail).
	secrets []string
	// codec is nil until Bind: the store then reads nothing and writes
	// nothing.
	codec atomic.Pointer[metastore.Codec]
	// tokenLife is the lifetime of a token.
	tokenLife time.Duration
	// maxListing is maxListingBytes, lowered by tests.
	maxListing int

	mu        sync.Mutex
	datarooms *metastore.DataroomList
}

var (
	_ metastore.MetaStore = (*Store)(nil)
	_ metastore.Binder    = (*Store)(nil)
)

// silence drops what go-redis would print on stderr (a connection it
// discards): the store reports through its errors only.
type silence struct{}

func (silence) Printf(context.Context, string, ...interface{}) {}

var silenceOnce sync.Once

// New connects to the Redis of opts.URL, and checks that it answers and is
// recent enough. The error never holds the URL.
func New(ctx context.Context, opts Options) (*Store, error) {
	if opts.ListingLife <= 0 || opts.EntryLife <= 0 || opts.NegativeEntryLife < 0 {
		return nil, errors.New("redisstore: ListingLife and EntryLife must be positive, NegativeEntryLife not negative")
	}
	// The parse error of a URL quotes it, password included: it is dropped.
	ropts, err := redis.ParseURL(opts.URL)
	if err != nil {
		return nil, errors.New("redisstore: invalid Redis URL, expected redis://[user:password@]host:port[/db] or rediss://")
	}
	ropts.DialTimeout = ioTimeout
	ropts.ReadTimeout = ioTimeout
	ropts.WriteTimeout = ioTimeout
	ropts.ContextTimeoutEnabled = true
	ropts.MaxRetries = 1
	silenceOnce.Do(func() { redis.SetLogger(silence{}) })

	s := &Store{
		rdb:       redis.NewClient(ropts),
		opts:      opts,
		prefix:    opts.Prefix,
		tokenLife: max(opts.ListingLife, opts.EntryLife, opts.NegativeEntryLife) + tokenSlack,

		maxListing: maxListingBytes,
	}
	if s.prefix == "" {
		s.prefix = DefaultPrefix
	}
	for _, secret := range []string{opts.URL, ropts.Password} {
		if secret != "" {
			s.secrets = append(s.secrets, secret)
		}
	}
	if err := s.check(ctx); err != nil {
		_ = s.rdb.Close()

		return nil, err
	}

	return s, nil
}

// check is the startup probe: a PING, then the version of the server.
func (s *Store) check(ctx context.Context) error {
	if err := s.rdb.Ping(ctx).Err(); err != nil {
		return s.fail("connecting to Redis", err)
	}
	info, err := s.rdb.Info(ctx, "server").Result()
	if err != nil {
		return s.fail("reading the Redis version", err)
	}
	version, ok := serverVersion(info)
	if !ok {
		return errors.New("redisstore: the server does not report a redis_version")
	}
	if !versionAtLeast(version, minVersion) {
		return fmt.Errorf("redisstore: Redis %s is too old, %d.%d or later is required (per-field expiry, HPEXPIRE)",
			version, minVersion[0], minVersion[1])
	}

	return nil
}

// serverVersion reads redis_version out of INFO server.
func serverVersion(info string) (string, bool) {
	for line := range strings.SplitSeq(info, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "redis_version:"); ok && v != "" {
			return v, true
		}
	}

	return "", false
}

// versionAtLeast compares the major and minor of version with least. A
// version it cannot read is too old.
func versionAtLeast(version string, least [2]int) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}

	return major > least[0] || (major == least[0] && minor >= least[1])
}

// Bind implements metastore.Binder.
func (s *Store) Bind(codec metastore.Codec) {
	if codec == nil {
		s.codec.Store(nil)

		return
	}
	s.codec.Store(&codec)
}

// Close implements metastore.MetaStore.
func (s *Store) Close() error {
	if err := s.rdb.Close(); err != nil && !errors.Is(err, redis.ErrClosed) {
		return s.fail("closing", err)
	}

	return nil
}

// GetDatarooms implements metastore.MetaStore. The list is this process's:
// it belongs to one user and is never written to Redis.
func (s *Store) GetDatarooms(context.Context) (*metastore.DataroomList, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.datarooms, s.datarooms != nil, nil
}

// PutDatarooms implements metastore.MetaStore.
func (s *Store) PutDatarooms(_ context.Context, list *metastore.DataroomList) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.datarooms = list

	return nil
}

// storeError is an error of Redis with the secrets of the URL taken out of
// its message. It still unwraps to the original (a context's end, a
// *net.OpError).
type storeError struct {
	msg string
	err error
}

func (e *storeError) Error() string { return e.msg }
func (e *storeError) Unwrap() error { return e.err }

// fail wraps an error of the client. go-redis does not quote the URL, but
// nothing here relies on that.
func (s *Store) fail(op string, err error) error {
	msg := "redisstore: " + op + ": " + err.Error()
	for _, secret := range s.secrets {
		msg = strings.ReplaceAll(msg, secret, "***")
	}

	return &storeError{msg: msg, err: err}
}

// hasher hashes for one dataroom. Its zero value hashes nothing.
type hasher struct {
	codec      metastore.Codec
	dataroomID string
}

// hasher returns the hasher of a dataroom; ok is false before Bind.
func (s *Store) hasher(dataroomID string) (hasher, bool) {
	c := s.codec.Load()
	if c == nil {
		return hasher{}, false
	}

	return hasher{codec: *c, dataroomID: dataroomID}, true
}

func (h hasher) hash(v string) (string, bool) {
	if h.codec == nil {
		return "", false
	}
	sum, ok := h.codec.Hash(h.dataroomID, v)

	return sum, ok && sum != ""
}

// folder is the keys of one folder of a dataroom.
type folder struct {
	hasher
	h string // hash of the folder's path
	// ls, entries and gen are the keys named after h.
	ls, entries, gen string
	// tl and te are the listing and entry tokens of each folder from the root
	// down to this one, the root first.
	tl, te []string
}

func (s *Store) key(dataroomID, kind, h string) string {
	return s.prefix + ":" + schema + ":{" + dataroomID + "}:" + kind + ":" + h
}

// folder returns the keys of the folder at p. ok is false when they cannot
// be named: no codec yet, or a dataroom whose session is not resolved. The
// caller then reads nothing and writes nothing.
func (s *Store) folder(dataroomID, p string) (folder, bool) {
	hs, ok := s.hasher(dataroomID)
	if !ok {
		return folder{}, false
	}
	h, ok := hs.hash(p)
	if !ok {
		return folder{}, false
	}
	f := folder{
		hasher:  hs,
		h:       h,
		ls:      s.key(dataroomID, KindListing, h),
		entries: s.key(dataroomID, KindEntries, h),
		gen:     s.key(dataroomID, KindGeneration, h),
	}
	hashes := []string{h}
	for p != "/" && p != "." && p != "" {
		p = path.Dir(p)
		ah, ok := hs.hash(p)
		if !ok {
			return folder{}, false
		}
		hashes = append(hashes, ah)
	}
	f.tl = make([]string, len(hashes))
	f.te = make([]string, len(hashes))
	for i, ah := range hashes { // the root first
		f.tl[len(hashes)-1-i] = s.key(dataroomID, KindListingToken, ah)
		f.te[len(hashes)-1-i] = s.key(dataroomID, KindEntryToken, ah)
	}

	return f, true
}

// withTokens returns keys followed by the listing token of each folder from
// the root down to f: the KEYS of a script that writes to its listing.
func (f folder) withTokens(keys ...string) []string {
	return append(keys, f.tl...)
}

// newToken draws a token: 128 random bits.
func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand never fails (it panics instead)

	return hex.EncodeToString(b[:])
}

// maxGenerationStart bounds the random start of a generation: the scripts
// add a 52-bit fingerprint to it, and the sum must stay below 2^53 (see
// lua/lib.lua), with room left for the writes that INCR it.
const maxGenerationStart = 1 << 51

// newGeneration draws the start of a generation, in [1, 2^51].
func newGeneration() string {
	var b [8]byte
	_, _ = rand.Read(b[:])

	return strconv.FormatUint(binary.BigEndian.Uint64(b[:])%maxGenerationStart+1, 10)
}

// tokensOf joins the answer of an MGET of tokens as the scripts record them;
// ok is false when one is absent: nothing recorded under it is valid.
func tokensOf(vals []any) (string, bool) {
	parts := make([]string, len(vals))
	for i, v := range vals {
		t, ok := v.(string)
		if !ok || t == "" {
			return "", false
		}
		parts[i] = t
	}

	return strings.Join(parts, ","), true
}

// sameTokens tells whether recorded, a field "t" as read by HMGET, is the
// tokens of now, read by MGET in the same MULTI.
func sameTokens(recorded any, now []any) bool {
	r, ok := recorded.(string)
	if !ok {
		return false
	}
	t, ok := tokensOf(now)

	return ok && r == t
}

// remaining is what is left of life for a value fetched at fetchedAt: the
// lifetime it is stored with, so that Redis counts its age from the fetch and
// not from the write. The difference is taken on this process's clock alone.
// A zero fetchedAt is "now".
func remaining(life time.Duration, fetchedAt time.Time) time.Duration {
	if fetchedAt.IsZero() {
		return life
	}
	if age := time.Since(fetchedAt); age > 0 {
		life -= age
	}

	return life.Truncate(time.Millisecond)
}

// fetchedAt turns what Redis says is left of a value's lifetime into the
// time it was fetched at, on this process's clock. asked is taken before the
// request leaves, so the value is never dated later than it is.
func fetchedAt(asked time.Time, lifeMS int64, left time.Duration) time.Time {
	age := time.Duration(lifeMS)*time.Millisecond - left
	if age < 0 {
		age = 0
	}

	return asked.Add(-age)
}
