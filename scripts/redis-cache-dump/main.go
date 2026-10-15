// Command redis-cache-dump prints, as JSON, what the shared metadata cache
// of `retyc fs mount` / `retyc fs webdav serve` (cache.store: redis) holds in
// a Redis. The values are binary (internal/vfs/metastore/redisstore/wire.go)
// and redis-cli shows them as escaped bytes: this decodes them with the
// decoder of the store itself (redisstore.Describe).
//
// It is a diagnostic tool, not part of the release, and it only reads: SCAN,
// PTTL, HGETALL, HPTTL and GET. It decrypts nothing: with
// cache.redis.high_confidentiality a name is printed as the size of its AGE
// payload; without it the names are in Redis and are printed.
//
//	go run ./scripts/redis-cache-dump -url redis://localhost:6379/0 [-prefix retyc] [-dataroom <id>] [-kind ls|e|g|tl|te]
//
// The URL may come from REDIS_URL instead; it is never printed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/retyc/retyc-cli/internal/vfs/metastore/redisstore"
)

const (
	// scanCount is the COUNT of a SCAN, fieldBatch how many fields one HPTTL
	// asks for.
	scanCount  = 500
	fieldBatch = 1000
	ioTimeout  = 5 * time.Second
)

// keyDump is what is printed for one key.
type keyDump struct {
	Name string `json:"key"`
	redisstore.Key
	// TTLMS is what is left of the key's lifetime; -1 for a key without one
	// (an entries hash: its fields expire one by one).
	TTLMS int64 `json:"ttl_ms"`
	// A listing.
	Meta     any            `json:"meta,omitempty"`
	ETag     any            `json:"etag,omitempty"`
	Children map[string]any `json:"children,omitempty"`
	// The entries of a folder, by the hash of the name.
	Entries map[string]entryDump `json:"entries,omitempty"`
	// A generation.
	Generation any `json:"generation,omitempty"`
	// A listing or entry token.
	Token any `json:"token,omitempty"`
	// Tokens is the field "t" of a listing or of an entries hash: the tokens
	// it was written under.
	Tokens any `json:"tokens,omitempty"`
	// Other is the fields of a listing this tool does not know.
	Other map[string]any `json:"other_fields,omitempty"`
}

type entryDump struct {
	// TTLMS is what is left of the field's lifetime.
	TTLMS int64 `json:"ttl_ms"`
	Entry any   `json:"entry"`
}

// problem is what is printed in place of a value that is not described.
type problem struct {
	Error string `json:"error"`
}

// described is Describe, its error printed in place of the value.
func described(kind, field, value string) any {
	d, err := redisstore.Describe(kind, field, []byte(value))
	if err != nil {
		return problem{Error: err.Error()}
	}

	return d
}

func dumpListing(ctx context.Context, rdb *redis.Client, d *keyDump) error {
	fields, err := rdb.HGetAll(ctx, d.Name).Result()
	if err != nil {
		return err
	}
	d.Children = make(map[string]any, len(fields))
	for field, value := range fields {
		switch v := described(redisstore.KindListing, field, value).(type) {
		case *redisstore.MetaDescription:
			d.Meta = v
		case *redisstore.TokensDescription:
			d.Tokens = v
		case string:
			d.ETag = v
		case *redisstore.NodeDescription:
			d.Children[field] = v
		case problem:
			if strings.HasPrefix(field, "n:") {
				d.Children[field] = v
			} else {
				if d.Other == nil {
					d.Other = map[string]any{}
				}
				d.Other[field] = v
			}
		}
	}

	return nil
}

func dumpEntries(ctx context.Context, rdb *redis.Client, d *keyDump) error {
	fields, err := rdb.HGetAll(ctx, d.Name).Result()
	if err != nil {
		return err
	}
	names := make([]string, 0, len(fields))
	for field := range fields {
		names = append(names, field)
	}
	d.Entries = make(map[string]entryDump, len(fields))
	for len(names) > 0 {
		batch := names[:min(fieldBatch, len(names))]
		names = names[len(batch):]
		left, err := rdb.HPTTL(ctx, d.Name, batch...).Result()
		if err != nil {
			return err
		}
		for i, field := range batch {
			if v, ok := described(redisstore.KindEntries, field, fields[field]).(*redisstore.TokensDescription); ok {
				d.Tokens = v

				continue
			}
			e := entryDump{TTLMS: -2, Entry: described(redisstore.KindEntries, field, fields[field])}
			if i < len(left) {
				e.TTLMS = left[i]
			}
			d.Entries[field] = e
		}
	}

	return nil
}

func dump(ctx context.Context, rdb *redis.Client, key string) (*keyDump, error) {
	parsed, ok := redisstore.ParseKey(key)
	if !ok {
		return nil, nil
	}
	ttl, err := rdb.PTTL(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	out := &keyDump{Name: key, Key: parsed, TTLMS: ttl.Milliseconds()}
	if ttl < 0 { // -1: no lifetime, -2: gone since the SCAN; go-redis returns them as they are
		out.TTLMS = int64(ttl)
	}
	switch parsed.Kind {
	case redisstore.KindListing:
		err = dumpListing(ctx, rdb, out)
	case redisstore.KindEntries:
		err = dumpEntries(ctx, rdb, out)
	case redisstore.KindGeneration:
		var value string
		if value, err = rdb.Get(ctx, key).Result(); err == nil {
			out.Generation = described(redisstore.KindGeneration, "", value)
		} else if errors.Is(err, redis.Nil) {
			err = nil
		}
	case redisstore.KindListingToken, redisstore.KindEntryToken:
		var value string
		if value, err = rdb.Get(ctx, key).Result(); err == nil {
			out.Token = described(parsed.Kind, "", value)
		} else if errors.Is(err, redis.Nil) {
			err = nil
		}
	}

	return out, err
}

func run() error {
	url := flag.String("url", "", "Redis URL (redis:// or rediss://); REDIS_URL when empty. Never printed")
	prefix := flag.String("prefix", redisstore.DefaultPrefix, "prefix of the keys (redisstore.Options.Prefix)")
	dataroom := flag.String("dataroom", "", "only the keys of this dataroom ID")
	kind := flag.String("kind", "",
		"only the keys of this kind: ls (listings), e (entries), g (generations), tl (listing tokens), te (entry tokens)")
	flag.Parse()
	switch *kind {
	case "", redisstore.KindListing, redisstore.KindEntries, redisstore.KindGeneration,
		redisstore.KindListingToken, redisstore.KindEntryToken:
	default:
		return fmt.Errorf("unknown kind %q: ls, e, g, tl or te", *kind)
	}
	if *url == "" {
		*url = os.Getenv("REDIS_URL")
	}
	if *url == "" {
		return errors.New("no Redis URL: pass -url or set REDIS_URL")
	}
	opts, err := redis.ParseURL(*url)
	if err != nil {
		// The error of the parser may quote the URL, password included.
		return errors.New("the Redis URL does not parse (redis://[user:password@]host:port/db)")
	}
	opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = ioTimeout, ioTimeout, ioTimeout
	rdb := redis.NewClient(opts)
	defer func() { _ = rdb.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var keys []string
	it := rdb.Scan(ctx, 0, redisstore.KeyPattern(*prefix, *dataroom, *kind), scanCount).Iterator()
	for it.Next(ctx) {
		keys = append(keys, it.Val())
	}
	if err := it.Err(); err != nil {
		return err
	}
	sort.Strings(keys)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	for _, key := range keys {
		d, err := dump(ctx, rdb, key)
		if err != nil {
			return err
		}
		if d == nil {
			continue
		}
		if err := enc.Encode(d); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "%d key(s)\n", len(keys))

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "redis-cache-dump:", err)
		os.Exit(1)
	}
}
