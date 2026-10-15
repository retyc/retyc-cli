package redisstore

import (
	"context"
	_ "embed" // the Lua sources
	"errors"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// The scripts, one per operation. Each is a redis.Script, run with Run:
// EVALSHA, and EVAL of the source when the server answers NOSCRIPT (a restart,
// a SCRIPT FLUSH, a failover to a replica that never ran it). Nothing is
// loaded ahead and nothing is remembered about the server: a script that is
// not cached costs one more round trip, once, never an error. The source is
// part of the binary, and a script is named by the hash of its source: two
// versions of the CLI on one Redis run each their own.
var (
	//go:embed lua/lib.lua
	libLua string
	//go:embed lua/generation.lua
	generationLua string
	//go:embed lua/put_listing.lua
	putListingLua string
	//go:embed lua/renew_listing.lua
	renewListingLua string
	//go:embed lua/upsert_node.lua
	upsertNodeLua string
	//go:embed lua/remove_node.lua
	removeNodeLua string
	//go:embed lua/drop_listing.lua
	dropListingLua string
	//go:embed lua/put_entry.lua
	putEntryLua string

	generationScript   = newScript(generationLua)
	putListingScript   = newScript(putListingLua)
	renewListingScript = newScript(renewListingLua)
	upsertNodeScript   = newScript(upsertNodeLua)
	removeNodeScript   = newScript(removeNodeLua)
	dropListingScript  = newScript(dropListingLua)
	putEntryScript     = newScript(putEntryLua)
)

// newScript is a script whose source follows lib.lua, the functions every
// script shares.
func newScript(body string) *redis.Script {
	return redis.NewScript(libLua + "\n" + body)
}

// run executes a script: one round trip, two the first time a server sees it.
func (s *Store) run(ctx context.Context, script *redis.Script, keys []string, args ...any) (any, error) {
	return script.Run(ctx, s.rdb, keys, args...).Result()
}

// runGeneration runs a script that answers a generation, as a decimal
// string (see lua/lib.lua). Zero is no generation.
func (s *Store) runGeneration(ctx context.Context, script *redis.Script, keys []string, args ...any) (uint64, error) {
	v, err := s.run(ctx, script, keys, args...)
	if err != nil {
		return 0, err
	}
	raw, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("the script answered a %T, not a generation", v)
	}
	gen, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("generation is not a number: %w", err)
	}
	if gen == 0 {
		return 0, errors.New("the script answered generation 0")
	}

	return gen, nil
}

// runFlag runs a script that answers 1 (done) or 0 (refused).
func (s *Store) runFlag(ctx context.Context, script *redis.Script, keys []string, args ...any) (bool, error) {
	v, err := s.run(ctx, script, keys, args...)
	if err != nil {
		return false, err
	}
	n, ok := v.(int64)
	if !ok || (n != 0 && n != 1) {
		return false, fmt.Errorf("the script answered %T %v, not 0 or 1", v, v)
	}

	return n == 1, nil
}
