package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/vfs"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/redisstore"
)

// newMetaStore returns the store of cache.store for the tree of an fs front
// end, shared by `fs webdav serve` and `fs mount`: nil for the memory (vfs
// then keeps its own), a Redis store otherwise. maxStale is the
// vfs.Options.MaxStale the front end builds its tree with, which is not
// always cache.max_stale: Redis keeps a listing for as long as that tree may
// still use it.
//
// A Redis that does not answer, or is too old, is an error here, before
// anything is mounted or bound. Neither the error nor the --debug line holds
// the URL, which carries the password. The tree closes the store it is given
// (vfs.FS.Close).
func newMetaStore(ctx context.Context, cfg *config.Config, maxStale time.Duration) (metastore.MetaStore, error) {
	if cfg.Cache.Store != config.CacheStoreRedis {
		return nil, nil
	}
	store, err := redisstore.New(ctx, redisstore.Options{
		URL:                 cfg.Cache.Redis.URL,
		HighConfidentiality: cfg.Cache.Redis.HighConfidentiality,
		ListingLife:         vfs.ListingRetention(cfg.Cache.TTL, maxStale),
		EntryLife:           cfg.Cache.TTL,
		NegativeEntryLife:   cfg.Cache.NegativeTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("cache.store redis: %w", err)
	}
	if debug {
		fmt.Fprintf(os.Stderr, "cache store: redis (high confidentiality: %t)\n",
			cfg.Cache.Redis.HighConfidentiality)
	}

	return store, nil
}
