package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
)

// The memory store is vfs's own: nothing is built, and nothing is dialed.
func TestNewMetaStore_Memory(t *testing.T) {
	cfg := &config.Config{Cache: config.CacheConfig{
		TTL: time.Minute, Store: config.CacheStoreMemory,
		// A URL without cache.store: redis is not used.
		Redis: config.CacheRedisConfig{URL: "redis://127.0.0.1:1"},
	}}
	store, err := newMetaStore(context.Background(), cfg, 0)
	if err != nil || store != nil {
		t.Fatalf("newMetaStore = (%v, %v), want (nil, nil)", store, err)
	}
}

// A Redis that does not answer fails the start, and the error holds neither
// the URL nor its credentials. The host and port the dial was refused at may
// be named (the network error does): they are what the operator needs.
func TestNewMetaStore_UnreachableRedis(t *testing.T) {
	const password = "s3cr3t-pw"
	for label, url := range map[string]string{
		// Port 1 of the loopback: refused at once.
		"refused":   "redis://user:" + password + "@127.0.0.1:1/0",
		"malformed": "redis://user:" + password + "@127.0.0.1:notaport/x",
	} {
		t.Run(label, func(t *testing.T) {
			cfg := &config.Config{Cache: config.CacheConfig{
				TTL: time.Minute, NegativeTTL: time.Second, Store: config.CacheStoreRedis,
				Redis: config.CacheRedisConfig{URL: url},
			}}
			store, err := newMetaStore(context.Background(), cfg, 0)
			if err == nil {
				_ = store.Close()
				t.Fatal("newMetaStore accepted a Redis that does not answer")
			}
			if store != nil {
				t.Errorf("newMetaStore returned a store with its error")
			}
			for _, secret := range []string{password, url} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error holds %q: %v", secret, err)
				}
			}
		})
	}
}
