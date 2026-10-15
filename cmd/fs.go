// Package cmd — fs command group (filesystem access to datarooms).
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/retyc/retyc-cli/internal/config"
)

// fsCmd groups the commands that expose datarooms as a filesystem. It must
// not carry a PersistentPreRun(E): cobra runs only the closest one, so it
// would mask the root hook (CA loading, tracing, concurrency).
var fsCmd = &cobra.Command{
	Use:   "fs",
	Short: "Filesystem access to your datarooms",
	Long: `Expose your RETYC datarooms as a filesystem, so that file managers and
ordinary tools can browse, read and write them. Content is encrypted and
decrypted locally, as with the other commands.`,
}

// cacheFlags maps the flags of the fs front ends to the keys of the common
// `cache:` section.
var cacheFlags = [][2]string{
	{"cache-ttl", "cache.ttl"},
	{"cache-max-stale", "cache.max_stale"},
	{"cache-negative-ttl", "cache.negative_ttl"},
	{"cache-store", "cache.store"},
	{"cache-redis-url", "cache.redis.url"},
	{"cache-redis-high-confidentiality", "cache.redis.high_confidentiality"},
}

// addCacheFlags declares the cache flags on an fs front end. maxStale is
// false for a front end that never serves an expired listing (`fs mount`):
// a flag that changes nothing is not offered.
func addCacheFlags(cmd *cobra.Command, maxStale bool) {
	cmd.Flags().Duration("cache-ttl", config.DefaultCacheTTL,
		"how long a folder listing, the dataroom list or a name looked up is served from memory")
	if maxStale {
		cmd.Flags().Duration("cache-max-stale", config.DefaultCacheMaxStale,
			"how much longer an expired listing is served while it is refreshed in the background (0 disables)")
	}
	cmd.Flags().Duration("cache-negative-ttl", config.DefaultCacheNegativeTTL,
		"how long a name found missing is answered missing without asking again (0 disables)")
	cmd.Flags().String("cache-store", config.CacheStoreMemory,
		"where listings and names looked up are kept: memory, or redis to share them between instances")
	cmd.Flags().String("cache-redis-url", "",
		"redis:// or rediss:// URL of the shared cache, password included "+
			"(prefer RETYC_CACHE_REDIS_URL: a flag shows in the process list)")
	cmd.Flags().Bool("cache-redis-high-confidentiality", false,
		"store in Redis the encrypted names the API sent, never the decrypted ones")
}

// resolveCacheFlags binds the cache flags the command declares to their
// viper keys, so that config.Load reads them with the usual precedence
// (flag > env > config file > default) and validates them like any other
// source. Same binding strategy as resolveMetricsAddr: from RunE, never from
// init(), to survive the viper.Reset() of the config tests.
func resolveCacheFlags(flags *pflag.FlagSet) {
	for _, f := range cacheFlags {
		if flag := flags.Lookup(f[0]); flag != nil {
			_ = viper.BindPFlag(f[1], flag)
		}
	}
}

func init() {
	rootCmd.AddCommand(fsCmd)
}
