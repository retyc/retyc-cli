// Package metrics declares the Prometheus metrics of the CLI.
//
// Every metric is a package-level collector, observed where the event happens
// (API client, session cache, WebDAV server, chunk crypto) and exposed only by
// `webdav serve --metrics-addr` and `fs mount --metrics-addr`, which register
// them. Unregistered collectors
// still accept observations, so instrumentation costs nothing to callers that
// never expose them (the MCP server, one-shot commands).
//
// Four prefixes: retyc_cli_ for what is not specific to a front end (API
// calls, token, crypto), retyc_cli_vfs_ for what internal/vfs does for every
// filesystem front end (caches, spools, uploads, API locks),
// retyc_cli_webdav_ for the WebDAV server itself and retyc_cli_fuse_ for the
// FUSE driver.
//
// Adding a metric: declare it here, add it to Register, observe it at the
// event. Keep label cardinality bounded (no IDs, no raw paths).
package metrics

import (
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Buckets tuned for a CLI talking to a remote API: from a cache hit to a
// multi-chunk upload.
var latencyBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

// A FUSE operation is most often answered from memory: the buckets start two
// decades lower.
var fuseBuckets = []float64{.00005, .0001, .00025, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

// A store operation is one round trip to a Redis that is usually close: from
// 100 µs to its 2 s I/O timeout, and past it for a retried command.
var storeBuckets = []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}

var (
	// WebdavRequests counts WebDAV requests by method and HTTP status.
	WebdavRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_webdav_requests_total",
		Help: "WebDAV requests served, by method and HTTP status.",
	}, []string{"method", "status"})

	// WebdavRequestDuration is the WebDAV request latency by method.
	WebdavRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retyc_cli_webdav_request_duration_seconds",
		Help:    "WebDAV request duration in seconds, by method.",
		Buckets: latencyBuckets,
	}, []string{"method"})

	// WebdavInflight is the number of WebDAV requests being served.
	WebdavInflight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retyc_cli_webdav_inflight_requests",
		Help: "WebDAV requests currently being served.",
	})

	// WebdavBytes counts plaintext bytes moved through the WebDAV server.
	WebdavBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_webdav_bytes_total",
		Help: "Plaintext bytes served (download) or received (upload) by the WebDAV server.",
	}, []string{"direction"})

	// VFSNodeCacheLookups counts node listing cache lookups: hit, stale
	// (expired listing served while a background refresh replaces it) or miss.
	// Observed in internal/vfs, so by every front end built on it.
	VFSNodeCacheLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_vfs_node_cache_lookups_total",
		Help: "Node listing cache lookups, by result (hit, stale, miss).",
	}, []string{"result"})

	// VFSDataroomCacheRefreshes counts refreshes of the dataroom list cache,
	// by result: ok, or error when the listing failed and the list held, if
	// any, stayed in place.
	VFSDataroomCacheRefreshes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_vfs_dataroom_cache_refreshes_total",
		Help: "Refreshes of the dataroom list cache (one API listing each), by result (ok, error).",
	}, []string{"result"})

	// VFSSpoolBytes is what the spool files of the files being written hold
	// on disk (a WebDAV upload of unknown length, a file open for writing
	// through the mount).
	VFSSpoolBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retyc_cli_vfs_spool_bytes",
		Help: "Bytes held in the spool files of the files being written.",
	})

	// VFSUploads counts the uploads of a file content (a creation or a new
	// version), by result.
	VFSUploads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_vfs_uploads_total",
		Help: "Uploads of a file content (new file or new version), by result (ok, error).",
	}, []string{"result"})

	// VFSLocksHeld is the number of API locks held on files.
	VFSLocksHeld = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retyc_cli_vfs_locks_held",
		Help: "API locks currently held on files (WebDAV LOCK, mount --mirror-locks).",
	})

	// VFSStoreOpDuration is the duration of one operation of a shared
	// metadata store (Redis), by operation (a fixed name per method of the
	// store: get_node, put_listing, ...) and result. The in-memory store
	// observes nothing.
	VFSStoreOpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retyc_cli_vfs_store_op_duration_seconds",
		Help:    "Duration of the operations of the shared metadata store (Redis) in seconds, by operation and result.",
		Buckets: storeBuckets,
	}, []string{"op", "result"})

	// FuseOps counts the FUSE operations served, by operation and result: ok
	// or the name of the errno answered ("other" for one the driver has no
	// name for).
	FuseOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_fuse_ops_total",
		Help: "FUSE operations served, by operation and result (ok, or the errno name).",
	}, []string{"op", "result"})

	// FuseBackgroundDeletes counts the deletes a mount sent after unlink had
	// answered (mount --background-delete), by result: ok or error.
	FuseBackgroundDeletes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_fuse_background_deletes_total",
		Help: "Deletes sent in the background after unlink answered (mount --background-delete), by result (ok, error).",
	}, []string{"result"})

	// FuseOpDuration is the time a FUSE operation took, by operation.
	FuseOpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retyc_cli_fuse_op_duration_seconds",
		Help:    "FUSE operation duration in seconds, by operation.",
		Buckets: fuseBuckets,
	}, []string{"op"})

	// FuseBytes counts plaintext bytes moved through the mount.
	FuseBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_fuse_bytes_total",
		Help: "Plaintext bytes read from (read) or written to (write) the mount.",
	}, []string{"direction"})

	// FuseOpenHandles is the number of file handles open on the mount, by
	// kind: write for a handle that changes its file, read otherwise.
	FuseOpenHandles = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "retyc_cli_fuse_open_handles",
		Help: "File handles open on the mount, by kind (read, write).",
	}, []string{"kind"})

	// APIRequests counts calls to the RETYC API by method, normalized route
	// and HTTP status ("error" when no response came back).
	APIRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_api_requests_total",
		Help: "RETYC API requests, by method, normalized route and HTTP status (error = transport failure).",
	}, []string{"method", "route", "status"})

	// APIRequestDuration is the API round-trip latency by method and route.
	APIRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retyc_cli_api_request_duration_seconds",
		Help:    "RETYC API request duration in seconds, by method and normalized route.",
		Buckets: latencyBuckets,
	}, []string{"method", "route"})

	// APIThrottleEpisodes counts the times the API rate limit (429) closed
	// the gate of a client; every refusal is already a status="429" request.
	APIThrottleEpisodes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "retyc_cli_api_throttle_episodes_total",
		Help: "Episodes of API rate limiting (429): times the client paused all its requests.",
	})

	// APIThrottleWait is the time one request was held back by the rate
	// limit, behind the gate or for its own Retry-After.
	APIThrottleWait = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "retyc_cli_api_throttle_wait_seconds",
		Help:    "Time an API request was held back by the rate limit, in seconds.",
		Buckets: latencyBuckets,
	})

	// APIRateLimited counts the requests given up after api.retry.max_wait or
	// api.retry.max_attempts, by method.
	APIRateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_api_rate_limited_total",
		Help: "API requests given up after retrying on 429, by method.",
	}, []string{"method"})

	// TokenRefreshes counts keepalive token checks by result (ok, error).
	TokenRefreshes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_token_refreshes_total",
		Help: "Login token checks by the keepalive, by result (ok, error).",
	}, []string{"result"})

	// TokenExpiry is the remaining lifetime of the access token.
	TokenExpiry = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retyc_cli_token_expiry_seconds",
		Help: "Seconds until the current access token expires (0 when unknown).",
	})

	// CryptoDuration is the per-chunk encryption/decryption time.
	CryptoDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retyc_cli_crypto_duration_seconds",
		Help:    "Per-chunk AGE operation duration in seconds, by op (encrypt, decrypt).",
		Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1},
	}, []string{"op"})
)

// all lists every collector, in the order of the declarations above.
var all = []prometheus.Collector{
	WebdavRequests, WebdavRequestDuration, WebdavInflight, WebdavBytes,
	VFSNodeCacheLookups, VFSDataroomCacheRefreshes,
	VFSSpoolBytes, VFSUploads, VFSLocksHeld, VFSStoreOpDuration,
	FuseOps, FuseOpDuration, FuseBytes, FuseOpenHandles, FuseBackgroundDeletes,
	APIRequests, APIRequestDuration,
	APIThrottleEpisodes, APIThrottleWait, APIRateLimited,
	TokenRefreshes, TokenExpiry, CryptoDuration,
}

// All returns every metric of the package, for callers that register them
// one by one (to wrap them with constant labels, or to report an error
// instead of panicking).
func All() []prometheus.Collector {
	return append([]prometheus.Collector(nil), all...)
}

// Register adds every metric of the package to reg. A collector may belong to
// several registries, so calling it for more than one registry is safe.
func Register(reg prometheus.Registerer) {
	reg.MustRegister(all...)
}

// routeTemplates lists every route the CLI calls, as the backend templates
// it maps to. NormalizeRoute matches a path against them position by
// position: a segment sitting where a template expects {id} or {n} is
// folded whatever its value, so an identifier that happens to equal a route
// word ("users", "dataroom", ...) is folded too. The optional /v1 prefix is
// the admin API. Extend the list when a new route appears.
var routeTemplates = [][]string{
	{"dataroom"},
	{"dataroom", "{id}"},
	{"dataroom", "{id}", "nodes"},
	{"dataroom", "{id}", "node"},
	{"dataroom", "{id}", "node", "file"},
	{"dataroom", "{id}", "node", "symlink"},
	{"dataroom", "{id}", "messages"},
	{"dataroom", "{id}", "stats"},
	{"dataroom", "{id}", "users"},
	{"dataroom", "{id}", "users", "rekey"},
	{"dataroom", "{id}", "user", "{id}"},
	{"dataroom", "{id}", "ownership", "{id}"},
	{"dataroom", "{id}", "rekey"},
	{"dataroom", "node", "{id}"},
	{"dataroom", "node", "{id}", "version"},
	{"dataroom", "node", "{id}", "download", "{n}"},
	{"dataroom", "node", "version", "{id}", "chunk", "{n}"},
	{"share"},
	{"share", "{id}"},
	{"share", "{id}", "details"},
	{"share", "{id}", "files"},
	{"share", "{id}", "file"},
	{"share", "{id}", "complete"},
	{"share", "{id}", "re-enable"},
	{"share", "{id}", "force"},
	{"file", "{id}", "{n}"},
	{"user", "me"},
	{"user", "me", "key", "active"},
	{"user", "quota"},
	{"organization"},
	{"organization", "quota"},
	{"organization", "members"},
	{"organization", "member", "{id}"},
	{"organization", "member", "{id}", "enable"},
	{"organization", "member", "{id}", "disable"},
	{"organization", "blacklist-domains"},
	{"organization", "blacklist-domains", "{id}"},
	{"info", "scopes"},
	{"transfer", "sent"},
	{"transfer", "{id}"},
	{"transfer", "{id}", "tracking"},
	{"transfer", "{id}", "re-enable"},
	{"transfer", "{id}", "force"},
	{"transfer", "{id}", "rekey"},
	{"login", "config", "public"},
	// Identity provider (Keycloak) routes, reached by the OIDC client: the
	// realm is folded like an identifier.
	{"realms", "{id}", ".well-known", "openid-configuration"},
	{"realms", "{id}", "protocol", "openid-connect", "token"},
	{"realms", "{id}", "protocol", "openid-connect", "auth", "device"},
	{"realms", "{id}", "protocol", "openid-connect", "logout"},
}

// routeWords is the vocabulary of literal segments of routeTemplates. It is
// the fallback for a path matching no template: route words are kept and
// every other segment is folded, so even an unknown route never exports
// anything a user typed.
var routeWords = func() map[string]bool {
	words := map[string]bool{"v1": true}
	for _, tpl := range routeTemplates {
		for _, seg := range tpl {
			if seg != "{id}" && seg != "{n}" {
				words[seg] = true
			}
		}
	}

	return words
}()

var (
	uuidSegment    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numericSegment = regexp.MustCompile(`^[0-9]+$`)
)

// NormalizeRoute turns an API path into its template. A path matching one of
// routeTemplates is normalized by position; otherwise route words are kept,
// numbers become {n} and every other segment becomes {id}. The result is
// bounded and never contains an identifier, UUID or user-typed.
func NormalizeRoute(path string) string {
	trailing := ""
	if strings.HasSuffix(path, "/") && path != "/" {
		trailing = "/"
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	prefix := ""
	if len(segments) > 0 && segments[0] == "v1" {
		prefix = "/v1"
		segments = segments[1:]
	}
	if tpl := matchTemplate(segments); tpl != nil {
		return prefix + "/" + strings.Join(tpl, "/") + trailing
	}
	for i, s := range segments {
		switch {
		case s == "" || routeWords[s]:
		case numericSegment.MatchString(s):
			segments[i] = "{n}"
		default:
			segments[i] = "{id}"
		}
	}

	return prefix + "/" + strings.Join(segments, "/") + trailing
}

// matchTemplate returns the first template of the same length whose literal
// segments equal the path's and whose {n} positions hold a number; {id}
// accepts anything. A trailing empty segment ("/dataroom/") is ignored.
func matchTemplate(segments []string) []string {
	for _, tpl := range routeTemplates {
		if len(tpl) != len(segments) {
			continue
		}
		ok := true
		for i, want := range tpl {
			got := segments[i]
			switch want {
			case "{id}":
				ok = got != ""
			case "{n}":
				ok = numericSegment.MatchString(got)
			default:
				ok = got == want
			}
			if !ok {
				break
			}
		}
		if ok {
			return tpl
		}
	}

	return nil
}

// IsUUIDSegment reports whether a path segment is a UUID (an identifier that
// NormalizeRoute turns into {id}).
func IsUUIDSegment(s string) bool { return uuidSegment.MatchString(s) }

// IsNumericSegment reports whether a path segment is a number (a chunk index
// that NormalizeRoute turns into {n}).
func IsNumericSegment(s string) bool { return numericSegment.MatchString(s) }
