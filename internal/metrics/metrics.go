// Package metrics declares the Prometheus metrics of `retyc fs mount`.
//
// Every metric is a package-level collector, observed where the event happens
// (FUSE driver, internal/vfs, API client, token keepalive) and exposed only by
// `fs mount --metrics-addr`, which registers them. Unregistered collectors
// still accept observations, so instrumentation costs nothing to the other
// commands, which share the code that observes them.
//
// One prefix, retycfs_: the mount is the only command that exposes metrics.
//
// Adding a metric: declare it here, add it to all, observe it at the event,
// document it in doc/retycfs.md. Keep label cardinality bounded (no IDs, no
// raw paths).
package metrics

import (
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Buckets tuned for a round trip to a remote API: from a small listing to a
// multi-chunk upload.
var latencyBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

// A filesystem operation is most often answered from memory: the buckets
// start two decades lower.
var opBuckets = []float64{.00005, .0001, .00025, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30}

// A store operation is one round trip to a Redis that is usually close: from
// 100 µs to its 2 s I/O timeout, and past it for a retried command.
var storeBuckets = []float64{.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}

var (
	// Ops counts filesystem operations by operation and result.
	Ops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_ops_total",
		Help: "Filesystem operations served, by operation and result (ok, or the errno name).",
	}, []string{"op", "result"})

	// OpDuration times filesystem operations.
	OpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retycfs_op_duration_seconds",
		Help:    "Filesystem operation duration in seconds, by operation.",
		Buckets: opBuckets,
	}, []string{"op"})

	// Bytes counts the plaintext bytes read from and written to the mount.
	Bytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_bytes_total",
		Help: "Plaintext bytes read from (read) or written to (write) the mount.",
	}, []string{"direction"})

	// OpenHandles counts the file handles open on the mount.
	OpenHandles = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "retycfs_open_handles",
		Help: "File handles open on the mount, by kind (read, write).",
	}, []string{"kind"})

	// BackgroundDeletes counts the deletes sent after unlink answered.
	BackgroundDeletes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_background_deletes_total",
		Help: "Deletes sent in the background after unlink answered (--background-delete), by result (ok, error).",
	}, []string{"result"})

	// CacheLookups counts the lookups of the node listing cache.
	CacheLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_cache_lookups_total",
		Help: "Node listing cache lookups, by result (hit, stale, miss).",
	}, []string{"result"})

	// DataroomListRefreshes counts the refreshes of the dataroom list.
	DataroomListRefreshes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_dataroom_list_refreshes_total",
		Help: "Refreshes of the dataroom list cache (one API listing each), by result (ok, error).",
	}, []string{"result"})

	// SpoolBytes is the size of the spool files of the files being written.
	SpoolBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retycfs_spool_bytes",
		Help: "Bytes held in the spool files of the files being written.",
	})

	// Uploads counts the uploads of a file content.
	Uploads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_uploads_total",
		Help: "Uploads of a file content (new file or new version), by result (ok, error).",
	}, []string{"result"})

	// LocksHeld is the number of API locks held on files.
	LocksHeld = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retycfs_locks_held",
		Help: "API locks currently held on files (--mirror-locks).",
	})

	// StoreOpDuration times the operations of the shared metadata store.
	StoreOpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retycfs_store_op_duration_seconds",
		Help:    "Duration of the operations of the shared metadata store (Redis) in seconds, by operation and result.",
		Buckets: storeBuckets,
	}, []string{"op", "result"})

	// APIRequests counts the RETYC API requests.
	APIRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_api_requests_total",
		Help: "RETYC API requests, by method, normalized route and HTTP status (error = transport failure).",
	}, []string{"method", "route", "status"})

	// APIRequestDuration times the RETYC API requests.
	APIRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "retycfs_api_request_duration_seconds",
		Help:    "RETYC API request duration in seconds, by method and normalized route.",
		Buckets: latencyBuckets,
	}, []string{"method", "route"})

	// APIThrottleEpisodes counts the pauses the API rate limit imposed.
	APIThrottleEpisodes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "retycfs_api_throttle_episodes_total",
		Help: "Episodes of API rate limiting (429): times the client paused all its requests.",
	})

	// APIRateLimited counts the requests given up on 429.
	APIRateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_api_rate_limited_total",
		Help: "API requests given up after retrying on 429, by method.",
	}, []string{"method"})

	// TokenRefreshes counts the login checks of the keepalive.
	TokenRefreshes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_token_refreshes_total",
		Help: "Login token checks by the keepalive, by result (ok, error).",
	}, []string{"result"})

	// TokenExpiry is the time left on the access token.
	TokenExpiry = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retycfs_token_expiry_seconds",
		Help: "Seconds until the current access token expires (0 when unknown).",
	})
)

// all lists every collector, in the order of the declarations above.
var all = []prometheus.Collector{
	Ops, OpDuration, Bytes, OpenHandles, BackgroundDeletes,
	CacheLookups, DataroomListRefreshes, SpoolBytes, Uploads, LocksHeld, StoreOpDuration,
	APIRequests, APIRequestDuration, APIThrottleEpisodes, APIRateLimited,
	TokenRefreshes, TokenExpiry,
}

// All returns every metric of the package, for callers that register them
// one by one (to wrap them with constant labels, or to report an error
// instead of panicking).
func All() []prometheus.Collector {
	return append([]prometheus.Collector(nil), all...)
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
