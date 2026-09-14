// Package metrics declares the Prometheus metrics of the CLI.
//
// Every metric is a package-level collector, observed where the event happens
// (API client, session cache, WebDAV server, chunk crypto) and exposed only by
// `webdav serve --metrics-addr`, which calls Register. Unregistered collectors
// still accept observations, so instrumentation costs nothing to callers that
// never expose them (the MCP server, one-shot commands).
//
// Two prefixes: retyc_cli_ for what is not specific to the WebDAV server (API
// calls, token, crypto) and retyc_cli_webdav_ for the server itself.
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

	// WebdavNodeCacheLookups counts node listing cache hits and misses.
	WebdavNodeCacheLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retyc_cli_webdav_node_cache_lookups_total",
		Help: "Node listing cache lookups, by result (hit, miss).",
	}, []string{"result"})

	// WebdavDataroomCacheRefreshes counts refreshes of the dataroom title cache.
	WebdavDataroomCacheRefreshes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "retyc_cli_webdav_dataroom_cache_refreshes_total",
		Help: "Refreshes of the dataroom list cache (one API listing each).",
	})

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
	WebdavNodeCacheLookups, WebdavDataroomCacheRefreshes,
	APIRequests, APIRequestDuration,
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

var (
	uuidSegment    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numericSegment = regexp.MustCompile(`^[0-9]+$`)
)

// NormalizeRoute replaces the identifiers of an API path with placeholders so
// the route label stays bounded: UUID segments become {id}, numeric ones {n}.
func NormalizeRoute(path string) string {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		switch {
		case uuidSegment.MatchString(s):
			segments[i] = "{id}"
		case numericSegment.MatchString(s):
			segments[i] = "{n}"
		}
	}

	return strings.Join(segments, "/")
}
