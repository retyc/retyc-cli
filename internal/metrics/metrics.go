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
