// Package metrics declares the measurement points of the core: what `retyc
// fs mount` exports as Prometheus metrics (retycfs_*), observed where the
// event happens (FUSE driver, core/vfs, API client, token keepalive).
//
// It depends on the standard library only. Every point is a small interface
// whose default does nothing; Install plugs an implementation in (the CLI's
// is pkg/prommetrics, installed in cmd's init()). An importer that installs
// nothing pays nothing.
//
// Adding a metric: a field in Set and its variable here, its collector in
// pkg/prommetrics, observe it at the event, document it in doc/retycfs.md.
// Keep label cardinality bounded (no IDs, no raw paths: NormalizeRoute).
package metrics

import (
	"regexp"
	"strings"
)

// Counter only goes up.
type Counter interface {
	Inc()
	Add(v float64)
}

// Gauge goes up and down.
type Gauge interface {
	Set(v float64)
	Inc()
	Dec()
	Add(v float64)
}

// Observer takes the samples of a histogram.
type Observer interface {
	Observe(v float64)
}

// CounterVec is a family of counters, one per set of label values.
type CounterVec interface {
	WithLabelValues(lvs ...string) Counter
}

// GaugeVec is a family of gauges, one per set of label values.
type GaugeVec interface {
	WithLabelValues(lvs ...string) Gauge
}

// HistogramVec is a family of histograms, one per set of label values.
type HistogramVec interface {
	WithLabelValues(lvs ...string) Observer
}

// The measurement points. Each comment gives the exported metric and its
// labels, in the order WithLabelValues takes them. They are no-ops until
// Install.
var (
	// Ops: retycfs_ops_total{op, result}.
	Ops CounterVec = noopCounterVec{}
	// OpDuration: retycfs_op_duration_seconds{op}.
	OpDuration HistogramVec = noopHistogramVec{}
	// Bytes: retycfs_bytes_total{direction}.
	Bytes CounterVec = noopCounterVec{}
	// OpenHandles: retycfs_open_handles{kind}.
	OpenHandles GaugeVec = noopGaugeVec{}
	// BackgroundDeletes: retycfs_background_deletes_total{result}.
	BackgroundDeletes CounterVec = noopCounterVec{}
	// CacheLookups: retycfs_cache_lookups_total{result}.
	CacheLookups CounterVec = noopCounterVec{}
	// DataroomListRefreshes: retycfs_dataroom_list_refreshes_total{result}.
	DataroomListRefreshes CounterVec = noopCounterVec{}
	// WarmupFolders: retycfs_warmup_folders_total{result}.
	WarmupFolders CounterVec = noopCounterVec{}
	// WarmupDuration: retycfs_warmup_duration_seconds.
	WarmupDuration Gauge = noop{}
	// SpoolBytes: retycfs_spool_bytes.
	SpoolBytes Gauge = noop{}
	// Uploads: retycfs_uploads_total{result}.
	Uploads CounterVec = noopCounterVec{}
	// LocksHeld: retycfs_locks_held.
	LocksHeld Gauge = noop{}
	// StoreOpDuration: retycfs_store_op_duration_seconds{op, result}.
	StoreOpDuration HistogramVec = noopHistogramVec{}
	// APIRequests: retycfs_api_requests_total{method, route, status}.
	APIRequests CounterVec = noopCounterVec{}
	// APIRequestDuration: retycfs_api_request_duration_seconds{method, route}.
	APIRequestDuration HistogramVec = noopHistogramVec{}
	// APIThrottleEpisodes: retycfs_api_throttle_episodes_total.
	APIThrottleEpisodes Counter = noop{}
	// APIRateLimited: retycfs_api_rate_limited_total{method}.
	APIRateLimited CounterVec = noopCounterVec{}
	// TokenRefreshes: retycfs_token_refreshes_total{result}.
	TokenRefreshes CounterVec = noopCounterVec{}
	// TokenExpiry: retycfs_token_expiry_seconds.
	TokenExpiry Gauge = noop{}
)

// Set holds an implementation of every measurement point; see the variables
// of the same names. A nil field leaves its point as it is.
type Set struct {
	Ops                   CounterVec
	OpDuration            HistogramVec
	Bytes                 CounterVec
	OpenHandles           GaugeVec
	BackgroundDeletes     CounterVec
	CacheLookups          CounterVec
	DataroomListRefreshes CounterVec
	WarmupFolders         CounterVec
	WarmupDuration        Gauge
	SpoolBytes            Gauge
	Uploads               CounterVec
	LocksHeld             Gauge
	StoreOpDuration       HistogramVec
	APIRequests           CounterVec
	APIRequestDuration    HistogramVec
	APIThrottleEpisodes   Counter
	APIRateLimited        CounterVec
	TokenRefreshes        CounterVec
	TokenExpiry           Gauge
}

// Install replaces the measurement points with the non-nil fields of s. It is
// not synchronized with the observations: call it before the first one,
// from an init() or at the start of main.
func Install(s Set) {
	set(&Ops, s.Ops)
	set(&OpDuration, s.OpDuration)
	set(&Bytes, s.Bytes)
	set(&OpenHandles, s.OpenHandles)
	set(&BackgroundDeletes, s.BackgroundDeletes)
	set(&CacheLookups, s.CacheLookups)
	set(&DataroomListRefreshes, s.DataroomListRefreshes)
	set(&WarmupFolders, s.WarmupFolders)
	set(&WarmupDuration, s.WarmupDuration)
	set(&SpoolBytes, s.SpoolBytes)
	set(&Uploads, s.Uploads)
	set(&LocksHeld, s.LocksHeld)
	set(&StoreOpDuration, s.StoreOpDuration)
	set(&APIRequests, s.APIRequests)
	set(&APIRequestDuration, s.APIRequestDuration)
	set(&APIThrottleEpisodes, s.APIThrottleEpisodes)
	set(&APIRateLimited, s.APIRateLimited)
	set(&TokenRefreshes, s.TokenRefreshes)
	set(&TokenExpiry, s.TokenExpiry)
}

func set[T comparable](dst *T, v T) {
	var zero T
	if v != zero {
		*dst = v
	}
}

// noop is the default of every single point, and what the default vectors
// hand out.
type noop struct{}

func (noop) Inc()            {}
func (noop) Dec()            {}
func (noop) Add(float64)     {}
func (noop) Set(float64)     {}
func (noop) Observe(float64) {}

type (
	noopCounterVec   struct{}
	noopGaugeVec     struct{}
	noopHistogramVec struct{}
)

func (noopCounterVec) WithLabelValues(...string) Counter    { return noop{} }
func (noopGaugeVec) WithLabelValues(...string) Gauge        { return noop{} }
func (noopHistogramVec) WithLabelValues(...string) Observer { return noop{} }

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
