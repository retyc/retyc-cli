// Package prommetrics holds the Prometheus collectors of `retyc fs mount`,
// one per measurement point of core/metrics, which Install plugs into it.
//
// The CLI installs them at startup (cmd/root.go init()), so every command
// observes into them, and only `fs mount --metrics-addr` registers them (All,
// cmd/observability.go). Unregistered collectors still accept observations,
// so instrumentation costs nothing to the other commands.
//
// One prefix, retycfs_: the mount is the only command that exposes metrics.
//
// Adding a metric: declare its point in core/metrics (Set and its variable),
// its collector here, add it to all and to Install, observe it at the event,
// document it in doc/retycfs.md. Keep label cardinality bounded (no IDs, no
// raw paths).
package prommetrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/retyc/retyc-cli/core/metrics"
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
		Help: "Refreshes of the storage space list cache (one API listing each), by result (ok, error).",
	}, []string{"result"})

	// WarmupFolders counts the folders the listing cache warmup walked.
	WarmupFolders = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "retycfs_warmup_folders_total",
		Help: "Folders listed by the listing cache warmup at mount (--warmup), by result (ok, error).",
	}, []string{"result"})

	// WarmupDuration is how long the warmup walk took.
	WarmupDuration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "retycfs_warmup_duration_seconds",
		Help: "Duration in seconds of the listing cache warmup at mount (--warmup), set when the walk ends.",
	})

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
	CacheLookups, DataroomListRefreshes, WarmupFolders, WarmupDuration, SpoolBytes, Uploads, LocksHeld, StoreOpDuration,
	APIRequests, APIRequestDuration, APIThrottleEpisodes, APIRateLimited,
	TokenRefreshes, TokenExpiry,
}

// All returns every metric of the package, for callers that register them
// one by one (to wrap them with constant labels, or to report an error
// instead of panicking).
func All() []prometheus.Collector {
	return append([]prometheus.Collector(nil), all...)
}

// Install plugs the collectors into core/metrics, where the core observes. It
// is idempotent, and must run before the first observation (an init()).
func Install() {
	metrics.Install(metrics.Set{
		Ops:                   counterVec{Ops},
		OpDuration:            histogramVec{OpDuration},
		Bytes:                 counterVec{Bytes},
		OpenHandles:           gaugeVec{OpenHandles},
		BackgroundDeletes:     counterVec{BackgroundDeletes},
		CacheLookups:          counterVec{CacheLookups},
		DataroomListRefreshes: counterVec{DataroomListRefreshes},
		WarmupFolders:         counterVec{WarmupFolders},
		WarmupDuration:        WarmupDuration,
		SpoolBytes:            SpoolBytes,
		Uploads:               counterVec{Uploads},
		LocksHeld:             LocksHeld,
		StoreOpDuration:       histogramVec{StoreOpDuration},
		APIRequests:           counterVec{APIRequests},
		APIRequestDuration:    histogramVec{APIRequestDuration},
		APIThrottleEpisodes:   APIThrottleEpisodes,
		APIRateLimited:        counterVec{APIRateLimited},
		TokenRefreshes:        counterVec{TokenRefreshes},
		TokenExpiry:           TokenExpiry,
	})
}

// The vectors of prometheus return their own child types: these adapters
// give core/metrics the ones it declares.

type counterVec struct{ v *prometheus.CounterVec }

func (c counterVec) WithLabelValues(lvs ...string) metrics.Counter {
	return c.v.WithLabelValues(lvs...)
}

type gaugeVec struct{ v *prometheus.GaugeVec }

func (g gaugeVec) WithLabelValues(lvs ...string) metrics.Gauge { return g.v.WithLabelValues(lvs...) }

type histogramVec struct{ v *prometheus.HistogramVec }

func (h histogramVec) WithLabelValues(lvs ...string) metrics.Observer {
	return h.v.WithLabelValues(lvs...)
}
