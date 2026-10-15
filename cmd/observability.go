package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// The observability listener of `fs mount`: Prometheus exposition and health
// probes, off unless the mount is given an address (--metrics-addr, bound to
// mount.metrics.* by resolveMountFlags). The mount flips the readiness.

// serveHealth is the state behind the readiness probe of the mount. Ready
// means the filesystem is mounted and not shutting down. It is flipped by the
// command, never by an API call from the probe itself, so a probe stays cheap
// and cannot be the cause of load.
type serveHealth struct {
	ready atomic.Bool
}

func newServeHealth() *serveHealth {
	return &serveHealth{}
}

func (h *serveHealth) setReady(ready bool) {
	h.ready.Store(ready)
}

func (h *serveHealth) isReady() bool {
	return h.ready.Load()
}

// observabilityOptions selects what newObservabilityHandler registers.
type observabilityOptions struct {
	// extra holds the collectors that need a handle on the running mount
	// (sessionsCachedGauge).
	extra []prometheus.Collector
	// labels are added as constant labels to every series, runtime
	// collectors included, so a parent aggregating several instances can
	// tell them apart.
	labels prometheus.Labels
}

// newObservabilityHandler serves the Prometheus exposition and the health
// probes on the listener of the mount.
//
//	/metrics  Go runtime + process collectors and retycfs_build_info
//	/healthz  liveness: 200 as long as the process answers
//	/readyz   readiness: 200 while the mount serves (see serveHealth), 503 otherwise
//
// The options decide what /metrics carries besides internal/metrics. A
// constant label whose name collides with a metric label (method, route,
// status, ...) is reported here, before the listener binds.
func newObservabilityHandler(health *serveHealth, opts observabilityOptions) (http.Handler, error) {
	reg := prometheus.NewRegistry()
	var registerer prometheus.Registerer = reg
	if len(opts.labels) > 0 {
		registerer = prometheus.WrapRegistererWith(opts.labels, reg)
	}
	cs := []prometheus.Collector{
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		newBuildInfoCollector(),
	}
	cs = append(cs, metrics.All()...)
	cs = append(cs, opts.extra...)
	for _, c := range cs {
		if err := registerer.Register(c); err != nil {
			return nil, fmt.Errorf("registering metrics: %w", err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "ok", http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if health.isReady() {
			http.Error(w, "ok", http.StatusOK)

			return
		}
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	})

	return mux, nil
}

// metricLabelName is the Prometheus label name syntax.
var metricLabelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// parseMetricsLabels turns "key=value" items into constant labels. The first
// "=" splits key and value, so a value may itself contain "=".
func parseMetricsLabels(items []string) (prometheus.Labels, error) {
	labels := make(prometheus.Labels, len(items))
	for _, item := range items {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("metrics label %q: expected key=value", item)
		}
		if !metricLabelName.MatchString(key) {
			return nil, fmt.Errorf(
				"metrics label %q: invalid label name (letters, digits and _ only, not starting with a digit)", item)
		}
		if key == "le" || key == "quantile" || strings.HasPrefix(key, "__") {
			// Histograms and summaries add le / quantile to their series, and
			// Prometheus reserves "__": the registry would accept them, then
			// every scrape would be rejected.
			return nil, fmt.Errorf("metrics label %q: reserved label name", item)
		}
		if _, dup := labels[key]; dup {
			return nil, fmt.Errorf("metrics label %q: key given twice", key)
		}
		labels[key] = value
	}

	return labels, nil
}

// sessionsCachedGauge reports how many dataroom sessions tree holds unlocked
// in memory: each one cost a key fetch and a decryption.
func sessionsCachedGauge(tree *vfs.FS) prometheus.Collector {
	return prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "retycfs_sessions_cached",
		Help: "Dataroom sessions held unlocked in memory by the mount.",
	}, func() float64 { return float64(tree.SessionsCached()) })
}

// newBuildInfoCollector exposes the binary identity as a constant gauge, the
// usual pattern to join a version label onto any other series in a query.
func newBuildInfoCollector() prometheus.Collector {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "retycfs_build_info",
		Help: "Build information of the retyc binary serving the mount, constant 1.",
	}, []string{"version", "goos", "goarch"})
	g.WithLabelValues(Version, runtime.GOOS, runtime.GOARCH).Set(1)

	return g
}

// metricsSettings are the settings of the observability listener of the
// mount: mount.metrics.*.
type metricsSettings struct {
	// addr is the host:port to bind; empty, there is no listener.
	addr string
	// labels are the constant labels, as "key=value" items.
	labels []string
}

// startObservability starts the observability listener settings ask for, and
// says on stderr where it listens. It returns nil, and no error, when none is
// asked for. tree is the tree the command serves, for the collectors that
// read it.
//
// The listener is bound here, synchronously: a bad address or a label that
// cannot be registered fails the command before it serves anything.
func startObservability(settings metricsSettings, health *serveHealth, tree *vfs.FS) (*http.Server, error) {
	if settings.addr == "" {
		return nil, nil
	}
	labels, err := parseMetricsLabels(settings.labels)
	if err != nil {
		return nil, err
	}
	handler, err := newObservabilityHandler(health, observabilityOptions{
		extra:  []prometheus.Collector{sessionsCachedGauge(tree)},
		labels: labels,
	})
	if err != nil {
		return nil, err
	}
	srv, err := startObservabilityServer(settings.addr, handler)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Metrics and probes listening on http://%s (/metrics, /healthz, /readyz)\n", srv.Addr)

	return srv, nil
}

// startObservabilityServer binds addr and serves handler in the background.
// The bind happens synchronously so a port already in use fails at startup,
// before anything is mounted; srv.Addr holds the resolved address.
func startObservabilityServer(addr string, handler http.Handler) (*http.Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics listener: %w", err)
	}
	srv := &http.Server{ //nolint:gosec // G112: metrics endpoint; Slowloris not a concern
		Addr:              ln.Addr().String(),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "metrics server: %v\n", err)
		}
	}()

	return srv, nil
}
