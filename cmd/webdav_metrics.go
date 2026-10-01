package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// webdavHealth is the state behind the readiness probe of `webdav serve`.
// Ready means the WebDAV listener is bound and the server is not shutting
// down; it is flipped by the serve command, never by an API call from the
// probe itself, so a probe stays cheap and cannot be the cause of load.
type webdavHealth struct {
	ready atomic.Bool
}

func newWebdavHealth() *webdavHealth {
	return &webdavHealth{}
}

func (h *webdavHealth) setReady(ready bool) {
	h.ready.Store(ready)
}

func (h *webdavHealth) isReady() bool {
	return h.ready.Load()
}

// observabilityOptions selects what newObservabilityHandler registers.
type observabilityOptions struct {
	// runtime adds the go_* and process_* collectors. Off when a parent
	// process aggregates several instances and reads their memory itself: the
	// same families with different labels and HELP strings do not merge.
	runtime bool
	// extra holds the collectors that need a handle on the running server
	// (sessionsCachedGauge).
	extra []prometheus.Collector
	// labels are added as constant labels to every series, runtime
	// collectors included, so a parent aggregating several instances can
	// tell them apart.
	labels prometheus.Labels
}

// newObservabilityHandler serves the Prometheus exposition and the health
// probes on a listener separate from the WebDAV one, so scrapers and kubelet
// need neither the Basic auth credentials nor a path in the WebDAV tree.
//
//	/metrics  Go runtime + process collectors and retyc_cli_build_info
//	/healthz  liveness: 200 as long as the process answers
//	/readyz   readiness: 200 while the WebDAV listener serves, 503 otherwise
//
// The options decide what /metrics carries besides internal/metrics. A
// constant label whose name collides with a metric label (method, route,
// status, ...) is reported here, before the listener binds.
func newObservabilityHandler(health *webdavHealth, opts observabilityOptions) (http.Handler, error) {
	reg := prometheus.NewRegistry()
	var registerer prometheus.Registerer = reg
	if len(opts.labels) > 0 {
		registerer = prometheus.WrapRegistererWith(opts.labels, reg)
	}
	var cs []prometheus.Collector
	if opts.runtime {
		cs = append(cs,
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
	}
	cs = append(cs, newBuildInfoCollector())
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

// sessionsCachedGauge reports how many dataroom sessions fs holds unlocked in
// memory: each one cost a key fetch and a decryption.
func sessionsCachedGauge(fs *webdavFS) prometheus.Collector {
	return prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "retyc_cli_sessions_cached",
		Help: "Dataroom sessions held unlocked in memory by the server.",
	}, func() float64 { return float64(fs.sessions.Len()) })
}

// newBuildInfoCollector exposes the binary identity as a constant gauge, the
// usual pattern to join a version label onto any other series in a query.
func newBuildInfoCollector() prometheus.Collector {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "retyc_cli_build_info",
		Help: "Build information of the retyc CLI, constant 1.",
	}, []string{"version", "goos", "goarch"})
	g.WithLabelValues(Version, runtime.GOOS, runtime.GOARCH).Set(1)

	return g
}

// resolveMetricsAddr returns the observability listener address with the
// usual precedence (flag > env > config file > default). Binding the flag to
// the viper key here rather than in init() keeps the binding alive across the
// viper.Reset() that the config tests perform.
func resolveMetricsAddr(flags *pflag.FlagSet) string {
	_ = viper.BindPFlag("webdav.metrics.addr", flags.Lookup("metrics-addr"))

	return viper.GetString("webdav.metrics.addr")
}

// resolveMetricsRuntime returns whether /metrics carries the Go runtime and
// process collectors, with the same precedence and binding strategy as
// resolveMetricsAddr. The flag must win over the environment: a parent process
// passes flags explicitly and does not control the inherited environment.
func resolveMetricsRuntime(flags *pflag.FlagSet) bool {
	_ = viper.BindPFlag("webdav.metrics.runtime", flags.Lookup("metrics-runtime"))

	return viper.GetBool("webdav.metrics.runtime")
}

// resolveMetricsLabels returns the constant label items ("key=value") with
// the same precedence and binding strategy as resolveMetricsAddr. From the
// environment the items are separated by spaces.
func resolveMetricsLabels(flags *pflag.FlagSet) []string {
	_ = viper.BindPFlag("webdav.metrics.labels", flags.Lookup("metrics-label"))

	return viper.GetStringSlice("webdav.metrics.labels")
}

// startObservabilityServer binds addr and serves handler in the background.
// The bind happens synchronously so a port already in use fails at startup,
// like the WebDAV listener does; srv.Addr holds the resolved address.
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

// webdavMethods are the label values of the WebDAV request metrics; anything
// else is folded into "OTHER" so a scanner cannot grow the label set.
var webdavMethods = map[string]bool{
	"OPTIONS": true, "GET": true, "HEAD": true, "PUT": true, "DELETE": true,
	"PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true, "MOVE": true,
	"LOCK": true, "UNLOCK": true,
}

// statusRecorder captures the status code and byte count written by the
// WebDAV handler. It keeps Flush and Unwrap so streaming responses behave as
// without the wrapper (http.ResponseController reaches the underlying writer
// through Unwrap).
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.written += int64(n)

	return n, err
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// instrumentWebdav feeds the retyc_cli_webdav_* request metrics and opens one
// root SERVER span per request, named "WEBDAV <method>". Incoming traceparent
// headers are ignored on purpose (WithNewRoot): the server's life is not one
// trace. otelhttp is not used here because it records url.path, and WebDAV
// paths are the file names the platform encrypts; only the method, the
// status and the sizes are exported.
func instrumentWebdav(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		if !webdavMethods[method] {
			method = "OTHER"
		}
		ctx, span := telemetry.Tracer().Start(r.Context(), "WEBDAV "+method,
			trace.WithNewRoot(),
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", method)))
		if r.ContentLength >= 0 {
			span.SetAttributes(attribute.Int64("http.request.body.size", r.ContentLength))
		}
		metrics.WebdavInflight.Inc()
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			metrics.WebdavInflight.Dec()
			metrics.WebdavRequestDuration.WithLabelValues(method).Observe(time.Since(start).Seconds())
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			metrics.WebdavRequests.WithLabelValues(method, strconv.Itoa(status)).Inc()
			span.SetAttributes(
				attribute.Int("http.response.status_code", status),
				attribute.Int64("http.response.body.size", rec.written),
			)
			if status >= http.StatusInternalServerError {
				span.SetStatus(codes.Error, "")
			}
			span.End()
		}()
		next.ServeHTTP(rec, r.WithContext(ctx))
	})
}
