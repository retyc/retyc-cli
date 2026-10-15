package cmd

import (
	"net/http"
	"strconv"
	"time"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// The observability listener itself (/metrics, /healthz, /readyz) is shared
// with `fs mount`: see observability.go. What stays here is what is WebDAV's
// own: the binding of its flags to webdav.metrics.*, and the instrumentation
// of its requests.

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

// resolveWebdavMetrics returns the settings of the observability listener of
// `webdav serve`.
func resolveWebdavMetrics(flags *pflag.FlagSet) metricsSettings {
	return metricsSettings{
		addr:    resolveMetricsAddr(flags),
		runtime: resolveMetricsRuntime(flags),
		labels:  resolveMetricsLabels(flags),
	}
}

// resolveMetricsLabels returns the constant label items ("key=value") with
// the same precedence and binding strategy as resolveMetricsAddr. From the
// environment the items are separated by spaces.
func resolveMetricsLabels(flags *pflag.FlagSet) []string {
	_ = viper.BindPFlag("webdav.metrics.labels", flags.Lookup("metrics-label"))

	return viper.GetStringSlice("webdav.metrics.labels")
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
