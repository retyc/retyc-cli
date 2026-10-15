package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"github.com/retyc/retyc-cli/internal/vfs"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

func getObservability(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	return rec.Code, string(body)
}

func mustObservability(t *testing.T, health *serveHealth, opts observabilityOptions) http.Handler {
	t.Helper()
	h, err := newObservabilityHandler(health, opts)
	if err != nil {
		t.Fatalf("newObservabilityHandler: %v", err)
	}

	return h
}

func TestObservability_MetricsExposesGoAndBuildInfo(t *testing.T) {
	h := mustObservability(t, newServeHealth(), observabilityOptions{runtime: true})

	code, body := getObservability(t, h, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", code)
	}
	for _, want := range []string{
		"go_goroutines ",
		`retyc_cli_build_info{goarch="`,
		`version="` + Version + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q", want)
		}
	}
	if !strings.Contains(body, "process_start_time_seconds ") {
		if runtime.GOOS != "linux" {
			t.Skip("ProcessCollector not supported on this platform")
		}
		t.Error("/metrics body missing process_start_time_seconds")
	}
}

// runtimeSeries returns the go_* and process_* lines of a /metrics body,
// HELP and TYPE comments included.
func runtimeSeries(body string) []string {
	var found []string
	for _, line := range strings.Split(body, "\n") {
		name := strings.TrimPrefix(strings.TrimPrefix(line, "# HELP "), "# TYPE ")
		if strings.HasPrefix(name, "go_") || strings.HasPrefix(name, "process_") {
			found = append(found, line)
		}
	}

	return found
}

func TestObservability_RuntimeDisabledKeepsCLIMetrics(t *testing.T) {
	metrics.WebdavRequests.WithLabelValues("GET", "200").Inc()
	h := mustObservability(t, newServeHealth(), observabilityOptions{runtime: false})

	code, body := getObservability(t, h, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", code)
	}
	if lines := runtimeSeries(body); len(lines) != 0 {
		t.Errorf("runtime collectors still exposed:\n%s", strings.Join(lines, "\n"))
	}
	for _, want := range []string{"retyc_cli_build_info{", "retyc_cli_webdav_requests_total{"} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q", want)
		}
	}
}

func TestResolveMetricsRuntime_FlagOverridesEnv(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_WEBDAV_METRICS_RUNTIME", "true")
	config.SetDefaults()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.Bool("metrics-runtime", true, "")
	if err := flags.Set("metrics-runtime", "false"); err != nil {
		t.Fatal(err)
	}
	if resolveMetricsRuntime(flags) {
		t.Error("flag false with env true: got enabled, want disabled")
	}
}

func TestResolveMetricsRuntime_EnvWithoutFlag(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_WEBDAV_METRICS_RUNTIME", "false")
	config.SetDefaults()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.Bool("metrics-runtime", true, "")
	if resolveMetricsRuntime(flags) {
		t.Error("env false without flag: got enabled, want disabled")
	}
}

func TestResolveMetricsRuntime_DefaultEnabled(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.Bool("metrics-runtime", true, "")
	if !resolveMetricsRuntime(flags) {
		t.Error("default: got disabled, want enabled")
	}
}

func TestObservability_HealthzAlwaysOK(t *testing.T) {
	health := newServeHealth()
	h := mustObservability(t, health, observabilityOptions{runtime: true})

	if code, _ := getObservability(t, h, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz before ready: status = %d, want 200", code)
	}
	health.setReady(true)
	health.setReady(false)
	if code, _ := getObservability(t, h, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz after shutdown: status = %d, want 200", code)
	}
}

func TestObservability_ReadyzFollowsServerState(t *testing.T) {
	health := newServeHealth()
	h := mustObservability(t, health, observabilityOptions{runtime: true})

	if code, _ := getObservability(t, h, "/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz before listen: status = %d, want 503", code)
	}
	health.setReady(true)
	if code, _ := getObservability(t, h, "/readyz"); code != http.StatusOK {
		t.Errorf("/readyz while serving: status = %d, want 200", code)
	}
	health.setReady(false)
	if code, _ := getObservability(t, h, "/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz during shutdown: status = %d, want 503", code)
	}
}

func TestObservability_UnknownPathIs404(t *testing.T) {
	h := mustObservability(t, newServeHealth(), observabilityOptions{runtime: true})
	if code, _ := getObservability(t, h, "/dataroom"); code != http.StatusNotFound {
		t.Errorf("/dataroom status = %d, want 404", code)
	}
}

func TestResolveMetricsAddr_FlagOverridesEnv(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_WEBDAV_METRICS_ADDR", "127.0.0.1:9090")
	config.SetDefaults()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("metrics-addr", "", "")

	if got := resolveMetricsAddr(flags); got != "127.0.0.1:9090" {
		t.Errorf("without flag: got %q, want env value 127.0.0.1:9090", got)
	}
	if err := flags.Set("metrics-addr", "0.0.0.0:9100"); err != nil {
		t.Fatal(err)
	}
	if got := resolveMetricsAddr(flags); got != "0.0.0.0:9100" {
		t.Errorf("with flag: got %q, want flag value 0.0.0.0:9100", got)
	}
}

func TestResolveMetricsAddr_DefaultDisabled(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("metrics-addr", "", "")
	if got := resolveMetricsAddr(flags); got != "" {
		t.Errorf("got %q, want empty (disabled)", got)
	}
}

func TestStartObservabilityServer_ServesProbes(t *testing.T) {
	srv, err := startObservabilityServer("127.0.0.1:0",
		mustObservability(t, newServeHealth(), observabilityOptions{runtime: true}))
	if err != nil {
		t.Fatalf("startObservabilityServer: %v", err)
	}
	defer srv.Close() //nolint:errcheck

	resp, err := http.Get("http://" + srv.Addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestStartObservabilityServer_BindError(t *testing.T) {
	first, err := startObservabilityServer("127.0.0.1:0", http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close() //nolint:errcheck

	if _, err := startObservabilityServer(first.Addr, http.NotFoundHandler()); err == nil {
		t.Error("second bind on the same address should fail")
	}
}

func TestInstrumentWebdav_CountsMethodStatusAndDuration(t *testing.T) {
	counter := metrics.WebdavRequests.WithLabelValues("PROPFIND", "207")
	before := testutil.ToFloat64(counter)
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if metrics.WebdavInflight != nil && testutil.ToFloat64(metrics.WebdavInflight) < 1 {
			t.Error("inflight gauge should be >= 1 inside the handler")
		}
		w.WriteHeader(http.StatusMultiStatus)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("PROPFIND", "/dataroom/", nil))

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status passthrough = %d, want 207", rec.Code)
	}
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("requests_total delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.WebdavInflight); got != 0 {
		t.Errorf("inflight after request = %v, want 0", got)
	}
}

func TestInstrumentWebdav_ImplicitStatusIs200(t *testing.T) {
	counter := metrics.WebdavRequests.WithLabelValues("GET", "200")
	before := testutil.ToFloat64(counter)
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("body")) // no explicit WriteHeader
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/f", nil))
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("requests_total delta = %v, want 1", got)
	}
}

func TestInstrumentWebdav_UnknownMethodIsOther(t *testing.T) {
	counter := metrics.WebdavRequests.WithLabelValues("OTHER", "405")
	before := testutil.ToFloat64(counter)
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("BREW", "/", nil))
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("requests_total delta = %v, want 1", got)
	}
}

func TestInstrumentWebdav_KeepsFlusher(t *testing.T) {
	var flushed bool
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("wrapped writer lost http.Flusher, streaming would stall")
		}
		f.Flush()
		flushed = true
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/f", nil))
	if !flushed {
		t.Error("handler did not run")
	}
}

func TestObservability_MetricsExposesCustomMetrics(t *testing.T) {
	metrics.WebdavRequests.WithLabelValues("GET", "200").Inc()
	h := mustObservability(t, newServeHealth(), observabilityOptions{runtime: true})
	_, body := getObservability(t, h, "/metrics")
	if !strings.Contains(body, "retyc_cli_webdav_requests_total{") {
		t.Error("/metrics does not expose retyc_cli_webdav_requests_total")
	}
}

func counterDelta(t *testing.T, c prometheus.Counter, before float64) float64 {
	t.Helper()

	return testutil.ToFloat64(c) - before
}

func TestCreateHandle_WriteCountsUploadBytes(t *testing.T) {
	counter := metrics.WebdavBytes.WithLabelValues("upload")
	before := testutil.ToFloat64(counter)
	pipeR, pipeW := io.Pipe()
	go func() { _, _ = io.Copy(io.Discard, pipeR) }()
	h := &createHandle{pw: pipeW}

	if _, err := h.Write(make([]byte, 300)); err != nil {
		t.Fatal(err)
	}
	if got := counterDelta(t, counter, before); got != 300 {
		t.Errorf("upload bytes delta = %v, want 300", got)
	}
}

func TestWriteFileHandle_WriteCountsUploadBytes(t *testing.T) {
	counter := metrics.WebdavBytes.WithLabelValues("upload")
	before := testutil.ToFloat64(counter)
	spool, err := newTestFS(nil, vfs.Options{SpoolDir: t.TempDir()}).tree.OpenSpool(
		context.Background(), "dr1", "/w", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spool.Close() }()
	h := &writeFileHandle{spool: spool, info: &webdavFileInfo{}}
	if _, err := h.Write(make([]byte, 120)); err != nil {
		t.Fatal(err)
	}
	if got := counterDelta(t, counter, before); got != 120 {
		t.Errorf("upload bytes delta = %v, want 120", got)
	}
}

func TestReadFileHandle_ReadCountsDownloadBytes(t *testing.T) {
	counter := metrics.WebdavBytes.WithLabelValues("download")
	before := testutil.ToFloat64(counter)
	f, err := os.CreateTemp(t.TempDir(), "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 50)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	h := &readFileHandle{ctx: context.Background(), file: contextReaderAt{f}}
	if _, err := io.ReadAll(h); err != nil {
		t.Fatal(err)
	}
	if got := counterDelta(t, counter, before); got != 50 {
		t.Errorf("download bytes delta = %v, want 50", got)
	}
}

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) { return nil, errors.New("refresh expired") }

func TestCheckToken_ObservesResultAndExpiry(t *testing.T) {
	okCounter := metrics.TokenRefreshes.WithLabelValues("ok")
	errCounter := metrics.TokenRefreshes.WithLabelValues("error")
	okBefore, errBefore := testutil.ToFloat64(okCounter), testutil.ToFloat64(errCounter)

	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", Expiry: time.Now().Add(10 * time.Minute)})
	if err := checkToken(src); err != nil {
		t.Fatal(err)
	}
	if got := counterDelta(t, okCounter, okBefore); got != 1 {
		t.Errorf("ok delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.TokenExpiry); got < 500 || got > 600 {
		t.Errorf("token_expiry_seconds = %v, want about 600", got)
	}

	if err := checkToken(failingTokenSource{}); err == nil {
		t.Fatal("expected the token error to propagate")
	}
	if got := counterDelta(t, errCounter, errBefore); got != 1 {
		t.Errorf("error delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.TokenExpiry); got != 0 {
		t.Errorf("token_expiry_seconds after failure = %v, want 0", got)
	}
}

func TestObservability_SessionsCachedGauge(t *testing.T) {
	fs := newTestFS(nil, vfs.Options{})
	fs.tree.SeedSession("dr1", &service.DataroomSession{})
	h := mustObservability(t, newServeHealth(), observabilityOptions{
		runtime: true, extra: []prometheus.Collector{sessionsCachedGauge(fs.tree)},
	})
	_, body := getObservability(t, h, "/metrics")
	if !strings.Contains(body, "retyc_cli_sessions_cached 1") {
		t.Errorf("/metrics missing retyc_cli_sessions_cached 1, body:\n%s", body)
	}
}

func TestParseMetricsLabels(t *testing.T) {
	got, err := parseMetricsLabels([]string{"identity=abc", "pod=node-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got["identity"] != "abc" || got["pod"] != "node-1" || len(got) != 2 {
		t.Errorf("labels = %v", got)
	}
	if got, err := parseMetricsLabels(nil); err != nil || len(got) != 0 {
		t.Errorf("nil input: got %v, %v", got, err)
	}
	for _, bad := range []string{"identity", "=abc", "1dentity=abc", "id-x=abc"} {
		if _, err := parseMetricsLabels([]string{bad}); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	for _, reserved := range []string{"le=x", "quantile=x", "__name__=x"} {
		if _, err := parseMetricsLabels([]string{reserved}); err == nil {
			t.Errorf("%q: expected a reserved-name error", reserved)
		}
	}
	if _, err := parseMetricsLabels([]string{"a=1", "a=2"}); err == nil {
		t.Error("duplicate key: expected an error")
	}
}

func TestParseMetricsLabels_ValueMayContainEquals(t *testing.T) {
	// The first "=" separates key and value; a value like a base64 blob
	// keeps its own "=" signs.
	got, err := parseMetricsLabels([]string{"identity=YWJj=="})
	if err != nil {
		t.Fatal(err)
	}
	if got["identity"] != "YWJj==" {
		t.Errorf("identity = %q, want YWJj==", got["identity"])
	}
}

func TestObservability_ConstLabelsOnEverySeries(t *testing.T) {
	metrics.WebdavRequests.WithLabelValues("GET", "200").Inc()
	h := mustObservability(t, newServeHealth(), observabilityOptions{
		runtime: true, labels: prometheus.Labels{"identity": "abc"},
	})
	_, body := getObservability(t, h, "/metrics")
	for _, prefix := range []string{"retyc_cli_build_info{", "retyc_cli_webdav_requests_total{", "go_goroutines{"} {
		var found bool
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, prefix) {
				found = true
				if !strings.Contains(line, `identity="abc"`) {
					t.Errorf("%s lacks the constant label: %s", prefix, line)
				}
			}
		}
		if !found {
			t.Errorf("no series with prefix %s", prefix)
		}
	}
}

func TestObservability_ConstLabelCollisionIsAnError(t *testing.T) {
	_, err := newObservabilityHandler(newServeHealth(), observabilityOptions{
		labels: prometheus.Labels{"method": "x"},
	})
	if err == nil {
		t.Fatal("a constant label colliding with a metric label must fail at startup")
	}
}

func TestResolveMetricsLabels_FlagOverridesEnv(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_WEBDAV_METRICS_LABELS", "identity=env")
	config.SetDefaults()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.StringArray("metrics-label", nil, "")
	if got := resolveMetricsLabels(flags); len(got) != 1 || got[0] != "identity=env" {
		t.Errorf("without flag: got %v, want [identity=env]", got)
	}
	for _, v := range []string{"identity=flag", "pod=x"} {
		if err := flags.Set("metrics-label", v); err != nil {
			t.Fatal(err)
		}
	}
	if got := resolveMetricsLabels(flags); len(got) != 2 || got[0] != "identity=flag" || got[1] != "pod=x" {
		t.Errorf("with flag: got %v, want [identity=flag pod=x]", got)
	}
}

func TestResolveWebdavAddr_FlagOverridesEnv(t *testing.T) {
	isolateConfig(t)
	t.Setenv("RETYC_WEBDAV_ADDR", "0.0.0.0:9000")
	config.SetDefaults()

	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("addr", "127.0.0.1:8888", "")
	if got, err := resolveWebdavAddr(flags); err != nil || got != "0.0.0.0:9000" {
		t.Errorf("without flag: got %q (%v), want env value 0.0.0.0:9000", got, err)
	}
	if err := flags.Set("addr", "127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveWebdavAddr(flags); err != nil || got != "127.0.0.1:9999" {
		t.Errorf("with flag: got %q (%v), want flag value 127.0.0.1:9999", got, err)
	}
}

func TestResolveWebdavAddr_Default(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("addr", "127.0.0.1:8888", "")
	if got, err := resolveWebdavAddr(flags); err != nil || got != "127.0.0.1:8888" {
		t.Errorf("got %q (%v), want 127.0.0.1:8888", got, err)
	}
}

func TestResolveWebdavAddr_RejectsMissingPort(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "localhost", "127.0.0.1:", ""} {
		t.Run(addr, func(t *testing.T) {
			isolateConfig(t)
			config.SetDefaults()
			flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
			flags.String("addr", "127.0.0.1:8888", "")
			if err := flags.Set("addr", addr); err != nil {
				t.Fatal(err)
			}
			if _, err := resolveWebdavAddr(flags); err == nil {
				t.Errorf("--addr %q: expected an error", addr)
			}
		})
	}
}

func TestInstrumentWebdav_RootSpanPerRequest(t *testing.T) {
	exp := telemetrytest.Install(t)
	var sawSpan bool
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSpan = oteltrace.SpanFromContext(r.Context()).SpanContext().IsValid()
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte("<multistatus/>"))
	}))
	req := httptest.NewRequest("PROPFIND", "/dataroom/Project%20SENTINEL/secret.pdf", strings.NewReader("<propfind/>"))
	req.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	// A remote span context in the request's own context must also be
	// ignored, not just the traceparent header: every WebDAV request is a
	// new root regardless of how a parent might have been carried in.
	remote := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:  oteltrace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		Remote:  true, TraceFlags: oteltrace.FlagsSampled,
	})
	req = req.WithContext(oteltrace.ContextWithRemoteSpanContext(req.Context(), remote))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !sawSpan {
		t.Error("the handler did not receive the request span in its context")
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name != "WEBDAV PROPFIND" || s.SpanKind != oteltrace.SpanKindServer {
		t.Errorf("span = %q kind %v", s.Name, s.SpanKind)
	}
	if s.Parent.IsValid() {
		t.Error("the span must be a new root even when the context carries a remote " +
			"parent (traceparent header or WithRemoteSpanContext)")
	}
	for _, kv := range s.Attributes {
		if strings.Contains(kv.Value.String(), "SENTINEL") || kv.Key == "url.path" {
			t.Errorf("attribute %s leaks the path: %s", kv.Key, kv.Value.String())
		}
	}
	var status, reqSize, respSize int64
	for _, kv := range s.Attributes {
		switch kv.Key {
		case "http.response.status_code":
			status = kv.Value.AsInt64()
		case "http.request.body.size":
			reqSize = kv.Value.AsInt64()
		case "http.response.body.size":
			respSize = kv.Value.AsInt64()
		}
	}
	if status != 207 || reqSize != int64(len("<propfind/>")) || respSize != int64(len("<multistatus/>")) {
		t.Errorf("status=%d reqSize=%d respSize=%d", status, reqSize, respSize)
	}
}

func TestInstrumentWebdav_5xxIsErrorStatus(t *testing.T) {
	exp := telemetrytest.Install(t)
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/f", nil))
	if s := exp.GetSpans()[0]; s.Status.Code != codes.Error {
		t.Errorf("status = %v, want Error", s.Status.Code)
	}
}

func TestWebdavServe_IsLongRunning(t *testing.T) {
	if webdavServeCmd.Annotations[annotationLongRunning] != "true" {
		t.Error("webdav serve must carry the long-running annotation")
	}
}

// A buffered PUT (unknown length, LOCK-driven create) uploads from Close, on
// a context that must still carry the request span: otherwise the session
// resolution, the chunk POSTs and the crypto spans become orphan traces.
func TestWriteFileHandle_CloseUploadsUnderTheRequestSpan(t *testing.T) {
	telemetrytest.Install(t)
	ctx, span := telemetry.Tracer().Start(context.Background(), "WEBDAV PUT")
	defer span.End()
	var sawSpan bool
	fs := newTestFS(nil, vfs.Options{Session: func(ctx context.Context, _ string) (*service.DataroomSession, error) {
		// The cache wraps the resolver in its own session.unlock span, so the
		// trace ID is what proves the request span is the ancestor.
		sawSpan = oteltrace.SpanFromContext(ctx).SpanContext().TraceID() == span.SpanContext().TraceID()

		return nil, errors.New("stop here")
	}})
	spool, err := fs.tree.OpenSpool(ctx, "dr1", "/f.txt", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	h := &writeFileHandle{
		ctx: ctx, spool: spool, info: &webdavFileInfo{},
		drID: "dr1", parentPath: "/", fileName: "f.txt", wfs: fs, isPut: true,
	}
	if err := h.Close(); err == nil {
		t.Fatal("expected the session error to propagate")
	}
	if !sawSpan {
		t.Error("the upload context lost the request span")
	}
}

func TestResolveUnsafeWrite(t *testing.T) {
	cases := map[string]struct {
		env  string // "" = unset
		flag string // "" = not passed
		want bool
	}{
		"default":            {want: false},
		"env without flag":   {env: "true", want: true},
		"flag overrides env": {env: "true", flag: "false", want: false},
		"flag without env":   {flag: "true", want: true},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			isolateConfig(t)
			if tc.env != "" {
				t.Setenv("RETYC_API_UNSAFE_WRITE", tc.env)
			}
			config.SetDefaults()
			flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
			flags.Bool("unsafe-write", false, "")
			if tc.flag != "" {
				if err := flags.Set("unsafe-write", tc.flag); err != nil {
					t.Fatal(err)
				}
			}
			bindUnsafeWrite(flags)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.API.UnsafeWrite != tc.want {
				t.Errorf("API.UnsafeWrite = %v, want %v", cfg.API.UnsafeWrite, tc.want)
			}
		})
	}
}

// The cache flags of the fs front ends land in the common cache section with
// the usual precedence, and go through the validation of config.Load.
func TestResolveCacheFlags(t *testing.T) {
	cases := map[string]struct {
		env, flags map[string]string
		want       config.CacheConfig
		wantErr    bool
	}{
		"defaults": {
			want: config.CacheConfig{TTL: time.Minute, MaxStale: 5 * time.Minute, NegativeTTL: time.Second, Store: "memory"},
		},
		"env without flag": {
			env:  map[string]string{"RETYC_CACHE_TTL": "90s", "RETYC_CACHE_NEGATIVE_TTL": "0"},
			want: config.CacheConfig{TTL: 90 * time.Second, MaxStale: 5 * time.Minute, Store: "memory"},
		},
		"flags override env": {
			env:   map[string]string{"RETYC_CACHE_TTL": "90s", "RETYC_CACHE_MAX_STALE": "1m"},
			flags: map[string]string{"cache-ttl": "10s", "cache-max-stale": "0s", "cache-negative-ttl": "250ms"},
			want:  config.CacheConfig{TTL: 10 * time.Second, NegativeTTL: 250 * time.Millisecond, Store: "memory"},
		},
		"redis from the flags": {
			env: map[string]string{"RETYC_CACHE_REDIS_URL": "redis://env.example:6379"},
			flags: map[string]string{
				"cache-store": "redis", "cache-redis-url": "rediss://:pw@flag.example:6380/2",
				"cache-redis-high-confidentiality": "true",
			},
			want: config.CacheConfig{
				TTL: time.Minute, MaxStale: 5 * time.Minute, NegativeTTL: time.Second, Store: "redis",
				Redis: config.CacheRedisConfig{URL: "rediss://:pw@flag.example:6380/2", HighConfidentiality: true},
			},
		},
		"redis from the environment": {
			env: map[string]string{
				"RETYC_CACHE_STORE": "redis", "RETYC_CACHE_REDIS_URL": "redis://env.example:6379",
				"RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY": "true",
			},
			want: config.CacheConfig{
				TTL: time.Minute, MaxStale: 5 * time.Minute, NegativeTTL: time.Second, Store: "redis",
				Redis: config.CacheRedisConfig{URL: "redis://env.example:6379", HighConfidentiality: true},
			},
		},
		"redis without a URL": {
			flags:   map[string]string{"cache-store": "redis"},
			wantErr: true,
		},
		"flag value is validated": {
			flags:   map[string]string{"cache-ttl": "10ms"},
			wantErr: true,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			isolateConfig(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			config.SetDefaults()
			cmd := &cobra.Command{Use: "serve"}
			addCacheFlags(cmd, true)
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatal(err)
				}
			}
			resolveCacheFlags(cmd.Flags())
			cfg, err := config.Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() accepted %v", tc.flags)
				}

				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cache != tc.want {
				t.Errorf("Cache = %+v, want %+v", cfg.Cache, tc.want)
			}
		})
	}
}

// A front end that declares no --cache-max-stale still binds the others.
func TestResolveCacheFlags_WithoutMaxStale(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	cmd := &cobra.Command{Use: "mount"}
	addCacheFlags(cmd, false)
	if err := cmd.Flags().Set("cache-ttl", "30s"); err != nil {
		t.Fatal(err)
	}
	resolveCacheFlags(cmd.Flags())
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cache.TTL != 30*time.Second || cfg.Cache.MaxStale != config.DefaultCacheMaxStale {
		t.Errorf("Cache = %+v, want ttl 30s and the default max_stale", cfg.Cache)
	}
}

// The serve command offers the three cache flags and none of the old names.
func TestWebdavServeCacheFlags(t *testing.T) {
	for _, name := range []string{"cache-ttl", "cache-max-stale", "cache-negative-ttl"} {
		if webdavServeCmd.Flags().Lookup(name) == nil {
			t.Errorf("fs webdav serve has no --%s", name)
		}
	}
}

// The metrics of the FUSE driver and those internal/vfs observes for both
// front ends are on /metrics of either command: they are registered with the
// rest of internal/metrics.
func TestObservability_ExposesFuseAndVFSMetrics(t *testing.T) {
	metrics.FuseOps.WithLabelValues("lookup", "ok").Inc()
	metrics.FuseOpDuration.WithLabelValues("lookup").Observe(0.001)
	metrics.FuseBytes.WithLabelValues("read").Add(1)
	metrics.FuseOpenHandles.WithLabelValues("read").Add(0)
	metrics.VFSUploads.WithLabelValues("ok").Add(0)

	h := mustObservability(t, newServeHealth(), observabilityOptions{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, name := range []string{
		`retyc_cli_fuse_ops_total{op="lookup",result="ok"}`,
		`retyc_cli_fuse_op_duration_seconds_bucket{op="lookup",`,
		`retyc_cli_fuse_bytes_total{direction="read"}`,
		`retyc_cli_fuse_open_handles{kind="read"}`,
		`retyc_cli_vfs_uploads_total{result="ok"}`,
		"retyc_cli_vfs_spool_bytes ",
		"retyc_cli_vfs_locks_held ",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics lacks %s", name)
		}
	}
}
