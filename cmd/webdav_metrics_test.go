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
	"github.com/spf13/pflag"
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

func mustObservability(t *testing.T, health *webdavHealth, opts observabilityOptions) http.Handler {
	t.Helper()
	h, err := newObservabilityHandler(health, opts)
	if err != nil {
		t.Fatalf("newObservabilityHandler: %v", err)
	}

	return h
}

func TestObservability_MetricsExposesGoAndBuildInfo(t *testing.T) {
	h := mustObservability(t, newWebdavHealth(), observabilityOptions{runtime: true})

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
	h := mustObservability(t, newWebdavHealth(), observabilityOptions{runtime: false})

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
	health := newWebdavHealth()
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
	health := newWebdavHealth()
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
	h := mustObservability(t, newWebdavHealth(), observabilityOptions{runtime: true})
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
		mustObservability(t, newWebdavHealth(), observabilityOptions{runtime: true}))
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
	h := mustObservability(t, newWebdavHealth(), observabilityOptions{runtime: true})
	_, body := getObservability(t, h, "/metrics")
	if !strings.Contains(body, "retyc_cli_webdav_requests_total{") {
		t.Error("/metrics does not expose retyc_cli_webdav_requests_total")
	}
}

func counterDelta(t *testing.T, c prometheus.Counter, before float64) float64 {
	t.Helper()

	return testutil.ToFloat64(c) - before
}

func TestStreamWriteHandle_WriteCountsUploadBytes(t *testing.T) {
	counter := metrics.WebdavBytes.WithLabelValues("upload")
	before := testutil.ToFloat64(counter)
	pipeR, pipeW := io.Pipe()
	go func() { _, _ = io.Copy(io.Discard, pipeR) }()
	h := &streamWriteHandle{pipeW: pipeW}

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
	f, err := os.CreateTemp(t.TempDir(), "w")
	if err != nil {
		t.Fatal(err)
	}
	h := &writeFileHandle{file: f}
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
	h := &readFileHandle{file: f}
	if _, err := io.ReadAll(h); err != nil {
		t.Fatal(err)
	}
	if got := counterDelta(t, counter, before); got != 50 {
		t.Errorf("download bytes delta = %v, want 50", got)
	}
}

func TestListNodes_CountsCacheHitsAndMisses(t *testing.T) {
	hits := metrics.WebdavNodeCacheLookups.WithLabelValues("hit")
	misses := metrics.WebdavNodeCacheLookups.WithLabelValues("miss")
	hitsBefore, missesBefore := testutil.ToFloat64(hits), testutil.ToFloat64(misses)
	fs := &webdavFS{listFn: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return nil, nil
	}}
	ctx := context.Background()
	for range 3 {
		if _, err := fs.listNodes(ctx, "dr1", "/"); err != nil {
			t.Fatal(err)
		}
	}
	if got := counterDelta(t, misses, missesBefore); got != 1 {
		t.Errorf("miss delta = %v, want 1", got)
	}
	if got := counterDelta(t, hits, hitsBefore); got != 2 {
		t.Errorf("hit delta = %v, want 2", got)
	}
}

func TestDataroomCache_CountsRefreshes(t *testing.T) {
	before := testutil.ToFloat64(metrics.WebdavDataroomCacheRefreshes)
	c := newDataroomCache(func(context.Context) ([]dataroomCacheItem, error) {
		return []dataroomCacheItem{{id: "dr1", title: "A"}}, nil
	})
	ctx := context.Background()
	if _, err := c.resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if got := counterDelta(t, metrics.WebdavDataroomCacheRefreshes, before); got != 1 {
		t.Errorf("refresh delta = %v, want 1 (second resolve is a cache hit)", got)
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
	fs := &webdavFS{}
	fs.sessions.Store("dr1", &service.DataroomSession{})
	h := mustObservability(t, newWebdavHealth(), observabilityOptions{
		runtime: true, extra: []prometheus.Collector{sessionsCachedGauge(fs)},
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
	h := mustObservability(t, newWebdavHealth(), observabilityOptions{
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
	_, err := newObservabilityHandler(newWebdavHealth(), observabilityOptions{
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
	if got := resolveWebdavAddr(flags); got != "0.0.0.0:9000" {
		t.Errorf("without flag: got %q, want env value 0.0.0.0:9000", got)
	}
	if err := flags.Set("addr", "127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	if got := resolveWebdavAddr(flags); got != "127.0.0.1:9999" {
		t.Errorf("with flag: got %q, want flag value 127.0.0.1:9999", got)
	}
}

func TestResolveWebdavAddr_Default(t *testing.T) {
	isolateConfig(t)
	config.SetDefaults()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	flags.String("addr", "127.0.0.1:8888", "")
	if got := resolveWebdavAddr(flags); got != "127.0.0.1:8888" {
		t.Errorf("got %q, want 127.0.0.1:8888", got)
	}
}
