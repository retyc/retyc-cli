package cmd

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs"
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
	h := mustObservability(t, newServeHealth(), observabilityOptions{})

	code, body := getObservability(t, h, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", code)
	}
	for _, want := range []string{
		"go_goroutines ",
		`retycfs_build_info{goarch="`,
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
func TestObservability_HealthzAlwaysOK(t *testing.T) {
	health := newServeHealth()
	h := mustObservability(t, health, observabilityOptions{})

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
	h := mustObservability(t, health, observabilityOptions{})

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
	h := mustObservability(t, newServeHealth(), observabilityOptions{})
	if code, _ := getObservability(t, h, "/dataroom"); code != http.StatusNotFound {
		t.Errorf("/dataroom status = %d, want 404", code)
	}
}

func TestStartObservabilityServer_ServesProbes(t *testing.T) {
	srv, err := startObservabilityServer("127.0.0.1:0",
		mustObservability(t, newServeHealth(), observabilityOptions{}))
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

func TestObservability_MetricsExposesCustomMetrics(t *testing.T) {
	metrics.APIRequests.WithLabelValues("GET", "/dataroom", "200").Inc()
	h := mustObservability(t, newServeHealth(), observabilityOptions{})
	_, body := getObservability(t, h, "/metrics")
	if !strings.Contains(body, "retycfs_api_requests_total{") {
		t.Error("/metrics does not expose retycfs_api_requests_total")
	}
}

func counterDelta(t *testing.T, c prometheus.Counter, before float64) float64 {
	t.Helper()

	return testutil.ToFloat64(c) - before
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
		extra: []prometheus.Collector{sessionsCachedGauge(fs.tree)},
	})
	_, body := getObservability(t, h, "/metrics")
	if !strings.Contains(body, "retycfs_sessions_cached 1") {
		t.Errorf("/metrics missing retycfs_sessions_cached 1, body:\n%s", body)
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
	metrics.APIRequests.WithLabelValues("GET", "/dataroom", "200").Inc()
	h := mustObservability(t, newServeHealth(), observabilityOptions{
		labels: prometheus.Labels{"identity": "abc"},
	})
	_, body := getObservability(t, h, "/metrics")
	for _, prefix := range []string{"retycfs_build_info{", "retycfs_api_requests_total{", "go_goroutines{"} {
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

// The metrics of the FUSE driver and those internal/vfs observes for both
// front ends are on /metrics of either command: they are registered with the
// rest of internal/metrics.
func TestObservability_ExposesMountMetrics(t *testing.T) {
	metrics.Ops.WithLabelValues("lookup", "ok").Inc()
	metrics.OpDuration.WithLabelValues("lookup").Observe(0.001)
	metrics.Bytes.WithLabelValues("read").Add(1)
	metrics.OpenHandles.WithLabelValues("read").Add(0)
	metrics.Uploads.WithLabelValues("ok").Add(0)

	h := mustObservability(t, newServeHealth(), observabilityOptions{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, name := range []string{
		`retycfs_ops_total{op="lookup",result="ok"}`,
		`retycfs_op_duration_seconds_bucket{op="lookup",`,
		`retycfs_bytes_total{direction="read"}`,
		`retycfs_open_handles{kind="read"}`,
		`retycfs_uploads_total{result="ok"}`,
		"retycfs_spool_bytes ",
		"retycfs_locks_held ",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics lacks %s", name)
		}
	}
}
