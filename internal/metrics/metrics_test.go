package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func gatheredNames(t *testing.T, reg *prometheus.Registry) map[string]bool {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}

	return names
}

func TestRegister_ExposesTouchedMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	Register(reg)

	WebdavRequests.WithLabelValues("PROPFIND", "207").Inc()
	WebdavRequestDuration.WithLabelValues("PROPFIND").Observe(0.01)
	WebdavInflight.Inc()
	WebdavBytes.WithLabelValues("download").Add(10)
	WebdavNodeCacheLookups.WithLabelValues("hit").Inc()
	WebdavDataroomCacheRefreshes.Inc()
	APIRequests.WithLabelValues("GET", "/dataroom", "200").Inc()
	APIRequestDuration.WithLabelValues("GET", "/dataroom").Observe(0.02)
	TokenRefreshes.WithLabelValues("ok").Inc()
	TokenExpiry.Set(3600)
	CryptoDuration.WithLabelValues("encrypt").Observe(0.001)

	names := gatheredNames(t, reg)
	for _, want := range []string{
		"retyc_cli_webdav_requests_total",
		"retyc_cli_webdav_request_duration_seconds",
		"retyc_cli_webdav_inflight_requests",
		"retyc_cli_webdav_bytes_total",
		"retyc_cli_webdav_node_cache_lookups_total",
		"retyc_cli_webdav_dataroom_cache_refreshes_total",
		"retyc_cli_api_requests_total",
		"retyc_cli_api_request_duration_seconds",
		"retyc_cli_token_refreshes_total",
		"retyc_cli_token_expiry_seconds",
		"retyc_cli_crypto_duration_seconds",
	} {
		if !names[want] {
			t.Errorf("registry missing %s", want)
		}
	}
}

func TestRegister_TwiceInDistinctRegistries(t *testing.T) {
	Register(prometheus.NewRegistry())
	Register(prometheus.NewRegistry()) // must not panic: one collector, many registries
}

func TestNormalizeRoute(t *testing.T) {
	tests := map[string]string{
		"/dataroom/":                                "/dataroom/",
		"/dataroom/019d3de3-cba2-76d0-962d-7817e9858661/nodes":     "/dataroom/{id}/nodes",
		"/dataroom/node/version/019d3de3-cba2-76d0-962d-7817e9858661/chunk/3": "/dataroom/node/version/{id}/chunk/{n}",
		"/file/019d3de3-cba2-76d0-962d-7817e9858661/12": "/file/{id}/{n}",
		"/user/me/key/active":                         "/user/me/key/active",
		"/share/019D3DE3-CBA2-76D0-962D-7817E9858661/details": "/share/{id}/details",
	}
	for in, want := range tests {
		if got := NormalizeRoute(in); got != want {
			t.Errorf("NormalizeRoute(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRoundTripper_ObservesStatusAndRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	route := "/dataroom/node/version/{id}/chunk/{n}"
	counter := APIRequests.WithLabelValues("POST", route, "201")
	before := testutil.ToFloat64(counter)

	client := &http.Client{Transport: RoundTripper(http.DefaultTransport)}
	resp, err := client.Post(srv.URL+"/dataroom/node/version/019d3de3-cba2-76d0-962d-7817e9858661/chunk/7",
		"application/octet-stream", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("counter delta = %v, want 1", got)
	}
}

type failingRT struct{}

func (failingRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestRoundTripper_TransportErrorIsStatusError(t *testing.T) {
	counter := APIRequests.WithLabelValues("GET", "/share", "error")
	before := testutil.ToFloat64(counter)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.test/share", nil)
	resp, err := RoundTripper(failingRT{}).RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the transport error to propagate")
	}
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("counter delta = %v, want 1", got)
	}
}
