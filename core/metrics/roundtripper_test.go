package metrics_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/core/metrics"
	"github.com/retyc/retyc-cli/core/metrics/metricstest"
)

func init() { metricstest.Install() }

func TestRoundTripper_ObservesStatusAndRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	route := "/dataroom/node/version/{id}/chunk/{n}"
	counter := metrics.APIRequests.WithLabelValues("POST", route, "201")
	before := metricstest.Get(counter)

	client := &http.Client{Transport: metrics.RoundTripper(http.DefaultTransport)}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/dataroom/node/version/019d3de3-cba2-76d0-962d-7817e9858661/chunk/7", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if got := metricstest.Get(counter) - before; got != 1 {
		t.Errorf("counter delta = %v, want 1", got)
	}
}

type failingRT struct{}

func (failingRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestRoundTripper_TransportErrorIsStatusError(t *testing.T) {
	counter := metrics.APIRequests.WithLabelValues("GET", "/share", "error")
	before := metricstest.Get(counter)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.test/share", nil)
	resp, err := metrics.RoundTripper(failingRT{}).RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the transport error to propagate")
	}
	if got := metricstest.Get(counter) - before; got != 1 {
		t.Errorf("counter delta = %v, want 1", got)
	}
}
