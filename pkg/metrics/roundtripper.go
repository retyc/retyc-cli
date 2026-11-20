package metrics

import (
	"net/http"
	"strconv"
	"time"
)

type roundTripper struct {
	base http.RoundTripper
}

// RoundTripper wraps base so every request feeds APIRequests and
// APIRequestDuration. A transport failure counts under status "error".
func RoundTripper(base http.RoundTripper) http.RoundTripper {
	return &roundTripper{base: base}
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	route := NormalizeRoute(req.URL.Path)
	start := time.Now()
	resp, err := rt.base.RoundTrip(req)
	APIRequestDuration.WithLabelValues(req.Method, route).Observe(time.Since(start).Seconds())
	status := "error"
	if err == nil {
		status = strconv.Itoa(resp.StatusCode)
	}
	APIRequests.WithLabelValues(req.Method, route, status).Inc()

	return resp, err
}
