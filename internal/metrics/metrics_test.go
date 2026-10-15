package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fqNamePattern pulls the metric name out of a Desc's String().
var fqNamePattern = regexp.MustCompile(`fqName: "([^"]+)"`)

func TestAll_OnePrefix(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		ch := make(chan *prometheus.Desc, 4)
		go func() { c.Describe(ch); close(ch) }()
		for d := range ch {
			m := fqNamePattern.FindStringSubmatch(d.String())
			if m == nil {
				t.Fatalf("no fqName in %s", d)
			}
			if !strings.HasPrefix(m[1], "retycfs_") {
				t.Errorf("%s: want the retycfs_ prefix", m[1])
			}
			if seen[m[1]] {
				t.Errorf("%s declared twice", m[1])
			}
			seen[m[1]] = true
		}
	}
	if len(seen) != len(all) {
		t.Errorf("%d names for %d collectors", len(seen), len(all))
	}
}

func TestNormalizeRoute(t *testing.T) {
	tests := map[string]string{
		"/dataroom/": "/dataroom/",
		"/dataroom/019d3de3-cba2-76d0-962d-7817e9858661/nodes":                "/dataroom/{id}/nodes",
		"/dataroom/node/version/019d3de3-cba2-76d0-962d-7817e9858661/chunk/3": "/dataroom/node/version/{id}/chunk/{n}",
		"/dataroom/019d3de3-cba2-76d0-962d-7817e9858661/node/file":            "/dataroom/{id}/node/file",
		"/file/019d3de3-cba2-76d0-962d-7817e9858661/12":                       "/file/{id}/{n}",
		"/user/me/key/active": "/user/me/key/active",
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

func TestSegmentPredicates(t *testing.T) {
	if !IsUUIDSegment("019d3de3-cba2-76d0-962d-7817e9858661") || IsUUIDSegment("nodes") {
		t.Error("IsUUIDSegment")
	}
	if !IsNumericSegment("3") || IsNumericSegment("v1") {
		t.Error("IsNumericSegment")
	}
}

// Any segment outside the route vocabulary is an identifier, UUID or not: a
// user-typed dataroom title must never reach a route label or a span name.
func TestNormalizeRoute_FoldsUnknownSegments(t *testing.T) {
	tests := map[string]string{
		"/dataroom/Projet Alpha/nodes":                               "/dataroom/{id}/nodes",
		"/share/SENTINEL-title/details":                              "/share/{id}/details",
		"/organization/member/bob@example.com":                       "/organization/member/{id}",
		"/v1/transfer/019d3de3-cba2-76d0-962d-7817e9858661/tracking": "/v1/transfer/{id}/tracking",
		"/user/me/key/active":                                        "/user/me/key/active",
		"/login/config/public":                                       "/login/config/public",
		"/dataroom/node/version/x/chunk/3":                           "/dataroom/node/version/{id}/chunk/{n}",
	}
	for in, want := range tests {
		if got := NormalizeRoute(in); got != want {
			t.Errorf("NormalizeRoute(%q) = %q, want %q", in, got, want)
		}
	}
}

// Routes are normalized by template position: a segment sitting where the
// template expects an identifier is folded whatever its value, even a route
// word. Only a path matching no template falls back to the vocabulary.
func TestNormalizeRoute_ByTemplatePosition(t *testing.T) {
	tests := map[string]string{
		"/dataroom/users/nodes":                           "/dataroom/{id}/nodes",
		"/dataroom/dataroom/node":                         "/dataroom/{id}/node",
		"/dataroom/file/node/file":                        "/dataroom/{id}/node/file",
		"/organization/member/users":                      "/organization/member/{id}",
		"/v1/organization/member/dataroom/enable":         "/v1/organization/member/{id}/enable",
		"/share/details/details":                          "/share/{id}/details",
		"/dataroom/node/version/chunk/chunk/3":            "/dataroom/node/version/{id}/chunk/{n}",
		"/dataroom/node/node/download/0":                  "/dataroom/node/{id}/download/{n}",
		"/dataroom/a/user/b":                              "/dataroom/{id}/user/{id}",
		"/file/file/9":                                    "/file/{id}/{n}",
		"/transfer/sent":                                  "/transfer/sent",
		"/transfer/sent/tracking":                         "/transfer/{id}/tracking",
		"/weird/foo/019d3de3-cba2-76d0-962d-7817e9858661": "/{id}/{id}/{id}",
	}
	for in, want := range tests {
		if got := NormalizeRoute(in); got != want {
			t.Errorf("NormalizeRoute(%q) = %q, want %q", in, got, want)
		}
	}
}

// The OIDC client is traced too: the realm is folded, the endpoint kept.
func TestNormalizeRoute_IdentityProvider(t *testing.T) {
	tests := map[string]string{ //nolint:gosec // G101: route paths, not credentials
		"/realms/SENTINEL-realm/.well-known/openid-configuration":    "/realms/{id}/.well-known/openid-configuration",
		"/realms/SENTINEL-realm/protocol/openid-connect/token":       "/realms/{id}/protocol/openid-connect/token",
		"/realms/SENTINEL-realm/protocol/openid-connect/auth/device": "/realms/{id}/protocol/openid-connect/auth/device",
		"/realms/SENTINEL-realm/protocol/openid-connect/logout":      "/realms/{id}/protocol/openid-connect/logout",
	}
	for in, want := range tests {
		if got := NormalizeRoute(in); got != want {
			t.Errorf("NormalizeRoute(%q) = %q, want %q", in, got, want)
		}
	}
}
