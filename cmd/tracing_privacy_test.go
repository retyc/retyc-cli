package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"github.com/retyc/retyc-cli/internal/vfs"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const sentinel = "SENTINEL-do-not-export"

// assertNoSentinel walks every exported field of every span.
func assertNoSentinel(t *testing.T, spans tracetest.SpanStubs) {
	t.Helper()
	telemetrytest.AssertNoLeak(t, spans, sentinel)
}

func TestTracing_NeverExportsNames(t *testing.T) {
	isolateConfig(t)
	exp := telemetrytest.Install(t)

	// 1. A tree listing whose path and names carry the sentinel, under the
	// root span a FUSE operation would open.
	fs := newTestFS(nil, vfs.Options{List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return []service.DataroomNodeInfo{{ID: "n1", Name: sentinel + ".pdf", Type: "file"}}, nil
	}})
	ctx, root := telemetry.Tracer().Start(context.Background(), "FUSE lookup")
	if _, err := fs.tree.ReadDir(ctx, "dr1", "/"+sentinel); err != nil {
		t.Error(err)
	}
	root.End()

	// 2. An API call whose query, header and body carry the sentinel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := &http.Client{Transport: telemetry.RoundTripper(http.DefaultTransport)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/dataroom/019d3de3-cba2-76d0-962d-7817e9858661/nodes?name="+sentinel, strings.NewReader(sentinel))
	req.Header.Set("X-Title", sentinel)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("expected at least 2 spans (fuse, api), got %d", len(spans))
	}
	assertNoSentinel(t, spans)
}

// The OIDC client (discovery, token refresh, device flow) runs before the API
// client exists: fs mount init spent seconds there with no span at all.
func TestNewHTTPClient_TracesRoundTrips(t *testing.T) {
	isolateConfig(t)
	exp := telemetrytest.Install(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/realms/"+sentinel+"/protocol/openid-connect/token", strings.NewReader(sentinel))
	resp, err := newHTTPClient(false, false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if want := "/realms/{id}/protocol/openid-connect/token"; spans[0].Name != want {
		t.Errorf("span name = %q, want %q", spans[0].Name, want)
	}
	assertNoSentinel(t, spans)
}
