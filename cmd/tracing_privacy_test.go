package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"github.com/retyc/retyc-cli/internal/vfs"
	"github.com/spf13/cobra"
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

	// 1. A WebDAV request whose path, body and listing all carry the sentinel.
	fs := newTestFS(nil, vfs.Options{List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
		return []service.DataroomNodeInfo{{ID: "n1", Name: sentinel + ".pdf", Type: "file"}}, nil
	}})
	h := instrumentWebdav(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.tree.ReadDir(r.Context(), "dr1", "/"+sentinel); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusMultiStatus)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PROPFIND", "/dataroom/"+sentinel+"/"+sentinel+".pdf",
		strings.NewReader("<propfind>"+sentinel+"</propfind>")))

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

	// 3. A command whose argument and error message carry the sentinel.
	probe := &cobra.Command{
		Use:  "privacy-probe",
		Args: cobra.ArbitraryArgs,
		RunE: func(*cobra.Command, []string) error { return errors.New("stat " + sentinel + ": no such file") },
	}
	withTestCommand(t, probe)
	_ = run(context.Background(), []string{"privacy-probe", "/tmp/" + sentinel + ".pdf"})

	spans := exp.GetSpans()
	if len(spans) < 3 {
		t.Fatalf("expected at least 3 spans (webdav, api, command), got %d", len(spans))
	}
	assertNoSentinel(t, spans)
}

// The OIDC client (discovery, token refresh, device flow) runs before the API
// client exists: webdav serve init spent seconds there with no span at all.
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
