package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func attr(span tracetest.SpanStub, key string) (attribute.Value, bool) {
	for _, kv := range span.Attributes {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}

	return attribute.Value{}, false
}

func TestRoundTripper_SpanPerCall(t *testing.T) {
	exp := telemetrytest.Install(t)
	var gotTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client := &http.Client{Transport: RoundTripper(http.DefaultTransport)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/dataroom/node/version/019d3de3-cba2-76d0-962d-7817e9858661/chunk/7?name=SECRET.pdf", nil)
	req.Header.Set("Authorization", "Bearer SECRET-TOKEN")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Name != "/dataroom/node/version/{id}/chunk/{n}" {
		t.Errorf("span name = %q", s.Name)
	}
	if s.SpanKind != trace.SpanKindClient {
		t.Errorf("kind = %v, want client", s.SpanKind)
	}
	if v, ok := attr(s, "http.response.status_code"); !ok || v.AsInt64() != 201 {
		t.Errorf("status attribute = %v", v)
	}
	if v, ok := attr(s, "retyc.version.id"); !ok || v.AsString() != "019d3de3-cba2-76d0-962d-7817e9858661" {
		t.Errorf("retyc.version.id = %v", v)
	}
	if v, ok := attr(s, "retyc.chunk.index"); !ok || v.AsInt64() != 7 {
		t.Errorf("retyc.chunk.index = %v, want 7", v)
	}
	if _, ok := attr(s, "retyc.path.params"); ok {
		t.Error("retyc.path.params must only appear for placeholders without a known resource")
	}
	for _, kv := range s.Attributes {
		if strings.Contains(kv.Value.String(), "SECRET") {
			t.Errorf("attribute %s leaks the query or the token: %s", kv.Key, kv.Value.String())
		}
		if kv.Key == "url.path" || kv.Key == "url.full" {
			t.Errorf("forbidden attribute %s", kv.Key)
		}
	}
	if gotTraceparent == "" {
		t.Error("traceparent header not injected on the outgoing request")
	}
}

type failingRT struct{}

func (failingRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connection refused to /SECRET")
}

func TestRoundTripper_TransportErrorRecordsTypeOnly(t *testing.T) {
	exp := telemetrytest.Install(t)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.test/share", nil)
	resp, err := RoundTripper(failingRT{}).RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the transport error to propagate")
	}
	s := exp.GetSpans()[0]
	if s.Status.Code != codes.Error || s.Status.Description != "" {
		t.Errorf("status = %+v, want Error with empty description", s.Status)
	}
	if v, ok := attr(s, "error.type"); !ok || v.AsString() != "errors.errorString" {
		t.Errorf("error.type = %v", v)
	}
}

// Route placeholders become named identifiers, keyed by the resource segment
// that precedes them; numbers are chunk indexes; anything unknown stays in
// retyc.path.params so nothing is lost.
func TestRouteAttributes(t *testing.T) {
	cases := []struct {
		path string
		want map[string]string
	}{
		{"/dataroom/019d7cba-c700-73c2-8eac-f3dc311d1b25/nodes",
			map[string]string{"retyc.dataroom.id": "019d7cba-c700-73c2-8eac-f3dc311d1b25"}},
		{"/dataroom/node/019e9e07-2200-743e-8ca4-054abf48702b/version",
			map[string]string{"retyc.node.id": "019e9e07-2200-743e-8ca4-054abf48702b"}},
		{"/dataroom/node/version/01a0a11c-8e25-7659-a358-e33684b6bb19/chunk/7",
			map[string]string{"retyc.version.id": "01a0a11c-8e25-7659-a358-e33684b6bb19", "retyc.chunk.index": "7"}},
		{"/dataroom/node/019e9e07-2200-743e-8ca4-054abf48702b/download/3",
			map[string]string{"retyc.node.id": "019e9e07-2200-743e-8ca4-054abf48702b", "retyc.chunk.index": "3"}},
		{"/share/019d7cba-c700-73c2-8eac-f3dc311d1b25/details",
			map[string]string{"retyc.transfer.id": "019d7cba-c700-73c2-8eac-f3dc311d1b25"}},
		{"/file/019d7cba-c700-73c2-8eac-f3dc311d1b25/12",
			map[string]string{"retyc.file.id": "019d7cba-c700-73c2-8eac-f3dc311d1b25", "retyc.chunk.index": "12"}},
		{"/organization/member/019d7cba-c700-73c2-8eac-f3dc311d1b25",
			map[string]string{"retyc.member.id": "019d7cba-c700-73c2-8eac-f3dc311d1b25"}},
		{"/v1/transfer/019d7cba-c700-73c2-8eac-f3dc311d1b25/tracking",
			map[string]string{"retyc.transfer.id": "019d7cba-c700-73c2-8eac-f3dc311d1b25"}},
		{"/unknown/019d7cba-c700-73c2-8eac-f3dc311d1b25",
			map[string]string{"retyc.path.params": `["019d7cba-c700-73c2-8eac-f3dc311d1b25"]`}},
		{"/user/me/key/active", map[string]string{}},
		// A user-typed identifier is not a UUID: it is never exported.
		{"/dataroom/SENTINEL-title/nodes", map[string]string{}},
		// A number is a chunk index only under the chunk routes.
		{"/dataroom/019d7cba-c700-73c2-8eac-f3dc311d1b25/nodes/2", map[string]string{
			"retyc.dataroom.id": "019d7cba-c700-73c2-8eac-f3dc311d1b25"}},
	}
	for _, tc := range cases {
		got := map[string]string{}
		for _, kv := range routeAttributes(tc.path) {
			got[string(kv.Key)] = kv.Value.String()
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: attributes = %v, want %v", tc.path, got, tc.want)

			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: %s = %q, want %q", tc.path, k, got[k], v)
			}
		}
	}
}

func TestRoundTripper_UserTypedIDNeverReachesTheSpan(t *testing.T) {
	exp := telemetrytest.Install(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client := &http.Client{Transport: RoundTripper(http.DefaultTransport)}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/dataroom/SENTINEL-title/nodes", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	s := exp.GetSpans()[0]
	if s.Name != "/dataroom/{id}/nodes" {
		t.Errorf("span name = %q, the user-typed segment must be folded", s.Name)
	}
	for _, kv := range s.Attributes {
		if strings.Contains(kv.Value.String(), "SENTINEL") {
			t.Errorf("attribute %s leaks the user-typed identifier", kv.Key)
		}
	}
}

// An upload span says whether the API was asked to store the chunk in the
// background (unsafe_write): the one query parameter a span records, and only
// as a boolean — anything else in the query never reaches it.
func TestRoundTripper_RecordsUnsafeWrite(t *testing.T) {
	cases := map[string]struct {
		query string
		want  *bool
	}{
		"unsafe":    {query: "?unsafe_write=true", want: new(true)},
		"safe":      {query: "?unsafe_write=false", want: new(false)},
		"absent":    {query: ""},
		"not bool":  {query: "?unsafe_write=SECRET"},
		"other key": {query: "?name=SECRET&unsafe_write=true", want: new(true)},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			exp := telemetrytest.Install(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			}))
			defer srv.Close()
			client := &http.Client{Transport: RoundTripper(http.DefaultTransport)}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
				srv.URL+"/dataroom/node/version/019d3de3-cba2-76d0-962d-7817e9858661/chunk/0"+tc.query, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()

			s := exp.GetSpans()[0]
			v, ok := attr(s, string(AttrUnsafeWrite))
			switch {
			case tc.want == nil && ok:
				t.Errorf("%s = %v, want absent", AttrUnsafeWrite, v.String())
			case tc.want != nil && (!ok || v.AsBool() != *tc.want):
				t.Errorf("%s = %v (present %v), want %v", AttrUnsafeWrite, v.String(), ok, *tc.want)
			}
			for _, kv := range s.Attributes {
				if strings.Contains(kv.Value.String(), "SECRET") {
					t.Errorf("attribute %s leaks the query: %s", kv.Key, kv.Value.String())
				}
			}
		})
	}
}
