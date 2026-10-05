package telemetry

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/retyc/retyc-cli/internal/metrics"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

type roundTripper struct {
	base http.RoundTripper
}

// RoundTripper wraps base so every API call becomes one CLIENT span named by
// its normalized route, with the W3C trace context injected in the request.
// It records methods, routes, hosts, status codes and the route parameters as
// named identifiers (retyc.dataroom.id, retyc.chunk.index, ...); never the raw
// path, the query, the headers or the bodies.
func RoundTripper(base http.RoundTripper) http.RoundTripper {
	return &roundTripper{base: base}
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	route := metrics.NormalizeRoute(req.URL.Path)
	attrs := append([]attribute.KeyValue{
		attribute.String("http.request.method", req.Method),
		attribute.String("url.template", route),
		attribute.String("server.address", req.URL.Host),
	}, routeAttributes(req.URL.Path)...)
	attrs = append(attrs, unsafeWriteAttribute(req.URL)...)
	ctx, span := Tracer().Start(req.Context(), route,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...))
	defer span.End()

	req = req.Clone(ctx)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		RecordError(span, err)

		return nil, err
	}
	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode >= http.StatusInternalServerError {
		span.SetStatus(codes.Error, "")
	}

	return resp, nil
}

// unsafeWriteAttribute records the unsafe_write parameter of an upload, the
// only query parameter a span carries, and only when it parses as a boolean:
// the query is otherwise never recorded.
func unsafeWriteAttribute(u *url.URL) []attribute.KeyValue {
	if u.RawQuery == "" {
		return nil
	}
	v, err := strconv.ParseBool(u.Query().Get("unsafe_write"))
	if err != nil {
		return nil
	}

	return []attribute.KeyValue{AttrUnsafeWrite.Bool(v)}
}

// resourceKeys maps the path segment that precedes an identifier to the
// attribute carrying it. The backend says "share"; the CLI says "transfer".
var resourceKeys = map[string]attribute.Key{
	"dataroom":          AttrDataroomID,
	"node":              AttrNodeID,
	"version":           AttrVersionID,
	"share":             AttrTransferID,
	"transfer":          AttrTransferID,
	"file":              AttrFileID,
	"member":            AttrMemberID,
	"user":              AttrUserID,
	"blacklist-domains": AttrBlacklistDomainID,
}

// chunkResources are the segments a chunk index follows: /…/chunk/{n},
// /…/download/{n} and /file/{id}/{n}.
var chunkResources = map[string]bool{"chunk": true, "download": true, "file": true}

// Unwrap returns the wrapped transport.
func (rt *roundTripper) Unwrap() http.RoundTripper { return rt.base }

// routeAttributes names the identifiers of an API path: a UUID gets the key of
// the resource segment before it (retyc.dataroom.id for /dataroom/{id}/...),
// a number is a chunk index, and a UUID under an unknown resource lands in
// retyc.path.params so it is never lost. Names never appear in an API path.
func routeAttributes(path string) []attribute.KeyValue {
	var attrs []attribute.KeyValue
	var unknown []string
	resource := ""
	for _, seg := range strings.Split(path, "/") {
		switch {
		case seg == "":
		case metrics.IsUUIDSegment(seg):
			if key, ok := resourceKeys[resource]; ok {
				attrs = append(attrs, key.String(seg))
			} else {
				unknown = append(unknown, seg)
			}
		case metrics.IsNumericSegment(seg) && chunkResources[resource]:
			n, _ := strconv.Atoi(seg)
			attrs = append(attrs, AttrChunkIndex.Int(n))
		default:
			resource = seg
		}
	}
	if len(unknown) > 0 {
		attrs = append(attrs, AttrPathParams.StringSlice(unknown))
	}

	return attrs
}
