package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/oauth2"
)

// TestReadDataroomChunk reads one chunk by index: the route of that chunk
// alone and one crypto.decrypt span under the caller's span, as the streamed
// download gives per chunk.
func TestReadDataroomChunk(t *testing.T) {
	exp := telemetrytest.Install(t)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.EncryptBinaryForKey([]byte("abcd"), identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write(enc)
	}))
	defer srv.Close()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "parent")
	got, err := ReadDataroomChunk(ctx, newKeyTestClient(srv), "v1", 3, identity)
	parent.End()
	if err != nil {
		t.Fatalf("ReadDataroomChunk: %v", err)
	}
	if string(got) != "abcd" {
		t.Errorf("chunk = %q, want %q", got, "abcd")
	}
	if len(paths) != 1 || paths[0] != "/dataroom/node/version/v1/chunk/3" {
		t.Errorf("requests = %v, want the chunk route once", paths)
	}
	spans := childSpans(exp, parent, "crypto.decrypt")
	if len(spans) != 1 {
		t.Fatalf("got %d crypto.decrypt spans under the parent, want 1", len(spans))
	}
	if index, size := chunkAttrs(t, spans[0]); index != 3 || size != int64(len(enc)) {
		t.Errorf("span attributes: index %d, size %d; want 3, %d", index, size, len(enc))
	}
}

// A chunk the store does not hold is asked for again before it is reported
// missing, as on the streamed download.
func TestReadDataroomChunk_Missing(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, `{"detail":"chunk_not_found"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}),
		false, false, api.WithMissingChunkRetries(time.Millisecond))

	_, err := ReadDataroomChunk(context.Background(), client, "v1", 0, nil)
	if !errors.Is(err, api.ErrChunkMissing) || !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("error = %v, want api.ErrChunkMissing", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("%d requests, want 2 (one retry)", got)
	}
}

// A rate limit that outlasts the client's retries reaches the caller as the
// API error it is.
func TestReadDataroomChunk_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}),
		false, false, api.WithRetry(time.Millisecond, 1))

	_, err := ReadDataroomChunk(context.Background(), client, "v1", 0, nil)
	if !errors.Is(err, api.ErrRateLimited) {
		t.Fatalf("error = %v, want api.ErrRateLimited", err)
	}
	if got := api.RetryAfter(err); got != 7*time.Second {
		t.Errorf("RetryAfter = %v, want 7s", got)
	}
}

func TestReadDataroomChunk_DecryptFailureMarksTheSpan(t *testing.T) {
	exp := telemetrytest.Install(t)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("garbage"))
	}))
	defer srv.Close()

	ctx, parent := otel.Tracer("test").Start(context.Background(), "parent")
	_, err = ReadDataroomChunk(ctx, newKeyTestClient(srv), "v1", 0, identity)
	parent.End()
	if err == nil {
		t.Fatal("expected the decryption error")
	}
	spans := childSpans(exp, parent, "crypto.decrypt")
	if len(spans) != 1 || spans[0].Status.Code != codes.Error || spans[0].Status.Description != "" {
		t.Fatalf("crypto.decrypt spans = %+v, want one with status Error and no description", spans)
	}
}
