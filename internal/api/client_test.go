package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func staticTokenSource() oauth2.TokenSource {
	return oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	})
}

func newTestClient(srv *httptest.Server) *Client {
	return New(srv.URL, "retyc-test/1.0", staticTokenSource(), false, false)
}

func TestClient_Get_Success(t *testing.T) {
	type body struct {
		Name string `json:"name"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		_ = json.NewEncoder(w).Encode(body{Name: "test-value"})
	}))
	defer srv.Close()

	var result body
	if err := newTestClient(srv).Get(context.Background(), "/test", &result); err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if result.Name != "test-value" {
		t.Errorf("Name = %q, want test-value", result.Name)
	}
}

func TestClient_Get_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	err := newTestClient(srv).Get(context.Background(), "/missing", nil)
	if err == nil {
		t.Fatal("Get() should return error for 404")
	}

	if !strings.Contains(err.Error(), "API error 404") {
		t.Errorf("error %q should contain 'API error 404'", err.Error())
	}
}

func TestClient_Get_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not valid json {{")
	}))
	defer srv.Close()

	var result struct{ Name string }

	err := newTestClient(srv).Get(context.Background(), "/bad", &result)
	if err == nil {
		t.Error("Get() should return error for invalid JSON response")
	}
}

func TestClient_Post_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}

		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "new-id"})
	}))
	defer srv.Close()

	body := strings.NewReader(`{"name":"test"}`)
	var result map[string]string

	if err := newTestClient(srv).Post(context.Background(), "/resource", body, &result); err != nil {
		t.Fatalf("Post() error = %v", err)
	}

	if result["id"] != "new-id" {
		t.Errorf("id = %q, want new-id", result["id"])
	}
}

func TestClient_Put_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}

		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	body := strings.NewReader(`{"key":"val"}`)
	if err := newTestClient(srv).Put(context.Background(), "/resource", body, nil); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
}

func TestClient_Put_NilBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			t.Errorf("Content-Type = %q, want empty for nil body", ct)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// nil body — no Content-Type should be set.
	if err := newTestClient(srv).Put(context.Background(), "/re-enable", nil, nil); err != nil {
		t.Fatalf("Put() nil body error = %v", err)
	}
}

func TestClient_Delete_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).Delete(context.Background(), "/resource/123"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestClient_GetBytes_Success(t *testing.T) {
	expected := []byte{0xde, 0xad, 0xbe, 0xef}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(expected)
	}))
	defer srv.Close()

	got, err := newTestClient(srv).GetBytes(context.Background(), "/file/chunk")
	if err != nil {
		t.Fatalf("GetBytes() error = %v", err)
	}

	if string(got) != string(expected) {
		t.Errorf("GetBytes() = %v, want %v", got, expected)
	}
}

func TestClient_GetBytes_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetBytes(context.Background(), "/fail")
	if err == nil {
		t.Error("GetBytes() should return error for non-2xx status")
	}
}

func TestClient_PostMultipartChunk(t *testing.T) {
	chunkData := []byte("encrypted chunk payload")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			t.Errorf("Content-Type = %q, want multipart/form-data", r.Header.Get("Content-Type"))
		}

		if err := r.ParseMultipartForm(10 << 20); err != nil { //nolint:gosec // G120: test server, no DoS risk
			t.Errorf("ParseMultipartForm() error = %v", err)

			return
		}

		f, hdr, err := r.FormFile("upload_file")
		if err != nil {
			t.Errorf("FormFile(upload_file) error = %v", err)
			http.Error(w, "missing field", http.StatusBadRequest)

			return
		}
		defer f.Close() //nolint:errcheck

		if hdr.Filename != "chunk.age" {
			t.Errorf("filename = %q, want chunk.age", hdr.Filename)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := newTestClient(srv).PostMultipartChunk(context.Background(), "/file/abc/0", chunkData); err != nil {
		t.Fatalf("PostMultipartChunk() error = %v", err)
	}
}

func TestUserAgentTransport_SetsHeader(t *testing.T) {
	var gotUA string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := &UserAgentTransport{
		UserAgent: "retyc-test/9.9",
		Base:      http.DefaultTransport,
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}

	defer resp.Body.Close() //nolint:errcheck

	if gotUA != "retyc-test/9.9" {
		t.Errorf("User-Agent = %q, want retyc-test/9.9", gotUA)
	}
}

func TestUserAgentTransport_NilBase(t *testing.T) {
	var gotUA string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Base is nil — should fall back to http.DefaultTransport.
	tr := &UserAgentTransport{UserAgent: "nil-base-test/1.0"}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() with nil Base error = %v", err)
	}

	defer resp.Body.Close() //nolint:errcheck

	if gotUA != "nil-base-test/1.0" {
		t.Errorf("User-Agent = %q, want nil-base-test/1.0", gotUA)
	}
}
