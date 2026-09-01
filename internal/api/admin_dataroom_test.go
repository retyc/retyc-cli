package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminGetDataroom(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"dr1","title":"Legal","status":"active","owner_id":"u1","owner_email":"o@x.co",
			"session_private_key_enc":"-----BEGIN AGE ENCRYPTED FILE-----","session_public_key":"age1pq1aaa",
			"created_at":"2026-01-01T00:00:00Z"}`)
	}))
	defer srv.Close()

	dr, err := newTestClient(srv).AdminGetDataroom(context.Background(), "dr1")
	if err != nil {
		t.Fatalf("AdminGetDataroom() error = %v", err)
	}
	if dr.Title != "Legal" || dr.SessionPublicKey != "age1pq1aaa" {
		t.Errorf("unexpected dataroom: %+v", dr)
	}
}

func TestAdminRekeyDataroom_Body(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/dataroom/dr1/rekey" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		var body struct {
			SessionPrivateKeyEnc string `json:"session_private_key_enc"`
		}
		_ = jsonDecode(r, &body)
		if body.SessionPrivateKeyEnc != "blob" {
			t.Errorf("session_private_key_enc = %q", body.SessionPrivateKeyEnc)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).AdminRekeyDataroom(context.Background(), "dr1", "blob"); err != nil {
		t.Fatalf("AdminRekeyDataroom() error = %v", err)
	}
}

func TestAdminDownloadNodeChunk_Path(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/node/n1/download/3" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte{0x01, 0x02})
	}))
	defer srv.Close()

	data, err := newTestClient(srv).AdminDownloadNodeChunk(context.Background(), "n1", 3)
	if err != nil {
		t.Fatalf("AdminDownloadNodeChunk() error = %v", err)
	}
	if len(data) != 2 {
		t.Errorf("len(data) = %d, want 2", len(data))
	}
}

func jsonDecode(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}
