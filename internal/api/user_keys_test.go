package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListUserKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/user/me/keys/all" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `[
{"id":"k3","user_id":"u","public_key":"pk3","private_key_enc":"enc3",`+
			`"created_at":"2026-10-03T00:00:00Z","deleted_at":null,"status":"active"},
{"id":"k2","user_id":"u","public_key":"pk2","private_key_enc":"enc2",`+
			`"created_at":"2026-10-02T00:00:00Z","deleted_at":null,"status":"pending"},
{"id":"k1","user_id":"u","public_key":"pk1","private_key_enc":null,`+
			`"created_at":"2026-10-01T00:00:00Z","deleted_at":"2026-10-02T00:00:00Z","status":"revoked"}]`)
	}))
	defer srv.Close()

	keys, err := newTestClient(srv).ListUserKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("len = %d", len(keys))
	}
	if keys[0].Status != UserKeyActive || keys[1].Status != UserKeyPending || keys[2].Status != UserKeyRevoked {
		t.Errorf("statuses = %v %v %v", keys[0].Status, keys[1].Status, keys[2].Status)
	}
	if keys[0].PrivateKeyEnc == nil || *keys[0].PrivateKeyEnc != "enc3" || keys[2].PrivateKeyEnc != nil {
		t.Errorf("private_key_enc not decoded: %v %v", keys[0].PrivateKeyEnc, keys[2].PrivateKeyEnc)
	}
	if keys[2].DeletedAt == nil || keys[1].DeletedAt != nil {
		t.Errorf("deleted_at not decoded")
	}
}

func TestCreateUserKey_Body(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/user/me/keys" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).CreateUserKey(context.Background(), "pub", "enc"); err != nil {
		t.Fatal(err)
	}
	if want := `{"private_key_enc":"enc","public_key":"pub"}`; gotBody != want {
		t.Errorf("body = %s, want %s", gotBody, want)
	}
}

func TestCreateUserKey_Conflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"detail":"Key rotation already in progress"}`)
	}))
	defer srv.Close()

	err := newTestClient(srv).CreateUserKey(context.Background(), "pub", "enc")
	if !errors.Is(err, ErrKeyRotationInProgress) {
		t.Errorf("err = %v, want ErrKeyRotationInProgress", err)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusConflict {
		t.Errorf("HTTPError not reachable: %v", err)
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("ErrConflict not matched")
	}
}

func TestRevokeUserKey(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).RevokeUserKey(context.Background(), "a/b"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/user/me/key/a%2Fb" {
		t.Errorf("path = %s", gotPath)
	}
}

func TestTransferRecipient_ExpectedPublicKey(t *testing.T) {
	var r []TransferRecipient
	in := `[{"share_id":"s","expected_public_key":"age1pq1x"},{"share_id":"s","expected_public_key":null}]`
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	if r[0].ExpectedPublicKey == nil || *r[0].ExpectedPublicKey != "age1pq1x" || r[1].ExpectedPublicKey != nil {
		t.Errorf("got %+v", r)
	}
}
