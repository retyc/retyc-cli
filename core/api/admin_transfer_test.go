package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminGetTransfer_NullSessionKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transfer/t1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"t1","title":"Docs","status":"active","web_url":"https://x/t1",
			"session_public_key":"age1pq1bbb","session_private_key_enc":null,
			"recipients":[{"email":"a@x.co","public_key":"age1pq1ccc","expected_public_key":null,
			"key_mismatch":false,"key_encrypted":true,"is_external":false,"is_service_account":false}],
			"created_at":"2026-01-01T00:00:00Z"}`)
	}))
	defer srv.Close()

	tr, err := newTestClient(srv).AdminGetTransfer(context.Background(), "t1")
	if err != nil {
		t.Fatalf("AdminGetTransfer() error = %v", err)
	}
	if tr.SessionPrivateKeyEnc != nil {
		t.Error("SessionPrivateKeyEnc should be nil")
	}
	if len(tr.Recipients) != 1 || *tr.Recipients[0].PublicKey != "age1pq1ccc" {
		t.Errorf("unexpected recipients: %+v", tr.Recipients)
	}
}

func TestAdminListTransfers_Filters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transfer/sent" {
			t.Errorf("path = %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("status") != "active" || q.Get("user_id") != "u1" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		fmt.Fprint(w, `{"items":[],"total":0,"page":1,"pages":0}`)
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).AdminListTransfers(context.Background(), "active", "u1", 1); err != nil {
		t.Fatalf("AdminListTransfers() error = %v", err)
	}
}

func TestAdminForceDeleteTransfer_Path(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/transfer/t1/force" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).AdminForceDeleteTransfer(context.Background(), "t1"); err != nil {
		t.Fatalf("AdminForceDeleteTransfer() error = %v", err)
	}
}
