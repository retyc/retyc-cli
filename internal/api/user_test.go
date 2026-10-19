package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetMe_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/me" {
			t.Errorf("path = %q, want /user/me", r.URL.Path)
		}

		_, _ = w.Write([]byte(`{"user":{"id":"user-123","email":"alice@example.com",` +
			`"full_name":"Alice Dupont","main_organization_id":"org-456",` +
			`"kind":"machine_account","status":"active","created_at":"2026-10-18T09:30:00Z","key_id":"key-789"}}`))
	}))
	defer srv.Close()

	user, err := newTestClient(srv).GetMe(context.Background())
	if err != nil {
		t.Fatalf("GetMe() error = %v", err)
	}

	if user.ID != "user-123" {
		t.Errorf("ID = %q, want user-123", user.ID)
	}

	if user.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", user.Email)
	}

	if user.MainOrganizationID == nil || *user.MainOrganizationID != "org-456" {
		t.Errorf("MainOrganizationID = %v, want org-456", user.MainOrganizationID)
	}

	if user.Kind != "machine_account" || user.Status != "active" {
		t.Errorf("Kind, Status = %q, %q, want machine_account, active", user.Kind, user.Status)
	}

	if want := time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC); !user.CreatedAt.Equal(want) {
		t.Errorf("CreatedAt = %v, want %v", user.CreatedAt, want)
	}

	if user.KeyID == nil || *user.KeyID != "key-789" {
		t.Errorf("KeyID = %v, want key-789", user.KeyID)
	}
}

func TestGetActiveKey_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/me/key/active" {
			t.Errorf("path = %q, want /user/me/key/active", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(UserKey{
			ID:            "key-abc",
			UserID:        "user-123",
			PublicKey:     "age1pq1testpublickey",
			PrivateKeyEnc: "AGE-ENCRYPTED-PRIVATE-KEY",
		})
	}))
	defer srv.Close()

	key, err := newTestClient(srv).GetActiveKey(context.Background())
	if err != nil {
		t.Fatalf("GetActiveKey() error = %v", err)
	}

	if key == nil {
		t.Fatal("GetActiveKey() returned nil")
	}

	if key.ID != "key-abc" {
		t.Errorf("ID = %q, want key-abc", key.ID)
	}
}

func TestGetActiveKey_Null(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "null")
	}))
	defer srv.Close()

	key, err := newTestClient(srv).GetActiveKey(context.Background())
	if err != nil {
		t.Fatalf("GetActiveKey() error = %v", err)
	}

	if key != nil {
		t.Errorf("GetActiveKey() = %v, want nil for null response", key)
	}
}

func TestGetQuota_Success(t *testing.T) {
	maxCount := 10

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/quota" {
			t.Errorf("path = %q, want /user/quota", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(UserQuota{
			CountShare:    3,
			MaxCountShare: &maxCount,
			UsedStorage:   1024 * 1024,
			MaxStorage:    10 * 1024 * 1024,
		})
	}))
	defer srv.Close()

	quota, err := newTestClient(srv).GetQuota(context.Background())
	if err != nil {
		t.Fatalf("GetQuota() error = %v", err)
	}

	if quota.CountShare != 3 {
		t.Errorf("CountShare = %d, want 3", quota.CountShare)
	}

	if quota.MaxCountShare == nil || *quota.MaxCountShare != 10 {
		t.Errorf("MaxCountShare = %v, want 10", quota.MaxCountShare)
	}

	if quota.UsedStorage != 1024*1024 {
		t.Errorf("UsedStorage = %d, want %d", quota.UsedStorage, 1024*1024)
	}
}

func TestGetActiveKeyNullPrivateKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"public_key":"age1pq1abc","private_key_enc":null}`)
	}))
	defer srv.Close()

	key, err := newTestClient(srv).GetActiveKey(context.Background())
	if err != nil {
		t.Fatalf("GetActiveKey() error = %v", err)
	}
	if key == nil || key.PublicKey != "age1pq1abc" || key.PrivateKeyEnc != "" {
		t.Errorf("GetActiveKey() = %+v, want public key and empty PrivateKeyEnc", key)
	}
}
