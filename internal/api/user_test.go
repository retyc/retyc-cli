package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetMe_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/me" {
			t.Errorf("path = %q, want /user/me", r.URL.Path)
		}

		name := "Alice Dupont"
		_ = json.NewEncoder(w).Encode(userMeResponse{
			User: UserInfo{
				ID:       "user-123",
				Email:    "alice@example.com",
				FullName: &name,
			},
		})
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
