package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/api"
)

// newOwnerFixture serves the member list of dr1 and records the user IDs the
// ownership route is called with.
func newOwnerFixture(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dataroom/dr1/users", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"user_id": "u-owner", "user_email": "owner@x.co", "role": "owner"},
			{"user_id": "u-admin", "user_email": "Admin@x.co", "role": "admin"},
			{"user_id": "u-editor", "user_email": "editor@x.co", "role": "editor"},
		})
	})
	mux.HandleFunc("PUT /dataroom/dr1/ownership/{user}", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.PathValue("user"))
		if r.PathValue("user") == "u-forbidden" {
			w.Header().Set(api.ErrorCodeHeader, api.CodeRoleForbidden)
			w.WriteHeader(http.StatusForbidden)

			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, &calls
}

func TestTransferDataroomOwnership(t *testing.T) {
	for _, user := range []string{"u-admin", "admin@x.co"} {
		srv, calls := newOwnerFixture(t)
		client := newKeyTestClient(srv)
		owner, err := ResolveNewDataroomOwner(context.Background(), client, "dr1", user)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if err := TransferDataroomOwnership(context.Background(), client, "dr1", owner.UserID); err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if owner.UserID != "u-admin" || len(*calls) != 1 || (*calls)[0] != "u-admin" {
			t.Errorf("%s: owner %q, calls %v", user, owner.UserID, *calls)
		}
	}
}

func TestTransferDataroomOwnershipRefused(t *testing.T) {
	for user, want := range map[string]string{
		"u-editor":     "only an admin",
		"owner@x.co":   "already owns",
		"nobody@x.co": "not a member",
	} {
		srv, calls := newOwnerFixture(t)
		_, err := ResolveNewDataroomOwner(context.Background(), newKeyTestClient(srv), "dr1", user)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", user, err, want)
		}
		if len(*calls) != 0 {
			t.Errorf("%s: ownership route called", user)
		}
	}
}

// An API refusal keeps its *api.HTTPError reachable, which the JSON error kind
// relies on, and a caller who is not the owner gets a plain explanation.
func TestTransferDataroomOwnershipAPIRefusal(t *testing.T) {
	srv, _ := newOwnerFixture(t)
	err := TransferDataroomOwnership(context.Background(), newKeyTestClient(srv), "dr1", "u-forbidden")
	var httpErr *api.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusForbidden {
		t.Fatalf("error %v, want a wrapped 403", err)
	}
	if !strings.Contains(err.Error(), "only the owner") {
		t.Errorf("error %q lacks the owner hint", err)
	}
}
