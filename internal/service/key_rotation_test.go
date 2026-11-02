package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
)

func newRotationTestClient(srv *httptest.Server) *api.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", TokenType: "Bearer"})

	return api.New(srv.URL, "retyc-test/1.0", ts, false, false)
}

func saBody(pub string) string {
	return `{"id":"1","email":"sa@x.co","public_key":` + pub + `,"status":"active","created_at":"2026-01-01T00:00:00Z"}`
}

func TestOrgRecipient(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    string
		wantErr bool
	}{
		{"account with key", http.StatusOK, saBody(`"age1pq1org"`), "age1pq1org", false},
		{"null body", http.StatusOK, `null`, "", false},
		{"account without key", http.StatusOK, saBody(`null`), "", false},
		{"not found", http.StatusNotFound, `{"detail":"none"}`, "", false},
		{"server error", http.StatusInternalServerError, `{"detail":"boom"}`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			got, err := orgRecipient(context.Background(), newRotationTestClient(srv))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWithOrgKey(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		org  string
		want []string
	}{
		{"added", []string{"a"}, "o", []string{"a", "o"}},
		{"already present", []string{"a", "o"}, "o", []string{"a", "o"}},
		{"empty org", []string{"a"}, "", []string{"a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withOrgKey(tt.keys, tt.org); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
