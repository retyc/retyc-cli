package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// saBody is a GET /organization/service-account answer with the given raw public_key and status.
func saBody(publicKey, status string) string {
	return `{"id":"sa","email":"e","created_at":"2026-10-01T00:00:00Z",` +
		`"public_key":` + publicKey + `,"status":"` + status + `"}`
}

func TestGetOrganizationServiceAccount(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantKey string
		wantNil bool
		wantErr bool
	}{
		{name: "active", status: 200, body: saBody(`"age1pq1org"`, "active"), wantKey: "age1pq1org"},
		{name: "disabled", status: 200, body: saBody(`"age1pq1org"`, "disabled")},
		{name: "no key", status: 200, body: saBody("null", "active")},
		{name: "none", status: 200, body: `null`, wantNil: true},
		{name: "route unknown", status: 404, body: `{"detail":"Not Found"}`, wantNil: true},
		{name: "server error", status: 500, body: `{}`, wantNil: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/organization/service-account" {
					t.Errorf("path = %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			sa, err := newTestClient(srv).GetOrganizationServiceAccount(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if (sa == nil) != tt.wantNil {
				t.Fatalf("service account = %+v, wantNil %v", sa, tt.wantNil)
			}
			if got := sa.OrganizationKey(); got != tt.wantKey {
				t.Errorf("OrganizationKey() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}
