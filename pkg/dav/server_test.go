package dav

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/vfs"
)

// New is what a program importing the core serves: a PROPFIND of /spaces
// lists the datarooms, and every request is reported to LogRequest.
func TestNewServesDatarooms(t *testing.T) {
	// The API only answers the quota of the datarooms.
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(apiSrv.Close)
	client := api.New(apiSrv.URL, "retyc-test/1.0", nil, false, false)
	var logged []string
	srv := New(client, Options{
		VFS: vfs.Options{ListDatarooms: func(context.Context) ([]vfs.Dataroom, error) {
			return []vfs.Dataroom{{ID: "dr1", Title: "Board"}}, nil
		}},
		LogRequest: func(r *http.Request, _ error) { logged = append(logged, r.Method) },
	})
	t.Cleanup(func() { _ = srv.Close() })

	req := httptest.NewRequestWithContext(t.Context(), "PROPFIND", "/spaces/", http.NoBody)
	req.Header.Set("Depth", "1")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND /spaces/ = %d, want 207: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "Board") {
		t.Errorf("the listing does not show the storage space: %s", rec.Body)
	}
	if len(logged) != 1 || logged[0] != "PROPFIND" {
		t.Errorf("LogRequest calls = %v, want [PROPFIND]", logged)
	}
}
