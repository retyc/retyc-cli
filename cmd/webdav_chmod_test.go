package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
)

const (
	proppatchExecutable = `<?xml version="1.0" encoding="utf-8"?>` +
		`<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apache.org/dav/props/">` +
		`<D:set><D:prop><A:executable>%s</A:executable></D:prop></D:set></D:propertyupdate>`
	propfindExecutable = `<?xml version="1.0" encoding="utf-8"?>` +
		`<D:propfind xmlns:D="DAV:" xmlns:A="http://apache.org/dav/props/">` +
		`<D:prop><A:executable/></D:prop></D:propfind>`
)

// chmodAPI is a fake API recording the bodies of PUT /dataroom/node/{id}.
type chmodAPI struct {
	status int

	mu     sync.Mutex
	bodies []string
}

func (a *chmodAPI) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut || r.URL.Path != "/dataroom/node/f-1" {
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)

		return
	}
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.bodies = append(a.bodies, string(body))
	a.mu.Unlock()
	if a.status != 0 {
		w.WriteHeader(a.status)

		return
	}
	_, _ = w.Write([]byte(`{"id":"f-1"}`))
}

func (a *chmodAPI) calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]string(nil), a.bodies...)
}

// davRequest runs one request through the WebDAV handler over fs.
func davRequest(fs *webdavFS, method, target, body string) *httptest.ResponseRecorder {
	h := &webdav.Handler{FileSystem: fs, LockSystem: webdav.NewMemLS()}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Depth", "0")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func newChmodFS(t *testing.T, a *chmodAPI, mode string) *webdavFS {
	t.Helper()
	node := service.DataroomNodeInfo{ID: "f-1", Name: "run.sh", Type: "file"}
	if mode != "" {
		node = node.WithMode(mustParseMode(t, mode))
	}
	fs, _ := newCachedListingsFS(t, a.handler, map[string][]service.DataroomNodeInfo{"retyc://dr1/": {node}})

	return fs
}

// A chmod +x through a mount is a PROPPATCH of the executable property: it
// reaches the API as the node's mode, and the next PROPFIND reports it.
func TestProppatchExecutable_SetsTheMode(t *testing.T) {
	for _, tc := range []struct {
		name, stored, value, wantMode string
	}{
		{"set on 0644", "0644", "T", "0755"},
		{"set on 0600", "0600", "T", "0700"},
		{"set without a stored mode", "", "T", "0755"},
		{"clear on 0755", "0755", "F", "0644"},
		{"special bits are kept", "4644", "T", "4755"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &chmodAPI{}
			fs := newChmodFS(t, a, tc.stored)

			rec := davRequest(fs, "PROPPATCH", "/dataroom/DR/run.sh", strings.Replace(proppatchExecutable, "%s", tc.value, 1))
			if rec.Code != http.StatusMultiStatus || !strings.Contains(rec.Body.String(), "200 OK") {
				t.Fatalf("PROPPATCH = %d %s, want 207 with 200 on the property", rec.Code, rec.Body)
			}
			calls := a.calls()
			if len(calls) != 1 || !strings.Contains(calls[0], `"access_mode":"`+tc.wantMode+`"`) {
				t.Fatalf("API calls = %v, want one PUT with access_mode %s", calls, tc.wantMode)
			}

			want := "<executable xmlns=\"http://apache.org/dav/props/\">" + tc.value + "</executable>"
			rec = davRequest(fs, "PROPFIND", "/dataroom/DR/run.sh", propfindExecutable)
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("PROPFIND after the chmod = %s, want %s", rec.Body, want)
			}
			if got := a.calls(); len(got) != 1 {
				t.Errorf("the PROPFIND cost %d API call(s), want it served from the cached listing", len(got)-1)
			}
		})
	}
}

// A mode that already says so costs no API call.
func TestProppatchExecutable_UnchangedModeSkipsTheAPI(t *testing.T) {
	a := &chmodAPI{}
	fs := newChmodFS(t, a, "0755")

	rec := davRequest(fs, "PROPPATCH", "/dataroom/DR/run.sh", strings.Replace(proppatchExecutable, "%s", "T", 1))
	if rec.Code != http.StatusMultiStatus || !strings.Contains(rec.Body.String(), "200 OK") {
		t.Fatalf("PROPPATCH = %d %s, want 207 with 200 on the property", rec.Code, rec.Body)
	}
	if calls := a.calls(); len(calls) != 0 {
		t.Errorf("API calls = %v, want none", calls)
	}
}

// The API's refusals reach the client on the property.
func TestProppatchExecutable_ReportsRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{http.StatusLocked, "423 Locked"},
		{http.StatusForbidden, "403 Forbidden"},
	} {
		a := &chmodAPI{status: tc.status}
		fs := newChmodFS(t, a, "0644")

		rec := davRequest(fs, "PROPPATCH", "/dataroom/DR/run.sh", strings.Replace(proppatchExecutable, "%s", "T", 1))
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("API %d: PROPPATCH = %d %s, want %s on the property", tc.status, rec.Code, rec.Body, tc.want)
		}
		rec = davRequest(fs, "PROPFIND", "/dataroom/DR/run.sh", propfindExecutable)
		if !strings.Contains(rec.Body.String(), ">F</executable>") {
			t.Errorf("API %d: PROPFIND = %s, want the file still not executable", tc.status, rec.Body)
		}
	}
}

// Any other property stays read-only, and takes the executable one with it.
func TestProppatch_OtherPropertiesAreRefused(t *testing.T) {
	a := &chmodAPI{}
	fs := newChmodFS(t, a, "0644")
	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apache.org/dav/props/" xmlns:Z="urn:x">` +
		`<D:set><D:prop><A:executable>T</A:executable><Z:color>red</Z:color></D:prop></D:set></D:propertyupdate>`

	rec := davRequest(fs, "PROPPATCH", "/dataroom/DR/run.sh", body)
	got := rec.Body.String()
	if !strings.Contains(got, "403 Forbidden") || !strings.Contains(got, "424 Failed Dependency") {
		t.Errorf("PROPPATCH = %d %s, want 403 on color and 424 on executable", rec.Code, got)
	}
	if calls := a.calls(); len(calls) != 0 {
		t.Errorf("API calls = %v, want none", calls)
	}
}

// An upload that does not learn the node's mode keeps the cached one.
func TestUpsertNodeCache_KeepsTheMode(t *testing.T) {
	a := &chmodAPI{}
	fs := newChmodFS(t, a, "0755")

	fs.upsertNodeCache("retyc://dr1/", service.DataroomNodeInfo{ID: "f-1", Name: "run.sh", Type: "file", Size: 3})
	rec := davRequest(fs, "PROPFIND", "/dataroom/DR/run.sh", propfindExecutable)
	if !strings.Contains(rec.Body.String(), ">T</executable>") {
		t.Errorf("PROPFIND after an overwrite = %s, want the file still executable", rec.Body)
	}
}

func mustParseMode(t *testing.T, s string) os.FileMode {
	t.Helper()
	mode, ok := api.ParseAccessMode(s)
	if !ok {
		t.Fatalf("invalid mode %q", s)
	}

	return mode
}
