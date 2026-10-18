package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"

	"github.com/retyc/retyc-cli/internal/machinekey"
)

const testOrgID = "0196a3f2-7c5e-7a10-8b3d-5f2e9c1d4a60"

// enrollServer is a fake API whose enrollment ends in state on the first poll.
type enrollServer struct {
	*httptest.Server
	calls atomic.Int32
}

func newEnrollServer(t *testing.T, state string, postStatus int) *enrollServer {
	t.Helper()
	es := &enrollServer{}
	var fp string
	es.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		es.calls.Add(1)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/machine/enrollments":
			if postStatus != 0 {
				w.WriteHeader(postStatus)
				_, _ = w.Write([]byte(`{"detail":"nope"}`))

				return
			}
			var req struct {
				SigningJWK   machinekey.JWK `json:"signing_jwk"`
				AgeRecipient string         `json:"age_recipient"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			fp = machinekey.Fingerprint(req.SigningJWK.Kid, req.AgeRecipient)
			_, _ = w.Write([]byte(`{"enrollment_id":"enr-1","fingerprint":"` + fp +
				`","approval_uri":"https://app.example/approve/enr-1","expires_in":600,"interval":1}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/machine/enrollments/"):
			_, _ = w.Write([]byte(`{"state":"` + state + `","machine_id":"m-1","organization_id":"` +
				testOrgID + `","client_id":"machine-m-1","issuer":"https://kc.example",` +
				`"token_endpoint":"https://kc.example/token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(es.Close)

	return es
}

// runEnroll runs `machine enroll` against baseURL and returns stdout, stderr
// and the error.
func runEnroll(t *testing.T, baseURL string, args ...string) (string, string, error) {
	t.Helper()
	isolateConfig(t)
	t.Setenv("RETYC_API_BASE_URL", baseURL)
	t.Setenv("RETYC_API_RETRY_MAX_ATTEMPTS", "1")
	t.Cleanup(resetEnrollFlags)
	resetEnrollFlags()
	var err error
	var stderr string
	stdout := captureStream(t, &os.Stdout, func() {
		stderr = captureStream(t, &os.Stderr, func() {
			err = run(context.Background(), append([]string{"machine", "enroll"}, args...))
		})
	})

	return stdout, stderr, err
}

func TestMachineEnrollJSONEvents(t *testing.T) {
	srv := newEnrollServer(t, "approved", 0)
	stdout, _, err := runEnroll(t, srv.URL, "--json", "--org", testOrgID, "--output-dir", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), stdout)
	}
	var pending, approved map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &pending); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &approved); err != nil {
		t.Fatal(err)
	}
	if pending["event"] != "pending" || pending["enrollment_id"] != "enr-1" ||
		pending["approval_uri"] == "" || pending["fingerprint"] == "" || pending["expires_at"] == nil {
		t.Errorf("pending = %v", pending)
	}
	if _, ok := pending["machine_id"]; ok {
		t.Errorf("pending carries machine_id: %v", pending)
	}
	if approved["event"] != "approved" || approved["machine_id"] != "m-1" ||
		approved["organization_id"] != testOrgID || approved["client_id"] != "machine-m-1" {
		t.Errorf("approved = %v", approved)
	}
	if _, ok := approved["expires_at"]; ok {
		t.Errorf("approved carries expires_at: %v", approved)
	}
}

func TestMachineEnrollHuman(t *testing.T) {
	srv := newEnrollServer(t, "approved", 0)
	stdout, stderr, err := runEnroll(t, srv.URL, "--org", testOrgID, "--output-dir", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q", stdout)
	}
	for _, want := range []string{"-", "https://app.example/approve/enr-1", "Organization > Machines"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q: %q", want, stderr)
		}
	}
}

func TestMachineEnrollExitCodes(t *testing.T) {
	tests := []struct {
		name       string
		state      string
		post       int
		wantCode   int
		wantKind   string
		wantEvents int
	}{
		{"expired", "expired", 0, 1, "enrollment_expired", 2},
		{"denied", "denied", 0, 78, "enrollment_denied", 2},
		{"no route", "", http.StatusNotFound, 78, "config", 0},
		{"plan 403", "", http.StatusForbidden, 78, "forbidden", 0},
		{"rate limited", "", http.StatusTooManyRequests, 1, "rate_limited", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newEnrollServer(t, tt.state, tt.post)
			stdout, _, err := runEnroll(t, srv.URL, "--json", "--org", testOrgID, "--output-dir", t.TempDir())
			if err == nil {
				t.Fatal("want an error")
			}
			if got := exitCode(err); got != tt.wantCode {
				t.Errorf("exit code = %d, want %d (%v)", got, tt.wantCode, err)
			}
			if got := newErrorJSON(err).Kind; got != tt.wantKind {
				t.Errorf("kind = %q, want %q (%v)", got, tt.wantKind, err)
			}
			if n := strings.Count(stdout, "\n"); n != tt.wantEvents {
				t.Errorf("stdout lines = %d, want %d: %q", n, tt.wantEvents, stdout)
			}
		})
	}
}

func TestMachineEnrollFlagValidation(t *testing.T) {
	tests := map[string][]string{
		"org not a uuid":  {"--org", "nope", "--output-dir", "x"},
		"missing org":     {"--output-dir", "x"},
		"missing dir":     {"--org", testOrgID},
		"name too long":   {"--org", testOrgID, "--output-dir", "x", "--name", strings.Repeat("a", 64)},
		"name empty":      {"--org", testOrgID, "--output-dir", "x", "--name", ""},
		"name with NUL":   {"--org", testOrgID, "--output-dir", "x", "--name", "a\x00b"},
		"cluster too big": {"--org", testOrgID, "--output-dir", "x", "--cluster-uid", strings.Repeat("a", 64)},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			srv := newEnrollServer(t, "approved", 0)
			dir := t.TempDir()
			for i, a := range args {
				if a == "x" {
					args[i] = dir
				}
			}
			_, _, err := runEnroll(t, srv.URL, args...)
			if err == nil {
				t.Fatal("want an error")
			}
			if got := exitCode(err); got != 78 {
				t.Errorf("exit code = %d, want 78 (%v)", got, err)
			}
			if n := srv.calls.Load(); n != 0 {
				t.Errorf("%d API calls", n)
			}
		})
	}
}

// resetEnrollFlags forgets the flags of a previous run: cobra keeps values and
// the Changed marker between two Execute calls.
func resetEnrollFlags() {
	jsonOutput = false
	enrollOrg, enrollOutputDir, enrollName, enrollClusterUID = "", "", "", ""
	machineEnrollCmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
}

// --org is sent in lower case: the API answers lower-case UUIDs, so the
// approval compares equal and machine.json is written.
func TestMachineEnrollOrgLowerCased(t *testing.T) {
	var posted atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/machine/enrollments":
			var req struct {
				OrganizationID string         `json:"organization_id"`
				SigningJWK     machinekey.JWK `json:"signing_jwk"`
				AgeRecipient   string         `json:"age_recipient"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			posted.Store(req.OrganizationID)
			fp := machinekey.Fingerprint(req.SigningJWK.Kid, req.AgeRecipient)
			_, _ = w.Write([]byte(`{"enrollment_id":"enr-1","fingerprint":"` + fp +
				`","approval_uri":"https://app.example/approve/enr-1","expires_in":600,"interval":1}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/machine/enrollments/"):
			_, _ = w.Write([]byte(`{"state":"approved","machine_id":"m-1","organization_id":"` +
				testOrgID + `","client_id":"machine-m-1","issuer":"https://kc.example",` +
				`"token_endpoint":"https://kc.example/token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, _, err := runEnroll(t, srv.URL, "--org", strings.ToUpper(testOrgID), "--output-dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := posted.Load().(string); got != testOrgID {
		t.Errorf("posted organization_id = %q, want %q", got, testOrgID)
	}
	if _, err := os.Stat(filepath.Join(dir, "machine.json")); err != nil {
		t.Errorf("machine.json: %v", err)
	}
}
