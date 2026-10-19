package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/pflag"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
)

const testEnrollmentID = "01a0fcf4-0000-7000-8000-000000000001"

// machineAdminServer fakes the management routes. approveDetail, when set,
// makes an approval without the acknowledgement answer 409 with that detail.
type machineAdminServer struct {
	approveDetail string
	// deleteConflict makes DELETE answer 409 (the machine owns datarooms).
	deleteConflict bool

	mu       sync.Mutex
	requests []string
	approve  map[string]any
}

func newMachineAdminServer(t *testing.T, s *machineAdminServer) *httptest.Server {
	t.Helper()
	var base string // the server URL, issuer of the fake login
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/organization/") {
			s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		}
		switch {
		// The user login: RETYC_TOKEN is refreshed through the OIDC provider.
		case r.URL.Path == "/login/config/public":
			_, _ = w.Write([]byte(`{"issuer":"` + base + `","client_id":"device","scopes":["openid"]}`))
		case r.URL.Path == "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"token_endpoint":"` + base + `/token",` +
				`"device_authorization_endpoint":"` + base + `/device"}`))
		case r.URL.Path == "/token":
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":300}`))
		case r.Method == http.MethodGet && r.URL.Path == "/organization/machines/enrollments":
			_, _ = w.Write([]byte(`[{"id":"` + testEnrollmentID + `","display_name":"prod-1",` +
				`"fingerprint":"K7QF-2MXA-PD9R-H3TB","cluster_uid":null,"created_ip":"10.0.0.1",` +
				`"created_at":"2026-10-18T10:00:00Z","expires_at":"2026-10-18T10:15:00Z","replaces_machine_id":null}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/organization/machines":
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/approve"):
			_ = json.NewDecoder(r.Body).Decode(&s.approve)
			if s.approveDetail != "" && s.approve["no_master_key_acknowledged"] != true {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"detail":"` + s.approveDetail + `"}`))

				return
			}
			_, _ = w.Write([]byte(`{"id":"m-1","display_name":"prod-1","fingerprint":"K7QF-2MXA-PD9R-H3TB",` +
				`"cluster_uid":null,"status":"active","created_at":"2026-10-18T10:01:00Z","created_by":"u-1"}`))
		case r.Method == http.MethodDelete && s.deleteConflict:
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":"Machine still owns datarooms"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/deny"),
			r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/organization/machines/"),
			r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/organization/machines/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	base = srv.URL

	return srv
}

// runMachineAdmin runs `machine <args>` as a logged-in user against baseURL
// and returns stdout and the error.
func runMachineAdmin(t *testing.T, baseURL string, args ...string) (string, error) {
	t.Helper()
	isolateConfig(t)
	t.Setenv("RETYC_API_BASE_URL", baseURL)
	t.Setenv("RETYC_API_RETRY_MAX_ATTEMPTS", "1")
	t.Setenv(config.EnvTokenName, "user-token")
	t.Cleanup(func() {
		jsonOutput = false
		for _, c := range machineCmd.Commands() {
			c.Flags().VisitAll(func(f *pflag.Flag) {
				_ = f.Value.Set(f.DefValue)
				f.Changed = false
			})
		}
	})
	var err error
	stdout := captureStream(t, &os.Stdout, func() {
		_ = captureStream(t, &os.Stderr, func() {
			err = run(context.Background(), append([]string{"machine"}, args...))
		})
	})

	return stdout, err
}

func TestMachineApproveChecksFingerprint(t *testing.T) {
	s := &machineAdminServer{}
	srv := newMachineAdminServer(t, s)

	_, err := runMachineAdmin(t, srv.URL, "approve", testEnrollmentID, "--fingerprint", "AAAA-BBBB-CCCC-DDDD")
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("error = %v, want a fingerprint mismatch", err)
	}
	if s.approve != nil {
		t.Error("approved despite the fingerprint mismatch")
	}

	out, err := runMachineAdmin(t, srv.URL, "--json", "approve", testEnrollmentID,
		"--fingerprint", "k7qf-2mxa-pd9r-h3tb")
	if err != nil {
		t.Fatalf("approve error = %v", err)
	}
	if s.approve["display_name"] != "prod-1" || s.approve["no_master_key_acknowledged"] != false {
		t.Errorf("approve body = %v", s.approve)
	}
	var m api.MachineAccount
	if err := json.Unmarshal([]byte(out), &m); err != nil || m.ID != "m-1" || m.Status != api.MachineActive {
		t.Errorf("stdout = %q (%v)", out, err)
	}
}

func TestMachineApproveNoOrganizationKey(t *testing.T) {
	s := &machineAdminServer{
		approveDetail: "Organization has no master key: acknowledge that only you can recover the data",
	}
	srv := newMachineAdminServer(t, s)
	approvals := func() int {
		n := 0
		for _, r := range s.requests {
			if strings.HasSuffix(r, "/approve") {
				n++
			}
		}

		return n
	}

	// --json without --yes: the second confirmation cannot be asked.
	_, err := runMachineAdmin(t, srv.URL, "--json", "approve", testEnrollmentID,
		"--fingerprint", "K7QF-2MXA-PD9R-H3TB")
	if !errors.Is(err, errJSONNeedsYes) || approvals() != 1 {
		t.Fatalf("error = %v after %d approvals, want errJSONNeedsYes after 1", err, approvals())
	}

	// --yes accepts: approved again with the acknowledgement.
	if _, err := runMachineAdmin(t, srv.URL, "approve", testEnrollmentID, "--yes", "--name", "renamed"); err != nil {
		t.Fatalf("approve error = %v", err)
	}
	if approvals() != 3 || s.approve["no_master_key_acknowledged"] != true || s.approve["display_name"] != "renamed" {
		t.Errorf("approvals = %d, last body = %v", approvals(), s.approve)
	}
}

func TestMachineApproveUnknownEnrollment(t *testing.T) {
	srv := newMachineAdminServer(t, &machineAdminServer{})

	_, err := runMachineAdmin(t, srv.URL, "approve", "01a0fcf4-0000-7000-8000-00000000ffff", "--yes")
	if !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestMachineDenyEnableDisable(t *testing.T) {
	s := &machineAdminServer{}
	srv := newMachineAdminServer(t, s)
	const machineID = "01a12b08-bccf-76bd-b768-df26b8c4d777"

	for _, tc := range []struct {
		args   []string
		route  string
		result string
	}{
		{[]string{"deny", testEnrollmentID, "--yes"},
			"POST /organization/machines/enrollments/" + testEnrollmentID + "/deny", "denied"},
		{[]string{"disable", machineID, "--yes"}, "PUT /organization/machines/" + machineID + "/disable", "disabled"},
		{[]string{"enable", machineID, "--yes"}, "PUT /organization/machines/" + machineID + "/enable", "enabled"},
		{[]string{"rm", machineID, "--yes"}, "DELETE /organization/machines/" + machineID, "deleted"},
	} {
		out, err := runMachineAdmin(t, srv.URL, append([]string{"--json"}, tc.args...)...)
		if err != nil {
			t.Fatalf("%v: error = %v", tc.args, err)
		}
		if got := s.requests[len(s.requests)-1]; got != tc.route {
			t.Errorf("%v: last request = %q, want %q", tc.args, got, tc.route)
		}
		var res machineActionJSON
		if err := json.Unmarshal([]byte(out), &res); err != nil || res.Result != tc.result {
			t.Errorf("%v: stdout = %q", tc.args, out)
		}
	}
}

func TestMachineLsEmptyJSON(t *testing.T) {
	srv := newMachineAdminServer(t, &machineAdminServer{})

	out, err := runMachineAdmin(t, srv.URL, "--json", "ls")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &got); err != nil || string(got["items"]) != "[]" {
		t.Errorf("stdout = %q, want an empty items list", out)
	}
}

// A machine account cannot manage machines: configuration error (78), no
// request sent.
func TestMachineAdminRefusedInMachineMode(t *testing.T) {
	s := &machineAdminServer{}
	newMachineAdminServer(t, s)
	isolateConfig(t)
	t.Setenv(config.EnvClientIDName, "machine-1")

	_, err := newMachineAdminClient(context.Background())
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("error = %v, want ErrMachineConfig", err)
	}
	if len(s.requests) != 0 {
		t.Errorf("requests sent: %v", s.requests)
	}
}

func TestMachineRmOwnsDatarooms(t *testing.T) {
	srv := newMachineAdminServer(t, &machineAdminServer{deleteConflict: true})

	_, err := runMachineAdmin(t, srv.URL, "rm", "01a12b08-bccf-76bd-b768-df26b8c4d777", "--yes")
	if !errors.Is(err, api.ErrConflict) || !strings.Contains(err.Error(), "still owns datarooms") ||
		!strings.Contains(err.Error(), "retyc admin dataroom chown") {
		t.Fatalf("error = %v, want the owns-datarooms hint", err)
	}
}
