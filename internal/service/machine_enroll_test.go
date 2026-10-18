package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/machinekey"
)

const testOrg = "11111111-1111-1111-1111-111111111111"

// fakeEnrollAPI is a scripted machine enrollment API. get answers the polls in
// order; the last answer repeats.
type fakeEnrollAPI struct {
	t       *testing.T
	mu      sync.Mutex
	dir     string
	posts   []api.EnrollmentRequest
	gets    int
	postErr func(w http.ResponseWriter) bool
	fpFn    func(api.EnrollmentRequest) string
	get     []func(w http.ResponseWriter)
	srv     *httptest.Server
	opts    []api.Option
}

func newFakeEnrollAPI(t *testing.T, dir string) *fakeEnrollAPI {
	t.Helper()
	f := &fakeEnrollAPI{t: t, dir: dir}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)

	return f
}

func (f *fakeEnrollAPI) client() *api.Client {
	return api.New(f.srv.URL, "test", nil, false, false, f.opts...)
}

func (f *fakeEnrollAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/machine/enrollments":
		var req api.EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.t.Error(err)
		}
		// The keys must be on disk before the API is called.
		for _, n := range []string{"client.key", "age.key"} {
			if _, err := os.Stat(filepath.Join(f.dir, n)); err != nil {
				f.t.Errorf("%s missing at POST time", n)
			}
		}
		f.posts = append(f.posts, req)
		if f.postErr != nil && f.postErr(w) {
			return
		}
		fp := machinekey.Fingerprint(req.SigningJWK.Kid, req.AgeRecipient)
		if f.fpFn != nil {
			fp = f.fpFn(req)
		}
		_ = json.NewEncoder(w).Encode(api.Enrollment{
			EnrollmentID: "enr-" + fmt.Sprint(len(f.posts)), Fingerprint: fp,
			ApprovalURI: "https://app/approve", ExpiresIn: 600, Interval: 5,
		})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/machine/enrollments/"):
		i := f.gets
		if i >= len(f.get) {
			i = len(f.get) - 1
		}
		f.gets++
		f.get[i](w)
	default:
		http.NotFound(w, r)
	}
}

func state(s string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _ = json.NewEncoder(w).Encode(map[string]any{"state": s}) }
}

func approved(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G101: test data
		"state": "approved", "machine_id": "m1", "organization_id": testOrg,
		"client_id": "machine-1",
		"issuer":    "https://idp", "token_endpoint": "https://idp/token",
	})
}

func status(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { http.Error(w, `{"detail":"x"}`, code) }
}

// enrollRun runs Enroll with a fake clock and returns the events.
func enrollRun(t *testing.T, f *fakeEnrollAPI, dir string) ([]EnrollEvent, error) {
	t.Helper()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	var events []EnrollEvent
	err := Enroll(context.Background(), f.client(), EnrollParams{
		OrganizationID: testOrg, Dir: dir, DisplayName: "node",
		Now: func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error {
			now = now.Add(d)

			return nil
		},
	}, func(e EnrollEvent) { events = append(events, e) })

	return events, err
}

func kinds(ev []EnrollEvent) string {
	var k []string
	for _, e := range ev {
		k = append(k, e.Kind)
	}

	return strings.Join(k, ",")
}

func seedKeys(t *testing.T, dir string) (sig, ageKey []byte) {
	t.Helper()
	k, err := machinekey.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, _ = machinekey.MarshalSigningKey(k)
	id, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ageKey = []byte(id.String() + "\n")
	writeFile(t, dir, "client.key", sig)
	writeFile(t, dir, "age.key", ageKey)

	return sig, ageKey
}

func writeFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func seedEnrollment(t *testing.T, dir, org string, exp time.Time) {
	t.Helper()
	b, _ := json.Marshal(config.EnrollmentInfo{Version: 1, EnrollmentID: "old", OrganizationID: org, ExpiresAt: exp})
	writeFile(t, dir, "enrollment.json", b)
}

func TestEnrollFreshDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){state("pending"), approved}
	ev, err := enrollRun(t, f, dir)
	if err != nil {
		t.Fatal(err)
	}
	if kinds(ev) != "pending,approved" {
		t.Errorf("events = %s", kinds(ev))
	}
	if ev[0].Fingerprint == "" || ev[0].ApprovalURI == "" || ev[0].EnrollmentID != "enr-1" {
		t.Errorf("pending = %+v", ev[0])
	}
	if ev[1].MachineID != "m1" || ev[1].ClientID != "machine-1" {
		t.Errorf("approved = %+v", ev[1])
	}
	for _, n := range []string{"client.key", "age.key", "enrollment.json", "machine.json"} {
		fi, err := os.Stat(filepath.Join(dir, n))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", n, err, fi)
		}
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", fi.Mode().Perm())
	}
	ageData, _ := readTestFile(filepath.Join(dir, "age.key"))
	if !strings.HasPrefix(string(ageData), "AGE-SECRET-KEY-PQ-1") ||
		!strings.HasPrefix(f.posts[0].AgeRecipient, "age1pq1") {
		t.Error("age key is not post-quantum")
	}
	mi, err := config.ReadMachineInfo(dir)
	if err != nil || mi.MachineID != "m1" || mi.TokenEndpoint != "https://idp/token" || mi.OrganizationID != testOrg {
		t.Errorf("machine.json = %+v %v", mi, err)
	}
	ei, err := config.ReadEnrollmentInfo(dir)
	start := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if err != nil || ei.EnrollmentID != "enr-1" || ei.ExpiresAt.Sub(start) != 600*time.Second {
		t.Errorf("enrollment.json = %+v %v", ei, err)
	}
}

func TestEnrollReusesKeys(t *testing.T) {
	dir := t.TempDir()
	sig, ageKey := seedKeys(t, dir)
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){approved}
	if _, err := enrollRun(t, f, dir); err != nil {
		t.Fatal(err)
	}
	k, _ := machinekey.ParseSigningKey(sig)
	if f.posts[0].SigningJWK != machinekey.PublicJWK(&k.PublicKey) {
		t.Error("JWK not derived from the existing key")
	}
	s2, _ := readTestFile(filepath.Join(dir, "client.key"))
	a2, _ := readTestFile(filepath.Join(dir, "age.key"))
	if string(s2) != string(sig) || string(a2) != string(ageKey) {
		t.Error("keys were rewritten")
	}
}

func TestEnrollHalfPair(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "age.key", []byte("x\n"))
	f := newFakeEnrollAPI(t, dir)
	_, err := enrollRun(t, f, dir)
	if !errors.Is(err, config.ErrMachineConfig) || len(f.posts)+f.gets != 0 {
		t.Errorf("err = %v", err)
	}
}

func TestEnrollRejectsX25519AgeKey(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	writeFile(t, dir, "age.key", []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQSDLRD3\n"))
	f := newFakeEnrollAPI(t, dir)
	_, err := enrollRun(t, f, dir)
	if !errors.Is(err, config.ErrMachineConfig) || len(f.posts)+f.gets != 0 {
		t.Errorf("err = %v", err)
	}
}

func TestEnrollAlreadyEnrolled(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	b, _ := json.Marshal(config.MachineInfo{Version: 1, MachineID: "m9", OrganizationID: testOrg,
		ClientID: "c9", Issuer: "i", TokenEndpoint: "t"})
	writeFile(t, dir, "machine.json", b)
	f := newFakeEnrollAPI(t, dir)
	ev, err := enrollRun(t, f, dir)
	if err != nil || kinds(ev) != "approved" || ev[0].MachineID != "m9" || ev[0].ClientID != "c9" {
		t.Errorf("ev = %+v err = %v", ev, err)
	}
	if len(f.posts)+f.gets != 0 {
		t.Error("API called")
	}
}

func TestEnrollMachineWithoutKeys(t *testing.T) {
	dir := t.TempDir()
	b, _ := json.Marshal(config.MachineInfo{Version: 1, MachineID: "m9"})
	writeFile(t, dir, "machine.json", b)
	f := newFakeEnrollAPI(t, dir)
	if _, err := enrollRun(t, f, dir); !errors.Is(err, config.ErrMachineConfig) {
		t.Errorf("err = %v", err)
	}
}

func TestEnrollResumeApproved(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	seedEnrollment(t, dir, testOrg, time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC))
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){approved}
	ev, err := enrollRun(t, f, dir)
	if err != nil || kinds(ev) != "approved" || len(f.posts) != 0 {
		t.Errorf("ev = %s err = %v posts = %d", kinds(ev), err, len(f.posts))
	}
	if mi, _ := config.ReadMachineInfo(dir); mi == nil {
		t.Error("machine.json missing")
	}
}

func TestEnrollResumePending(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	exp := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	seedEnrollment(t, dir, testOrg, exp)
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){state("pending"), state("pending"), approved}
	ev, err := enrollRun(t, f, dir)
	if err != nil || kinds(ev) != "pending,approved" || len(f.posts) != 0 {
		t.Fatalf("ev = %s err = %v", kinds(ev), err)
	}
	if ev[0].EnrollmentID != "old" || ev[0].Fingerprint == "" || !ev[0].ExpiresAt.Equal(exp) {
		t.Errorf("pending = %+v", ev[0])
	}
}

func TestEnrollResumeExpired(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	seedEnrollment(t, dir, testOrg, time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC))
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){status(404), approved}
	ev, err := enrollRun(t, f, dir)
	if err != nil || kinds(ev) != "pending,approved" || len(f.posts) != 1 {
		t.Fatalf("ev = %s err = %v posts = %d", kinds(ev), err, len(f.posts))
	}
	ei, _ := config.ReadEnrollmentInfo(dir)
	if ei.EnrollmentID != "enr-1" {
		t.Errorf("enrollment.json not replaced: %+v", ei)
	}
}

func TestEnrollResumeOtherOrg(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	seedEnrollment(t, dir, "22222222-2222-2222-2222-222222222222", time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC))
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){approved}
	if _, err := enrollRun(t, f, dir); err != nil {
		t.Fatal(err)
	}
	if len(f.posts) != 1 {
		t.Errorf("posts = %d", len(f.posts))
	}
}

func TestEnrollDenied(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){state("denied")}
	ev, err := enrollRun(t, f, dir)
	if !errors.Is(err, ErrEnrollmentDenied) || kinds(ev) != "pending,denied" {
		t.Errorf("ev = %s err = %v", kinds(ev), err)
	}
	if mi, _ := config.ReadMachineInfo(dir); mi != nil {
		t.Error("machine.json written")
	}
}

func TestEnrollExpired(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){state("pending"), state("pending"), state("expired")}
	ev, err := enrollRun(t, f, dir)
	if !errors.Is(err, ErrEnrollmentExpired) || kinds(ev) != "pending,expired" {
		t.Errorf("ev = %s err = %v", kinds(ev), err)
	}
}

func TestEnrollLocalDeadline(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){state("pending")}
	ev, err := enrollRun(t, f, dir)
	if !errors.Is(err, ErrEnrollmentExpired) || kinds(ev) != "pending,expired" {
		t.Errorf("ev = %s err = %v", kinds(ev), err)
	}
}

func TestEnrollFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.fpFn = func(api.EnrollmentRequest) string { return "AAAA-AAAA-AAAA-AAAA" }
	ev, err := enrollRun(t, f, dir)
	if !errors.Is(err, ErrFingerprintMismatch) || len(ev) != 0 {
		t.Errorf("ev = %v err = %v", ev, err)
	}
	if ei, _ := config.ReadEnrollmentInfo(dir); ei != nil {
		t.Error("enrollment.json written")
	}
}

func TestEnrollPollTransient(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){status(503), approved}
	ev, err := enrollRun(t, f, dir)
	if err != nil || kinds(ev) != "pending,approved" {
		t.Errorf("ev = %s err = %v", kinds(ev), err)
	}
}

func TestEnrollPollFatal4xx(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){status(400)}
	if _, err := enrollRun(t, f, dir); err == nil || errors.Is(err, ErrEnrollmentExpired) {
		t.Errorf("err = %v", err)
	}
}

func TestEnrollApprovedMalformed(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){state("approved")}
	if _, err := enrollRun(t, f, dir); err == nil {
		t.Error("expected an error")
	}
	if mi, _ := config.ReadMachineInfo(dir); mi != nil {
		t.Error("machine.json written")
	}
}

func TestEnrollPostErrors(t *testing.T) {
	tests := []struct {
		name string
		fn   func(http.ResponseWriter) bool
		is   error
		cfg  bool
	}{
		{"unsupported", func(w http.ResponseWriter) bool {
			http.NotFound(w, nil)

			return true
		}, api.ErrMachineUnsupported, true},
		{"unknown org", func(w http.ResponseWriter) bool {
			http.Error(w, `{"detail":"Unknown organization"}`, 404)

			return true
		}, api.ErrUnknownOrganization, true},
		{"plan 403", func(w http.ResponseWriter) bool {
			http.Error(w, `{"detail":"no"}`, http.StatusForbidden)

			return true
		}, nil, true},
		{"rate limited", func(w http.ResponseWriter) bool {
			http.Error(w, `{}`, http.StatusTooManyRequests)

			return true
		}, api.ErrRateLimited, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeEnrollAPI(t, dir)
			f.postErr = tt.fn
			f.opts = []api.Option{api.WithRetry(time.Second, 1)}
			_, err := enrollRun(t, f, dir)
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, config.ErrMachineConfig) != tt.cfg {
				t.Errorf("ErrMachineConfig match = %v, err = %v", !tt.cfg, err)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("lost %v: %v", tt.is, err)
			}
		})
	}
}

func TestEnrollRequiresParams(t *testing.T) {
	if err := Enroll(context.Background(), nil, EnrollParams{}, func(EnrollEvent) {}); err == nil {
		t.Error("expected an error")
	}
}

func readTestFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: test path
}

func TestEnrollResumePendingThenExpired(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	seedEnrollment(t, dir, testOrg, time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC))
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){state("pending"), state("expired")}
	ev, err := enrollRun(t, f, dir)
	if !errors.Is(err, ErrEnrollmentExpired) || kinds(ev) != "pending,expired" || len(f.posts) != 0 {
		t.Errorf("ev = %s err = %v posts = %d", kinds(ev), err, len(f.posts))
	}
}

func TestEnrollRegeneratedKeysIgnoreStaleEnrollment(t *testing.T) {
	dir := t.TempDir()
	seedEnrollment(t, dir, testOrg, time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC))
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){approved}
	ev, err := enrollRun(t, f, dir)
	if err != nil || len(f.posts) != 1 || kinds(ev) != "pending,approved" {
		t.Fatalf("ev = %s err = %v posts = %d", kinds(ev), err, len(f.posts))
	}
	if ev[0].EnrollmentID != "enr-1" {
		t.Errorf("old request resumed: %+v", ev[0])
	}
}

func TestEnrollMachineOtherOrganization(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	b, _ := json.Marshal(config.MachineInfo{Version: 1, MachineID: "m9",
		OrganizationID: "22222222-2222-2222-2222-222222222222", ClientID: "c9", Issuer: "i", TokenEndpoint: "t"})
	writeFile(t, dir, "machine.json", b)
	f := newFakeEnrollAPI(t, dir)
	ev, err := enrollRun(t, f, dir)
	if !errors.Is(err, config.ErrMachineConfig) || len(ev) != 0 || len(f.posts)+f.gets != 0 {
		t.Errorf("ev = %v err = %v", ev, err)
	}
}

func TestEnrollApprovalOtherOrganization(t *testing.T) {
	dir := t.TempDir()
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G101: test data
			"state": "approved", "machine_id": "m1", "organization_id": "22222222-2222-2222-2222-222222222222",
			"client_id": "machine-1", "issuer": "https://idp", "token_endpoint": "https://idp/token",
		})
	}}
	_, err := enrollRun(t, f, dir)
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Errorf("err = %v", err)
	}
	if mi, _ := config.ReadMachineInfo(dir); mi != nil {
		t.Error("machine.json written")
	}
}

// Organization ids compare case-insensitively: machine.json written with an
// upper-case id still counts as enrolled.
func TestEnrollAlreadyEnrolledCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	b, _ := json.Marshal(config.MachineInfo{Version: 1, MachineID: "m9", OrganizationID: strings.ToUpper(testOrg),
		ClientID: "c9", Issuer: "i", TokenEndpoint: "t"})
	writeFile(t, dir, "machine.json", b)
	f := newFakeEnrollAPI(t, dir)
	ev, err := enrollRun(t, f, dir)
	if err != nil || kinds(ev) != "approved" || ev[0].MachineID != "m9" {
		t.Errorf("ev = %+v err = %v", ev, err)
	}
	if len(f.posts)+f.gets != 0 {
		t.Error("API called")
	}
}

// A pending request saved with an upper-case organization id is resumed.
func TestEnrollResumeCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	seedKeys(t, dir)
	seedEnrollment(t, dir, strings.ToUpper(testOrg), time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC))
	f := newFakeEnrollAPI(t, dir)
	f.get = []func(http.ResponseWriter){approved}
	if _, err := enrollRun(t, f, dir); err != nil {
		t.Fatal(err)
	}
	if len(f.posts) != 0 {
		t.Errorf("%d POSTs, want a resume", len(f.posts))
	}
}

// When age.key cannot be written, the client.key written just before is
// removed. A dangling symlink named age.key counts as absent for the
// existence check but is refused by the writer.
func TestGenerateMachineKeysRemovesSigningKeyOnFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "age.key")); err != nil {
		t.Skip(err)
	}
	if _, _, _, err := loadOrCreateMachineKeys(dir); err == nil {
		t.Fatal("want an error")
	}
	if _, err := os.Stat(filepath.Join(dir, "client.key")); !os.IsNotExist(err) {
		t.Errorf("client.key left behind: %v", err)
	}
}
