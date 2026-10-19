package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// createServer fakes the routes of a dataroom creation. createCodes are the
// X-Error-Code of the 409 served in order by POST /dataroom ("" or past the
// end: 201).
type createServer struct {
	t           *testing.T
	userKey     *age.HybridIdentity
	orgKey      *age.HybridIdentity
	createCodes []string
	// saStatus, when set, is the failing status of GET
	// /organization/service-account.
	saStatus int
	// noActiveKey serves `null` as the active key.
	noActiveKey bool

	mu      sync.Mutex
	creates []map[string]any
}

func (s *createServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/user/me/key/active":
		if s.noActiveKey {
			_, _ = w.Write([]byte("null"))

			return
		}
		_ = json.NewEncoder(w).Encode(api.UserKey{ID: "k1", PublicKey: s.userKey.Recipient().String()})
	case r.Method == http.MethodGet && r.URL.Path == "/organization/service-account":
		if s.saStatus != 0 {
			w.WriteHeader(s.saStatus)

			return
		}
		_ = json.NewEncoder(w).Encode(serviceAccountJSON("active", s.orgKey))
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom":
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.t.Errorf("decoding create body: %v", err)
		}
		n := len(s.creates)
		s.creates = append(s.creates, body)
		if n < len(s.createCodes) && s.createCodes[n] != "" {
			w.Header().Set(api.ErrorCodeHeader, s.createCodes[n])
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":"mismatch"}`))

			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.Dataroom{ID: "dr1", Title: "T"})
	default:
		s.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// create runs CreateDataroom against s and returns what it wrote as warnings.
func (s *createServer) create(t *testing.T) (*CreateDataroomResult, string, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)

	var buf bytes.Buffer
	old := warnWriter
	warnWriter = &buf
	t.Cleanup(func() { warnWriter = old })
	res, err := CreateDataroom(context.Background(), nil, client, "T", api.DataroomOptions{}, nil)

	return res, buf.String(), err
}

func machineModeEnv(t *testing.T) {
	t.Helper()
	t.Setenv(config.EnvClientIDName, "client-1")
}

func userModeEnv(t *testing.T) {
	t.Helper()
	t.Setenv(config.EnvClientIDName, "")
	t.Setenv(config.EnvMachineDirName, "")
}

func assertCannotOpen(t *testing.T, body map[string]any, id *age.HybridIdentity) {
	t.Helper()
	enc, _ := body["session_private_key_enc"].(string)
	if _, err := crypto.DecryptToString(enc, id); err == nil {
		t.Error("session private key opens with an identity that is not a recipient")
	}
}

// A machine encrypts for itself and the organization key, and sends no
// recovery key (removed from the API).
func TestCreateDataroomMachineRecipients(t *testing.T) {
	machineModeEnv(t)
	machine, org, other := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	s := &createServer{t: t, userKey: machine, orgKey: org}

	_, warn, err := s.create(t)
	if err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
	if len(s.creates) != 1 {
		t.Fatalf("POST /dataroom calls = %d, want 1", len(s.creates))
	}
	body := s.creates[0]
	if body["master_public_key"] != org.Recipient().String() {
		t.Errorf("master_public_key = %v, want the organization key", body["master_public_key"])
	}
	if _, ok := body["recovery_public_key"]; ok {
		t.Error("recovery_public_key sent")
	}
	assertOpens(t, body, machine, "machine")
	assertOpens(t, body, org, "organization")
	assertCannotOpen(t, body, other)
	if warn != "" {
		t.Errorf("warning = %q, want none", warn)
	}
}

// A machine account does not create a dataroom without the organization key
// because the key could not be read.
func TestCreateDataroomMachineUnreadableOrgKeyFails(t *testing.T) {
	machineModeEnv(t)
	s := &createServer{t: t, userKey: mustKeyPair(t), orgKey: mustKeyPair(t), saStatus: http.StatusInternalServerError}

	_, _, err := s.create(t)
	if err == nil || !strings.Contains(err.Error(), "reading the organization key") {
		t.Fatalf("CreateDataroom() error = %v, want reading the organization key", err)
	}
	if len(s.creates) != 0 {
		t.Errorf("POST /dataroom calls = %d, want 0", len(s.creates))
	}
}

// An organization with no service account (404) has no organization key: a
// machine account still creates the dataroom, and warns that it alone can
// decrypt it.
func TestCreateDataroomMachineNoOrganizationKey(t *testing.T) {
	machineModeEnv(t)
	s := &createServer{t: t, userKey: mustKeyPair(t), saStatus: http.StatusNotFound}

	_, warn, err := s.create(t)
	if err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
	if _, ok := s.creates[0]["master_public_key"]; ok {
		t.Error("master_public_key sent without a service account")
	}
	const want = "warning: the organization has no organization key: only this machine can decrypt the " +
		"dataroom; add members with `retyc dataroom user add`\n"
	if warn != want {
		t.Errorf("warning = %q, want %q", warn, want)
	}
}

// A user creates the dataroom without the organization key when it cannot be
// read, and gets no machine warning.
func TestCreateDataroomUserUnreadableOrgKeyContinues(t *testing.T) {
	userModeEnv(t)
	s := &createServer{t: t, userKey: mustKeyPair(t), orgKey: mustKeyPair(t), saStatus: http.StatusInternalServerError}

	_, warn, err := s.create(t)
	if err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
	if len(s.creates) != 1 || warn != "" {
		t.Errorf("POST /dataroom calls = %d, warning = %q, want 1 and none", len(s.creates), warn)
	}
}

// A machine account with no active key is a configuration error (exit 78).
func TestCreateDataroomMachineNoActiveKey(t *testing.T) {
	machineModeEnv(t)
	s := &createServer{t: t, userKey: mustKeyPair(t), noActiveKey: true}

	_, _, err := s.create(t)
	if !errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "no active key") {
		t.Fatalf("CreateDataroom() error = %v, want ErrMachineConfig", err)
	}
	if len(s.creates) != 0 {
		t.Errorf("POST /dataroom calls = %d, want 0", len(s.creates))
	}
}

// A user with no active key keeps the error that sends to the web interface.
func TestCreateDataroomUserNoActiveKey(t *testing.T) {
	userModeEnv(t)
	s := &createServer{t: t, userKey: mustKeyPair(t), noActiveKey: true}

	_, _, err := s.create(t)
	if err == nil || errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "web interface") {
		t.Fatalf("CreateDataroom() error = %v, want the web interface hint", err)
	}
}

// A machine retries MASTER_KEY_MISMATCH once, as a user does.
func TestCreateDataroomMachineRetryBudget(t *testing.T) {
	machineModeEnv(t)
	s := &createServer{
		t: t, userKey: mustKeyPair(t), orgKey: mustKeyPair(t),
		createCodes: []string{api.CodeMasterKeyMismatch, api.CodeMasterKeyMismatch, ""},
	}

	_, _, err := s.create(t)
	const want = "the organization key changed during the creation, retry"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("CreateDataroom() error = %v, want %q", err, want)
	}
	if api.ErrorCode(err) != api.CodeMasterKeyMismatch {
		t.Errorf("ErrorCode = %q, want the last API error wrapped", api.ErrorCode(err))
	}
	if len(s.creates) != 2 {
		t.Errorf("POST /dataroom calls = %d, want 2", len(s.creates))
	}
}

func TestAddDataroomUserMachineOtherOrg(t *testing.T) {
	err := machineAddUserError(&api.HTTPError{Status: 400, Code: api.CodeMachineOtherOrganization})
	if err == nil || !strings.Contains(err.Error(), "a machine account can only join datarooms of its organization") {
		t.Fatalf("error = %v", err)
	}
	if api.ErrorCode(err) != api.CodeMachineOtherOrganization {
		t.Error("the API error is not wrapped")
	}
	plain := machineAddUserError(&api.HTTPError{Status: 400, Code: "OTHER"})
	if strings.Contains(plain.Error(), "machine account") {
		t.Errorf("unrelated error rewritten: %v", plain)
	}
}
