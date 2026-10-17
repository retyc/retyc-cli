package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"golang.org/x/oauth2"
)

// orgKeyServer fakes the routes a dataroom creation goes through. serviceAccounts
// is served in order by GET /organization/service-account (the last one
// repeated); a nil entry answers JSON null, an int entry that status. saStatus,
// when set, is answered to every call.
// createCodes are the X-Error-Code of a 409 served in order by POST /dataroom
// ("" or past the end: 201).
type orgKeyServer struct {
	t               *testing.T
	userKey         *age.HybridIdentity
	serviceAccounts []any
	saStatus        int
	createCodes     []string

	mu      sync.Mutex
	saCalls int
	creates []map[string]any
}

func (s *orgKeyServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/user/me/key/active":
		_ = json.NewEncoder(w).Encode(api.UserKey{ID: "k1", PublicKey: s.userKey.Recipient().String()})
	case r.Method == http.MethodGet && r.URL.Path == "/organization/service-account":
		if s.saStatus != 0 {
			w.WriteHeader(s.saStatus)

			return
		}
		sa := s.serviceAccounts[min(s.saCalls, len(s.serviceAccounts)-1)]
		s.saCalls++
		if status, ok := sa.(int); ok {
			w.WriteHeader(status)

			return
		}
		_ = json.NewEncoder(w).Encode(sa)
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
			_, _ = w.Write([]byte(`{"detail":"Organization master key mismatch: refresh it and retry"}`))

			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.Dataroom{ID: "dr1", Title: "T"})
	default:
		s.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func newOrgKeyClient(t *testing.T, s *orgKeyServer) *api.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)

	return api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)
}

func createTestDataroom(t *testing.T, s *orgKeyServer) (*CreateDataroomResult, error) {
	t.Helper()

	return CreateDataroom(context.Background(), nil, newOrgKeyClient(t, s), "T", api.DataroomOptions{}, nil)
}

func mustKeyPair(t *testing.T) *age.HybridIdentity {
	t.Helper()
	k, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func serviceAccountJSON(status string, key *age.HybridIdentity) map[string]any {
	sa := map[string]any{
		"id": "sa1", "email": "sa-account-1@org.ryc", "full_name": nil,
		"status": status, "created_at": "2026-10-01T00:00:00Z", "public_key": nil,
	}
	if key != nil {
		sa["public_key"] = key.Recipient().String()
	}

	return sa
}

// assertOpens checks that the session private key sent in body opens with id.
func assertOpens(t *testing.T, body map[string]any, id *age.HybridIdentity, who string) {
	t.Helper()
	enc, _ := body["session_private_key_enc"].(string)
	if _, err := crypto.DecryptToString(enc, id); err != nil {
		t.Errorf("session private key does not open with the %s key: %v", who, err)
	}
}

// The organization key is a recipient of the session key and is announced in
// master_public_key, as the web app does.
func TestCreateDataroom_EncryptsForOrganizationKey(t *testing.T) {
	userKey, orgKey := mustKeyPair(t), mustKeyPair(t)
	s := &orgKeyServer{t: t, userKey: userKey, serviceAccounts: []any{serviceAccountJSON("active", orgKey)}}

	if _, err := createTestDataroom(t, s); err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
	if len(s.creates) != 1 {
		t.Fatalf("POST /dataroom calls = %d, want 1", len(s.creates))
	}
	body := s.creates[0]
	if got := body["master_public_key"]; got != orgKey.Recipient().String() {
		t.Errorf("master_public_key = %v, want the organization key", got)
	}
	assertOpens(t, body, userKey, "user")
	assertOpens(t, body, orgKey, "organization")
}

// A 409 MASTER_KEY_MISMATCH (the key changed between read and write) re-reads
// the key and retries once with a fresh encryption.
func TestCreateDataroom_MasterKeyMismatchRetriesOnce(t *testing.T) {
	userKey, oldKey, newKey := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	s := &orgKeyServer{
		t: t, userKey: userKey,
		serviceAccounts: []any{serviceAccountJSON("active", oldKey), serviceAccountJSON("active", newKey)},
		createCodes:     []string{api.CodeMasterKeyMismatch},
	}

	if _, err := createTestDataroom(t, s); err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
	if len(s.creates) != 2 {
		t.Fatalf("POST /dataroom calls = %d, want 2", len(s.creates))
	}
	retry := s.creates[1]
	if got := retry["master_public_key"]; got != newKey.Recipient().String() {
		t.Errorf("retry master_public_key = %v, want the new organization key", got)
	}
	assertOpens(t, retry, newKey, "new organization")
	assertOpens(t, retry, userKey, "user")
}

// A retry whose second read of the key fails creates the dataroom without it.
func TestCreateDataroom_MasterKeyMismatchThenUnreadableKey(t *testing.T) {
	userKey, orgKey := mustKeyPair(t), mustKeyPair(t)
	s := &orgKeyServer{
		t: t, userKey: userKey,
		serviceAccounts: []any{serviceAccountJSON("active", orgKey), http.StatusInternalServerError},
		createCodes:     []string{api.CodeMasterKeyMismatch},
	}

	if _, err := createTestDataroom(t, s); err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
	if len(s.creates) != 2 {
		t.Fatalf("POST /dataroom calls = %d, want 2", len(s.creates))
	}
	if _, ok := s.creates[1]["master_public_key"]; ok {
		t.Error("retry sent master_public_key although the key could not be read")
	}
	assertOpens(t, s.creates[1], userKey, "user")
}

// A second mismatch is not retried again.
func TestCreateDataroom_MasterKeyMismatchTwiceFails(t *testing.T) {
	userKey, orgKey := mustKeyPair(t), mustKeyPair(t)
	s := &orgKeyServer{
		t: t, userKey: userKey, serviceAccounts: []any{serviceAccountJSON("active", orgKey)},
		createCodes: []string{api.CodeMasterKeyMismatch, api.CodeMasterKeyMismatch},
	}

	_, err := createTestDataroom(t, s)
	if api.ErrorCode(err) != api.CodeMasterKeyMismatch {
		t.Fatalf("CreateDataroom() error = %v, want MASTER_KEY_MISMATCH", err)
	}
	if len(s.creates) != 2 {
		t.Errorf("POST /dataroom calls = %d, want 2", len(s.creates))
	}
}

// Without a usable organization key the dataroom is created for the user
// only, and master_public_key is not sent.
func TestCreateDataroom_NoUsableOrganizationKey(t *testing.T) {
	tests := []struct {
		name     string
		sa       any
		saStatus int
	}{
		{name: "no service account", sa: nil},
		{name: "disabled service account", sa: serviceAccountJSON("disabled", mustKeyPair(t))},
		{name: "service account without key", sa: serviceAccountJSON("active", nil)},
		{name: "route unknown", saStatus: http.StatusNotFound},
		{name: "route failing", saStatus: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userKey := mustKeyPair(t)
			s := &orgKeyServer{t: t, userKey: userKey, serviceAccounts: []any{tt.sa}, saStatus: tt.saStatus}

			if _, err := createTestDataroom(t, s); err != nil {
				t.Fatalf("CreateDataroom() error = %v", err)
			}
			if len(s.creates) != 1 {
				t.Fatalf("POST /dataroom calls = %d, want 1", len(s.creates))
			}
			if _, ok := s.creates[0]["master_public_key"]; ok {
				t.Error("master_public_key sent without a usable organization key")
			}
			assertOpens(t, s.creates[0], userKey, "user")
		})
	}
}

// POST /share adds the organization key to public_keys: it is not a
// recipient, and must not count as one when deciding whether every recipient
// can open the transfer with their own key.
func TestRecipientsAllHaveKeys(t *testing.T) {
	emails := []string{"a@x", "b@x"}
	tests := []struct {
		name       string
		emails     []string
		publicKeys []string
		orgKey     string
		orgKnown   bool
		want       bool
	}{
		{
			name: "no organization key, all keyed", emails: emails,
			publicKeys: []string{"ka", "kb"}, orgKnown: true, want: true,
		},
		{
			name: "no organization key, one missing", emails: emails,
			publicKeys: []string{"ka"}, orgKnown: true, want: false,
		},
		{
			name: "organization key, all keyed", emails: emails,
			publicKeys: []string{"ka", "kb", "org"}, orgKey: "org", orgKnown: true, want: true,
		},
		{
			name: "organization key, one missing", emails: emails,
			publicKeys: []string{"ka", "org"}, orgKey: "org", orgKnown: true, want: false,
		},
		{
			name: "no recipients", emails: nil,
			publicKeys: []string{"org"}, orgKey: "org", orgKnown: true, want: false,
		},
		{
			name: "organization key unknown", emails: emails,
			publicKeys: []string{"ka", "org"}, orgKnown: false, want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := recipientsAllHaveKeys(tt.emails, tt.publicKeys, tt.orgKey, tt.orgKnown); got != tt.want {
				t.Errorf("recipientsAllHaveKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}

// transferServer fakes the routes of SendTransfer. sa is served by
// GET /organization/service-account like orgKeyServer.serviceAccounts[0];
// publicKeys is the public_keys POST /share answers.
type transferServer struct {
	t          *testing.T
	userKey    *age.HybridIdentity
	sa         any
	publicKeys []string

	mu       sync.Mutex
	shares   int
	complete map[string]any
	deleted  bool
}

func (s *transferServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/user/me/key/active":
		_ = json.NewEncoder(w).Encode(api.UserKey{ID: "k1", PublicKey: s.userKey.Recipient().String()})
	case r.Method == http.MethodGet && r.URL.Path == "/organization/service-account":
		if status, ok := s.sa.(int); ok {
			w.WriteHeader(status)

			return
		}
		_ = json.NewEncoder(w).Encode(s.sa)
	case r.Method == http.MethodPost && r.URL.Path == "/share":
		s.shares++
		_ = json.NewEncoder(w).Encode(api.ShareCreateResponse{ID: "sh1", PublicKeys: s.publicKeys})
	case r.Method == http.MethodPost && r.URL.Path == "/share/sh1/file":
		_ = json.NewEncoder(w).Encode(api.FileModel{ID: "f1", ChunkCount: 1})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/file/f1/"):
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut && r.URL.Path == "/share/sh1/complete":
		if err := json.NewDecoder(r.Body).Decode(&s.complete); err != nil {
			s.t.Errorf("decoding complete body: %v", err)
		}
	case r.Method == http.MethodGet && r.URL.Path == "/share/sh1/details":
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "sh1"})
	case r.Method == http.MethodDelete && r.URL.Path == "/share/sh1/force":
		s.deleted = true
		w.WriteHeader(http.StatusNoContent)
	default:
		s.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func sendTestTransfer(t *testing.T, s *transferServer, emails []string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)
	file := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := SendTransfer(context.Background(), nil, client,
		SendTransferParams{FilePaths: []string{file}, ToEmails: emails, ExpireSecs: 3600}, nil, nil)

	return err
}

// Every recipient has a key and the organization key is in public_keys: the
// transfer is sent without a passphrase and opens with the organization key.
func TestSendTransfer_OrganizationKeyIsNotARecipient(t *testing.T) {
	userKey, recipient, orgKey := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	s := &transferServer{
		t: t, userKey: userKey, sa: serviceAccountJSON("active", orgKey),
		publicKeys: []string{recipient.Recipient().String(), orgKey.Recipient().String()},
	}

	if err := sendTestTransfer(t, s, []string{"a@x"}); err != nil {
		t.Fatalf("SendTransfer() error = %v", err)
	}
	if _, ok := s.complete["session_private_key_enc_for_passphrase"]; ok {
		t.Error("a passphrase path was added although every recipient has a key")
	}
	for who, id := range map[string]*age.HybridIdentity{"user": userKey, "recipient": recipient, "organization": orgKey} {
		assertOpens(t, s.complete, id, who)
	}
}

// A recipient without a key, the organization key in public_keys: the
// passphrase is required, and the share created is cleaned up.
func TestSendTransfer_RecipientWithoutKeyNeedsPassphrase(t *testing.T) {
	userKey, orgKey := mustKeyPair(t), mustKeyPair(t)
	s := &transferServer{
		t: t, userKey: userKey, sa: serviceAccountJSON("active", orgKey),
		publicKeys: []string{orgKey.Recipient().String()},
	}

	err := sendTestTransfer(t, s, []string{"a@x"})
	if err == nil || !strings.Contains(err.Error(), "passphrase required") {
		t.Fatalf("SendTransfer() error = %v, want passphrase required", err)
	}
	if !s.deleted {
		t.Error("the pending share was not cleaned up")
	}
}

// An API without the route (404) keeps the former count.
func TestSendTransfer_OldAPIWithoutServiceAccountRoute(t *testing.T) {
	userKey, recipient := mustKeyPair(t), mustKeyPair(t)
	s := &transferServer{
		t: t, userKey: userKey, sa: http.StatusNotFound,
		publicKeys: []string{recipient.Recipient().String()},
	}

	if err := sendTestTransfer(t, s, []string{"a@x"}); err != nil {
		t.Fatalf("SendTransfer() error = %v", err)
	}
	assertOpens(t, s.complete, recipient, "recipient")
}

// The organization key cannot be read and no passphrase is given: the
// command fails before creating anything.
func TestSendTransfer_UnreadableOrganizationKeyFailsEarly(t *testing.T) {
	s := &transferServer{t: t, userKey: mustKeyPair(t), sa: http.StatusInternalServerError}

	err := sendTestTransfer(t, s, []string{"a@x"})
	if err == nil || !strings.Contains(err.Error(), "organization key") {
		t.Fatalf("SendTransfer() error = %v, want an organization key error", err)
	}
	if s.shares != 0 {
		t.Errorf("POST /share calls = %d, want 0", s.shares)
	}
}
