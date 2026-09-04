package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/retyc/retyc-cli/internal/crypto"
)

// userRmFixture serves the minimal admin API used by AdminRemoveDataroomUser:
// the dataroom (session key encrypted for sessionRecipients), its user list,
// the member removal endpoint and the rekey endpoint.
type userRmFixture struct {
	srv      *httptest.Server
	deletes  atomic.Int32
	rekeyed  atomic.Int32
	lastBlob string
}

func newUserRmFixture(
	t *testing.T, sessionPrivKey string, sessionRecipients []string, memberPub string,
) *userRmFixture {
	t.Helper()
	f := &userRmFixture{}
	enc, err := crypto.EncryptStringForKeys(sessionPrivKey, sessionRecipients)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dataroom/dr1", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "dr1", "session_private_key_enc": enc, "session_public_key": "age1pq1unused",
		})
	})
	mux.HandleFunc("GET /dataroom/dr1/users", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"user_id": "u1", "email": "member@x.co", "public_key": memberPub},
		})
	})
	mux.HandleFunc("DELETE /dataroom/dr1/user/u2", func(w http.ResponseWriter, _ *http.Request) {
		f.deletes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /dataroom/dr1/rekey", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastBlob = body["session_private_key_enc"]
		f.rekeyed.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	return f
}

func TestAdminRemoveDataroomUser_RefusesBeforeDeleteWhenOrgKeyHasNoAccess(t *testing.T) {
	orgKey, _ := crypto.GenerateKeyPair()
	other, _ := crypto.GenerateKeyPair()
	member, _ := crypto.GenerateKeyPair()
	sessKey, _ := crypto.GenerateKeyPair()

	// Session key encrypted for someone else only: the organization key cannot open it.
	f := newUserRmFixture(t, sessKey.String(), []string{other.Recipient().String()}, member.Recipient().String())

	_, err := AdminRemoveDataroomUser(t.Context(), newExportTestClient(f.srv), orgKey, "dr1", "u2")
	if !errors.Is(err, ErrOrgKeyNoAccess) {
		t.Fatalf("error = %v, want ErrOrgKeyNoAccess", err)
	}
	if n := f.deletes.Load(); n != 0 {
		t.Errorf("DELETE called %d time(s) before the access check, want 0", n)
	}
	if n := f.rekeyed.Load(); n != 0 {
		t.Errorf("rekey called %d time(s), want 0", n)
	}
}

func TestAdminRemoveDataroomUser_RemovesThenRekeys(t *testing.T) {
	orgKey, _ := crypto.GenerateKeyPair()
	member, _ := crypto.GenerateKeyPair()
	sessKey, _ := crypto.GenerateKeyPair()

	f := newUserRmFixture(t, sessKey.String(), []string{orgKey.Recipient().String()}, member.Recipient().String())

	res, err := AdminRemoveDataroomUser(t.Context(), newExportTestClient(f.srv), orgKey, "dr1", "u2")
	if err != nil {
		t.Fatalf("AdminRemoveDataroomUser() error = %v", err)
	}
	if f.deletes.Load() != 1 || f.rekeyed.Load() != 1 {
		t.Fatalf("deletes=%d rekeys=%d, want 1 and 1", f.deletes.Load(), f.rekeyed.Load())
	}
	if res.Reencrypted != 2 {
		t.Errorf("Reencrypted = %d, want 2 (member + organization key)", res.Reencrypted)
	}
	got, err := crypto.DecryptToString(f.lastBlob, orgKey)
	if err != nil || got != sessKey.String() {
		t.Fatalf("pushed blob not decryptable by the organization key: %v", err)
	}
}
