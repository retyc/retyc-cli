package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

const testPassphrase = "correct horse battery staple"

// cheapPassphraseEnc encrypts an identity with a low scrypt work factor, so
// fixtures stay fast; decryption accepts any work factor up to the default.
func cheapPassphraseEnc(t *testing.T, id *age.HybridIdentity, passphrase string) string {
	t.Helper()
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(10)
	out, err := crypto.Encrypt([]byte(id.String()), r)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// userKeyServer is a stateful fake of the user key routes on top of rekeyServer.
type userKeyServer struct {
	*rekeyServer

	mu        sync.Mutex
	keys      []api.UserKeyInfo
	posts     []map[string]string
	deletes   []string
	conflict  func(s *userKeyServer) // when set, POST answers 409 after calling it
	orgStatus int
	orgPub    string
}

func newUserKeyServer(t *testing.T, keys ...api.UserKeyInfo) *userKeyServer {
	t.Helper()
	s := &userKeyServer{rekeyServer: newRekeyServer(t), keys: keys, orgStatus: http.StatusOK}
	s.handlers["/organization/service-account"] = func(w http.ResponseWriter, _ *http.Request) {
		if s.orgStatus != http.StatusOK {
			w.WriteHeader(s.orgStatus)
			_, _ = w.Write([]byte(`{"detail":"boom"}`))

			return
		}
		pub := "null"
		if s.orgPub != "" {
			pub = `"` + s.orgPub + `"`
		}
		_, _ = w.Write([]byte(saBody(pub)))
	}
	s.handlers["/user/me/keys/all"] = func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(s.keys)
	}
	s.handlers["/user/me/keys"] = func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.posts = append(s.posts, body)
		if s.conflict != nil {
			s.conflict(s)
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":"Key rotation already in progress"}`))

			return
		}
		s.addKeyLocked("new", body["public_key"], body["private_key_enc"])
		_, _ = w.Write([]byte(`{}`))
	}
	// Keys added while serving get their DELETE route now: handlers is not
	// guarded and must not change once requests flow.
	for _, id := range []string{"new", "other"} {
		s.handlers["/user/me/key/"+id] = s.deleteHandler(id)
	}
	s.handlers["/dataroom/pending-rekey"] = jsonHandler([]api.PendingRekeyDataroom{})
	transferFixture(s.rekeyServer, [][]api.Transfer{{}}, nil)

	return s
}

// addKeyLocked turns the active key into pending and appends a new active one.
func (s *userKeyServer) addKeyLocked(id, pub, enc string) {
	for i := range s.keys {
		if s.keys[i].Status == api.UserKeyActive {
			s.keys[i].Status = api.UserKeyPending
		}
	}
	s.keys = append([]api.UserKeyInfo{{ID: id, PublicKey: pub, PrivateKeyEnc: &enc, Status: api.UserKeyActive}},
		s.keys...)
}

func (s *userKeyServer) deleteHandler(id string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.deletes = append(s.deletes, id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *userKeyServer) writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rekeyServer.mu.Lock()
	defer s.rekeyServer.mu.Unlock()

	return len(s.posts) + len(s.deletes) + len(s.puts)
}

// userKey builds a key fixture encrypted with passphrase and registers its
// DELETE route on s.
func (s *userKeyServer) userKey(t *testing.T, id string, status api.UserKeyStatus, ident *age.HybridIdentity,
	passphrase string,
) {
	t.Helper()
	enc := cheapPassphraseEnc(t, ident, passphrase)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, api.UserKeyInfo{
		ID: id, PublicKey: ident.Recipient().String(), PrivateKeyEnc: &enc, Status: status,
	})
	s.handlers["/user/me/key/"+id] = s.deleteHandler(id)
}

func reader(p string) PassphraseReader { return func() (string, error) { return p, nil } }

// stubKeyringClear keeps the tests away from the developer's session keyring
// and counts the calls.
func stubKeyringClear(t *testing.T) *int {
	t.Helper()
	n := 0
	prev := clearKeyring
	clearKeyring = func() error {
		n++

		return nil
	}
	t.Cleanup(func() { clearKeyring = prev })

	return &n
}

// withPendingDataroom serves one pending-rekey dataroom encrypted for holder.
func (s *userKeyServer) withPendingDataroom(t *testing.T, holder *age.HybridIdentity) {
	t.Helper()
	s.handlers["/dataroom/pending-rekey"] = jsonHandler([]api.PendingRekeyDataroom{{
		DataroomID:           "d1",
		PublicKey:            holder.Recipient().String(),
		SessionPrivateKeyEnc: enc(t, "SESSION", holder.Recipient().String()),
		UserPublicKeys:       []string{holder.Recipient().String()},
	}})
}

func TestRotateUserKey_Full(t *testing.T) {
	cleared := stubKeyringClear(t)
	old, org := genKey(t), genKey(t)
	s := newUserKeyServer(t)
	s.orgPub = org.Recipient().String()
	s.userKey(t, "old", api.UserKeyActive, old, testPassphrase)
	s.withPendingDataroom(t, old)
	transferFixture(s.rekeyServer, [][]api.Transfer{{{ID: "t1", Status: "active"}}}, func(string) api.TransferDetails {
		return api.TransferDetails{SessionPrivateKeyEnc: ptr(enc(t, "S", old.Recipient().String()))}
	})

	var msgs []string
	res, err := RotateUserKey(context.Background(), s.client(), reader(testPassphrase),
		func(m string) { msgs = append(msgs, m) })
	if err != nil {
		t.Fatalf("RotateUserKey: %v", err)
	}

	if len(s.posts) != 1 {
		t.Fatalf("POSTs = %d, want 1", len(s.posts))
	}
	pub := s.posts[0]["public_key"]
	if !strings.HasPrefix(pub, "age1pq1") {
		t.Errorf("public_key = %q", pub)
	}
	plain, err := crypto.DecryptToStringWithPassphrase(s.posts[0]["private_key_enc"], testPassphrase)
	if err != nil {
		t.Fatalf("private_key_enc does not open with the passphrase: %v", err)
	}
	newID, err := crypto.ParseIdentity(plain)
	if err != nil || newID.Recipient().String() != pub {
		t.Fatalf("private_key_enc does not hold the key of public_key (%v)", err)
	}

	if res.Resumed || res.OldKeyKept || res.Machine {
		t.Errorf("result = %+v", res)
	}
	if res.KeyID != "new" || res.PublicKey != pub {
		t.Errorf("KeyID/PublicKey = %q/%q", res.KeyID, res.PublicKey)
	}
	if res.Datarooms.Rekeyed != 1 || res.Transfers.Rekeyed != 1 {
		t.Errorf("rekeys = %+v / %+v", res.Datarooms, res.Transfers)
	}
	if blob := s.puts["/share/t1/rekey"]; blob == "" {
		t.Error("no transfer rekey")
	} else if got, err := crypto.DecryptToString(blob, newID); err != nil || got != "S" {
		t.Errorf("new key cannot open the transfer: %v", err)
	} else if _, err := crypto.DecryptToString(blob, org); err != nil {
		t.Errorf("organization key cannot open the transfer: %v", err)
	}
	if len(s.deletes) != 1 || s.deletes[0] != "old" || len(res.Revoked) != 1 || res.Revoked[0] != "old" {
		t.Errorf("deletes = %v, revoked = %v", s.deletes, res.Revoked)
	}
	if *cleared != 1 {
		t.Errorf("keyring cleared %d times, want 1", *cleared)
	}
	for _, m := range msgs {
		if strings.Contains(m, "age1") || strings.Contains(m, "AGE-SECRET") {
			t.Errorf("progress leaks a key: %q", m)
		}
	}
}

func TestRotateUserKey_ResumesPending(t *testing.T) {
	cleared := stubKeyringClear(t)
	old, nw := genKey(t), genKey(t)
	s := newUserKeyServer(t)
	s.userKey(t, "new", api.UserKeyActive, nw, testPassphrase)
	s.userKey(t, "old", api.UserKeyPending, old, testPassphrase)
	s.withPendingDataroom(t, old)

	res, err := RotateUserKey(context.Background(), s.client(), reader(testPassphrase), func(string) {})
	if err != nil {
		t.Fatalf("RotateUserKey: %v", err)
	}
	if len(s.posts) != 0 {
		t.Errorf("unexpected POST: %v", s.posts)
	}
	if !res.Resumed || res.KeyID != "new" || res.Datarooms.Rekeyed != 1 {
		t.Errorf("result = %+v", res)
	}
	if len(s.deletes) != 1 || s.deletes[0] != "old" {
		t.Errorf("deletes = %v", s.deletes)
	}
	if *cleared != 1 {
		t.Errorf("keyring cleared %d times, want 1", *cleared)
	}
}

func TestRotateUserKey_ConflictResumes(t *testing.T) {
	stubKeyringClear(t)
	old, other := genKey(t), genKey(t)
	s := newUserKeyServer(t)
	s.userKey(t, "old", api.UserKeyActive, old, testPassphrase)
	otherEnc := cheapPassphraseEnc(t, other, testPassphrase)
	// Another process wins the race: its key is registered, ours is refused.
	s.conflict = func(s *userKeyServer) {
		s.addKeyLocked("other", other.Recipient().String(), otherEnc)
	}

	res, err := RotateUserKey(context.Background(), s.client(), reader(testPassphrase), func(string) {})
	if err != nil {
		t.Fatalf("RotateUserKey: %v", err)
	}
	if !res.Resumed || res.KeyID != "other" || res.PublicKey != other.Recipient().String() {
		t.Errorf("result = %+v", res)
	}
	if len(s.deletes) != 1 || s.deletes[0] != "old" {
		t.Errorf("deletes = %v", s.deletes)
	}
}

func TestRotateUserKey_FailureKeepsOldKey(t *testing.T) {
	cleared := stubKeyringClear(t)
	old := genKey(t)
	s := newUserKeyServer(t)
	s.userKey(t, "old", api.UserKeyActive, old, testPassphrase)
	s.withPendingDataroom(t, old)
	s.failPUT = true

	res, err := RotateUserKey(context.Background(), s.client(), reader(testPassphrase), func(string) {})
	if !errors.Is(err, ErrKeyRotationIncomplete) {
		t.Fatalf("error = %v, want ErrKeyRotationIncomplete", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if !res.OldKeyKept || len(res.Datarooms.Failed) != 1 || len(res.Revoked) != 0 {
		t.Errorf("result = %+v", res)
	}
	if len(s.deletes) != 0 {
		t.Errorf("unexpected DELETE: %v", s.deletes)
	}
	if *cleared != 1 {
		t.Errorf("keyring cleared %d times, want 1 (a key was created)", *cleared)
	}
}

func TestRotateUserKey_RevokeFailureIsIncomplete(t *testing.T) {
	stubKeyringClear(t)
	old := genKey(t)
	s := newUserKeyServer(t)
	s.userKey(t, "old", api.UserKeyActive, old, testPassphrase)
	s.handlers["/user/me/key/old"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}

	res, err := RotateUserKey(context.Background(), s.client(), reader(testPassphrase), func(string) {})
	if !errors.Is(err, ErrKeyRotationIncomplete) {
		t.Fatalf("error = %v, want ErrKeyRotationIncomplete", err)
	}
	var httpErr *api.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusInternalServerError {
		t.Errorf("the API error is not in the chain: %v", err)
	}
	if res == nil || !res.OldKeyKept || len(res.Revoked) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestRotateUserKey_WrongPassphrase(t *testing.T) {
	stubKeyringClear(t)
	old := genKey(t)
	s := newUserKeyServer(t)
	s.userKey(t, "old", api.UserKeyActive, old, testPassphrase)

	_, err := RotateUserKey(context.Background(), s.client(), reader("wrong"), func(string) {})
	if !errors.Is(err, ErrWrongKeyPassphrase) {
		t.Fatalf("error = %v, want ErrWrongKeyPassphrase", err)
	}
	if n := s.writes(); n != 0 {
		t.Errorf("%d writes, want none", n)
	}
}

func TestRotateUserKey_PendingOtherPassphrase(t *testing.T) {
	cleared := stubKeyringClear(t)
	old, nw := genKey(t), genKey(t)
	s := newUserKeyServer(t)
	s.userKey(t, "new", api.UserKeyActive, nw, testPassphrase)
	s.userKey(t, "old", api.UserKeyPending, old, "another passphrase")
	s.withPendingDataroom(t, old)

	_, err := RotateUserKey(context.Background(), s.client(), reader(testPassphrase), func(string) {})
	if !errors.Is(err, ErrWrongKeyPassphrase) || !strings.Contains(err.Error(), "key old does not open") {
		t.Fatalf("error = %v", err)
	}
	if n := s.writes(); n != 0 {
		t.Errorf("%d writes, want none", n)
	}
	if *cleared != 0 {
		t.Errorf("keyring cleared %d times, want 0", *cleared)
	}
}

func TestRotateUserKey_OrgKeyReadFails(t *testing.T) {
	stubKeyringClear(t)
	old := genKey(t)
	s := newUserKeyServer(t)
	s.userKey(t, "old", api.UserKeyActive, old, testPassphrase)
	s.orgStatus = http.StatusInternalServerError

	if _, err := RotateUserKey(context.Background(), s.client(), reader(testPassphrase), func(string) {}); err == nil {
		t.Fatal("no error")
	}
	if n := s.writes(); n != 0 {
		t.Errorf("%d writes, want none", n)
	}
}
