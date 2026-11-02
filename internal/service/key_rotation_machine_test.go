package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/machinekey"
)

const testMachineClientID = "machine-42"

// machineDataroom is a dataroom link of the fake server: blob is encrypted
// for pub.
type machineDataroom struct {
	pub, blob string
}

// machineRotationServer fakes the routes used by RotateMachineKey: active key,
// rotation (signature checked), pending rekeys and their PUTs.
type machineRotationServer struct {
	t   *testing.T
	sig *ecdsa.PublicKey
	org *age.HybridIdentity
	now time.Time

	mu         sync.Mutex
	active     string
	posted     []string // age_recipient of each POST /machine/me/key
	postStatus int      // 0 = accept
	postDetail string
	// activateOnRefusal applies the rotation before answering postStatus.
	activateOnRefusal bool
	failPUT           bool
	datarooms         map[string]*machineDataroom

	srv *httptest.Server
}

func newMachineRotationServer(t *testing.T, sig *ecdsa.PublicKey, active string) *machineRotationServer {
	t.Helper()
	ms := &machineRotationServer{
		t: t, sig: sig, org: genKey(t), now: time.Unix(1_800_000_000, 0),
		active: active, datarooms: map[string]*machineDataroom{},
	}
	ms.srv = httptest.NewServer(http.HandlerFunc(ms.serve))
	t.Cleanup(ms.srv.Close)

	return ms
}

func (ms *machineRotationServer) client() *api.Client { return newRotationTestClient(ms.srv) }

func (ms *machineRotationServer) fail(w http.ResponseWriter, status int, detail string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

func (ms *machineRotationServer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ms.mu.Lock()
	defer ms.mu.Unlock()

	switch {
	case r.URL.Path == "/organization/service-account":
		_, _ = w.Write([]byte(saBody(`"` + ms.org.Recipient().String() + `"`)))
	case r.URL.Path == "/user/me/key/active":
		_ = json.NewEncoder(w).Encode(api.UserKey{ID: "k-" + ms.active[len(ms.active)-6:], PublicKey: ms.active})
	case r.URL.Path == "/machine/me/key" && r.Method == http.MethodPost:
		ms.rotate(w, r)
	case r.URL.Path == "/dataroom/pending-rekey":
		out := []api.PendingRekeyDataroom{}
		for id, d := range ms.datarooms {
			if d.pub != ms.active {
				out = append(out, api.PendingRekeyDataroom{
					DataroomID: id, PublicKey: d.pub, SessionPrivateKeyEnc: d.blob,
					UserPublicKeys: []string{ms.active},
				})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case strings.HasSuffix(r.URL.Path, "/users/rekey") && r.Method == http.MethodPut:
		if ms.failPUT {
			ms.fail(w, http.StatusInternalServerError, "boom")

			return
		}
		var body struct {
			Enc string `json:"session_private_key_enc"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/dataroom/"), "/users/rekey")
		ms.datarooms[id] = &machineDataroom{pub: ms.active, blob: body.Enc}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// rotate checks the proof like the API does, then applies it.
func (ms *machineRotationServer) rotate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Proof string `json:"proof"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	claims, err := ms.verify(body.Proof)
	if err != nil {
		ms.t.Errorf("invalid proof: %v", err)
		ms.fail(w, http.StatusBadRequest, "Invalid rotation proof: "+err.Error())

		return
	}
	ms.posted = append(ms.posted, claims.AgeRecipient)
	if ms.postStatus != 0 {
		if ms.activateOnRefusal {
			ms.active = claims.AgeRecipient
		}
		ms.fail(w, ms.postStatus, ms.postDetail)

		return
	}
	ms.active = claims.AgeRecipient
	_ = json.NewEncoder(w).Encode(map[string]string{"fingerprint": "SRV0-FING-ERPR-INT0"})
}

type rotationClaims struct {
	Sub          string `json:"sub"`
	Aud          string `json:"aud"`
	Iat          int64  `json:"iat"`
	Exp          int64  `json:"exp"`
	AgeRecipient string `json:"age_recipient"`
}

func (ms *machineRotationServer) verify(proof string) (*rotationClaims, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	var claims rotationClaims
	for i, dst := range []any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return nil, err
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("bad signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	rr, ss := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	switch {
	case !ecdsa.Verify(ms.sig, digest[:], rr, ss):
		return nil, errors.New("bad signature")
	case header.Alg != "ES256" || header.Kid != machinekey.Thumbprint(ms.sig):
		return nil, errors.New("bad header")
	case claims.Sub != testMachineClientID || claims.Aud != machinekey.RotationAudience:
		return nil, errors.New("bad sub or aud")
	case claims.Iat < ms.now.Unix() || claims.Exp-claims.Iat > 300:
		return nil, errors.New("bad iat or exp")
	case !strings.HasPrefix(claims.AgeRecipient, "age1pq1"):
		return nil, errors.New("bad age_recipient")
	}

	return &claims, nil
}

// addDataroom registers a dataroom whose link is encrypted for key.
func (ms *machineRotationServer) addDataroom(t *testing.T, id string, key *age.HybridIdentity) {
	t.Helper()
	pub := key.Recipient().String()
	ms.datarooms[id] = &machineDataroom{pub: pub, blob: enc(t, "SESSION-"+id, pub)}
}

// machineRotationFixture is a machine directory and its fake server.
type machineRotationFixture struct {
	m       *config.Machine
	srv     *machineRotationServer
	cur     *age.HybridIdentity
	ageFile string
}

// newMachineRotationFixture writes client.key and the given key files
// (suffix "" = age.key) and starts a server whose active key is active.
func newMachineRotationFixture(
	t *testing.T, files map[string]*age.HybridIdentity, active *age.HybridIdentity,
) *machineRotationFixture {
	t.Helper()
	k, err := machinekey.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := machinekey.MarshalSigningKey(k)
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{"client.key": strings.TrimSpace(string(pem))}
	for suffix, id := range files {
		contents["age.key"+suffix] = id.String()
	}
	dir := keyfilesDir(t, contents)

	f := &machineRotationFixture{
		m: &config.Machine{
			ClientID:      testMachineClientID,
			ClientKeyFile: filepath.Join(dir, "client.key"),
			AgeKeyFile:    filepath.Join(dir, "age.key"),
		},
		srv:     newMachineRotationServer(t, &k.PublicKey, active.Recipient().String()),
		cur:     files[""],
		ageFile: filepath.Join(dir, "age.key"),
	}

	return f
}

func (f *machineRotationFixture) run(t *testing.T) (*KeyRotationResult, error) {
	t.Helper()

	return RotateMachineKey(context.Background(), f.srv.client(), f.m,
		func() time.Time { return f.srv.now }, func(string) {})
}

func (f *machineRotationFixture) key(t *testing.T, suffix string) string {
	t.Helper()

	return readTrim(t, f.ageFile+suffix)
}

func pubOf(t *testing.T, secret string) string {
	t.Helper()
	id, err := age.ParseHybridIdentity(secret)
	if err != nil {
		t.Fatal(err)
	}

	return id.Recipient().String()
}

// assertRekeyed checks that every dataroom link is encrypted for the active
// key and opens with id and the organization key.
func (f *machineRotationFixture) assertRekeyed(t *testing.T, id *age.HybridIdentity) {
	t.Helper()
	for name, d := range f.srv.datarooms {
		if d.pub != f.srv.active {
			t.Errorf("%s still encrypted for a previous key", name)
		}
		for who, key := range map[string]*age.HybridIdentity{"new key": id, "org": f.srv.org} {
			if got, err := crypto.DecryptToString(d.blob, key); err != nil || got != "SESSION-"+name {
				t.Errorf("%s: %s cannot open the blob: %v", name, who, err)
			}
		}
	}
}

func (f *machineRotationFixture) assertFinal(t *testing.T) *age.HybridIdentity {
	t.Helper()
	newKey := f.key(t, "")
	if pubOf(t, newKey) != f.srv.active {
		t.Errorf("age.key is not the active key of the server")
	}
	if existsPath(f.ageFile + machineKeyOldSuffix) {
		t.Errorf(".old still present")
	}
	if existsPath(f.ageFile + machineKeyNewSuffix) {
		t.Errorf(".new still present")
	}
	id, err := age.ParseHybridIdentity(newKey)
	if err != nil {
		t.Fatal(err)
	}

	return id
}

func TestRotateMachineKey_Full(t *testing.T) {
	cur := genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur}, cur)
	f.srv.addDataroom(t, "d1", cur)

	res, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	newID := f.assertFinal(t)
	if newID.String() == cur.String() {
		t.Fatal("age.key was not rotated")
	}
	if len(f.srv.posted) != 1 || f.srv.posted[0] != newID.Recipient().String() {
		t.Errorf("posted = %v", f.srv.posted)
	}
	f.assertRekeyed(t, newID)
	if !res.Machine || res.Resumed || res.OldKeyKept || res.Datarooms.Rekeyed != 1 ||
		res.PublicKey != newID.Recipient().String() || res.Fingerprint != "SRV0-FING-ERPR-INT0" {
		t.Errorf("result = %+v", res)
	}
}

func TestRotateMachineKey_ResumeAfterPostLost(t *testing.T) {
	cur, next := genKey(t), genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur, ".new": next}, cur)
	f.srv.addDataroom(t, "d1", cur)

	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if len(f.srv.posted) != 1 || f.srv.posted[0] != next.Recipient().String() {
		t.Errorf("posted = %v, want the existing .new", f.srv.posted)
	}
	got := f.assertFinal(t)
	if got.String() != next.String() {
		t.Error("age.key is not the former .new")
	}
	f.assertRekeyed(t, next)
}

func TestRotateMachineKey_ResumeAfterPostDone(t *testing.T) {
	cur, next := genKey(t), genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur, ".new": next}, next)
	f.srv.addDataroom(t, "d1", cur)

	res, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.srv.posted) != 0 {
		t.Errorf("unexpected POST: %v", f.srv.posted)
	}
	if got := f.assertFinal(t); got.String() != next.String() {
		t.Error("age.key is not the former .new")
	}
	f.assertRekeyed(t, next)
	kid := machinekey.Thumbprint(f.srv.sig)
	if !res.Resumed || res.Fingerprint != machinekey.Fingerprint(kid, next.Recipient().String()) {
		t.Errorf("result = %+v", res)
	}
}

func TestRotateMachineKey_ResumeRekey(t *testing.T) {
	old, cur := genKey(t), genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur, ".old": old}, cur)
	f.srv.addDataroom(t, "d1", old)

	res, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.srv.posted) != 0 {
		t.Errorf("unexpected POST: %v", f.srv.posted)
	}
	if got := f.assertFinal(t); got.String() != cur.String() {
		t.Error("age.key changed")
	}
	f.assertRekeyed(t, cur)
	if !res.Resumed || res.Datarooms.Rekeyed != 1 {
		t.Errorf("result = %+v", res)
	}
}

func TestRotateMachineKey_FinishInterruptedSwap(t *testing.T) {
	old, next := genKey(t), genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{".old": old, ".new": next}, next)
	f.srv.addDataroom(t, "d1", old)

	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if len(f.srv.posted) != 0 {
		t.Errorf("unexpected POST: %v", f.srv.posted)
	}
	if got := f.assertFinal(t); got.String() != next.String() {
		t.Error("age.key is not the former .new")
	}
	f.assertRekeyed(t, next)
}

func TestRotateMachineKey_StaleNewWithOld(t *testing.T) {
	old, cur, stale := genKey(t), genKey(t), genKey(t)
	f := newMachineRotationFixture(t,
		map[string]*age.HybridIdentity{"": cur, ".old": old, ".new": stale}, cur)
	f.srv.addDataroom(t, "d1", old)

	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if len(f.srv.posted) != 0 {
		t.Errorf("unexpected POST: %v", f.srv.posted)
	}
	if got := f.assertFinal(t); got.String() != cur.String() {
		t.Error("age.key changed")
	}
	f.assertRekeyed(t, cur)
}

func TestRotateMachineKey_Unfinished409(t *testing.T) {
	cur := genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur}, cur)
	f.srv.postStatus = http.StatusConflict
	f.srv.postDetail = "Previous key rotation not finished: some datarooms are not rekeyed yet"

	_, err := f.run(t)
	if !errors.Is(err, api.ErrMachineRotationUnfinished) || !strings.Contains(err.Error(), "human admin") {
		t.Fatalf("err = %v", err)
	}
	if existsPath(f.ageFile + machineKeyNewSuffix) {
		t.Error(".new not removed")
	}
	if f.key(t, "") != cur.String() {
		t.Error("age.key changed")
	}
}

func TestRotateMachineKey_OtherRefusalRemovesNew(t *testing.T) {
	cur := genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur}, cur)
	f.srv.postStatus = http.StatusForbidden
	f.srv.postDetail = "Not a machine account"

	if _, err := f.run(t); err == nil {
		t.Fatal("no error")
	}
	if existsPath(f.ageFile + machineKeyNewSuffix) {
		t.Error(".new not removed")
	}
}

func TestRotateMachineKey_UnknownOutcomeKeepsNew(t *testing.T) {
	cur := genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur}, cur)
	f.srv.postStatus = http.StatusBadGateway
	f.srv.postDetail = "gateway"

	if _, err := f.run(t); err == nil {
		t.Fatal("no error")
	}
	if !existsPath(f.ageFile + machineKeyNewSuffix) {
		t.Error(".new removed although the server may have accepted it")
	}
}

func TestRotateMachineKey_AlreadyActiveIsSuccess(t *testing.T) {
	cur, next := genKey(t), genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur, ".new": next}, cur)
	f.srv.postStatus = http.StatusConflict
	f.srv.postDetail = "This age key is already the active one"
	f.srv.activateOnRefusal = true // the key became active, but the answer says 409
	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if f.key(t, "") != next.String() {
		t.Error("age.key is not the former .new")
	}
}

func TestRotateMachineKey_RekeyFailureKeepsOld(t *testing.T) {
	cur := genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur}, cur)
	f.srv.addDataroom(t, "d1", cur)
	f.srv.failPUT = true

	res, err := f.run(t)
	if !errors.Is(err, ErrKeyRotationIncomplete) {
		t.Fatalf("err = %v, want ErrKeyRotationIncomplete", err)
	}
	if !strings.Contains(err.Error(), "1 error(s), the previous key is kept: run the command again") {
		t.Errorf("err = %v", err)
	}
	if res == nil || !res.OldKeyKept || len(res.Datarooms.Failed) != 1 {
		t.Errorf("result = %+v", res)
	}
	if f.key(t, machineKeyOldSuffix) != cur.String() {
		t.Error(".old is not the previous key")
	}
	if pubOf(t, f.key(t, "")) != f.srv.active {
		t.Error("age.key is not the active key")
	}
}

func TestRotateMachineKey_UnknownState(t *testing.T) {
	cur, next, other := genKey(t), genKey(t), genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur, ".new": next}, other)

	before := snapshotDir(t, filepath.Dir(f.ageFile))
	_, err := f.run(t)
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
	if len(f.srv.posted) != 0 {
		t.Errorf("unexpected POST: %v", f.srv.posted)
	}
	if after := snapshotDir(t, filepath.Dir(f.ageFile)); after != before {
		t.Errorf("files changed:\n%s\n---\n%s", before, after)
	}
}

func snapshotDir(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: test path
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(e.Name() + "=" + string(data) + "\n")
	}

	return b.String()
}

func TestRotateMachineKey_RefusalButActiveKeepsNew(t *testing.T) {
	cur := genKey(t)
	f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur}, cur)
	f.srv.postStatus = http.StatusConflict
	f.srv.postDetail = "Some unlisted conflict"
	f.srv.activateOnRefusal = true

	if _, err := f.run(t); err != nil {
		t.Fatal(err)
	}
	if len(f.srv.posted) != 1 {
		t.Fatalf("posted = %v", f.srv.posted)
	}
	if got := f.assertFinal(t); got.Recipient().String() != f.srv.posted[0] {
		t.Error("age.key is not the key the server made active")
	}
}

func TestRotateMachineKey_TooOldAPI(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cur := genKey(t)
			f := newMachineRotationFixture(t, map[string]*age.HybridIdentity{"": cur}, cur)
			f.srv.postStatus = status
			f.srv.postDetail = "Not Found"

			_, err := f.run(t)
			if err == nil || !strings.Contains(err.Error(), "the API does not support machine key rotation (too old)") {
				t.Fatalf("err = %v", err)
			}
			var httpErr *api.HTTPError
			if !errors.As(err, &httpErr) || httpErr.Status != status {
				t.Errorf("the HTTP error is not in the chain: %v", err)
			}
			if existsPath(f.ageFile + machineKeyNewSuffix) {
				t.Error(".new not removed")
			}
			if f.key(t, "") != cur.String() {
				t.Error("age.key changed")
			}
		})
	}
}
