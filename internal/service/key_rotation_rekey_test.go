package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

func genKey(t *testing.T) *age.HybridIdentity {
	t.Helper()
	id, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	return id
}

// rekeyServer records the PUT bodies by path and answers the other routes
// from handlers.
type rekeyServer struct {
	mu       sync.Mutex
	puts     map[string]string
	failPUT  bool
	handlers map[string]func(w http.ResponseWriter, r *http.Request)
	srv      *httptest.Server
}

func newRekeyServer(t *testing.T) *rekeyServer {
	t.Helper()
	rs := &rekeyServer{puts: map[string]string{}, handlers: map[string]func(http.ResponseWriter, *http.Request){}}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			var body struct {
				Enc string `json:"session_private_key_enc"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			rs.mu.Lock()
			defer rs.mu.Unlock()
			if rs.failPUT {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"detail":"boom"}`))

				return
			}
			rs.puts[r.URL.Path] = body.Enc
			_, _ = w.Write([]byte(`{}`))

			return
		}
		if h, ok := rs.handlers[r.URL.Path]; ok {
			h(w, r)

			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(rs.srv.Close)

	return rs
}

func (rs *rekeyServer) client() *api.Client { return newRotationTestClient(rs.srv) }

func jsonHandler(v any) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(v) }
}

func enc(t *testing.T, plain string, keys ...string) string {
	t.Helper()
	out, err := crypto.EncryptStringForKeys(plain, keys)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func TestRekeyPendingDatarooms_ReencryptsForMembersAndOrg(t *testing.T) {
	old, member, org := genKey(t), genKey(t), genKey(t)
	rs := newRekeyServer(t)
	rs.handlers["/dataroom/pending-rekey"] = jsonHandler([]api.PendingRekeyDataroom{{
		DataroomID:           "d1",
		PublicKey:            old.Recipient().String(),
		SessionPrivateKeyEnc: enc(t, "SESSION", old.Recipient().String()),
		UserPublicKeys:       []string{member.Recipient().String()},
	}})

	keys := map[string]*age.HybridIdentity{old.Recipient().String(): old}
	out := rekeyPendingDatarooms(context.Background(), rs.client(), keys, "", org.Recipient().String())
	if out.Rekeyed != 1 || len(out.Failed) != 0 || len(out.Skipped) != 0 {
		t.Fatalf("outcome = %+v", out)
	}

	blob := rs.puts["/dataroom/d1/users/rekey"]
	for name, id := range map[string]*age.HybridIdentity{"member": member, "org": org} {
		got, err := crypto.DecryptToString(blob, id)
		if err != nil || got != "SESSION" {
			t.Errorf("%s cannot open the blob: %v (%q)", name, err, got)
		}
	}
}

// The members listed by the API may omit the caller (its new key not yet
// registered as a member key): the blob must still open with the new identity.
func TestRekeyPendingDatarooms_AlwaysIncludesNewKey(t *testing.T) {
	old, nw, member := genKey(t), genKey(t), genKey(t)
	rs := newRekeyServer(t)
	rs.handlers["/dataroom/pending-rekey"] = jsonHandler([]api.PendingRekeyDataroom{{
		DataroomID:           "d1",
		PublicKey:            old.Recipient().String(),
		SessionPrivateKeyEnc: enc(t, "SESSION", old.Recipient().String()),
		UserPublicKeys:       []string{member.Recipient().String()},
	}})

	keys := map[string]*age.HybridIdentity{old.Recipient().String(): old}
	out := rekeyPendingDatarooms(context.Background(), rs.client(), keys, nw.Recipient().String(), "")
	if out.Rekeyed != 1 {
		t.Fatalf("outcome = %+v", out)
	}

	blob := rs.puts["/dataroom/d1/users/rekey"]
	for name, id := range map[string]*age.HybridIdentity{"new": nw, "member": member} {
		if got, err := crypto.DecryptToString(blob, id); err != nil || got != "SESSION" {
			t.Errorf("%s cannot open the blob: %v (%q)", name, err, got)
		}
	}
}

func TestRekeyPendingDatarooms_UnknownKeySkipped(t *testing.T) {
	old, other := genKey(t), genKey(t)
	rs := newRekeyServer(t)
	rs.handlers["/dataroom/pending-rekey"] = jsonHandler([]api.PendingRekeyDataroom{{
		DataroomID:           "d1",
		PublicKey:            other.Recipient().String(),
		SessionPrivateKeyEnc: enc(t, "S", other.Recipient().String()),
		UserPublicKeys:       []string{old.Recipient().String()},
	}})

	keys := map[string]*age.HybridIdentity{old.Recipient().String(): old}
	out := rekeyPendingDatarooms(context.Background(), rs.client(), keys, "", "")
	if out.Rekeyed != 0 || len(out.Skipped) != 1 || !strings.HasPrefix(out.Skipped[0], "d1: ") {
		t.Fatalf("outcome = %+v", out)
	}
	if len(rs.puts) != 0 {
		t.Errorf("unexpected PUT: %v", rs.puts)
	}
}

func TestRekeyPendingDatarooms_PutFailureCounted(t *testing.T) {
	old := genKey(t)
	rs := newRekeyServer(t)
	rs.failPUT = true
	rs.handlers["/dataroom/pending-rekey"] = jsonHandler([]api.PendingRekeyDataroom{{
		DataroomID:           "d1",
		PublicKey:            old.Recipient().String(),
		SessionPrivateKeyEnc: enc(t, "S", old.Recipient().String()),
		UserPublicKeys:       []string{old.Recipient().String()},
	}})

	keys := map[string]*age.HybridIdentity{old.Recipient().String(): old}
	out := rekeyPendingDatarooms(context.Background(), rs.client(), keys, "", "")
	if out.Rekeyed != 0 || len(out.Failed) != 1 || !strings.HasPrefix(out.Failed[0], "d1: ") {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestRekeyPendingDatarooms_ListFailure(t *testing.T) {
	rs := newRekeyServer(t)
	rs.handlers["/dataroom/pending-rekey"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
	out := rekeyPendingDatarooms(context.Background(), rs.client(), nil, "", "")
	if len(out.Failed) != 1 || !strings.HasPrefix(out.Failed[0], "list: ") {
		t.Fatalf("outcome = %+v", out)
	}
}

// transferFixture registers a list of sent transfers (statuses by ID, one page
// per entry of pages) and details built by detail.
func transferFixture(
	rs *rekeyServer, pages [][]api.Transfer, detail func(id string) api.TransferDetails,
) {
	rs.handlers["/share"] = func(w http.ResponseWriter, r *http.Request) {
		var p int
		_, _ = fmt.Sscanf(r.URL.Query().Get("page"), "%d", &p)
		_ = json.NewEncoder(w).Encode(api.TransferPage{Items: pages[p-1], Page: p, Pages: len(pages)})
	}
	for _, page := range pages {
		for _, tr := range page {
			d := detail(tr.ID)
			rs.handlers["/share/"+tr.ID+"/details"] = jsonHandler(d)
		}
	}
}

func TestRekeySentTransfers_OnlyActiveAndExpired(t *testing.T) {
	old, nw := genKey(t), genKey(t)
	rs := newRekeyServer(t)
	var items []api.Transfer
	for _, st := range []api.TransferStatus{"active", "expired", "disabled", "pending", "deleted"} {
		items = append(items, api.Transfer{ID: "t-" + string(st), Status: st})
	}
	transferFixture(rs, [][]api.Transfer{items}, func(string) api.TransferDetails {
		return api.TransferDetails{SessionPrivateKeyEnc: ptr(enc(t, "S", old.Recipient().String()))}
	})

	out := rekeySentTransfers(context.Background(), rs.client(), []*age.HybridIdentity{old}, nw.Recipient().String(), "")
	if out.Rekeyed != 2 || len(out.Failed) != 0 || len(out.Skipped) != 0 {
		t.Fatalf("outcome = %+v", out)
	}
	if len(rs.puts) != 2 {
		t.Errorf("PUTs = %v, want 2", rs.puts)
	}
}

func TestRekeySentTransfers_Recipients(t *testing.T) {
	old, nw, org := genKey(t), genKey(t), genKey(t)
	recipOld, recipNew, eph := genKey(t), genKey(t), genKey(t)
	rs := newRekeyServer(t)
	transferFixture(rs, [][]api.Transfer{{{ID: "t1", Status: "active"}}}, func(string) api.TransferDetails {
		return api.TransferDetails{
			SessionPrivateKeyEnc: ptr(enc(t, "S", old.Recipient().String())),
			EphemeralPublicKey:   ptr(eph.Recipient().String()),
			Recipients: []api.TransferRecipient{{
				PublicKey:         ptr(recipOld.Recipient().String()),
				ExpectedPublicKey: ptr(recipNew.Recipient().String()),
			}},
		}
	})

	out := rekeySentTransfers(context.Background(), rs.client(), []*age.HybridIdentity{old},
		nw.Recipient().String(), org.Recipient().String())
	if out.Rekeyed != 1 {
		t.Fatalf("outcome = %+v", out)
	}

	blob := rs.puts["/share/t1/rekey"]
	for name, id := range map[string]*age.HybridIdentity{"new": nw, "recipient": recipNew, "org": org} {
		if got, err := crypto.DecryptToString(blob, id); err != nil || got != "S" {
			t.Errorf("%s cannot open the blob: %v", name, err)
		}
	}
	for name, id := range map[string]*age.HybridIdentity{"old recipient": recipOld, "ephemeral": eph, "old": old} {
		if _, err := crypto.DecryptToString(blob, id); err == nil {
			t.Errorf("%s can open the blob", name)
		}
	}
}

func TestRekeySentTransfers_Pagination(t *testing.T) {
	old, nw := genKey(t), genKey(t)
	rs := newRekeyServer(t)
	pages := [][]api.Transfer{{{ID: "a", Status: "active"}}, {{ID: "b", Status: "expired"}}}
	transferFixture(rs, pages, func(string) api.TransferDetails {
		return api.TransferDetails{SessionPrivateKeyEnc: ptr(enc(t, "S", old.Recipient().String()))}
	})

	out := rekeySentTransfers(context.Background(), rs.client(), []*age.HybridIdentity{old}, nw.Recipient().String(), "")
	if out.Rekeyed != 2 || len(rs.puts) != 2 {
		t.Fatalf("outcome = %+v, puts = %v", out, rs.puts)
	}
}

func TestRekeySentTransfers_UndecryptableSkipped(t *testing.T) {
	old, other, nw := genKey(t), genKey(t), genKey(t)
	rs := newRekeyServer(t)
	pages := [][]api.Transfer{{{ID: "a", Status: "active"}, {ID: "b", Status: "active"}}}
	transferFixture(rs, pages, func(id string) api.TransferDetails {
		if id == "a" {
			return api.TransferDetails{} // no session key
		}

		return api.TransferDetails{SessionPrivateKeyEnc: ptr(enc(t, "S", other.Recipient().String()))}
	})

	out := rekeySentTransfers(context.Background(), rs.client(), []*age.HybridIdentity{old}, nw.Recipient().String(), "")
	if out.Rekeyed != 0 || len(out.Skipped) != 2 || len(out.Failed) != 0 {
		t.Fatalf("outcome = %+v", out)
	}
}
