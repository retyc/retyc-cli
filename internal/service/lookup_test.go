package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// lookupAPI is a fake API for LookupNodeByName: one folder "d-1" holding a
// file, a symlink and a node whose name this session cannot decrypt.
type lookupAPI struct {
	t      *testing.T
	sess   *DataroomSession
	probe  int // status of the MIME table route, 200 by default
	probes atomic.Int32
	nodes  atomic.Int32
	// lastQuery is the raw query of the last lookup.
	lastQuery atomic.Value
}

func (a *lookupAPI) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/dataroom/dr-1/mime-types":
		a.probes.Add(1)
		if a.probe != 0 {
			http.Error(w, `{"detail":"probe"}`, a.probe)

			return
		}
		fmt.Fprint(w, `[]`)
	case "/dataroom/dr-1/nodes":
		a.nodes.Add(1)
		a.lastQuery.Store(r.URL.RawQuery)
		hash := r.URL.Query().Get("name_hash")
		enc := func(s string) string {
			out, err := crypto.EncryptStringForKeys(s, []string{a.sess.PublicKey})
			if err != nil {
				a.t.Errorf("EncryptStringForKeys: %v", err)
			}

			return out
		}
		var items []any
		switch hash {
		case nodeNameHash("report.pdf", a.sess.NameSalt):
			items = append(items, map[string]any{
				"node": map[string]any{
					"id": "f-1", "type": "file", "name_enc": enc("report.pdf"), "name_hash": hash,
					"type_enc": enc("application/pdf"), "access_mode": "0640", "parent_id": "d-1",
					"created_at": "2026-10-01T10:00:00Z",
				},
				"node_version": map[string]any{
					"id": "v-1", "node_id": "f-1", "original_size": 42, "chunk_count": 1,
					"created_at": "2026-10-02T10:00:00Z", "client_mtime": "2026-09-30T09:00:00Z",
				},
			})
		case nodeNameHash("link", a.sess.NameSalt):
			items = append(items, map[string]any{
				"node": map[string]any{
					"id": "l-1", "type": "symlink", "name_enc": enc("link"), "name_hash": hash,
					"type_enc": nil, "target_enc": enc("../elsewhere"), "parent_id": nil,
					"created_at": "2026-10-03T10:00:00Z",
				},
				"node_version": nil,
			})
		case nodeNameHash("foreign", a.sess.NameSalt):
			// Encrypted for a key this session does not hold.
			items = append(items, map[string]any{
				"node": map[string]any{
					"id": "f-x", "type": "file", "name_enc": "not a ciphertext", "name_hash": hash,
					"type_enc": nil, "parent_id": nil,
				},
				"node_version": nil,
			})
		}
		if items == nil {
			items = []any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "total": len(items), "pages": 1, "page": 1})
	default:
		http.Error(w, `{"detail":"unexpected"}`, http.StatusInternalServerError)
	}
}

func newLookupAPI(t *testing.T, salt string) (*lookupAPI, *api.Client) {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a := &lookupAPI{t: t, sess: &DataroomSession{
		Identity: identity, PublicKey: identity.Recipient().String(), NameSalt: salt,
	}}
	srv := httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(srv.Close)

	return a, newExportTestClient(srv)
}

// One request finds the node and decrypts it alone, with everything a listing
// would say of it, its parent and its creation time included.
func TestLookupNodeByName(t *testing.T) {
	for _, salt := range []string{"s4lt", ""} { // a dataroom without salt hashes its names unsalted
		a, client := newLookupAPI(t, salt)
		ctx := context.Background()
		parent := "d-1"

		node, found, err := LookupNodeByName(ctx, client, "dr-1", &parent, "report.pdf", a.sess)
		if err != nil || !found {
			t.Fatalf("salt %q: LookupNodeByName = (%+v, %v, %v), want the file", salt, node, found, err)
		}
		want := DataroomNodeInfo{
			ID: "f-1", Name: "report.pdf", Type: "file", MIMEType: "application/pdf", Size: 42,
			VersionID: "v-1", ChunkCount: 1,
		}
		if node.ID != want.ID || node.Name != want.Name || node.Type != want.Type || node.MIMEType != want.MIMEType ||
			node.Size != want.Size || node.VersionID != want.VersionID || node.ChunkCount != want.ChunkCount {
			t.Errorf("salt %q: node = %+v, want %+v", salt, node, want)
		}
		if node.ParentID() != "d-1" || node.Mode() != 0640 ||
			!node.CreatedAt().Equal(time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)) ||
			!node.ModTime().Equal(time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)) {
			t.Errorf("salt %q: parent %q, mode %v, created %v, modified %v", salt,
				node.ParentID(), node.Mode(), node.CreatedAt(), node.ModTime())
		}
		if got := a.lastQuery.Load(); got != "name_hash="+nodeNameHash("report.pdf", salt)+"&parent_id=d-1" {
			t.Errorf("salt %q: query = %v, want the hash of the name under the parent", salt, got)
		}

		link, found, err := LookupNodeByName(ctx, client, "dr-1", nil, "link", a.sess)
		if err != nil || !found || link.Type != "symlink" || link.Target() != "../elsewhere" || link.ParentID() != "" {
			t.Errorf("salt %q: symlink = (%+v, %v, %v), want the link at the root with its target", salt, link, found, err)
		}

		if _, found, err := LookupNodeByName(ctx, client, "dr-1", nil, "nothing", a.sess); err != nil || found {
			t.Errorf("salt %q: a missing name = (%v, %v), want not found", salt, found, err)
		}
		// A node whose name does not decrypt to the name asked is not it.
		if n, found, err := LookupNodeByName(ctx, client, "dr-1", nil, "foreign", a.sess); err != nil || found {
			t.Errorf("salt %q: an undecryptable node = (%+v, %v, %v), want not found", salt, n, found, err)
		}
		if a.nodes.Load() != 4 || a.probes.Load() != 1 {
			t.Errorf("salt %q: %d lookups and %d probes for 4 calls, want 4 and 1", salt, a.nodes.Load(), a.probes.Load())
		}
	}
}

// A node the API answers from another folder than the one asked is not the
// child looked up: the root is asked without parent_id, and must not be
// answered a node of that name from anywhere in the dataroom.
func TestLookupNodeByName_NodeOfAnotherFolder(t *testing.T) {
	a, client := newLookupAPI(t, "s4lt")
	ctx := context.Background()

	// The fake answers report.pdf, a child of d-1, whatever parent is asked.
	if n, found, err := LookupNodeByName(ctx, client, "dr-1", nil, "report.pdf", a.sess); err != nil || found {
		t.Errorf("at the root: (%+v, %v, %v), want not found: the node belongs to d-1", n, found, err)
	}
	other := "d-2"
	if n, found, err := LookupNodeByName(ctx, client, "dr-1", &other, "report.pdf", a.sess); err != nil || found {
		t.Errorf("under d-2: (%+v, %v, %v), want not found: the node belongs to d-1", n, found, err)
	}
	parent := "d-1"
	if _, found, err := LookupNodeByName(ctx, client, "dr-1", &parent, "report.pdf", a.sess); err != nil || !found {
		t.Errorf("under d-1: (%v, %v), want the node", found, err)
	}
}

// On an API without the lookup, and when the probe could not tell, nothing is
// looked up: ErrNoNameLookup, and the caller lists.
func TestLookupNodeByName_NoLookup(t *testing.T) {
	for _, probe := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		a, client := newLookupAPI(t, "s")
		a.probe = probe
		for range 2 {
			_, found, err := LookupNodeByName(context.Background(), client, "dr-1", nil, "report.pdf", a.sess)
			if !errors.Is(err, ErrNoNameLookup) || found {
				t.Errorf("probe %d: LookupNodeByName = (%v, %v), want ErrNoNameLookup", probe, found, err)
			}
		}
		if a.nodes.Load() != 0 {
			t.Errorf("probe %d: %d lookups sent to an API that may ignore the hash", probe, a.nodes.Load())
		}
		// A 404 settles it for the session; a failure is asked again.
		if want := map[int]int32{http.StatusNotFound: 1, http.StatusInternalServerError: 2}[probe]; a.probes.Load() != want {
			t.Errorf("probe %d: %d probes, want %d", probe, a.probes.Load(), want)
		}
		supported, err := a.sess.SupportsNameLookup(context.Background(), client, "dr-1")
		if supported || (err != nil) != (probe != http.StatusNotFound) {
			t.Errorf("probe %d: SupportsNameLookup = (%v, %v)", probe, supported, err)
		}
	}
}

// A session marked as one of the older API never probes.
func TestAssumeLegacyAPI(t *testing.T) {
	a, client := newLookupAPI(t, "s")
	a.sess.AssumeLegacyAPI()
	if supported, err := a.sess.SupportsNameLookup(context.Background(), client, "dr-1"); supported || err != nil {
		t.Errorf("SupportsNameLookup = (%v, %v), want an older API", supported, err)
	}
	if a.probes.Load() != 0 {
		t.Errorf("%d probes, want none", a.probes.Load())
	}
}

// A probe that fails is no proof of an older API: a replace returns the
// failure as it is, a rate limit included, and sends no rename. Only a 404 on
// the table is ErrReplaceUnsupported.
func TestReplaceDataroomNodeByID_ProbeFailure(t *testing.T) {
	for _, probe := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusNotFound} {
		var puts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				puts.Add(1)
			}
			http.Error(w, `{"detail":"no"}`, probe)
		}))
		identity, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String(), NameSalt: "s"}
		client := api.New(srv.URL, "retyc-test/1.0",
			oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", TokenType: "Bearer"}), false, false,
			api.WithRetry(time.Millisecond, 1))

		err = ReplaceDataroomNodeByID(context.Background(), client, "dr-1", "n-1", nil, "new.txt", sess)
		switch probe {
		case http.StatusNotFound:
			if !errors.Is(err, ErrReplaceUnsupported) {
				t.Errorf("404: ReplaceDataroomNodeByID = %v, want ErrReplaceUnsupported", err)
			}
		default:
			var httpErr *api.HTTPError
			if errors.Is(err, ErrReplaceUnsupported) || !errors.As(err, &httpErr) || httpErr.Status != probe {
				t.Errorf("%d: ReplaceDataroomNodeByID = %v, want the failure of the probe", probe, err)
			}
			if errors.Is(err, api.ErrRateLimited) != (probe == http.StatusTooManyRequests) {
				t.Errorf("%d: ReplaceDataroomNodeByID = %v, rate limit mismatch", probe, err)
			}
		}
		if puts.Load() != 0 {
			t.Errorf("%d: %d rename(s) sent to an API that could not be told apart", probe, puts.Load())
		}
		srv.Close()
	}
}

// DataroomNodeInfo is marshalled as it is by the MCP server: its JSON shape is
// a contract. What was added since (target, times, mode, parent) is
// unexported and read through accessors.
func TestDataroomNodeInfo_JSONShape(t *testing.T) {
	info := DataroomNodeInfo{
		ID: "n1", Name: "f.txt", Type: "file", MIMEType: "text/plain", Size: 12, VersionID: "v1", ChunkCount: 2,
	}.WithMode(0640).WithModTime(time.Unix(1, 0)).WithOrigin("d-1", time.Unix(2, 0))
	info.target = "t"
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"ID":"n1","Name":"f.txt","Type":"file","MIMEType":"text/plain",` +
		`"Size":12,"VersionID":"v1","ChunkCount":2}`
	if string(raw) != want {
		t.Errorf("JSON = %s, want %s", raw, want)
	}
	exported := 0
	for field := range reflect.TypeFor[DataroomNodeInfo]().Fields() {
		if field.IsExported() {
			exported++
		}
	}
	if exported != 7 {
		t.Errorf("%d exported fields, want 7: a new one changes what the MCP server emits", exported)
	}
	if info.ParentID() != "d-1" || !info.CreatedAt().Equal(time.Unix(2, 0)) {
		t.Errorf("origin = (%q, %v), want what WithOrigin set", info.ParentID(), info.CreatedAt())
	}
}
