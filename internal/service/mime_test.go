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

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// mimeAPI is a fake of the node-type era API for one dataroom: a MIME table,
// a name-hash index, and the three write routes. Every request is recorded.
type mimeAPI struct {
	t        *testing.T
	identity *age.HybridIdentity
	salt     string

	mu       sync.Mutex
	legacy   bool // answer 404 on the MIME table route
	limit    int  // 400 mime_types_limit past this many rows (0: unbounded)
	rows     []api.DataroomMimeType
	nodes    []api.DataroomNodeItem // listed at the root
	requests []string               // "METHOD path"
	// forms records the decoded fields of every write, in order.
	forms []map[string]string
}

func newMimeAPI(t *testing.T, identity *age.HybridIdentity) *mimeAPI {
	t.Helper()

	return &mimeAPI{t: t, identity: identity, salt: "salt"}
}

func (a *mimeAPI) session() *DataroomSession {
	return &DataroomSession{Identity: a.identity, PublicKey: a.identity.Recipient().String(), NameSalt: a.salt}
}

// addType puts mimeType in the table and returns its row ID.
func (a *mimeAPI) addType(mimeType string) string {
	enc, err := crypto.EncryptStringForKeys(mimeType, []string{a.identity.Recipient().String()})
	if err != nil {
		a.t.Fatal(err)
	}
	id := fmt.Sprintf("mt-%d", len(a.rows)+1)
	a.rows = append(a.rows, api.DataroomMimeType{ID: id, Hash: nodeNameHash(mimeType, a.salt), NameEnc: enc})

	return id
}

func (a *mimeAPI) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/mime-types":
		if a.legacy {
			http.Error(w, `{"detail":"Not Found"}`, http.StatusNotFound)

			return
		}
		_ = json.NewEncoder(w).Encode(a.rows)
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
		items := a.nodes
		if hash := r.URL.Query().Get("name_hash"); hash != "" && !a.legacy {
			items = nil
			for _, n := range a.nodes {
				if n.Node.NameHash == hash && n.Node.ParentID == nil {
					items = append(items, n)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(api.DataroomNodePage{Items: items, Total: len(items), Page: 1, Pages: 1})
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node",
		r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/version"):
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		form := map[string]string{}
		for k, v := range body {
			if s, ok := v.(string); ok {
				form[k] = s
			}
		}
		a.write(w, form, r.URL.Path)
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node/file":
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		if err := r.ParseMultipartForm(10 << 20); err != nil { //nolint:gosec // G120: test server
			a.t.Errorf("ParseMultipartForm: %v", err)
		}
		form := map[string]string{}
		for k, v := range r.MultipartForm.Value {
			form[k] = v[0]
		}
		a.write(w, form, r.URL.Path)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
}

// write validates the MIME fields of a write the way the API does, records
// the request and answers it. a.mu is held.
func (a *mimeAPI) write(w http.ResponseWriter, form map[string]string, path string) {
	a.forms = append(a.forms, form)
	if form["type_enc"] != "" && form["mime_hash"] != "" {
		http.Error(w, `{"detail":"type_enc and mime_hash are exclusive"}`, http.StatusUnprocessableEntity)

		return
	}
	var mimeID *string
	if hash := form["mime_hash"]; hash != "" {
		if a.legacy {
			a.t.Errorf("mime_hash sent to a legacy API")
		}
		for _, row := range a.rows {
			if row.Hash == hash {
				id := row.ID
				mimeID = &id
			}
		}
		if mimeID == nil {
			if form["mime_name_enc"] == "" {
				http.Error(w, `{"detail":"mime_type_unknown"}`, http.StatusUnprocessableEntity)

				return
			}
			if a.limit > 0 && len(a.rows) >= a.limit {
				http.Error(w, `{"detail":"mime_types_limit"}`, http.StatusBadRequest)

				return
			}
			name, err := crypto.DecryptToString(form["mime_name_enc"], a.identity)
			if err != nil || nodeNameHash(name, a.salt) != hash {
				http.Error(w, `{"detail":"bad mime_name_enc"}`, http.StatusUnprocessableEntity)

				return
			}
			id := a.addType(name)
			mimeID = &id
		}
	}
	w.WriteHeader(http.StatusCreated)
	switch {
	case strings.HasSuffix(path, "/version"):
		fmt.Fprint(w, `{"id":"v-2","node_id":"n-1","original_size":9,"chunk_count":0,"version_number":2,`+
			`"created_at":"2026-10-05T10:00:00Z"}`)
	case strings.HasSuffix(path, "/node/file"):
		node := api.DataroomNode{ID: "n-1", Type: api.NodeTypeFile, NameEnc: form["name_enc"], MimeTypeID: mimeID,
			AccessMode: "0644"}
		_ = json.NewEncoder(w).Encode(api.DataroomNodeItem{Node: node, Version: &api.DataroomNodeVersion{
			ID: "v-1", NodeID: "n-1", OriginalSize: 5, ChunkCount: 1, VersionNumber: 1,
			CreatedAt: time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)}})
	default:
		_ = json.NewEncoder(w).Encode(api.DataroomNode{ID: "n-1", Type: api.NodeTypeFile, MimeTypeID: mimeID})
	}
}

func (a *mimeAPI) server() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(a.handle))
	a.t.Cleanup(srv.Close)

	return srv
}

func (a *mimeAPI) count(prefix string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}

	return n
}

// Reading a listing resolves MIME table rows with one table fetch per
// session and one decryption per row, falls back to the legacy per-node
// ciphertext, and reloads the table once for a row it does not know.
func TestNodesFromItems_MimeTable(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := newMimeAPI(t, identity)
	pdf := fake.addType("application/pdf")
	srv := fake.server()
	client := newExportTestClient(srv)
	sess := fake.session()
	pub := identity.Recipient().String()
	nameEnc, _ := crypto.EncryptStringForKeys("f", []string{pub})
	legacyEnc, _ := crypto.EncryptStringForKeys("text/plain", []string{pub})
	created := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	mtime := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	later := "mt-later"

	items := []api.DataroomNodeItem{
		{Node: api.DataroomNode{ID: "a", Type: api.NodeTypeFile, NameEnc: nameEnc, MimeTypeID: &pdf, AccessMode: "0640"},
			Version: &api.DataroomNodeVersion{ID: "v", OriginalSize: 3, ChunkCount: 1, CreatedAt: created, ClientMtime: &mtime}},
		{Node: api.DataroomNode{ID: "b", Type: api.NodeTypeFile, NameEnc: nameEnc, TypeEnc: &legacyEnc},
			Version: &api.DataroomNodeVersion{ID: "v2", CreatedAt: created}},
		{Node: api.DataroomNode{ID: "c", Type: api.NodeTypeFolder, NameEnc: nameEnc, CreatedAt: created}},
		{Node: api.DataroomNode{ID: "d", Type: api.NodeTypeFile, NameEnc: nameEnc, MimeTypeID: &later}},
	}
	nodes := nodesFromItems(context.Background(), client, "dr1", items, sess)

	want := []struct {
		typ, mime string
		mod       time.Time
		mode      os.FileMode
	}{
		{"file", "application/pdf", mtime, 0o640},
		{"file", "text/plain", created, 0},
		{"dir", "", created, 0},
		{"file", "", time.Time{}, 0},
	}
	for i, w := range want {
		n := nodes[i]
		if n.Type != w.typ || n.MIMEType != w.mime || !n.ModTime().Equal(w.mod) || n.Mode() != w.mode {
			t.Errorf("node %d = %+v (mod %v, mode %v), want %+v", i, n, n.ModTime(), n.Mode(), w)
		}
	}
	// One load, one reload for the unknown row, and no further reload when
	// the same unknown row shows up again.
	nodesFromItems(context.Background(), client, "dr1", items[3:], sess)
	if got := fake.count("GET /dataroom/dr1/mime-types"); got != 2 {
		t.Errorf("MIME table fetched %d times, want 2 (load + one reload for an unknown row)", got)
	}

	// A row added since the load is found by the reload.
	fake.mu.Lock()
	later = fake.addType("image/png")
	fake.mu.Unlock()
	items[3].Node.MimeTypeID = &later
	if got := nodesFromItems(context.Background(), client, "dr1", items[3:], sess)[0].MIMEType; got != "image/png" {
		t.Errorf("MIME of a row added since the load = %q, want image/png", got)
	}
}

// Writes send the salted hash of the MIME type, with its ciphertext only for
// a type the dataroom does not know yet; the type is then known for the
// session and the next write sends the hash alone.
func TestUploadSmallFile_MimeHash(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := newMimeAPI(t, identity)
	fake.addType("application/pdf")
	srv := fake.server()
	client := newExportTestClient(srv)
	sess := fake.session()

	// Known type: hash only.
	node, _, err := UploadSmallFile(context.Background(), client, "dr1", nil, "a.pdf", []byte("x"), sess)
	if err != nil {
		t.Fatal(err)
	}
	if node.MIMEType != "application/pdf" || node.Mode() != 0o644 {
		t.Errorf("node = %+v", node)
	}
	form := fake.forms[0]
	if form["mime_hash"] != nodeNameHash("application/pdf", "salt") || form["mime_name_enc"] != "" ||
		form["type_enc"] != "" || form["type"] != "file" {
		t.Errorf("known type form = %v", form)
	}

	// Unknown type: hash and ciphertext, once.
	for range 2 {
		if _, _, err := UploadSmallFile(context.Background(), client, "dr1", nil, "b.txt", []byte("x"), sess); err != nil {
			t.Fatal(err)
		}
	}
	if fake.forms[1]["mime_name_enc"] == "" {
		t.Error("first write of an unknown type sent no ciphertext")
	}
	if fake.forms[2]["mime_name_enc"] != "" || fake.forms[2]["mime_hash"] == "" {
		t.Errorf("second write of a now-known type = %v, want the hash alone", fake.forms[2])
	}
	if len(fake.forms) != 3 {
		t.Errorf("%d writes, want 3 (no retry needed)", len(fake.forms))
	}
}

// A hash the session believes known but the API does not (422
// mime_type_unknown) is resent with the ciphertext; a dataroom at its limit
// of distinct types (400 mime_types_limit) gets the legacy ciphertext.
func TestWithMIME_Fallbacks(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := newMimeAPI(t, identity)
	fake.addType("application/pdf")
	srv := fake.server()
	client := newExportTestClient(srv)
	sess := fake.session()

	// Load the table, then drop the row behind the session's back.
	if _, err := sess.mimeTable(context.Background(), client, "dr1"); err != nil {
		t.Fatal(err)
	}
	sess.mime.mu.Unlock()
	fake.mu.Lock()
	fake.rows = nil
	fake.mu.Unlock()
	if _, _, err := UploadSmallFile(context.Background(), client, "dr1", nil, "a.pdf", []byte("x"), sess); err != nil {
		t.Fatalf("unknown hash: %v", err)
	}
	if len(fake.forms) != 2 || fake.forms[0]["mime_name_enc"] != "" || fake.forms[1]["mime_name_enc"] == "" {
		t.Errorf("forms = %v, want a hash-only write then a retry with the ciphertext", fake.forms)
	}

	// Limit reached: a new type falls back to type_enc.
	fake.mu.Lock()
	fake.limit = 1
	fake.forms = nil
	fake.mu.Unlock()
	if _, _, err := UploadSmallFile(context.Background(), client, "dr1", nil, "c.png", []byte("x"), sess); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if len(fake.forms) != 2 || fake.forms[1]["type_enc"] == "" || fake.forms[1]["mime_hash"] != "" {
		t.Errorf("forms = %v, want a hash write then a legacy retry", fake.forms)
	}
	if got, _ := crypto.DecryptToString(fake.forms[1]["type_enc"], identity); got != "image/png" {
		t.Errorf("legacy type_enc = %q", got)
	}
}

// Against an API without the MIME table (404 on its route) every write
// carries the legacy ciphertext and no node is looked up by hash; the probe
// runs once per session.
func TestLegacyAPI_TypeEncAndListing(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := newMimeAPI(t, identity)
	fake.legacy = true
	srv := fake.server()
	client := newExportTestClient(srv)
	sess := fake.session()
	pub := identity.Recipient().String()
	nameEnc, _ := crypto.EncryptStringForKeys("doc.txt", []string{pub})
	fake.nodes = []api.DataroomNodeItem{{Node: api.DataroomNode{ID: "n-doc", NameEnc: nameEnc, TypeEnc: &nameEnc},
		Version: &api.DataroomNodeVersion{ID: "v-doc"}}}

	if _, _, err := UploadSmallFile(context.Background(), client, "dr1", nil, "a.pdf", []byte("x"), sess); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStreamUploadInto(context.Background(), client, "dr1", nil, "b.txt", 9, sess); err != nil {
		t.Fatal(err)
	}
	for i, form := range fake.forms {
		if form["type_enc"] == "" || form["mime_hash"] != "" {
			t.Errorf("write %d = %v, want the legacy type_enc", i, form)
		}
	}
	id, err := resolvePathWithSession(context.Background(), client, "dr1", "/doc.txt", sess)
	if err != nil || id == nil || *id != "n-doc" {
		t.Fatalf("resolvePathWithSession = %v, %v", id, err)
	}
	if got := fake.count("GET /dataroom/dr1/mime-types"); got != 1 {
		t.Errorf("probe ran %d times, want 1", got)
	}
	for _, r := range fake.requests {
		if strings.Contains(r, "name_hash") {
			t.Errorf("legacy API asked a hash lookup: %s", r)
		}
	}
}

// A dataroom without name salt cannot hash MIME types (the API refuses an
// unsalted hash): writes carry the legacy ciphertext even on a new API.
func TestMimeFor_NoSalt(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := newMimeAPI(t, identity)
	srv := fake.server()
	sess := fake.session()
	sess.NameSalt = ""
	m, err := sess.mimeFor(context.Background(), newExportTestClient(srv), "dr1", "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if m.TypeEnc == "" || m.Hash != "" {
		t.Errorf("mimeFor without salt = %+v, want type_enc", m)
	}
	if fake.count("GET") != 0 {
		t.Error("the table was fetched although it cannot be used")
	}
}

// On an API with the lookup, a path resolves with one request per component
// and nothing decrypted; a missing component is os.ErrNotExist.
func TestResolvePathWithSession_Lookup(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := newMimeAPI(t, identity)
	srv := fake.server()
	client := newExportTestClient(srv)
	sess := fake.session()
	fake.nodes = []api.DataroomNodeItem{
		{Node: api.DataroomNode{ID: "n-a", Type: api.NodeTypeFolder, NameEnc: "x", NameHash: nodeNameHash("a", "salt")}},
	}

	id, err := resolvePathWithSession(context.Background(), client, "dr1", "/a", sess)
	if err != nil || id == nil || *id != "n-a" {
		t.Fatalf("resolvePathWithSession(/a) = %v, %v", id, err)
	}
	_, err = resolvePathWithSession(context.Background(), client, "dr1", "/missing", sess)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing path err = %v, want os.ErrNotExist", err)
	}
	if root, err := resolvePathWithSession(context.Background(), client, "dr1", "/", sess); err != nil || root != nil {
		t.Errorf("root = %v, %v", root, err)
	}
	lookups := 0
	for _, r := range fake.requests {
		if strings.HasPrefix(r, "GET /dataroom/dr1/nodes") {
			lookups++
		}
	}
	if lookups != 2 {
		t.Errorf("%d node requests, want 2 (one per resolved component)", lookups)
	}
}

// A downloaded file gets the modification time its uploader declared.
func TestDownloadVersion_SetsClientMtime(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	chunk, err := crypto.EncryptBinaryForKey([]byte("hello"), pub)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/node/version/v-1/chunk/0" {
			http.Error(w, "unexpected "+r.URL.Path, http.StatusInternalServerError)

			return
		}
		_, _ = w.Write(chunk)
	}))
	defer srv.Close()
	dir := t.TempDir()
	mtime := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	version := &api.DataroomNodeVersion{ID: "v-1", OriginalSize: 5, ChunkCount: 1, ClientMtime: &mtime}
	sess := &DataroomSession{Identity: identity, PublicKey: pub}
	err = downloadVersion(context.Background(), newExportTestClient(srv), dir, "hello.txt", version, sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(mtime) {
		t.Errorf("mtime = %v, want %v", info.ModTime(), mtime)
	}
}
