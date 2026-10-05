package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel"
	"golang.org/x/oauth2"
)

// — ParseRetycURI —————————————————————————————————————————————————————————————

func TestParseRetycURI_Valid(t *testing.T) {
	tests := []struct {
		input    string
		wantDrID string
		wantPath string
	}{
		{"retyc://dr-123", "dr-123", "/"},
		{"retyc://dr-123/", "dr-123", "/"},
		{"retyc://dr-123/docs", "dr-123", "/docs"},
		{"retyc://dr-123/docs/report.pdf", "dr-123", "/docs/report.pdf"},
		{"retyc://019d3de3-cba2-76d0-962d-7817e9858661/folder", "019d3de3-cba2-76d0-962d-7817e9858661", "/folder"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			uri, err := ParseRetycURI(tt.input)
			if err != nil {
				t.Fatalf("ParseRetycURI(%q) error = %v", tt.input, err)
			}
			if uri.DataroomID != tt.wantDrID {
				t.Errorf("DataroomID = %q, want %q", uri.DataroomID, tt.wantDrID)
			}
			if uri.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", uri.Path, tt.wantPath)
			}
		})
	}
}

func TestParseRetycURI_Invalid(t *testing.T) {
	tests := []struct {
		input string
	}{
		{""},
		{"retyc://"},
		{"/just/a/path"},
		{"s3://bucket/key"},
		{"retyc:no-slashes"},
		{"http://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := ParseRetycURI(tt.input)
			if err == nil {
				t.Errorf("ParseRetycURI(%q) expected error, got nil", tt.input)
			}
		})
	}
}

// — hasGlob ———————————————————————————————————————————————————————————————————

func TestHasGlob(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"*.go", true},
		{"file?.txt", true},
		{"[abc]", true},
		{"report.pdf", false},
		{"Documents", false},
		{"", false},
		{"*", true},
		{"a*b", true},
		{"no-special-chars", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := hasGlob(tt.input); got != tt.want {
				t.Errorf("hasGlob(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// — nodeNameHash ——————————————————————————————————————————————————————————————

func TestNodeNameHash_NoSalt(t *testing.T) {
	name := "report.pdf"
	h := sha256.Sum256([]byte(name))
	want := hex.EncodeToString(h[:])

	got := nodeNameHash(name, "")
	if got != want {
		t.Errorf("nodeNameHash(%q, \"\") = %q, want %q", name, got, want)
	}
}

func TestNodeNameHash_WithSalt(t *testing.T) {
	name := "report.pdf"
	salt := "abc123"
	h := sha256.Sum256([]byte(salt + name))
	want := hex.EncodeToString(h[:])

	got := nodeNameHash(name, salt)
	if got != want {
		t.Errorf("nodeNameHash(%q, %q) = %q, want %q", name, salt, got, want)
	}
}

func TestNodeNameHash_SaltChangesOutput(t *testing.T) {
	name := "document.txt"
	withoutSalt := nodeNameHash(name, "")
	withSalt := nodeNameHash(name, "my-salt")

	if withoutSalt == withSalt {
		t.Error("nodeNameHash with and without salt returned the same hash")
	}
}

func TestNodeNameHash_DifferentSaltsProduceDifferentHashes(t *testing.T) {
	name := "file.go"
	h1 := nodeNameHash(name, "salt1")
	h2 := nodeNameHash(name, "salt2")

	if h1 == h2 {
		t.Error("different salts produced the same hash")
	}
}

func TestNodeNameHash_Length(t *testing.T) {
	got := nodeNameHash("any-name.pdf", "any-salt")
	if len(got) != 64 {
		t.Errorf("hash length = %d, want 64 (hex SHA-256)", len(got))
	}
}

// — splitPathParent ———————————————————————————————————————————————————————————

func TestSplitPathParent(t *testing.T) {
	tests := []struct {
		input      string
		wantParent string
		wantName   string
	}{
		{"/Documents/report.pdf", "/Documents", "report.pdf"},
		{"/Documents/Reports", "/Documents", "Reports"},
		{"/file.txt", "/", "file.txt"},
		{"file.txt", "/", "file.txt"},
		{"/a/b/c/d", "/a/b/c", "d"},
		// trailing slash is stripped
		{"/Documents/Reports/", "/Documents", "Reports"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parent, name := splitPathParent(tt.input)
			if parent != tt.wantParent {
				t.Errorf("splitPathParent(%q) parent = %q, want %q", tt.input, parent, tt.wantParent)
			}
			if name != tt.wantName {
				t.Errorf("splitPathParent(%q) name = %q, want %q", tt.input, name, tt.wantName)
			}
		})
	}
}

// — isConflict ————————————————————————————————————————————————————————————————

func TestIsConflict(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("%w: duplicate node name hash", api.ErrConflict), true},
		{fmt.Errorf("wrapping: %w", fmt.Errorf("%w: conflict", api.ErrConflict)), true},
		{fmt.Errorf("API error 400: bad request"), false},
		{fmt.Errorf("API error 500: internal server error"), false},
		{fmt.Errorf("network timeout"), false},
	}

	for _, tt := range tests {
		got := isConflict(tt.err)
		if got != tt.want {
			t.Errorf("isConflict(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

// — nodesFromItems ————————————————————————————————————————————————————————————

// TestNodesFromItems_ModTime: the version's creation time is the only
// modification signal the API exposes; it must reach callers (WebDAV
// Last-Modified) through the accessor without changing the marshalled shape.
func TestNodesFromItems_ModTime(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub := identity.Recipient().String()
	nameEnc, err := crypto.EncryptStringForKeys("f.txt", []string{pub})
	if err != nil {
		t.Fatalf("EncryptStringForKeys: %v", err)
	}
	typeEnc, err := crypto.EncryptStringForKeys("text/plain", []string{pub})
	if err != nil {
		t.Fatalf("EncryptStringForKeys: %v", err)
	}
	created := time.Date(2026, 9, 4, 10, 30, 0, 0, time.UTC)

	nodes := nodesFromItems(context.Background(), []api.DataroomNodeItem{
		{
			Node:    api.DataroomNode{ID: "n1", NameEnc: nameEnc, TypeEnc: &typeEnc},
			Version: &api.DataroomNodeVersion{ID: "v1", OriginalSize: 5, ChunkCount: 1, CreatedAt: created},
		},
		{Node: api.DataroomNode{ID: "n2", NameEnc: nameEnc}},
	}, identity)

	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}
	if !nodes[0].ModTime().Equal(created) {
		t.Errorf("file ModTime() = %v, want %v", nodes[0].ModTime(), created)
	}
	if !nodes[1].ModTime().IsZero() {
		t.Errorf("dir ModTime() = %v, want zero (API exposes no timestamp for folders)", nodes[1].ModTime())
	}
}

// — GetDataroomSessionWithIdentity ———————————————————————————————————————————

// A caller that already holds the unlocked user identity (webdav serve unlocks
// it once at startup) must get a session without fetching the user key again:
// only /dataroom/{id} may be hit.
func TestGetDataroomSessionWithIdentity_SkipsUserKey(t *testing.T) {
	userKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessPrivEnc, err := crypto.EncryptStringForKeys(sessKey.String(), []string{userKey.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	saltEnc, err := crypto.EncryptStringForKeys("salt-123", []string{sessKey.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)

			return
		}
		_ = json.NewEncoder(w).Encode(api.Dataroom{
			ID: "dr1", SessionPublicKey: sessKey.Recipient().String(),
			SessionPrivateKeyEnc: sessPrivEnc, NodeNameSaltEnc: &saltEnc,
		})
	}))
	t.Cleanup(srv.Close)
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)

	sess, err := GetDataroomSessionWithIdentity(context.Background(), client, "dr1", userKey)
	if err != nil {
		t.Fatalf("GetDataroomSessionWithIdentity() error = %v", err)
	}
	if sess.PublicKey != sessKey.Recipient().String() {
		t.Errorf("PublicKey = %q, want %q", sess.PublicKey, sessKey.Recipient().String())
	}
	if sess.PrivateKey != sessKey.String() {
		t.Error("PrivateKey does not match the dataroom session key")
	}
	if sess.NameSalt != "salt-123" {
		t.Errorf("NameSalt = %q, want salt-123", sess.NameSalt)
	}
}

// Decrypting a listing's names is one span under the caller's span, with the
// node count only.
func TestNodesFromItems_DecryptNamesSpan(t *testing.T) {
	exp := telemetrytest.Install(t)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	items := make([]api.DataroomNodeItem, 3)
	for i := range items {
		nameEnc, err := crypto.EncryptStringForKeys(fmt.Sprintf("SENTINEL-%d.txt", i), []string{pub})
		if err != nil {
			t.Fatal(err)
		}
		items[i] = api.DataroomNodeItem{Node: api.DataroomNode{ID: fmt.Sprintf("n%d", i), NameEnc: nameEnc}}
	}
	ctx, parent := otel.Tracer("test").Start(context.Background(), "parent")
	nodesFromItems(ctx, items, identity)
	parent.End()

	var found bool
	for _, s := range exp.GetSpans() {
		if s.Name != "crypto.decrypt_names" {
			continue
		}
		found = true
		if s.Parent.SpanID() != parent.SpanContext().SpanID() {
			t.Error("crypto.decrypt_names is not a child of the caller's span")
		}
		if len(s.Attributes) != 1 || s.Attributes[0].Key != "retyc.node.count" || s.Attributes[0].Value.AsInt64() != 3 {
			t.Errorf("attributes = %v, want node.count=3 only", s.Attributes)
		}
	}
	if !found {
		t.Fatal("no crypto.decrypt_names span")
	}
}

// Resolving a path tags the current span with the node ID it lands on.
func TestResolvePath_TagsSpanWithNodeID(t *testing.T) {
	exp := telemetrytest.Install(t)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	nameEnc, err := crypto.EncryptStringForKeys("SENTINEL.pdf", []string{pub})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(api.DataroomNodePage{
			Items: []api.DataroomNodeItem{{
				Node: api.DataroomNode{ID: "019e9e07-2200-743e-8ca4-054abf48702b", NameEnc: nameEnc},
			}},
			Pages: 1,
		})
	}))
	defer srv.Close()
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", TokenType: "Bearer"}), false, false)

	ctx, span := otel.Tracer("test").Start(context.Background(), "parent")
	id, err := resolvePath(ctx, client, "dr1", "/SENTINEL.pdf", identity)
	if err != nil || id == nil {
		t.Fatalf("resolvePath = %v, %v", id, err)
	}
	span.End()

	var got string
	for _, s := range exp.GetSpans() {
		if s.Name != "parent" {
			continue
		}
		for _, kv := range s.Attributes {
			if kv.Key == "retyc.node.id" {
				got = kv.Value.AsString()
			}
			if strings.Contains(kv.Value.String(), "SENTINEL") {
				t.Errorf("attribute %s leaks the name", kv.Key)
			}
		}
	}
	if got != "019e9e07-2200-743e-8ca4-054abf48702b" {
		t.Errorf("retyc.node.id = %q", got)
	}
}

// TestDiscardFailedUpload verifies that a failed upload removes the node only
// when it created it, and otherwise just its own version, so that the earlier
// versions of a pre-existing file survive.
func TestDiscardFailedUpload(t *testing.T) {
	cases := []struct {
		newNode bool
		want    string
	}{
		{true, "DELETE /dataroom/node/n1"},
		{false, "DELETE /dataroom/node/version/v2"},
	}
	for _, c := range cases {
		var calls []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, r.Method+" "+r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		err := DiscardFailedUpload(newExportTestClient(srv), "n1", "v2", c.newNode)
		srv.Close()
		if err != nil {
			t.Errorf("newNode=%v: DiscardFailedUpload() = %v", c.newNode, err)
		}
		if len(calls) != 1 || calls[0] != c.want {
			t.Errorf("newNode=%v: calls = %v, want [%s]", c.newNode, calls, c.want)
		}
	}
}

// TestInitStreamUploadInto_NameHeldByDeletedNode verifies that a 409 whose node
// no fresh listing shows — a deleted node the async purge has not removed yet —
// reports ErrNameBeingDeleted instead of an unexplained "could not be located".
func TestInitStreamUploadInto_NameHeldByDeletedNode(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
			http.Error(w, `{"detail":"Duplicate node name hash in the same folder"}`, http.StatusConflict)
		case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
			fmt.Fprint(w, `{"items":[],"total":0,"page":1,"pages":1}`)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}
	_, err = InitStreamUploadInto(context.Background(), newExportTestClient(srv), "dr1", nil, "doc.txt", 10, sess)
	if !errors.Is(err, ErrNameBeingDeleted) {
		t.Fatalf("err = %v, want ErrNameBeingDeleted", err)
	}
}

// smallFileServer answers POST /dataroom/dr1/node/file with status, records the
// decrypted form of every request in got, and fails on any other request.
func smallFileServer(
	t *testing.T, identity *age.HybridIdentity, status int, got *[]map[string]string,
) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		if r.Method != http.MethodPost || r.URL.Path != "/dataroom/dr1/node/file" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)

			return
		}
		if err := r.ParseMultipartForm(10 << 20); err != nil { //nolint:gosec // G120: test server
			t.Errorf("ParseMultipartForm: %v", err)
		}
		form := map[string]string{"parent_id": r.FormValue("parent_id"), "overwrite": r.FormValue("overwrite"),
			"original_size": r.FormValue("original_size"), "name_hash": r.FormValue("name_hash")}
		form["name"], _ = crypto.DecryptToString(r.FormValue("name_enc"), identity)
		form["type"], _ = crypto.DecryptToString(r.FormValue("type_enc"), identity)
		if f, _, err := r.FormFile("upload_file"); err == nil {
			enc, _ := io.ReadAll(f)
			plain, decErr := crypto.DecryptBinary(enc, identity)
			if decErr != nil {
				t.Errorf("upload_file does not decrypt: %v", decErr)
			}
			form["content"] = string(plain)
		}
		*got = append(*got, form)
		if status != http.StatusCreated {
			http.Error(w, "refused", status)

			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, `{"node":{"id":"n-1","name_enc":"x","type_enc":"x","parent_id":null},`+
			`"node_version":{"id":"v-3","node_id":"n-1","original_size":5,"chunk_count":1,"version_number":3,`+
			`"created_at":"2026-10-05T10:00:00Z"},"max_version_number":3,"capabilities":{}}`)
	}))
	t.Cleanup(srv.Close)

	return srv
}

// A file that fits in one chunk is sent in a single request, its name, type and
// content encrypted for the session key, overwriting by default.
func TestUploadSmallFile(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]string
	srv := smallFileServer(t, identity, http.StatusCreated, &got)
	sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String(), NameSalt: "salt"}
	parent := "d-1"

	node, newNode, err := UploadSmallFile(context.Background(), newExportTestClient(srv), "dr1", &parent,
		"notes.txt", []byte("hello"), sess)
	if err != nil {
		t.Fatalf("UploadSmallFile: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("requests = %d, want 1", len(got))
	}
	want := map[string]string{
		"parent_id": "d-1", "overwrite": "true", "original_size": "5", "name_hash": nodeNameHash("notes.txt", "salt"),
		"name": "notes.txt", "type": "text/plain; charset=utf-8", "content": "hello",
	}
	for k, v := range want {
		if got[0][k] != v {
			t.Errorf("%s = %q, want %q", k, got[0][k], v)
		}
	}
	if node.ID != "n-1" || node.VersionID != "v-3" || node.Size != 5 || node.ChunkCount != 1 ||
		node.Name != "notes.txt" || node.Type != "file" || node.ModTime().IsZero() {
		t.Errorf("node = %+v", node)
	}
	if newNode {
		t.Error("newNode is true for version 3 of an existing file")
	}
}

// An empty file sends no content part and reports no chunk.
func TestUploadSmallFile_Empty(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]string
	srv := smallFileServer(t, identity, http.StatusCreated, &got)
	sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}

	node, _, err := UploadSmallFile(context.Background(), newExportTestClient(srv), "dr1", nil, "empty", nil, sess)
	if err != nil {
		t.Fatalf("UploadSmallFile: %v", err)
	}
	if _, sent := got[0]["content"]; sent {
		t.Error("upload_file sent for an empty file")
	}
	if got[0]["parent_id"] != "" || node.ChunkCount != 0 || node.Size != 0 {
		t.Errorf("form = %v, node = %+v", got[0], node)
	}
}

// The API answers 410 when the name is held by a node pending deletion: the
// caller gets ErrNameBeingDeleted, which does not read as a missing parent.
func TestUploadSmallFile_NameBeingDeleted(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]string
	srv := smallFileServer(t, identity, http.StatusGone, &got)
	sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}

	_, _, err = UploadSmallFile(context.Background(), newExportTestClient(srv), "dr1", nil, "doc.txt", []byte("x"), sess)
	if !errors.Is(err, ErrNameBeingDeleted) || errors.Is(err, api.ErrNotFound) {
		t.Errorf("err = %v, want ErrNameBeingDeleted and not api.ErrNotFound", err)
	}
}

// A file above one chunk cannot go through the single request.
func TestUploadSmallFile_RejectsMoreThanOneChunk(t *testing.T) {
	sess := &DataroomSession{}
	_, _, err := UploadSmallFile(context.Background(), nil, "dr1", nil, "big", make([]byte, UploadChunkSize+1), sess)
	if err == nil {
		t.Error("UploadSmallFile accepted a file larger than one chunk")
	}
}

// dataroom cp (and the MCP upload tool) send a file that fits in one chunk in a
// single request instead of node, version and chunk.
func TestUploadToDataroom_SmallFileIsOneRequest(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]string
	srv := smallFileServer(t, identity, http.StatusCreated, &got)
	sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	var progressed int
	progress := func(_ string, n int, _ int64) { progressed += n }

	if err := UploadToDataroomWithSession(context.Background(), newExportTestClient(srv), "dr1", "/",
		[]string{path}, sess, progress); err != nil {
		t.Fatalf("UploadToDataroomWithSession: %v", err)
	}
	if len(got) != 1 || got[0]["content"] != "hello" {
		t.Errorf("requests = %v, want one carrying the content", got)
	}
	if progressed != 5 {
		t.Errorf("progress reported %d bytes, want 5", progressed)
	}
}
