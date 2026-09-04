package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
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

	nodes := nodesFromItems([]api.DataroomNodeItem{
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
