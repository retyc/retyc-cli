package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// nodeTreeFixture serves GET /dataroom/dr1/nodes (filtered by parent_id) and
// DELETE /dataroom/node/{id} for a static tree whose names are encrypted with
// the session key, and records which node IDs were deleted.
type nodeTreeFixture struct {
	srv     *httptest.Server
	client  *api.Client
	sess    *DataroomSession
	deleted []string
}

type fixtureNode struct {
	id, name, parent string
	folder           bool
}

func newNodeTreeFixture(t *testing.T, nodes []fixtureNode) *nodeTreeFixture {
	t.Helper()
	sessKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := sessKey.Recipient().String()
	mime := encName(t, "text/plain", pub)
	items := make([]api.DataroomNodeItem, 0, len(nodes))
	for _, n := range nodes {
		node := api.DataroomNode{ID: n.id, NameEnc: encName(t, n.name, pub)}
		if n.parent != "" {
			node.ParentID = ptr(n.parent)
		}
		if !n.folder {
			node.TypeEnc = &mime
		}
		items = append(items, api.DataroomNodeItem{Node: node})
	}
	f := &nodeTreeFixture{sess: &DataroomSession{Identity: sessKey, PublicKey: pub, PrivateKey: sessKey.String()}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dataroom/dr1/nodes", func(w http.ResponseWriter, r *http.Request) {
		parent := r.URL.Query().Get("parent_id")
		var page api.DataroomNodePage
		for _, it := range items {
			p := ""
			if it.Node.ParentID != nil {
				p = *it.Node.ParentID
			}
			if p == parent {
				page.Items = append(page.Items, it)
			}
		}
		page.Pages, page.Page, page.Total = 1, 1, len(page.Items)
		_ = json.NewEncoder(w).Encode(page)
	})
	mux.HandleFunc("DELETE /dataroom/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/dataroom/node/"))
		w.WriteHeader(http.StatusNoContent)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.client = api.New(f.srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)

	return f
}

// A folder whose name contains glob metacharacters must be listed by its
// literal name (its children), not treated as a pattern matching itself.
func TestListNodesLiteralWithSession_GlobCharsInFolderName(t *testing.T) {
	f := newNodeTreeFixture(t, []fixtureNode{
		{id: "dir", name: "v[1]", folder: true},
		{id: "child", name: "child.txt", parent: "dir"},
	})

	nodes, err := ListNodesLiteralWithSession(context.Background(), f.client, "dr1", "/v[1]", f.sess)
	if err != nil {
		t.Fatalf("ListNodesLiteralWithSession() error = %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "child.txt" {
		t.Errorf("nodes = %+v, want the folder's child", nodes)
	}
}

// A file whose name contains a character class must be deleted by its literal
// name, never a sibling matching the class.
func TestDeleteDataroomNodeLiteralWithSession_GlobCharsInFileName(t *testing.T) {
	f := newNodeTreeFixture(t, []fixtureNode{
		{id: "sibling", name: "notesd.txt"},
		{id: "target", name: "notes[draft].txt"},
	})

	n, err := DeleteDataroomNodeLiteralWithSession(context.Background(), f.client, "dr1", "/notes[draft].txt", f.sess)
	if err != nil {
		t.Fatalf("DeleteDataroomNodeLiteralWithSession() error = %v", err)
	}
	if n != 1 || len(f.deleted) != 1 || f.deleted[0] != "target" {
		t.Errorf("deleted = %v (n=%d), want exactly [target]", f.deleted, n)
	}
}
