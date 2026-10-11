package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestListDatarooms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom" {
			t.Errorf("path = %q, want /dataroom", r.URL.Path)
		}
		if got := r.URL.Query().Get("page"); got != "1" {
			t.Errorf("page = %q, want 1", got)
		}
		_ = json.NewEncoder(w).Encode(DataroomPage{
			Items: []Dataroom{{ID: "dr-1", Title: "Test DR", SessionPublicKey: "pubkey", CreatedAt: time.Now()}},
			Total: 1, Page: 1, Pages: 1,
		})
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListDatarooms(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListDatarooms() error = %v", err)
	}
	if page.Total != 1 {
		t.Errorf("Total = %d, want 1", page.Total)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "dr-1" {
		t.Errorf("Items[0].ID = %q, want dr-1", page.Items[0].ID)
	}
}

func TestGetDataroom(t *testing.T) {
	salt := "enc-salt"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr-abc" {
			t.Errorf("path = %q, want /dataroom/dr-abc", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(Dataroom{
			ID:                   "dr-abc",
			Title:                "My DR",
			SessionPublicKey:     "pubkey",
			SessionPrivateKeyEnc: "enc-priv",
			NodeNameSaltEnc:      &salt,
		})
	}))
	defer srv.Close()

	dr, err := newTestClient(srv).GetDataroom(context.Background(), "dr-abc")
	if err != nil {
		t.Fatalf("GetDataroom() error = %v", err)
	}
	if dr.ID != "dr-abc" {
		t.Errorf("ID = %q, want dr-abc", dr.ID)
	}
	if dr.NodeNameSaltEnc == nil || *dr.NodeNameSaltEnc != "enc-salt" {
		t.Errorf("NodeNameSaltEnc = %v, want &enc-salt", dr.NodeNameSaltEnc)
	}
}

func TestGetDataroom_NoSalt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Dataroom{ID: "dr-old", SessionPublicKey: "pk", SessionPrivateKeyEnc: "enc"})
	}))
	defer srv.Close()

	dr, err := newTestClient(srv).GetDataroom(context.Background(), "dr-old")
	if err != nil {
		t.Fatalf("GetDataroom() error = %v", err)
	}
	if dr.NodeNameSaltEnc != nil {
		t.Errorf("NodeNameSaltEnc = %v, want nil for old dataroom", dr.NodeNameSaltEnc)
	}
}

func TestCreateDataroom(t *testing.T) {
	saltEnc := "enc-salt"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/dataroom" {
			t.Errorf("path = %q, want /dataroom", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["title"] != "My DR" {
			t.Errorf("body.title = %v, want My DR", body["title"])
		}
		if body["session_private_key_enc"] != "priv-enc" {
			t.Errorf("body.session_private_key_enc = %v", body["session_private_key_enc"])
		}
		if body["node_name_salt_enc"] != "enc-salt" {
			t.Errorf("body.node_name_salt_enc = %v, want enc-salt", body["node_name_salt_enc"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Dataroom{ID: "new-dr", Title: "My DR"})
	}))
	defer srv.Close()

	dr, err := newTestClient(srv).CreateDataroom(context.Background(), "My DR", "priv-enc", "pub-key", &saltEnc)
	if err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
	if dr.ID != "new-dr" {
		t.Errorf("ID = %q, want new-dr", dr.ID)
	}
}

func TestCreateDataroom_NoSalt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["node_name_salt_enc"]; ok && body["node_name_salt_enc"] != nil {
			t.Errorf("node_name_salt_enc should be nil, got %v", body["node_name_salt_enc"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Dataroom{ID: "new-dr"})
	}))
	defer srv.Close()

	_, err := newTestClient(srv).CreateDataroom(context.Background(), "My DR", "priv-enc", "pub-key", nil)
	if err != nil {
		t.Fatalf("CreateDataroom() error = %v", err)
	}
}

func TestDeleteDataroom(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if r.URL.Path != "/dataroom/dr-abc" {
			t.Errorf("path = %q, want /dataroom/dr-abc", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeleteDataroom(context.Background(), "dr-abc"); err != nil {
		t.Fatalf("DeleteDataroom() error = %v", err)
	}
}

func TestListDataroomNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr-1/nodes" {
			t.Errorf("path = %q, want /dataroom/dr-1/nodes", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("page") != "2" {
			t.Errorf("page = %q, want 2", q.Get("page"))
		}
		if q.Get("size") != "50" {
			t.Errorf("size = %q, want 50", q.Get("size"))
		}
		if q.Get("parent_id") != "parent-123" {
			t.Errorf("parent_id = %q, want parent-123", q.Get("parent_id"))
		}
		_ = json.NewEncoder(w).Encode(DataroomNodePage{
			Items: []DataroomNodeItem{{Node: DataroomNode{ID: "node-1", NameEnc: "enc-name"}}},
			Total: 1, Page: 2, Pages: 2,
		})
	}))
	defer srv.Close()

	parentID := "parent-123"
	page, err := newTestClient(srv).ListDataroomNodes(context.Background(), "dr-1", &parentID, 2, 50)
	if err != nil {
		t.Fatalf("ListDataroomNodes() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Node.ID != "node-1" {
		t.Errorf("Items[0].Node.ID = %q, want node-1", page.Items[0].Node.ID)
	}
}

func TestListDataroomNodes_Root(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("parent_id") != "" {
			t.Errorf("parent_id should be absent for root, got %q", r.URL.Query().Get("parent_id"))
		}
		_ = json.NewEncoder(w).Encode(DataroomNodePage{})
	}))
	defer srv.Close()

	_, err := newTestClient(srv).ListDataroomNodes(context.Background(), "dr-1", nil, 1, 50)
	if err != nil {
		t.Fatalf("ListDataroomNodes() error = %v", err)
	}
}

// A file node in the legacy MIME form: type_enc carries the ciphertext, and
// the explicit type is sent too for an API that knows it.
func TestCreateDataroomNode_File(t *testing.T) {
	parentID := "parent-456"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/dataroom/dr-1/node" {
			t.Errorf("path = %q, want /dataroom/dr-1/node", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		for k, want := range map[string]any{
			"name_enc": "enc-name", "name_hash": "hash", "type_enc": "enc-type", "parent_id": "parent-456", "type": "file",
		} {
			if body[k] != want {
				t.Errorf("%s = %v, want %v", k, body[k], want)
			}
		}
		for _, k := range []string{"mime_hash", "mime_name_enc", "access_mode"} {
			if _, sent := body[k]; sent {
				t.Errorf("%s sent in the legacy form", k)
			}
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomNode{ID: "node-new", Type: NodeTypeFile})
	}))
	defer srv.Close()

	node, err := newTestClient(srv).CreateDataroomNode(context.Background(), "dr-1", NodeCreate{
		ParentID: &parentID, NameEnc: "enc-name", NameHash: "hash", MIME: NodeMIME{TypeEnc: "enc-type"},
	})
	if err != nil {
		t.Fatalf("CreateDataroomNode() error = %v", err)
	}
	if node.ID != "node-new" || node.IsFolder() {
		t.Errorf("node = %+v, want file node-new", node)
	}
}

// A file node in the shared-table MIME form: the hash, the ciphertext only
// when given, and the mode when given.
func TestCreateDataroomNode_FileMimeHash(t *testing.T) {
	for _, withName := range []bool{false, true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["mime_hash"] != "mh" || body["type"] != "file" || body["access_mode"] != "0755" {
				t.Errorf("body = %v", body)
			}
			if _, sent := body["type_enc"]; sent {
				t.Error("type_enc sent with mime_hash")
			}
			if _, sent := body["mime_name_enc"]; sent != withName {
				t.Errorf("mime_name_enc sent = %v, want %v", sent, withName)
			}
			w.WriteHeader(http.StatusCreated)
			mimeID := "mt-1"
			_ = json.NewEncoder(w).Encode(DataroomNode{ID: "node-new", Type: NodeTypeFile, MimeTypeID: &mimeID})
		}))
		p := NodeCreate{NameEnc: "n", NameHash: "h", MIME: NodeMIME{Hash: "mh"}, AccessMode: "0755"}
		if withName {
			p.MIME.NameEnc = "enc-mime"
		}
		node, err := newTestClient(srv).CreateDataroomNode(context.Background(), "dr-1", p)
		srv.Close()
		if err != nil {
			t.Fatalf("CreateDataroomNode() error = %v", err)
		}
		if node.MimeTypeID == nil || *node.MimeTypeID != "mt-1" {
			t.Errorf("MimeTypeID = %v, want mt-1", node.MimeTypeID)
		}
	}
}

func TestCreateDataroomNode_Directory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["type"] != "folder" {
			t.Errorf("type = %v, want folder", body["type"])
		}
		for _, k := range []string{"type_enc", "mime_hash", "mime_name_enc"} {
			if _, sent := body[k]; sent {
				t.Errorf("%s sent for a folder", k)
			}
		}
		if _, sent := body["parent_id"]; !sent || body["parent_id"] != nil {
			t.Errorf("parent_id = %v, want an explicit null for the root", body["parent_id"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomNode{ID: "dir-new", Type: NodeTypeFolder})
	}))
	defer srv.Close()

	node, err := newTestClient(srv).CreateDataroomNode(context.Background(), "dr-1", NodeCreate{
		NameEnc: "enc-name", NameHash: "hash", Folder: true,
		// A folder's MIME is ignored, whatever the caller passes.
		MIME: NodeMIME{TypeEnc: "ignored"},
	})
	if err != nil {
		t.Fatalf("CreateDataroomNode() error = %v", err)
	}
	if node.ID != "dir-new" || !node.IsFolder() {
		t.Errorf("node = %+v, want folder dir-new", node)
	}
}

func TestDeleteDataroomNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if r.URL.Path != "/dataroom/node/node-xyz" {
			t.Errorf("path = %q, want /dataroom/node/node-xyz", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeleteDataroomNode(context.Background(), "node-xyz"); err != nil {
		t.Fatalf("DeleteDataroomNode() error = %v", err)
	}
}

func TestDeleteDataroomNodeVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if r.URL.Path != "/dataroom/node/version/ver-9" {
			t.Errorf("path = %q, want /dataroom/node/version/ver-9", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeleteDataroomNodeVersion(context.Background(), "ver-9"); err != nil {
		t.Fatalf("DeleteDataroomNodeVersion() error = %v", err)
	}
}

func TestCreateDataroomNodeVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/dataroom/node/node-1/version" {
			t.Errorf("path = %q, want /dataroom/node/node-1/version", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["original_size"] != float64(1024) {
			t.Errorf("original_size = %v, want 1024", body["original_size"])
		}
		if body["chunk_count_expected"] != float64(1) {
			t.Errorf("chunk_count_expected = %v, want 1", body["chunk_count_expected"])
		}
		if body["mime_hash"] != "mh" || body["mime_name_enc"] != "enc-mime" {
			t.Errorf("mime fields = %v / %v, want mh / enc-mime", body["mime_hash"], body["mime_name_enc"])
		}
		if body["client_mtime"] != "2026-10-01T12:00:00Z" {
			t.Errorf("client_mtime = %v, want 2026-10-01T12:00:00Z", body["client_mtime"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomNodeVersion{ID: "ver-1", ChunkCount: 0, OriginalSize: 1024})
	}))
	defer srv.Close()

	mtime := time.Date(2026, 10, 1, 14, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	ver, err := newTestClient(srv).CreateDataroomNodeVersion(context.Background(), "node-1", VersionCreate{
		OriginalSize: 1024, ChunkCount: 1, MIME: NodeMIME{Hash: "mh", NameEnc: "enc-mime"}, ClientMtime: &mtime,
	})
	if err != nil {
		t.Fatalf("CreateDataroomNodeVersion() error = %v", err)
	}
	if ver.ID != "ver-1" {
		t.Errorf("ID = %q, want ver-1", ver.ID)
	}
}

// Without a modification time or MIME type, neither field is sent: the API
// keeps the node's MIME type and records no client_mtime.
func TestCreateDataroomNodeVersion_Minimal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, k := range []string{"client_mtime", "type_enc", "mime_hash", "mime_name_enc"} {
			if _, sent := body[k]; sent {
				t.Errorf("%s sent without a value", k)
			}
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomNodeVersion{ID: "ver-1"})
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).CreateDataroomNodeVersion(context.Background(), "node-1",
		VersionCreate{OriginalSize: 1, ChunkCount: 1}); err != nil {
		t.Fatalf("CreateDataroomNodeVersion() error = %v", err)
	}
}

func TestUploadDataroomChunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/dataroom/node/version/ver-1/chunk/3" {
			t.Errorf("path = %q, want /dataroom/node/version/ver-1/chunk/3", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			t.Errorf("Content-Type = %q, want multipart/form-data", r.Header.Get("Content-Type"))
		}
	}))
	defer srv.Close()

	data := []byte("encrypted-chunk-data")
	if err := newTestClient(srv).UploadDataroomChunk(context.Background(), "ver-1", 3, data); err != nil {
		t.Fatalf("UploadDataroomChunk() error = %v", err)
	}
}

func TestDownloadDataroomChunk(t *testing.T) {
	want := []byte("encrypted-chunk-content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/node/version/ver-2/chunk/0" {
			t.Errorf("path = %q, want /dataroom/node/version/ver-2/chunk/0", r.URL.Path)
		}
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	got, err := newTestClient(srv).DownloadDataroomChunk(context.Background(), "ver-2", 0)
	if err != nil {
		t.Fatalf("DownloadDataroomChunk() error = %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("chunk data = %q, want %q", got, want)
	}
}

func TestAddDataroomUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/dataroom/dr-1/users" {
			t.Errorf("path = %q, want /dataroom/dr-1/users", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["user_email"] != "alice@example.com" {
			t.Errorf("user_email = %v, want alice@example.com", body["user_email"])
		}
		if body["role"] != "editor" {
			t.Errorf("role = %v, want editor", body["role"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomUser{UserID: "user-1", UserEmail: "alice@example.com", Role: "editor"})
	}))
	defer srv.Close()

	u, err := newTestClient(srv).AddDataroomUser(context.Background(), "dr-1", "alice@example.com", "editor")
	if err != nil {
		t.Fatalf("AddDataroomUser() error = %v", err)
	}
	if u.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", u.UserID)
	}
}

func TestRemoveDataroomUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if r.URL.Path != "/dataroom/dr-1/user/user-99" {
			t.Errorf("path = %q, want /dataroom/dr-1/user/user-99", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).RemoveDataroomUser(context.Background(), "dr-1", "user-99"); err != nil {
		t.Fatalf("RemoveDataroomUser() error = %v", err)
	}
}

func TestRekeyDataroom(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/dataroom/dr-1/users/rekey" {
			t.Errorf("path = %q, want /dataroom/dr-1/users/rekey", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["session_private_key_enc"] != "new-enc-key" {
			t.Errorf("session_private_key_enc = %v, want new-enc-key", body["session_private_key_enc"])
		}
	}))
	defer srv.Close()

	if err := newTestClient(srv).RekeyDataroom(context.Background(), "dr-1", "new-enc-key"); err != nil {
		t.Fatalf("RekeyDataroom() error = %v", err)
	}
}

func TestUpdateDataroomNode(t *testing.T) {
	parentID := "parent-new"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/dataroom/node/node-1" {
			t.Errorf("path = %q, want /dataroom/node/node-1", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["name_enc"] != "new-enc-name" || body["name_hash"] != "new-hash" {
			t.Errorf("name = %v / %v", body["name_enc"], body["name_hash"])
		}
		if body["parent_id"] != "parent-new" {
			t.Errorf("parent_id = %v, want parent-new", body["parent_id"])
		}
		if _, sent := body["access_mode"]; sent {
			t.Error("access_mode sent by a rename")
		}
	}))
	defer srv.Close()

	err := newTestClient(srv).RenameDataroomNode(context.Background(), "node-1", "new-enc-name", "new-hash", &parentID)
	if err != nil {
		t.Fatalf("RenameDataroomNode() error = %v", err)
	}
}

// The API leaves an absent field as it is and reads an explicit null parent
// as "move to the root": a move to the root sends null, a chmod sends nothing
// but access_mode. A Go client marshalling a nil pointer unconditionally
// would move every renamed node to the root.
func TestUpdateDataroomNode_OnlySetFields(t *testing.T) {
	cases := map[string]struct {
		update NodeUpdate
		want   map[string]any
	}{
		"move to root": {
			update: NodeUpdate{SetParent: true},
			want:   map[string]any{"parent_id": nil},
		},
		"chmod": {
			update: NodeUpdate{AccessMode: ptr("0755")},
			want:   map[string]any{"access_mode": "0755"},
		},
		"rename in place": {
			update: NodeUpdate{NameEnc: ptr("e"), NameHash: ptr("h")},
			want:   map[string]any{"name_enc": "e", "name_hash": "h"},
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if len(body) != len(tc.want) {
					t.Errorf("body = %v, want exactly %v", body, tc.want)
				}
				for k, v := range tc.want {
					got, sent := body[k]
					if !sent || got != v {
						t.Errorf("%s = %v (sent %v), want %v", k, got, sent, v)
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()
			if err := newTestClient(srv).UpdateDataroomNode(context.Background(), "node-1", tc.update); err != nil {
				t.Fatalf("UpdateDataroomNode() error = %v", err)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestSetDataroomNodeAccessMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method != http.MethodPut || r.URL.Path != "/dataroom/node/n-1" ||
			len(body) != 1 || body["access_mode"] != "0700" {
			t.Errorf("request = %s %s %v", r.Method, r.URL.Path, body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if err := newTestClient(srv).SetDataroomNodeAccessMode(context.Background(), "n-1", "0700"); err != nil {
		t.Fatal(err)
	}
}

// The modification time of an existing version is declared with a PATCH, in
// UTC with an explicit offset (a naive timestamp is a 422), and no version is
// created.
func TestSetDataroomVersionClientMtime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method != http.MethodPatch || r.URL.Path != "/dataroom/node/version/v-1" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if body["client_mtime"] != "2026-10-01T12:00:00.5Z" {
			t.Errorf("client_mtime = %v", body["client_mtime"])
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	mtime := time.Date(2026, 10, 1, 14, 0, 0, 500_000_000, time.FixedZone("CEST", 2*3600))
	if err := newTestClient(srv).SetDataroomVersionClientMtime(context.Background(), "v-1", mtime); err != nil {
		t.Fatal(err)
	}
}

// The lookup by name hash goes through the listing route with name_hash (and
// parent_id outside the root) and yields the single item, or nil.
func TestFindDataroomNodeByHash(t *testing.T) {
	parent := "p-1"
	cases := map[string]struct {
		parentID *string
		items    []DataroomNodeItem
		wantID   string
		wantErr  bool
	}{
		"found in folder": {
			parentID: &parent, items: []DataroomNodeItem{{Node: DataroomNode{ID: "n-1", NameHash: "h"}}}, wantID: "n-1",
		},
		"found at root": {items: []DataroomNodeItem{{Node: DataroomNode{ID: "n-2"}}}, wantID: "n-2"},
		"none":          {},
		"another hash":  {items: []DataroomNodeItem{{Node: DataroomNode{ID: "n-3", NameHash: "other"}}}, wantErr: true},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if r.URL.Path != "/dataroom/dr-1/nodes" || q.Get("name_hash") != "h" {
					t.Errorf("request = %s %s", r.URL.Path, r.URL.RawQuery)
				}
				if got, want := q.Get("parent_id"), tc.parentID; (want == nil && got != "") || (want != nil && got != *want) {
					t.Errorf("parent_id = %q, want %v", got, want)
				}
				_ = json.NewEncoder(w).Encode(DataroomNodePage{Items: tc.items, Total: len(tc.items), Page: 1, Pages: 1})
			}))
			defer srv.Close()
			item, err := newTestClient(srv).FindDataroomNodeByHash(context.Background(), "dr-1", tc.parentID, "h")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			switch {
			case tc.wantErr:
			case tc.wantID == "" && item != nil:
				t.Errorf("item = %+v, want nil", item)
			case tc.wantID != "" && (item == nil || item.Node.ID != tc.wantID):
				t.Errorf("item = %+v, want %s", item, tc.wantID)
			}
		})
	}
}

func TestListDataroomMimeTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr-1/mime-types" {
			t.Errorf("path = %q", r.URL.Path)
		}
		fmt.Fprint(w, `[{"id":"mt-1","hash":"h1","name_enc":"e1"},{"id":"mt-2","hash":"h2","name_enc":"e2"}]`)
	}))
	defer srv.Close()
	rows, err := newTestClient(srv).ListDataroomMimeTypes(context.Background(), "dr-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1].ID != "mt-2" || rows[1].Hash != "h2" || rows[1].NameEnc != "e2" {
		t.Errorf("rows = %+v", rows)
	}
}

// An API that predates the MIME table answers 404 on the route, which callers
// read as "legacy API" through ErrNotFound without ErrGone.
func TestListDataroomMimeTypes_LegacyAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"Not Found"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := newTestClient(srv).ListDataroomMimeTypes(context.Background(), "dr-1")
	if !errors.Is(err, ErrNotFound) || errors.Is(err, ErrGone) {
		t.Errorf("err = %v, want ErrNotFound and not ErrGone", err)
	}
}

func TestGetDataroomStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr-1/stats" {
			t.Errorf("path = %q, want /dataroom/dr-1/stats", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(DataroomStats{FilesCount: 42, FilesEncryptedSize: 1024 * 1024})
	}))
	defer srv.Close()

	stats, err := newTestClient(srv).GetDataroomStats(context.Background(), "dr-1")
	if err != nil {
		t.Fatalf("GetDataroomStats() error = %v", err)
	}
	if stats.FilesCount != 42 {
		t.Errorf("FilesCount = %d, want 42", stats.FilesCount)
	}
}

func TestGetDataroomUsers(t *testing.T) {
	pubKey := "current-pubkey"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr-1/users" {
			t.Errorf("path = %q, want /dataroom/dr-1/users", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]DataroomUser{
			{UserID: "u-1", UserEmail: "alice@example.com", Role: "admin", PublicKey: "pubkey", CurrentPublicKey: &pubKey},
			{UserID: "u-2", UserEmail: "bob@example.com", Role: "viewer", PublicKey: "pubkey2"},
		})
	}))
	defer srv.Close()

	users, err := newTestClient(srv).GetDataroomUsers(context.Background(), "dr-1")
	if err != nil {
		t.Fatalf("GetDataroomUsers() error = %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("len(users) = %d, want 2", len(users))
	}
	if users[0].CurrentPublicKey == nil || *users[0].CurrentPublicKey != "current-pubkey" {
		t.Errorf("users[0].CurrentPublicKey = %v, want current-pubkey", users[0].CurrentPublicKey)
	}
	if users[1].CurrentPublicKey != nil {
		t.Errorf("users[1].CurrentPublicKey should be nil")
	}
}

func TestGetDataroomNode(t *testing.T) {
	// The API returns a flat DataroomNodeModel (no "node" wrapper, no version),
	// matching the real GET /dataroom/node/{id} response. See OpenAPI getDataroomNodeById.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/node/node-abc" {
			t.Errorf("path = %q, want /dataroom/node/node-abc", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"id": "node-abc",
			"dataroom_id": "dr-1",
			"parent_id": "parent-1",
			"name_hash": "hash",
			"name_enc": "enc-name",
			"type_enc": "enc-mime"
		}`))
	}))
	defer srv.Close()

	node, err := newTestClient(srv).GetDataroomNode(context.Background(), "node-abc")
	if err != nil {
		t.Fatalf("GetDataroomNode() error = %v", err)
	}
	if node.ID != "node-abc" {
		t.Errorf("ID = %q, want node-abc", node.ID)
	}
	if node.TypeEnc == nil {
		t.Fatal("TypeEnc is nil, want non-nil for file node")
	}
	if *node.TypeEnc != "enc-mime" {
		t.Errorf("TypeEnc = %q, want enc-mime", *node.TypeEnc)
	}
}

func TestGetDataroomNode_Directory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"id": "dir-1",
			"dataroom_id": "dr-1",
			"parent_id": null,
			"name_hash": "hash",
			"name_enc": "enc-name",
			"type_enc": null
		}`))
	}))
	defer srv.Close()

	node, err := newTestClient(srv).GetDataroomNode(context.Background(), "dir-1")
	if err != nil {
		t.Fatalf("GetDataroomNode() error = %v", err)
	}
	if node.TypeEnc != nil {
		t.Errorf("TypeEnc should be nil for directory node")
	}
}

// A small file is created with its version and its single chunk in one
// multipart request; an empty file sends no upload_file, a root file no
// parent_id.
func TestCreateDataroomFileNode(t *testing.T) {
	parent := "d-1"
	cases := map[string]struct {
		parentID *string
		chunk    []byte
	}{
		"in a folder":         {parentID: &parent, chunk: []byte("encrypted")},
		"empty file, at root": {},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
				if r.Method != http.MethodPost || r.URL.Path != "/dataroom/dr-1/node/file" {
					t.Errorf("request = %s %s, want POST /dataroom/dr-1/node/file", r.Method, r.URL.Path)
				}
				if err := r.ParseMultipartForm(10 << 20); err != nil { //nolint:gosec // G120: test server
					t.Fatalf("ParseMultipartForm() error = %v", err)
				}
				want := map[string]string{
					"name_enc": "N", "name_hash": "H", "mime_hash": "MH", "mime_name_enc": "MN", "type": "file",
					"original_size": "9", "overwrite": "true", "access_mode": "0600",
					"client_mtime": "2026-10-01T12:00:00Z",
				}
				if tc.parentID != nil {
					want["parent_id"] = *tc.parentID
				}
				for k, v := range want {
					if got := r.FormValue(k); got != v {
						t.Errorf("%s = %q, want %q", k, got, v)
					}
				}
				if _, ok := r.MultipartForm.Value["parent_id"]; ok && tc.parentID == nil {
					t.Error("parent_id sent for a root file")
				}
				if _, ok := r.MultipartForm.Value["type_enc"]; ok {
					t.Error("type_enc sent with mime_hash")
				}
				f, _, err := r.FormFile("upload_file")
				switch {
				case tc.chunk == nil && err == nil:
					t.Error("upload_file sent for an empty file")
				case tc.chunk != nil && err != nil:
					t.Errorf("FormFile(upload_file) error = %v", err)
				case tc.chunk != nil:
					var got bytes.Buffer
					_, _ = got.ReadFrom(f)
					if got.String() != string(tc.chunk) {
						t.Errorf("upload_file = %q, want %q", got.String(), tc.chunk)
					}
				}
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, `{"node":{"id":"n-1","name_enc":"N","type_enc":"T","parent_id":null},`+
					`"node_version":{"id":"v-1","node_id":"n-1","original_size":9,"chunk_count":1,`+
					`"version_number":2,"created_at":"2026-10-05T10:00:00Z"},"max_version_number":2,"capabilities":{}}`)
			}))
			defer srv.Close()

			mtime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
			item, err := newTestClient(srv).CreateDataroomFileNode(context.Background(), "dr-1", FileNodeCreate{
				ParentID: tc.parentID, NameEnc: "N", NameHash: "H", MIME: NodeMIME{Hash: "MH", NameEnc: "MN"},
				OriginalSize: 9, Overwrite: true, AccessMode: "0600", ClientMtime: &mtime, Chunk: tc.chunk,
			})
			if err != nil {
				t.Fatalf("CreateDataroomFileNode() error = %v", err)
			}
			if item.Node.ID != "n-1" || item.Version == nil || item.Version.ID != "v-1" || item.Version.VersionNumber != 2 {
				t.Errorf("item = %+v / %+v, want node n-1, version v-1 number 2", item.Node, item.Version)
			}
		})
	}
}

// Both upload routes carry unsafe_write explicitly, false unless the client
// was built with WithUnsafeWrite(true): the server's own default is true, so
// leaving the parameter out would not be the safe choice it looks like.
func TestUploadRoutes_SendUnsafeWrite(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		var got []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = append(got, r.URL.Path+" unsafe_write="+r.URL.Query().Get("unsafe_write"))
			if strings.HasSuffix(r.URL.Path, "/node/file") {
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, `{"node":{"id":"n"},"node_version":{"id":"v"}}`)

				return
			}
			w.WriteHeader(http.StatusAccepted)
		}))
		c := New(srv.URL, "retyc-test/1.0", staticTokenSource(), false, false, WithUnsafeWrite(unsafe))
		ctx := context.Background()
		if _, err := c.CreateDataroomFileNode(ctx, "dr", FileNodeCreate{
			NameEnc: "N", NameHash: "H", MIME: NodeMIME{TypeEnc: "T"}, OriginalSize: 1, Overwrite: true, Chunk: []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
		if err := c.UploadDataroomChunk(ctx, "v", 0, []byte("x")); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		want := fmt.Sprintf("unsafe_write=%t", unsafe)
		if len(got) != 2 || !strings.HasSuffix(got[0], want) || !strings.HasSuffix(got[1], want) {
			t.Errorf("WithUnsafeWrite(%t): requests = %v, want both with %s", unsafe, got, want)
		}
	}
}

// A chunk stored in the background (unsafe_write) is counted before it reaches
// the object store: within that window, a version announced complete answers
// 404 for it. The download retries a 404 after a short pause, and reports a
// chunk still missing as ErrChunkMissing — a 410 (node pending deletion) or
// another error is not retried.
func TestDownloadChunk_RetriesMissingChunk(t *testing.T) {
	cases := map[string]struct {
		statuses []int // answer per attempt, the last one repeated
		wantErr  error // nil: the data comes back
		attempts int
	}{
		"found on retry":   {statuses: []int{404, 404, 200}, attempts: 3},
		"still missing":    {statuses: []int{404}, wantErr: ErrChunkMissing, attempts: 3},
		"pending deletion": {statuses: []int{410}, wantErr: ErrGone, attempts: 1},
		"server error":     {statuses: []int{500}, attempts: 1},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			var attempts int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				status := tc.statuses[min(attempts, len(tc.statuses)-1)]
				attempts++
				if status != http.StatusOK {
					http.Error(w, "nope", status)

					return
				}
				_, _ = w.Write([]byte("chunk"))
			}))
			defer srv.Close()
			c := New(srv.URL, "retyc-test/1.0", staticTokenSource(), false, false,
				WithMissingChunkRetries(time.Millisecond, time.Millisecond))

			for _, get := range []func() ([]byte, error){
				func() ([]byte, error) { return c.DownloadDataroomChunk(context.Background(), "v", 0) },
				func() ([]byte, error) { return c.AdminDownloadNodeChunk(context.Background(), "n", 0) },
			} {
				attempts = 0
				data, err := get()
				switch {
				case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
					t.Errorf("err = %v, want %v", err, tc.wantErr)
				case tc.wantErr == nil && tc.statuses[len(tc.statuses)-1] == 200 && (err != nil || string(data) != "chunk"):
					t.Errorf("got (%q, %v), want the chunk", data, err)
				}
				if errors.Is(tc.wantErr, ErrChunkMissing) && !errors.Is(err, ErrNotFound) {
					t.Error("a missing chunk no longer matches ErrNotFound")
				}
				if attempts != tc.attempts {
					t.Errorf("attempts = %d, want %d", attempts, tc.attempts)
				}
			}
		})
	}
}
