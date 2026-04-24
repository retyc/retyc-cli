package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestListDatarooms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/" {
			t.Errorf("path = %q, want /dataroom/", r.URL.Path)
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
		if r.URL.Path != "/dataroom/" {
			t.Errorf("path = %q, want /dataroom/", r.URL.Path)
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

func TestCreateDataroomNode_File(t *testing.T) {
	typeEnc := "enc-type"
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
		if body["name_enc"] != "enc-name" {
			t.Errorf("name_enc = %v", body["name_enc"])
		}
		if body["type_enc"] != "enc-type" {
			t.Errorf("type_enc = %v, want enc-type", body["type_enc"])
		}
		if body["parent_id"] != "parent-456" {
			t.Errorf("parent_id = %v, want parent-456", body["parent_id"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomNodeCreateResponse{ID: "node-new"})
	}))
	defer srv.Close()

	node, err := newTestClient(srv).CreateDataroomNode(
		context.Background(), "dr-1", "enc-name", "hash", &typeEnc, &parentID,
	)
	if err != nil {
		t.Fatalf("CreateDataroomNode() error = %v", err)
	}
	if node.ID != "node-new" {
		t.Errorf("ID = %q, want node-new", node.ID)
	}
}

func TestCreateDataroomNode_Directory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["type_enc"] != nil {
			t.Errorf("type_enc should be nil for directory, got %v", body["type_enc"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomNodeCreateResponse{ID: "dir-new"})
	}))
	defer srv.Close()

	node, err := newTestClient(srv).CreateDataroomNode(
		context.Background(), "dr-1", "enc-name", "hash", nil, nil,
	)
	if err != nil {
		t.Fatalf("CreateDataroomNode() error = %v", err)
	}
	if node.ID != "dir-new" {
		t.Errorf("ID = %q, want dir-new", node.ID)
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
		if body["type_enc"] != "enc-mime" {
			t.Errorf("type_enc = %v, want enc-mime", body["type_enc"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DataroomNodeVersion{ID: "ver-1", ChunkCount: 0, OriginalSize: 1024})
	}))
	defer srv.Close()

	ver, err := newTestClient(srv).CreateDataroomNodeVersion(context.Background(), "node-1", 1024, "enc-mime")
	if err != nil {
		t.Fatalf("CreateDataroomNodeVersion() error = %v", err)
	}
	if ver.ID != "ver-1" {
		t.Errorf("ID = %q, want ver-1", ver.ID)
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
		if body["name_enc"] != "new-enc-name" {
			t.Errorf("name_enc = %v", body["name_enc"])
		}
		if body["parent_id"] != "parent-new" {
			t.Errorf("parent_id = %v, want parent-new", body["parent_id"])
		}
	}))
	defer srv.Close()

	err := newTestClient(srv).UpdateDataroomNode(
		context.Background(), "node-1", "new-enc-name", "new-hash", &parentID,
	)
	if err != nil {
		t.Fatalf("UpdateDataroomNode() error = %v", err)
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
	typeEnc := "enc-mime"
	parentID := "parent-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/node/node-abc" {
			t.Errorf("path = %q, want /dataroom/node/node-abc", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(DataroomNodeItem{
			Node: DataroomNode{
				ID:       "node-abc",
				NameEnc:  "enc-name",
				TypeEnc:  &typeEnc,
				ParentID: &parentID,
			},
			Version: &DataroomNodeVersion{
				ID:           "ver-1",
				NodeID:       "node-abc",
				OriginalSize: 2048,
				ChunkCount:   1,
			},
		})
	}))
	defer srv.Close()

	item, err := newTestClient(srv).GetDataroomNode(context.Background(), "node-abc")
	if err != nil {
		t.Fatalf("GetDataroomNode() error = %v", err)
	}
	if item.Node.ID != "node-abc" {
		t.Errorf("Node.ID = %q, want node-abc", item.Node.ID)
	}
	if item.Version == nil {
		t.Fatal("Version is nil, want non-nil for file node")
	}
	if item.Version.OriginalSize != 2048 {
		t.Errorf("Version.OriginalSize = %d, want 2048", item.Version.OriginalSize)
	}
}

func TestGetDataroomNode_Directory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DataroomNodeItem{
			Node:    DataroomNode{ID: "dir-1", NameEnc: "enc-name"},
			Version: nil,
		})
	}))
	defer srv.Close()

	item, err := newTestClient(srv).GetDataroomNode(context.Background(), "dir-1")
	if err != nil {
		t.Fatalf("GetDataroomNode() error = %v", err)
	}
	if item.Node.TypeEnc != nil {
		t.Errorf("TypeEnc should be nil for directory node")
	}
	if item.Version != nil {
		t.Errorf("Version should be nil for directory node")
	}
}
