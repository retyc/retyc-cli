package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// On an API with the lookup by name, a Stat whose folder is not cached asks
// for that one name instead of listing the folder, a missing name is
// remembered, and a symbolic link found that way does not exist for WebDAV,
// as when a listing holds it.
func TestWebdavFS_StatLooksTheNameUp(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	hash := func(name string) string {
		h := sha256.Sum256([]byte(name)) // the dataroom has no name salt

		return hex.EncodeToString(h[:])
	}
	enc := func(s string) string {
		out, err := crypto.EncryptStringForKeys(s, []string{pub})
		if err != nil {
			t.Errorf("EncryptStringForKeys: %v", err)
		}

		return out
	}
	var lookups, listings atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dataroom/dr1/mime-types":
			_, _ = w.Write([]byte(`[]`))
		case r.URL.Path == "/dataroom/dr1/nodes" && r.URL.Query().Get("name_hash") == "":
			// Never what a Stat waits for: one that did would fail with it.
			listings.Add(1)
			http.Error(w, "no Stat is answered by a listing", http.StatusInternalServerError)
		case r.URL.Path == "/dataroom/dr1/nodes":
			lookups.Add(1)
			var items []any
			switch r.URL.Query().Get("name_hash") {
			case hash("doc.txt"):
				items = append(items, map[string]any{
					"node": map[string]any{
						"id": "f-1", "type": "file", "name_enc": enc("doc.txt"), "name_hash": hash("doc.txt"),
						"type_enc": enc("text/plain"), "parent_id": nil, "access_mode": "0755",
					},
					"node_version": map[string]any{
						"id": "v-1", "node_id": "f-1", "original_size": 7, "chunk_count": 1,
						"created_at": "2026-10-02T10:00:00Z",
					},
				})
			case hash("link"):
				items = append(items, map[string]any{
					"node": map[string]any{
						"id": "l-1", "type": "symlink", "name_enc": enc("link"), "name_hash": hash("link"),
						"type_enc": nil, "target_enc": enc("doc.txt"), "parent_id": nil,
					},
					"node_version": nil,
				})
			}
			if items == nil {
				items = []any{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "total": len(items), "pages": 1, "page": 1})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	fs := newTestFS(newWebdavTestFS(srv).client, vfs.Options{NegativeTTL: vfs.DefaultNegativeTTL})
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})
	fs.tree.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	ctx := context.Background()

	for range 2 {
		info, err := fs.Stat(ctx, "/dataroom/DR/doc.txt")
		if err != nil {
			t.Fatalf("Stat of a file: %v", err)
		}
		wfi := info.(*webdavFileInfo)
		if wfi.isDir || wfi.size != 7 || wfi.versionID != "v-1" || wfi.Mode().Perm() != 0755 {
			t.Errorf("Stat = %+v, want the file as a listing would report it", wfi)
		}
		if ct, _ := wfi.ContentType(ctx); ct != "text/plain" {
			t.Errorf("content type = %q, want the MIME type of the node", ct)
		}
		for _, name := range []string{"link", "nothing"} {
			if _, err := fs.Stat(ctx, "/dataroom/DR/"+name); !os.IsNotExist(err) {
				t.Errorf("Stat(%s) = %v, want a bare not-exist error", name, err)
			}
		}
	}
	// The listing of the folder is asked for in the background from the
	// second name on (vfs: noteNameLookup), which is not counted here: it
	// fails, and no Stat depended on it.
	if lookups.Load() != 3 {
		t.Errorf("%d lookups (and %d listings) for three names asked twice, want 3 lookups", lookups.Load(), listings.Load())
	}
}
