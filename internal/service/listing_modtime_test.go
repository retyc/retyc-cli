package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/crypto"
)

// A folder listed by the API carries its creation time as modification time,
// through the real decode path (ListNodesByIDWithSession).
func TestListNodesByIDWithSession_FolderModTime(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	nameEnc, _ := crypto.EncryptStringForKeys("sub", []string{pub})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/dr1/nodes" {
			http.Error(w, "unexpected "+r.URL.Path, http.StatusInternalServerError)

			return
		}
		fmt.Fprintf(w, `{"items":[{"node":{"deleted_at":null,"created_at":"2026-10-10T12:02:32.704547Z",`+
			`"id":"n-sub","dataroom_id":"dr1","parent_id":null,"type":"folder","name_hash":"h","name_enc":%q,`+
			`"type_enc":null,"mime_type_id":null,"access_mode":"0755","created_user_id":"u"},"node_version":null,`+
			`"max_version_number":null,"capabilities":{}}],"total":1,"page":1,"size":100,"pages":1}`, nameEnc)
	}))
	defer srv.Close()
	sess := &DataroomSession{Identity: identity, PublicKey: pub, NameSalt: "s"}
	nodes, err := ListNodesByIDWithSession(context.Background(), newExportTestClient(srv), "dr1", nil, sess)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 10, 12, 2, 32, 704547000, time.UTC)
	if len(nodes) != 1 || nodes[0].Type != "dir" || !nodes[0].ModTime().Equal(want) || nodes[0].Mode() != 0o755 {
		t.Errorf("nodes = %+v (mod %v, mode %v)", nodes, nodes[0].ModTime(), nodes[0].Mode())
	}
}
