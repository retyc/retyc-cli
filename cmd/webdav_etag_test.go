package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// An expired listing is refreshed with the ETag it came with: an unchanged
// dataroom answers 304 and the listing is kept for another TTL; a listing
// this server edited in place has lost its ETag and is fetched again.
func TestListNodes_RevalidatesWithETag(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	nameEnc, _ := crypto.EncryptStringForKeys("doc.txt", []string{pub})
	var mu sync.Mutex
	var answers []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/dataroom/dr1/nodes" {
			http.Error(w, "unexpected "+r.URL.Path, http.StatusInternalServerError)

			return
		}
		w.Header().Set("ETag", `W/"r7"`)
		if r.Header.Get("If-None-Match") == `W/"r7"` {
			answers = append(answers, http.StatusNotModified)
			w.WriteHeader(http.StatusNotModified)

			return
		}
		answers = append(answers, http.StatusOK)
		fmt.Fprintf(w, `{"items":[{"node":{"id":"n1","type":"file","name_hash":"h","name_enc":%q,"type_enc":null,`+
			`"access_mode":"0644","parent_id":null},"node_version":{"id":"v1","node_id":"n1","original_size":3,`+
			`"chunk_count":1,"created_at":"2026-10-10T12:00:00Z"}}],"total":1,"page":1,"size":100,"pages":1}`, nameEnc)
	}))
	defer srv.Close()
	fs := newWebdavTestFS(srv)
	fs.nodeCache = map[string]*nodeCacheEntry{} // drop the helper's warm root listing
	fs.sessions.Store("dr1", &service.DataroomSession{Identity: identity, PublicKey: pub})
	ctx := context.Background()
	expire := func() {
		fs.nodeMu.Lock()
		fs.nodeCache["retyc://dr1/"].fetchedAt = time.Now().Add(-time.Hour)
		fs.nodeMu.Unlock()
	}
	list := func(want int) {
		t.Helper()
		nodes, err := fs.listNodes(ctx, "dr1", "/")
		if err != nil || len(nodes) != want {
			t.Fatalf("listing = %+v, %v; want %d node(s)", nodes, err, want)
		}
	}

	list(1)
	expire()
	list(1)
	fs.nodeMu.Lock()
	fresh := time.Since(fs.nodeCache["retyc://dr1/"].fetchedAt) < time.Minute
	fs.nodeMu.Unlock()
	if !fresh {
		t.Error("a 304 did not renew the listing")
	}
	fs.removeFromNodeCache("retyc://dr1/", "doc.txt")
	expire()
	list(1)

	mu.Lock()
	defer mu.Unlock()
	if want := []int{http.StatusOK, http.StatusNotModified, http.StatusOK}; fmt.Sprint(answers) != fmt.Sprint(want) {
		t.Errorf("API answers = %v, want %v", answers, want)
	}
}
