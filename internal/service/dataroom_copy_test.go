package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// copyAPI fakes the copy route and the version it seals after `polls` reads.
type copyAPI struct {
	mu       sync.Mutex
	polls    int // reads of the version before it is complete
	reads    int
	vanish   int // status the version answers once polled (0: none)
	requests []string
}

func (a *copyAPI) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/n-src/copy":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"node":{"id":"n-copy","type":"file","name_enc":"x","type_enc":null,"mime_type_id":null,`+
			`"access_mode":"0640","parent_id":null},"node_version":{"id":"v-copy","node_id":"n-copy",`+
			`"original_size":9,"chunk_count":0,"chunk_count_expected":2,"version_number":1,`+
			`"created_at":"2026-10-10T12:00:00Z","client_mtime":"2024-05-06T07:08:09Z"}}`)
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/node/version/v-copy":
		a.reads++
		if a.vanish != 0 {
			http.Error(w, `{"detail":"gone"}`, a.vanish)

			return
		}
		count := 1
		if a.reads >= a.polls {
			count = 2
		}
		fmt.Fprintf(w, `{"id":"v-copy","node_id":"n-copy","original_size":9,"chunk_count":%d,`+
			`"chunk_count_expected":2,"version_number":1,"created_at":"2026-10-10T12:00:00Z",`+
			`"client_mtime":"2024-05-06T07:08:09Z"}`, count)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
}

// A copy is requested once, then its version polled until sealed; the node
// comes back as a listing would report it, with the copied metadata.
func TestCopyDataroomNodeByID_WaitsForSeal(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	copyPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { copyPollInterval = time.Second })
	fake := &copyAPI{polls: 3}
	srv := httptest.NewServer(http.HandlerFunc(fake.handle))
	defer srv.Close()
	sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String(), NameSalt: "s"}

	node, err := CopyDataroomNodeByID(context.Background(), newExportTestClient(srv), "n-src", nil, "copy.bin", sess)
	if err != nil {
		t.Fatal(err)
	}
	if node.ID != "n-copy" || node.Name != "copy.bin" || node.Type != "file" || node.Size != 9 ||
		node.ChunkCount != 2 || node.VersionID != "v-copy" || node.Mode() != 0o640 ||
		!node.ModTime().Equal(time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)) {
		t.Errorf("node = %+v (mode %v, mod %v)", node, node.Mode(), node.ModTime())
	}
	if fake.reads != 3 {
		t.Errorf("version polled %d times, want 3", fake.reads)
	}
}

// A version that disappears while polled means a discarded copy (404) or a
// deleted target (410).
func TestCopyDataroomNodeByID_Vanishes(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	copyPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { copyPollInterval = time.Second })
	for status, want := range map[int]error{http.StatusNotFound: ErrCopyDiscarded, http.StatusGone: ErrCopyTargetDeleted} {
		fake := &copyAPI{polls: 10, vanish: status}
		srv := httptest.NewServer(http.HandlerFunc(fake.handle))
		sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}
		_, err := CopyDataroomNodeByID(context.Background(), newExportTestClient(srv), "n-src", nil, "c", sess)
		srv.Close()
		if !errors.Is(err, want) {
			t.Errorf("status %d: err = %v, want %v", status, err, want)
		}
	}
}

// A copy still running when the context ends stops polling with the
// context's error; the server finishes it on its own.
func TestCopyDataroomNodeByID_Cancelled(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	copyPollInterval = 50 * time.Millisecond
	t.Cleanup(func() { copyPollInterval = time.Second })
	fake := &copyAPI{polls: 1000}
	srv := httptest.NewServer(http.HandlerFunc(fake.handle))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	sess := &DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}
	_, err = CopyDataroomNodeByID(ctx, newExportTestClient(srv), "n-src", nil, "c", sess)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

// Copying needs two paths of one dataroom; the source must be a file.
func TestCopyDataroomNode_Validation(t *testing.T) {
	_, err := CopyDataroomNode(context.Background(), nil, nil, "retyc://a/x", "retyc://b/y", nil)
	if err == nil || err.Error() != "source and destination must be in the same dataroom" {
		t.Errorf("cross-dataroom err = %v", err)
	}
	identity, _ := crypto.GenerateKeyPair()
	fake := newMimeAPI(t, identity)
	srv := fake.server()
	sess := fake.session()
	fake.nodes = []api.DataroomNodeItem{
		{Node: api.DataroomNode{ID: "n-d", Type: api.NodeTypeFolder, NameEnc: "x", NameHash: nodeNameHash("d", "salt")}},
	}
	_, err = CopyDataroomNodeWithSession(context.Background(), newExportTestClient(srv), "dr1", "/d", "/e", sess)
	if err == nil || err.Error() != "/d is a folder: server-side copy applies to files only" {
		t.Errorf("folder err = %v", err)
	}
	_, err = CopyDataroomNodeWithSession(context.Background(), newExportTestClient(srv), "dr1", "/", "/e", sess)
	if err == nil || err.Error() != "cannot copy the root folder" {
		t.Errorf("root err = %v", err)
	}
}
