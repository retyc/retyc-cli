package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// A listing comes with the dataroom's ETag; handing it back answers
// api.ErrNotModified while the dataroom has not changed, and the new listing
// with its new ETag once it has.
func TestListNodesByIDIfChanged(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	nameEnc, _ := crypto.EncryptStringForKeys("sub", []string{pub})
	revision := 3
	var conditions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := fmt.Sprintf(`W/"r%d"`, revision)
		conditions = append(conditions, r.Header.Get("If-None-Match"))
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)

			return
		}
		fmt.Fprintf(w, `{"items":[{"node":{"id":"n-sub","type":"folder","name_hash":"h","name_enc":%q,`+
			`"type_enc":null,"access_mode":"0755","parent_id":null},"node_version":null}],`+
			`"total":1,"page":1,"size":100,"pages":1}`, nameEnc)
	}))
	defer srv.Close()
	client := newExportTestClient(srv)
	sess := &DataroomSession{Identity: identity, PublicKey: pub, NameSalt: "s"}
	ctx := context.Background()

	nodes, etag, err := ListNodesByIDIfChanged(ctx, client, "dr1", nil, sess, "")
	if err != nil || len(nodes) != 1 || nodes[0].Name != "sub" || etag != `W/"r3"` {
		t.Fatalf("first listing = %+v, %q, %v; want sub and W/\"r3\"", nodes, etag, err)
	}
	if _, _, err = ListNodesByIDIfChanged(ctx, client, "dr1", nil, sess, etag); !errors.Is(err, api.ErrNotModified) {
		t.Fatalf("unchanged dataroom: err = %v, want api.ErrNotModified", err)
	}
	revision = 4
	nodes, etag, err = ListNodesByIDIfChanged(ctx, client, "dr1", nil, sess, etag)
	if err != nil || len(nodes) != 1 || etag != `W/"r4"` {
		t.Fatalf("changed dataroom = %+v, %q, %v; want the listing and W/\"r4\"", nodes, etag, err)
	}
	if want := []string{"", `W/"r3"`, `W/"r3"`}; fmt.Sprint(conditions) != fmt.Sprint(want) {
		t.Errorf("If-None-Match sent = %q, want %q", conditions, want)
	}
}

// A folder larger than the limit is refused on its first page, the only one
// requested, whether the API reports it through the total or the page count;
// a folder of exactly the limit is listed.
func TestListNodesByIDWithin(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	var total, pages int
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprintf(w, `{"items":[],"total":%d,"page":1,"size":100,"pages":%d}`, total, pages)
	}))
	defer srv.Close()
	client := newExportTestClient(srv)
	sess := &DataroomSession{Identity: identity, PublicKey: pub, NameSalt: "s"}
	ctx := context.Background()

	for _, tc := range []struct {
		name         string
		total, pages int
		tooLarge     bool
	}{
		{"total over the limit", 301, 1, true},
		{"pages over the limit, no total", 0, 4, true},
		{"at the limit", 300, 1, false},
	} {
		total, pages = tc.total, tc.pages
		requests.Store(0)
		_, _, err := ListNodesByIDWithin(ctx, client, "dr1", nil, sess, "", 300)
		if got := errors.Is(err, ErrFolderTooLarge); got != tc.tooLarge || (!tc.tooLarge && err != nil) {
			t.Errorf("%s: err = %v, want too large = %v", tc.name, err, tc.tooLarge)
		}
		if got := requests.Load(); got != 1 {
			t.Errorf("%s: %d pages requested, want 1", tc.name, got)
		}
	}
	// No limit: the same folder is listed, every page of it.
	total, pages = 301, 4
	requests.Store(0)
	if _, _, err := ListNodesByIDIfChanged(ctx, client, "dr1", nil, sess, ""); err != nil || requests.Load() != 4 {
		t.Errorf("without a limit: err = %v after %d pages, want the 4 pages listed", err, requests.Load())
	}
}
