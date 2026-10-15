package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/vfs"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
	"github.com/retyc/retyc-cli/internal/vfs/metastore/memstore"
)

// countingStore counts the lookups of one name a store is asked for.
type countingStore struct {
	metastore.MetaStore

	nodes atomic.Int64
}

func (s *countingStore) GetNode(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, error) {
	s.nodes.Add(1)

	return s.MetaStore.GetNode(ctx, key, name)
}

func (s *countingStore) GetNamed(
	ctx context.Context, key metastore.ListingKey, name string,
) (*metastore.Node, metastore.ListingMeta, bool, *metastore.Entry, bool, error) {
	s.nodes.Add(1)

	return s.MetaStore.GetNamed(ctx, key, name)
}

// A PROPFIND of a folder reads its listing once and answers for its children
// from it: no lookup by name per child, each of which is a round trip when
// the store is over the network.
func TestPropfind_ChildrenAreAnsweredFromTheListing(t *testing.T) {
	const children = 50
	store := &countingStore{MetaStore: memstore.New()}
	// The API answers nothing: the quota is then reported unknown.
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	client := api.New(srv.URL, "retyc-test/1.0", oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour),
	}), false, false)
	fs := newWebdavFS(client, vfs.Options{Store: store})
	fs.tree.SeedDatarooms([]vfs.Dataroom{{ID: "dr1", Title: "DR"}})

	nodes := []vfs.Node{{ID: "link", Name: "link", Type: vfs.TypeSymlink, Target: "t"}}
	for i := range children {
		nodes = append(nodes, vfs.Node{ID: fmt.Sprintf("n%d", i), Name: fmt.Sprintf("f%02d.txt", i), Type: vfs.TypeFile})
	}
	nodes = append(nodes, vfs.Node{ID: "sub", Name: "sub", Type: vfs.TypeDir})
	ctx := context.Background()
	if err := store.PutListing(ctx, vfs.ListingKey{DataroomID: "dr1", Path: "/"},
		&vfs.Listing{Nodes: nodes, FetchedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("PROPFIND", "/dataroom/DR/", nil)
	req.Header.Set("Depth", "1")
	rec := httptest.NewRecorder()
	markReadRequests(newWebdavHandler(fs, webdav.NewMemLS(), nil)).ServeHTTP(rec, req)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if got := strings.Count(body, "<D:response>"); got != children+2 {
		t.Errorf("%d responses, want %d (the folder, its files and its sub-folder; never the symlink)", got, children+2)
	}
	if strings.Contains(body, "link") {
		t.Error("the symbolic link is listed")
	}
	if got := store.nodes.Load(); got > 2 {
		t.Errorf("%d lookups by name in the store for a listing of %d children, want none per child", got, children)
	}
}
