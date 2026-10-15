package vfs

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/service"
)

// A hidden node is absent whatever the API lists, by its ID: a node created
// under its name is not. Revealed as not deleted it is back; revealed as
// deleted it stays absent from a listing answered late.
func TestHideNode(t *testing.T) {
	listed := []service.DataroomNodeInfo{{ID: "n1", Name: "a", Type: "file"}, {ID: "n2", Name: "b", Type: "file"}}
	fs := New(nil, Options{
		List: func(context.Context, string, string) ([]service.DataroomNodeInfo, error) {
			return listed, nil
		},
		TTL: time.Minute, FetchTimeout: time.Minute,
	})
	ctx := context.Background()
	names := func() []string {
		t.Helper()
		nodes, err := fs.ReadDir(ctx, "dr1", "/")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, n := range nodes {
			out = append(out, n.ID+":"+n.Name)
		}

		return out
	}
	want := func(when string, ids ...string) {
		t.Helper()
		got := names()
		if len(got) != len(ids) {
			t.Fatalf("%s: listing = %v, want %v", when, got, ids)
		}
		for i := range ids {
			if got[i] != ids[i] {
				t.Fatalf("%s: listing = %v, want %v", when, got, ids)
			}
		}
	}
	want("at first", "n1:a", "n2:b")

	fs.HideNode("dr1", "/", Node{ID: "n1", Name: "a"})
	want("hidden, from the cache", "n2:b")
	if _, err := fs.Lookup(ctx, "dr1", "/", "a"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Lookup of a hidden node = %v, want not found", err)
	}
	fs.InvalidateListing("dr1", "/")
	want("hidden, the API still lists it", "n2:b")
	if l := cachedListing(fs, "dr1", "/"); l == nil || l.ETag != "" {
		t.Errorf("the filtered listing = %+v, want one without ETag", l)
	}

	// The same name under another node is not hidden.
	listed = append(listed, service.DataroomNodeInfo{ID: "n3", Name: "a", Type: "file"})
	fs.InvalidateListing("dr1", "/")
	want("another node under the name", "n2:b", "n3:a")
	listed = listed[:2]

	fs.RevealNode("dr1", "/", "n1", false)
	want("not deleted after all", "n1:a", "n2:b")

	fs.HideNode("dr1", "/", Node{ID: "n2", Name: "b"})
	fs.RevealNode("dr1", "/", "n2", true)
	fs.InvalidateListing("dr1", "/")
	want("deleted, a listing answered before the delete", "n1:a")

	// Forgotten once no request can name it any more.
	fs.mu.Lock()
	fs.hidden["n2"] = time.Now().Add(-time.Second)
	fs.hiddenPruned = time.Time{}
	fs.pruneHiddenLocked()
	left := len(fs.hidden)
	fs.unlock()
	if left != 0 {
		t.Errorf("%d hidden nodes left after the prune", left)
	}
}
