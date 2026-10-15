package memstore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

func entryKey(dataroomID, parent, name string) metastore.EntryKey {
	return metastore.EntryKey{DataroomID: dataroomID, ParentPath: parent, Name: name}
}

func hasEntry(t *testing.T, s *Store, k metastore.EntryKey) bool {
	t.Helper()
	_, ok, err := s.GetEntry(context.Background(), k)
	if err != nil {
		t.Fatalf("GetEntry: %v", err)
	}

	return ok
}

// An entry is stored as given, positive or negative, and replaced by the next
// one put under its key.
func TestStore_Entries(t *testing.T) {
	s := New()
	ctx := context.Background()
	k := entryKey("dr1", "/a", "x")
	if hasEntry(t, s, k) {
		t.Fatal("an empty store holds an entry")
	}

	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	node := metastore.Node{ID: "n1", ParentID: "d-a", Name: "x", Type: metastore.TypeFile, CreatedAt: at}
	if err := s.PutEntry(ctx, k, &metastore.Entry{Node: &node, FetchedAt: at}); err != nil {
		t.Fatalf("PutEntry: %v", err)
	}
	got, ok, _ := s.GetEntry(ctx, k)
	if !ok || got.Node == nil || *got.Node != node || !got.FetchedAt.Equal(at) {
		t.Errorf("GetEntry = (%+v, %v), want the positive entry as stored", got, ok)
	}

	if err := s.PutEntry(ctx, k, &metastore.Entry{FetchedAt: at.Add(time.Second)}); err != nil {
		t.Fatalf("PutEntry: %v", err)
	}
	got, ok, _ = s.GetEntry(ctx, k)
	if !ok || got.Node != nil || !got.FetchedAt.Equal(at.Add(time.Second)) {
		t.Errorf("GetEntry = (%+v, %v), want the negative entry that replaced it", got, ok)
	}
	// The same name in another folder or another dataroom is another entry.
	if hasEntry(t, s, entryKey("dr1", "/b", "x")) || hasEntry(t, s, entryKey("dr2", "/a", "x")) {
		t.Error("an entry leaked to another folder or dataroom")
	}
}

// entryKeys are the entries the deletion tests start from.
var entryKeys = []metastore.EntryKey{
	entryKey("dr1", "/", "a"), entryKey("dr1", "/a", "x"), entryKey("dr1", "/a", "y"),
	entryKey("dr1", "/a/b", "z"), entryKey("dr1", "/ab", "x"), entryKey("dr2", "/a", "x"),
}

func filledStore(t *testing.T) *Store {
	t.Helper()
	s := New()
	for _, k := range entryKeys {
		if err := s.PutEntry(context.Background(), k, &metastore.Entry{FetchedAt: time.Now()}); err != nil {
			t.Fatalf("PutEntry: %v", err)
		}
	}

	return s
}

// entriesLeft lists the entries of entryKeys the store still holds.
func entriesLeft(t *testing.T, s *Store) string {
	t.Helper()
	var out []string
	for _, k := range entryKeys {
		if hasEntry(t, s, k) {
			out = append(out, k.DataroomID+":"+k.ParentPath+":"+k.Name)
		}
	}

	return fmt.Sprint(out)
}

// DeleteEntries drops the entries of one folder; DeleteEntriesBelow those of
// a folder and of every folder below it, and of no sibling.
func TestStore_DeleteEntries(t *testing.T) {
	ctx := context.Background()

	s := filledStore(t)
	if err := s.DeleteEntries(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("DeleteEntries: %v", err)
	}
	if got, want := entriesLeft(t, s), "[dr1:/:a dr1:/a/b:z dr1:/ab:x dr2:/a:x]"; got != want {
		t.Errorf("after DeleteEntries(/a): %s, want %s", got, want)
	}

	s = filledStore(t)
	if err := s.DeleteEntriesBelow(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("DeleteEntriesBelow: %v", err)
	}
	if got, want := entriesLeft(t, s), "[dr1:/:a dr1:/ab:x dr2:/a:x]"; got != want {
		t.Errorf("after DeleteEntriesBelow(/a): %s, want %s", got, want)
	}

	s = filledStore(t)
	if err := s.DeleteEntriesBelow(ctx, "dr1", "/"); err != nil {
		t.Fatalf("DeleteEntriesBelow: %v", err)
	}
	if got, want := entriesLeft(t, s), "[dr2:/a:x]"; got != want {
		t.Errorf("after DeleteEntriesBelow(/): %s, want %s", got, want)
	}
}

// Entries and listings are apart: dropping the ones leaves the others.
func TestStore_EntriesAndListingsAreApart(t *testing.T) {
	ctx := context.Background()
	s := filledStore(t)
	put(t, s, key("dr1", "/a"), "x")
	if err := s.DeleteSubtree(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("DeleteSubtree: %v", err)
	}
	if !hasEntry(t, s, entryKey("dr1", "/a", "x")) {
		t.Error("DeleteSubtree dropped entries: it is an operation on listings")
	}
	put(t, s, key("dr1", "/a"), "x")
	if err := s.DeleteEntriesBelow(ctx, "dr1", "/a"); err != nil {
		t.Fatalf("DeleteEntriesBelow: %v", err)
	}
	if !has(t, s, key("dr1", "/a")) {
		t.Error("DeleteEntriesBelow dropped a listing")
	}
}

// The list of datarooms is stored as given and replaced as a whole.
func TestStore_Datarooms(t *testing.T) {
	s := New()
	ctx := context.Background()
	if list, ok, err := s.GetDatarooms(ctx); err != nil || ok || list != nil {
		t.Fatalf("GetDatarooms on an empty store = (%+v, %v, %v)", list, ok, err)
	}
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	first := &metastore.DataroomList{
		Items:     []metastore.DataroomInfo{{ID: "id-1", Title: "Docs", DisplayName: "Docs"}},
		FetchedAt: at,
	}
	if err := s.PutDatarooms(ctx, first); err != nil {
		t.Fatalf("PutDatarooms: %v", err)
	}
	got, ok, _ := s.GetDatarooms(ctx)
	if !ok || len(got.Items) != 1 || got.Items[0] != first.Items[0] || !got.FetchedAt.Equal(at) {
		t.Errorf("GetDatarooms = (%+v, %v), want the list as stored", got, ok)
	}
	if err := s.PutDatarooms(ctx, &metastore.DataroomList{FetchedAt: at.Add(time.Minute)}); err != nil {
		t.Fatalf("PutDatarooms: %v", err)
	}
	if got, _, _ := s.GetDatarooms(ctx); len(got.Items) != 0 || !got.FetchedAt.Equal(at.Add(time.Minute)) {
		t.Errorf("GetDatarooms = %+v, want the list that replaced it", got)
	}
}

// Entries and the dataroom list are safe for concurrent use.
func TestStore_EntriesConcurrent(t *testing.T) {
	s := New()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			k := entryKey("dr1", fmt.Sprintf("/d%d", i%3), fmt.Sprintf("n%d", i))
			for range 100 {
				_ = s.PutEntry(ctx, k, &metastore.Entry{FetchedAt: time.Now()})
				_, _, _ = s.GetEntry(ctx, k)
				_ = s.DeleteEntries(ctx, "dr1", k.ParentPath)
				_ = s.DeleteEntriesBelow(ctx, "dr1", "/")
				_ = s.PutDatarooms(ctx, &metastore.DataroomList{FetchedAt: time.Now()})
				_, _, _ = s.GetDatarooms(ctx)
			}
		})
	}
	wg.Wait()
}

// PutEntryIf stores under the generation of the folder's listing only, and
// leaves that generation as it is.
func TestPutEntryIf(t *testing.T) {
	ctx := context.Background()
	s := New()
	folder := metastore.ListingKey{DataroomID: "dr1", Path: "/d"}
	ek := metastore.EntryKey{DataroomID: "dr1", ParentPath: "/d", Name: "x"}
	gen, _ := s.Generation(ctx, folder)

	if stored, err := s.PutEntryIf(ctx, ek, &metastore.Entry{}, gen+1); stored || err != nil {
		t.Fatalf("PutEntryIf under another generation = (%v, %v), want refused", stored, err)
	}
	if _, ok, _ := s.GetEntry(ctx, ek); ok {
		t.Fatal("a refused entry was stored")
	}
	if stored, err := s.PutEntryIf(ctx, ek, &metastore.Entry{}, gen); !stored || err != nil {
		t.Fatalf("PutEntryIf under the current generation = (%v, %v), want stored", stored, err)
	}
	if now, _ := s.Generation(ctx, folder); now != gen {
		t.Errorf("generation after PutEntryIf = %d, want %d unchanged", now, gen)
	}

	// Any write to the folder's listing makes the generation read stale; one
	// to another folder does not.
	if _, err := s.RemoveNode(ctx, metastore.ListingKey{DataroomID: "dr1", Path: "/other"}, "x"); err != nil {
		t.Fatal(err)
	}
	if stored, _ := s.PutEntryIf(ctx, ek, &metastore.Entry{}, gen); !stored {
		t.Error("a write to another folder refused the entry")
	}
	if _, err := s.RemoveNode(ctx, folder, "x"); err != nil {
		t.Fatal(err)
	}
	if stored, _ := s.PutEntryIf(ctx, ek, &metastore.Entry{}, gen); stored {
		t.Error("an entry looked up before a write to its folder was stored")
	}
}
