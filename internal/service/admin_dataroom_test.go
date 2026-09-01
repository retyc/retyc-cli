package service

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// encName encrypts a node name for the given recipient, as the platform does.
func encName(t *testing.T, name, pubKey string) string {
	t.Helper()
	enc, err := crypto.EncryptStringForKeys(name, []string{pubKey})
	if err != nil {
		t.Fatal(err)
	}

	return enc
}

func ptr[T any](v T) *T { return &v }

func TestBuildAdminNodeTree(t *testing.T) {
	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := sess.Recipient().String()

	size := int64(42)
	chunks := 1
	version := 3
	nodes := []api.AdminDataroomNode{
		{ID: "root-folder", IsFolder: true, NameEnc: encName(t, "docs", pub)},
		{ID: "child-file", ParentID: ptr("root-folder"), NameEnc: encName(t, "report.pdf", pub),
			OriginalSize: &size, ChunkCount: &chunks, VersionNumber: &version, VersionID: ptr("v1")},
		{ID: "top-file", NameEnc: encName(t, "readme.md", pub), OriginalSize: &size, ChunkCount: &chunks,
			VersionNumber: ptr(1), VersionID: ptr("v2")},
	}

	infos, err := buildAdminNodeTree(nodes, sess)
	if err != nil {
		t.Fatalf("buildAdminNodeTree() error = %v", err)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Path < infos[j].Path })

	want := []struct {
		path     string
		isFolder bool
	}{
		{"/docs", true},
		{"/docs/report.pdf", false},
		{"/readme.md", false},
	}
	if len(infos) != len(want) {
		t.Fatalf("got %d nodes, want %d: %+v", len(infos), len(want), infos)
	}
	for i, w := range want {
		if infos[i].Path != w.path || infos[i].IsFolder != w.isFolder {
			t.Errorf("node %d = {%s %v}, want {%s %v}", i, infos[i].Path, infos[i].IsFolder, w.path, w.isFolder)
		}
	}
	if infos[1].Size != 42 || infos[1].ChunkCount != 1 || !infos[1].HasContent {
		t.Errorf("file info = %+v", infos[1])
	}
	if infos[0].HasContent {
		t.Error("folder should not have content")
	}
}

func TestBuildAdminNodeTree_OrphanParent(t *testing.T) {
	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nodes := []api.AdminDataroomNode{
		{ID: "n1", ParentID: ptr("missing"), NameEnc: encName(t, "lost.txt", sess.Recipient().String())},
	}
	infos, err := buildAdminNodeTree(nodes, sess)
	if err != nil {
		t.Fatalf("buildAdminNodeTree() error = %v", err)
	}
	// An orphan is rooted at "/" rather than dropped: admin must see everything.
	if len(infos) != 1 || infos[0].Path != "/lost.txt" {
		t.Errorf("infos = %+v, want lost.txt at root", infos)
	}
}

// TestBuildAdminNodeTree_ParentCycle guards the nodePath depth guard: two nodes
// whose ParentID point at each other bypass the orphan check entirely (both
// parents are present in the batch), so only the depth guard prevents infinite
// recursion. This must terminate and must not drop either node.
func TestBuildAdminNodeTree_ParentCycle(t *testing.T) {
	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := sess.Recipient().String()

	nodes := []api.AdminDataroomNode{
		{ID: "a", ParentID: ptr("b"), NameEnc: encName(t, "a.txt", pub)},
		{ID: "b", ParentID: ptr("a"), NameEnc: encName(t, "b.txt", pub)},
	}

	type result struct {
		infos []AdminNodeInfo
		err   error
	}
	done := make(chan result, 1)
	go func() {
		infos, err := buildAdminNodeTree(nodes, sess)
		done <- result{infos, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("buildAdminNodeTree() error = %v", r.err)
		}
		if len(r.infos) != 2 {
			t.Fatalf("got %d nodes, want 2: %+v", len(r.infos), r.infos)
		}
		for _, info := range r.infos {
			if info.Path == "" {
				t.Errorf("node %+v has empty Path", info)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("buildAdminNodeTree() did not return: parent_id cycle likely caused infinite recursion")
	}
}

// TestBuildAdminNodeTree_MaliciousName guards against path traversal: a
// dataroom owner controls decrypted node names, so a name like "../evil.sh"
// must never be able to escape the root when building on-disk/display paths.
func TestBuildAdminNodeTree_MaliciousName(t *testing.T) {
	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := sess.Recipient().String()

	nodes := []api.AdminDataroomNode{
		{ID: "n1", NameEnc: encName(t, "../evil.sh", pub)},
	}
	infos, err := buildAdminNodeTree(nodes, sess)
	if err != nil {
		t.Fatalf("buildAdminNodeTree() error = %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d nodes, want 1", len(infos))
	}
	if strings.Contains(infos[0].Path, "..") {
		t.Errorf("Path = %q, must not contain \"..\"", infos[0].Path)
	}
	if !strings.HasPrefix(infos[0].Path, "/") {
		t.Errorf("Path = %q, must stay rooted at \"/\"", infos[0].Path)
	}
}

// TestBuildAdminNodeTree_MaliciousFolderName covers a folder literally named
// ".." with a child file: the child's path must stay under the root too.
func TestBuildAdminNodeTree_MaliciousFolderName(t *testing.T) {
	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := sess.Recipient().String()

	nodes := []api.AdminDataroomNode{
		{ID: "folder", IsFolder: true, NameEnc: encName(t, "..", pub)},
		{ID: "child", ParentID: ptr("folder"), NameEnc: encName(t, "evil.sh", pub)},
	}
	infos, err := buildAdminNodeTree(nodes, sess)
	if err != nil {
		t.Fatalf("buildAdminNodeTree() error = %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d nodes, want 2: %+v", len(infos), infos)
	}
	for _, info := range infos {
		if strings.Contains(info.Path, "..") {
			t.Errorf("Path = %q, must not contain \"..\"", info.Path)
		}
		if !strings.HasPrefix(info.Path, "/") {
			t.Errorf("Path = %q, must stay rooted at \"/\"", info.Path)
		}
	}
}

func TestBuildAdminNodeTree_UndecryptableName(t *testing.T) {
	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nodes := []api.AdminDataroomNode{
		{ID: "n1", NameEnc: encName(t, "secret.txt", other.Recipient().String())},
	}
	_, err = buildAdminNodeTree(nodes, sess)
	if err == nil {
		t.Fatal("expected error for a name encrypted for another key")
	}
}

func TestMatchAdminNodes(t *testing.T) {
	nodes := []AdminNodeInfo{
		{ID: "d1", Path: "/docs", Name: "docs", IsFolder: true},
		{ID: "f1", Path: "/docs/report.pdf", Name: "report.pdf", HasContent: true},
		{ID: "f2", Path: "/docs/notes.txt", Name: "notes.txt", HasContent: true},
		{ID: "f3", Path: "/readme.md", Name: "readme.md", HasContent: true},
		{ID: "f4", Path: "/empty.bin", Name: "empty.bin", HasContent: false},
	}

	t.Run("empty pattern selects every file with content", func(t *testing.T) {
		files, skipped, err := matchAdminNodes(nodes, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 3 {
			t.Errorf("files = %+v, want 3 entries", files)
		}
		if len(skipped) != 0 {
			t.Errorf("skipped = %v", skipped)
		}
	})

	t.Run("glob on path", func(t *testing.T) {
		files, _, err := matchAdminNodes(nodes, "/docs/*.pdf")
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 1 || files[0].ID != "f1" {
			t.Errorf("files = %+v", files)
		}
	})

	t.Run("glob matching a folder reports it skipped", func(t *testing.T) {
		files, skipped, err := matchAdminNodes(nodes, "/docs")
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 0 || len(skipped) != 1 || skipped[0] != "/docs" {
			t.Errorf("files = %+v, skipped = %v", files, skipped)
		}
	})

	t.Run("no match is an error", func(t *testing.T) {
		if _, _, err := matchAdminNodes(nodes, "/nope/*"); err == nil {
			t.Error("expected error for no match")
		}
	})
}
