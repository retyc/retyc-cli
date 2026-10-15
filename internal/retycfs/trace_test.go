//go:build linux

package retycfs

import (
	"go.opentelemetry.io/otel/codes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/telemetry/telemetrytest"
)

// spanAttr returns the string value of an attribute of s.
func spanAttr(s tracetest.SpanStub, key string) string {
	for _, kv := range s.Attributes {
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}

	return ""
}

// The privacy rule of the traces holds for the driver: no span a FUSE
// operation emits carries a file name, a folder name, a path, a link target
// or a dataroom title. Every name of the tree holds the sentinel.
func TestTracing_NoNameInAnySpan(t *testing.T) {
	const sentinel = "ZZSECRETZZ"
	exporter := telemetrytest.Install(t)

	a := newFakeAPI(t)
	dr := a.dataroom("dr1", "Title "+sentinel)
	folder := a.dir(dr, "", "folder-"+sentinel)
	file := a.file(dr, folder, "file-"+sentinel+".txt", testData(2*testChunkSize+10, 0))
	a.put(dr, folder, "link-"+sentinel, fakeNode{kind: api.NodeTypeSymlink, target: "target-" + sentinel})
	other := a.dataroom("dr2", "Other "+sentinel)
	a.file(other, "", "other-"+sentinel, []byte("x"))

	m := mountFS(t, a, mountOptions{driver: Options{All: true}})
	entries, err := os.ReadDir(m.dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("ReadDir = %v, %v", entries, err)
	}
	root := filepath.Join(m.dir, "Title "+sentinel)
	dir := filepath.Join(root, "folder-"+sentinel)
	if _, err := os.ReadDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "file-"+sentinel+".txt")
	if _, err := readFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path); err != nil { // from the page cache
		t.Fatal(err)
	}
	if _, err := os.Readlink(filepath.Join(dir, "link-"+sentinel)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "missing-"+sentinel)); err == nil {
		t.Fatal("missing name found")
	}
	if _, err := os.Lstat(filepath.Join(m.dir, "Other "+sentinel, "other-"+sentinel)); err != nil {
		t.Fatal(err)
	}
	// A name asked of the API and missing there: an answer, not an error.
	if _, err := os.Lstat(filepath.Join(root, "absent-"+sentinel)); err == nil {
		t.Fatal("missing name found")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	if _, err := getxattr(t, path, xattrMIME); err != nil {
		t.Fatal(err)
	}
	// Writes: a file created with a mode of its own, a folder, a rename, a
	// change of time, a removal.
	created := filepath.Join(dir, "new-"+sentinel)
	if err := os.WriteFile(created, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir-"+sentinel), 0o750); err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(dir, "dir-"+sentinel, "moved-"+sentinel)
	if err := os.Rename(created, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(renamed, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatal(err)
	}
	if err := m.srv.Unmount(); err != nil {
		t.Fatalf("Unmount: %v", err)
	}

	spans := exporter.GetSpans()
	telemetrytest.AssertNoLeak(t, spans, sentinel)
	lookups := 0
	for _, span := range spans {
		if span.Name != "FUSE lookup" {
			continue
		}
		lookups++
		if span.Status.Code == codes.Error {
			t.Errorf("a lookup span is an error: %q", span.Status.Description)
		}
	}
	if lookups == 0 {
		t.Error("no lookup span: the missing name was not asked of the API")
	}
	// The names the driver itself could add: none of them in a span either.
	telemetrytest.AssertNoLeak(t, spans, m.dir)
	if logs := m.logs.text(); strings.Contains(logs, sentinel) {
		t.Errorf("the driver's log holds a name:\n%s", logs)
	}

	// The operations that reached the API have their root span, with
	// identifiers only; those answered from memory have none.
	byName := map[string][]tracetest.SpanStub{}
	for _, s := range spans {
		byName[s.Name] = append(byName[s.Name], s)
		if !strings.HasPrefix(s.Name, "FUSE ") {
			continue
		}
		if s.Parent.IsValid() {
			t.Errorf("%s is not a root span", s.Name)
		}
		if s.ChildSpanCount == 0 {
			t.Errorf("%s was exported without having reached the API", s.Name)
		}
		if op := spanAttr(s, string(telemetry.AttrFuseOp)); "FUSE "+op != s.Name {
			t.Errorf("%s carries the operation %q", s.Name, op)
		}
	}
	for _, name := range []string{"FUSE readdir", "FUSE lookup", "FUSE read", "FUSE statfs"} {
		if len(byName[name]) == 0 {
			t.Errorf("no %q span; got %v", name, spanNames(byName))
		}
	}
	for _, name := range []string{"FUSE getattr", "FUSE readlink", "FUSE opendir", "FUSE release"} {
		if len(byName[name]) != 0 {
			t.Errorf("%d %q spans, want none", len(byName[name]), name)
		}
	}
	// Three chunks, three reads that started a download at most: not one
	// span per read request of the kernel.
	if n := len(byName["FUSE read"]); n > 3 {
		t.Errorf("%d FUSE read spans for a file of 3 chunks", n)
	}
	for _, s := range byName["FUSE read"] {
		if spanAttr(s, string(telemetry.AttrNodeID)) != file.id ||
			spanAttr(s, string(telemetry.AttrVersionID)) != file.version ||
			spanAttr(s, string(telemetry.AttrDataroomID)) != "dr1" {
			t.Errorf("FUSE read attributes = %v", s.Attributes)
		}
	}
}

func spanNames(byName map[string][]tracetest.SpanStub) []string {
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}

	return names
}
