package vfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// — Helpers ———————————————————————————————————————————————————————————————————

// The times the store API gives what it creates.
var (
	storeNodeCreated    = time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	storeVersionCreated = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
)

// small is a size sent in a single request, chunked the smallest one that is
// not: a version and two chunks (a full one and one byte).
const (
	small   = 10
	chunked = service.SmallUploadMaxSize + 1
)

type storedNode struct {
	id, parent, hash, nameEnc string
	versions                  []string
	mode                      string // access_mode as sent, "" when none was
}

type storedVersion struct {
	id, nodeID string
	size       int64
	expected   int
	number     int
	mtime      string // client_mtime as sent, "" when none was
	chunks     map[int][]byte
}

// storeAPI is a fake API that keeps what is uploaded to it: the single-request
// route, node and version creation, chunk upload and download, deletion and
// the listing of a folder. It records every request as "METHOD path".
type storeAPI struct {
	t *testing.T

	mu       sync.Mutex
	calls    []string
	nodes    map[string]*storedNode
	versions map[string]*storedVersion
	seq      int
	// intercept answers a request in place of the store when it returns
	// true. It runs before the store is touched, without the lock: it may
	// block.
	intercept func(w http.ResponseWriter, r *http.Request) bool
}

func newStoreAPI(t *testing.T) *storeAPI {
	return &storeAPI{t: t, nodes: map[string]*storedNode{}, versions: map[string]*storedVersion{}}
}

func (a *storeAPI) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return slices.Clone(a.calls)
}

// count returns the number of requests whose "METHOD path" starts with prefix.
func (a *storeAPI) count(prefix string) int {
	n := 0
	for _, c := range a.list() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}

	return n
}

func (a *storeAPI) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = nil
}

func (a *storeAPI) setIntercept(fn func(w http.ResponseWriter, r *http.Request) bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.intercept = fn
}

// version returns a stored version.
func (a *storeAPI) version(id string) storedVersion {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.versions[id]
	if v == nil {
		a.t.Errorf("the API holds no version %q", id)

		return storedVersion{}
	}

	return *v
}

// nodeVersions returns the versions a node holds, oldest first.
func (a *storeAPI) nodeVersions(nodeID string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := a.nodes[nodeID]; n != nil {
		return slices.Clone(n.versions)
	}

	return nil
}

// content returns the plaintext of a stored version, checking that it holds
// every chunk it announced.
func (a *storeAPI) content(identity *age.HybridIdentity, versionID string) []byte {
	a.t.Helper()
	v := a.version(versionID)
	if len(v.chunks) != v.expected {
		a.t.Errorf("version %s holds %d chunks, announced %d", versionID, len(v.chunks), v.expected)
	}
	var out []byte
	for i := 0; i < v.expected; i++ {
		plain, err := crypto.DecryptBinary(v.chunks[i], identity)
		if err != nil {
			a.t.Errorf("decrypting chunk %d of %s: %v", i, versionID, err)

			return nil
		}
		out = append(out, plain...)
	}
	if int64(len(out)) != v.size {
		a.t.Errorf("version %s holds %d bytes, announced %d", versionID, len(out), v.size)
	}

	return out
}

func (a *storeAPI) nextID(prefix string) string {
	a.seq++

	return fmt.Sprintf("%s-%d", prefix, a.seq)
}

func (a *storeAPI) findLocked(parent, hash string) *storedNode {
	for _, n := range a.nodes {
		if n.parent == parent && n.hash == hash {
			return n
		}
	}

	return nil
}

func (a *storeAPI) addVersionLocked(n *storedNode, size int64, expected int, mtime string) *storedVersion {
	v := &storedVersion{
		id: a.nextID("v"), nodeID: n.id, size: size, expected: expected, mtime: mtime,
		number: len(n.versions) + 1, chunks: map[int][]byte{},
	}
	a.versions[v.id] = v
	n.versions = append(n.versions, v.id)

	return v
}

func nodeJSON(n *storedNode) map[string]any {
	node := map[string]any{
		"id": n.id, "name_enc": n.nameEnc, "type_enc": "x", "parent_id": nil,
		"created_at": storeNodeCreated.Format(time.RFC3339),
	}
	if n.parent != "" {
		node["parent_id"] = n.parent
	}
	if n.mode != "" {
		node["access_mode"] = n.mode
	}

	return node
}

func versionJSON(v *storedVersion) map[string]any {
	version := map[string]any{
		"id": v.id, "node_id": v.nodeID, "original_size": v.size, "chunk_count": len(v.chunks),
		"chunk_count_expected": v.expected, "version_number": v.number,
		"created_at": storeVersionCreated.Format(time.RFC3339),
	}
	if v.mtime != "" {
		version["client_mtime"] = v.mtime
	}

	return version
}

func (a *storeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.calls = append(a.calls, r.Method+" "+r.URL.Path)
	intercept := a.intercept
	a.mu.Unlock()
	if intercept != nil && intercept(w, r) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node/file":
		a.createFile(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
		a.createNode(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr1/nodes":
		a.listNodes(w, r)
	case r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "version":
		a.createVersion(w, r, parts[2])
	case r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "copy":
		a.copyNode(w, r, parts[2])
	case len(parts) == 6 && parts[2] == "version" && parts[4] == "chunk":
		a.chunk(w, r, parts[3], parts[5])
	case r.Method == http.MethodPatch && len(parts) == 4 && parts[2] == "version":
		a.patchVersion(w, r, parts[3])
	case r.Method == http.MethodDelete && len(parts) == 4 && parts[2] == "version":
		a.deleteVersionLocked(parts[3])
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && len(parts) == 3:
		if n := a.nodes[parts[2]]; n != nil {
			for _, v := range n.versions {
				delete(a.versions, v)
			}
			delete(a.nodes, n.id)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}
}

func (a *storeAPI) deleteVersionLocked(id string) {
	v := a.versions[id]
	if v == nil {
		return
	}
	delete(a.versions, id)
	if n := a.nodes[v.nodeID]; n != nil {
		n.versions = slices.DeleteFunc(n.versions, func(s string) bool { return s == id })
	}
}

func (a *storeAPI) createFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil { //nolint:gosec // G120: test server
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}
	form := func(name string) string {
		if values := r.MultipartForm.Value[name]; len(values) > 0 {
			return values[0]
		}

		return ""
	}
	parent, hash := form("parent_id"), form("name_hash")
	size, _ := strconv.ParseInt(form("original_size"), 10, 64)
	n := a.findLocked(parent, hash)
	if n == nil {
		n = &storedNode{id: a.nextID("f"), parent: parent, hash: hash, nameEnc: form("name_enc")}
		a.nodes[n.id] = n
	}
	if mode := form("access_mode"); mode != "" {
		n.mode = mode
	}
	expected := 0
	var chunk []byte
	if files := r.MultipartForm.File["upload_file"]; len(files) > 0 {
		f, _ := files[0].Open()
		chunk, _ = io.ReadAll(f)
		expected = 1
	}
	v := a.addVersionLocked(n, size, expected, form("client_mtime"))
	if expected == 1 {
		v.chunks[0] = chunk
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node": nodeJSON(n), "node_version": versionJSON(v), "max_version_number": v.number, "capabilities": map[string]any{},
	})
}

func (a *storeAPI) createNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ParentID *string `json:"parent_id"`
		NameHash string  `json:"name_hash"`
		NameEnc  string  `json:"name_enc"`
		Mode     string  `json:"access_mode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	parent := ""
	if body.ParentID != nil {
		parent = *body.ParentID
	}
	if a.findLocked(parent, body.NameHash) != nil {
		http.Error(w, `{"detail":"Name hash conflict in a folder"}`, http.StatusConflict)

		return
	}
	n := &storedNode{id: a.nextID("f"), parent: parent, hash: body.NameHash, nameEnc: body.NameEnc, mode: body.Mode}
	a.nodes[n.id] = n
	_ = json.NewEncoder(w).Encode(nodeJSON(n))
}

// copyNode is the server-side copy: a new node whose one version holds the
// chunks of the current version of the source, complete at once.
func (a *storeAPI) copyNode(w http.ResponseWriter, r *http.Request, nodeID string) {
	var body struct {
		ParentID *string `json:"parent_id"`
		NameHash string  `json:"name_hash"`
		NameEnc  string  `json:"name_enc"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	parent := ""
	if body.ParentID != nil {
		parent = *body.ParentID
	}
	src := a.nodes[nodeID]
	switch {
	case src == nil || len(src.versions) == 0:
		http.Error(w, `{"detail":"Node not found"}`, http.StatusNotFound)

		return
	case a.findLocked(parent, body.NameHash) != nil:
		http.Error(w, `{"detail":"Name hash conflict in a folder"}`, http.StatusConflict)

		return
	}
	from := a.versions[src.versions[len(src.versions)-1]]
	n := &storedNode{id: a.nextID("f"), parent: parent, hash: body.NameHash, nameEnc: body.NameEnc, mode: src.mode}
	a.nodes[n.id] = n
	v := a.addVersionLocked(n, from.size, from.expected, from.mtime)
	maps.Copy(v.chunks, from.chunks)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"node": nodeJSON(n), "node_version": versionJSON(v)})
}

func (a *storeAPI) listNodes(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get("parent_id")
	items := []any{}
	for _, n := range a.nodes {
		if n.parent == parent {
			items = append(items, map[string]any{"node": nodeJSON(n), "node_version": nil})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "total": len(items), "pages": 1, "page": 1})
}

func (a *storeAPI) createVersion(w http.ResponseWriter, r *http.Request, nodeID string) {
	n := a.nodes[nodeID]
	if n == nil {
		http.Error(w, `{"detail":"Node not found"}`, http.StatusNotFound)

		return
	}
	var body struct {
		OriginalSize int64  `json:"original_size"`
		Expected     int    `json:"chunk_count_expected"`
		ClientMtime  string `json:"client_mtime"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	_ = json.NewEncoder(w).Encode(versionJSON(a.addVersionLocked(n, body.OriginalSize, body.Expected, body.ClientMtime)))
}

func (a *storeAPI) chunk(w http.ResponseWriter, r *http.Request, versionID, index string) {
	v := a.versions[versionID]
	i, _ := strconv.Atoi(index)
	if v == nil {
		http.Error(w, `{"detail":"Version not found"}`, http.StatusNotFound)

		return
	}
	if r.Method == http.MethodGet {
		data, ok := v.chunks[i]
		if !ok {
			http.Error(w, `{"detail":"Chunk not found"}`, http.StatusNotFound)

			return
		}
		_, _ = w.Write(data)

		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil { //nolint:gosec // G120: test server
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}
	if _, stored := v.chunks[i]; stored || i >= v.expected {
		http.Error(w, `{"detail":"Chunk refused"}`, http.StatusUnprocessableEntity)

		return
	}
	f, _ := r.MultipartForm.File["upload_file"][0].Open()
	v.chunks[i], _ = io.ReadAll(f)
	w.WriteHeader(http.StatusCreated)
}

func (a *storeAPI) patchVersion(w http.ResponseWriter, r *http.Request, versionID string) {
	v := a.versions[versionID]
	if v == nil {
		http.Error(w, `{"detail":"Version not found"}`, http.StatusNotFound)

		return
	}
	var body struct {
		ClientMtime string `json:"client_mtime"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	v.mtime = body.ClientMtime
	_ = json.NewEncoder(w).Encode(versionJSON(v))
}

// refuse makes an intercept that answers the requests whose "METHOD path"
// starts with prefix with status and body, the first times of them (all of
// them when times is negative).
func refuse(prefix string, code int, body string, times int) func(http.ResponseWriter, *http.Request) bool {
	var mu sync.Mutex

	return func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasPrefix(r.Method+" "+r.URL.Path, prefix) {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		if times == 0 {
			return false
		}
		times--
		http.Error(w, body, code)

		return true
	}
}

// writeFS is an FS on a storeAPI with an unlocked session for "dr1".
type writeFS struct {
	*FS
	api      *storeAPI
	identity *age.HybridIdentity
	logs     *logRecorder
}

// newWriteFS returns an FS on a new storeAPI, with the given listings cached.
// The dataroom has no lookup by name: a name is found in its listing.
func newWriteFS(t *testing.T, opts Options, listings map[string][]service.DataroomNodeInfo) *writeFS {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	fake := newStoreAPI(t)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false,
		api.WithRetry(time.Millisecond, 1), api.WithMissingChunkRetries())

	logs := &logRecorder{}
	opts.Logf = logs.logf
	if opts.SpoolDir == "" {
		opts.SpoolDir = t.TempDir()
	}
	fs := New(client, opts)
	t.Cleanup(func() { _ = fs.Close() })
	fs.SeedSession("dr1", (&service.DataroomSession{
		Identity: identity, PublicKey: identity.Recipient().String(),
	}).AssumeLegacyAPI())
	for path, nodes := range listings {
		seedNodeCache(fs, map[string]*nodeCacheEntry{path: {nodes: nodes, fetchedAt: time.Now()}})
	}

	return &writeFS{FS: fs, api: fake, identity: identity, logs: logs}
}

// emptyRoot is the listing of a dataroom that holds nothing.
func emptyRoot() map[string][]service.DataroomNodeInfo {
	return map[string][]service.DataroomNodeInfo{"/": {}}
}

// create sends data as the file at path and fails the test on an error.
func (w *writeFS) create(t *testing.T, path string, data []byte) Node {
	t.Helper()
	node, err := w.Create(context.Background(), "dr1", path, int64(len(data)), time.Time{}, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Create(%s, %d bytes): %v", path, len(data), err)
	}

	return node
}

// readBack reads the whole of node through FS.Open.
func (w *writeFS) readBack(t *testing.T, node Node) []byte {
	t.Helper()
	f, err := w.Open(context.Background(), "dr1", node)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.NewSectionReader(f, 0, node.Size))
	if err != nil {
		t.Fatalf("reading the file back: %v", err)
	}

	return data
}

func (w *writeFS) spool(t *testing.T, path string, existing *Node, truncate bool) *spool {
	t.Helper()
	s, err := w.OpenSpool(context.Background(), "dr1", path, existing, truncate)
	if err != nil {
		t.Fatalf("OpenSpool(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = s.Close() })

	return s.(*spool)
}

func mustWriteAt(t *testing.T, s Spool, data []byte, off int64) {
	t.Helper()
	if n, err := s.WriteAt(data, off); err != nil || n != len(data) {
		t.Fatalf("WriteAt(%d bytes at %d) = (%d, %v)", len(data), off, n, err)
	}
}

func mustFlush(t *testing.T, s Spool) Node {
	t.Helper()
	node, err := s.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}

	return node
}

func spoolContent(t *testing.T, s Spool) []byte {
	t.Helper()
	data := make([]byte, s.Size())
	if _, err := s.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt: %v", err)
	}

	return data
}

func wantCalls(t *testing.T, a *storeAPI, want ...string) {
	t.Helper()
	got := sortChunks(a.list())
	if want = sortChunks(want); !slices.Equal(got, want) {
		t.Errorf("requests:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// sortChunks sorts each run of chunk uploads: the chunks of a version are
// sent in parallel.
func sortChunks(calls []string) []string {
	calls = slices.Clone(calls)
	isChunk := func(c string) bool { return strings.Contains(c, "/chunk/") }
	for i := 0; i < len(calls); {
		j := i
		for j < len(calls) && isChunk(calls[j]) {
			j++
		}
		if j > i {
			slices.Sort(calls[i:j])
			i = j
		} else {
			i++
		}
	}

	return calls
}

func spoolFiles(t *testing.T, fs *FS) int {
	t.Helper()
	entries, err := os.ReadDir(fs.opts.SpoolDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	return len(entries)
}

// — Create ————————————————————————————————————————————————————————————————————

// A small file is one request, declares no modification time unless given
// one, and lands in the cached listing as a listing would report it.
func TestCreate_Small(t *testing.T) {
	fs := newWriteFS(t, Options{}, map[string][]service.DataroomNodeInfo{
		"/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"/a": {},
	})
	data := testData(small)
	node := fs.create(t, "/a/doc.txt", data)

	wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
	if node.Type != TypeFile || node.Name != "doc.txt" || node.Size != small || node.ChunkCount != 1 ||
		node.ParentID != "d-a" || node.MIMEType != "text/plain; charset=utf-8" && node.MIMEType != "text/plain" {
		t.Errorf("node = %+v", node)
	}
	if !node.CreatedAt.Equal(storeNodeCreated) || !node.ModTime.Equal(storeVersionCreated) {
		t.Errorf("CreatedAt = %v, ModTime = %v, want those of the API", node.CreatedAt, node.ModTime)
	}
	if v := fs.api.version(node.VersionID); v.mtime != "" {
		t.Errorf("client_mtime = %q, want none declared", v.mtime)
	}
	if listed := cachedNodes(fs.FS, "dr1", "/a"); len(listed) != 1 || listed[0] != node {
		t.Errorf("listing = %+v, want the node returned", listed)
	}
	if got := fs.readBack(t, node); !bytes.Equal(got, data) {
		t.Errorf("read back %d bytes that differ from the %d written", len(got), len(data))
	}
}

// A modification time given to Create is the client_mtime of the version, on
// both routes, and the ModTime of the node.
func TestCreate_DeclaresMtime(t *testing.T) {
	mtime := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	for label, size := range map[string]int{"single request": small, "chunked": chunked} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			node, err := fs.Create(context.Background(), "dr1", "/f", int64(size), mtime, bytes.NewReader(testData(size)))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if got := fs.api.version(node.VersionID).mtime; got != mtime.Format(time.RFC3339Nano) {
				t.Errorf("client_mtime = %q, want %v", got, mtime)
			}
			if !node.ModTime.Equal(mtime) {
				t.Errorf("ModTime = %v, want %v", node.ModTime, mtime)
			}
		})
	}
}

func TestCreate_Empty(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	node := fs.create(t, "/empty", nil)

	wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
	if node.Size != 0 || node.ChunkCount != 0 || node.VersionID == "" {
		t.Errorf("node = %+v, want an empty file with a version", node)
	}
	if v := fs.api.version(node.VersionID); v.size != 0 || len(v.chunks) != 0 {
		t.Errorf("version = %+v, want no content", v)
	}
}

// The single-request route takes a file up to service.SmallUploadMaxSize, a
// chunk: one byte more goes through a version and two chunks.
func TestCreate_Threshold(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())

	atLimit := testData(service.SmallUploadMaxSize)
	node := fs.create(t, "/limit.bin", atLimit)
	wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
	if got := fs.readBack(t, node); !bytes.Equal(got, atLimit) {
		t.Error("the file at the limit reads back different")
	}

	fs.api.reset()
	above := testData(chunked)
	node = fs.create(t, "/above.bin", above)
	wantCalls(t, fs.api,
		"POST /dataroom/dr1/node",
		"POST /dataroom/node/"+node.ID+"/version",
		"POST /dataroom/node/version/"+node.VersionID+"/chunk/0",
		"POST /dataroom/node/version/"+node.VersionID+"/chunk/1",
		// readBack of the first file
	)
	if got := fs.readBack(t, node); !bytes.Equal(got, above) {
		t.Error("the file above the limit reads back different")
	}
}

// A streamed upload caches everything a listing would report: the creation
// time of the node, the folder it was put in, the time of the version (not
// the local clock when the last chunk went), the MIME type stored, and the
// number of chunks announced, which is what a download reads.
func TestCreate_Chunked_CachesWhatAListingReports(t *testing.T) {
	fs := newWriteFS(t, Options{}, map[string][]service.DataroomNodeInfo{
		"/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"/a": {},
	})
	node := fs.create(t, "/a/f.txt", testData(chunked))

	want := Node{
		ID: node.ID, ParentID: "d-a", CreatedAt: storeNodeCreated, Name: "f.txt", Type: TypeFile,
		VersionID: node.VersionID, ChunkCount: 2, Size: chunked, MIMEType: node.MIMEType, ModTime: storeVersionCreated,
	}
	if node != want || !strings.HasPrefix(node.MIMEType, "text/plain") {
		t.Errorf("node = %+v, want %+v", node, want)
	}
	if listed := cachedNodes(fs.FS, "dr1", "/a"); len(listed) != 1 || listed[0] != node {
		t.Errorf("listing = %+v, want the node returned", listed)
	}
	if v := fs.api.version(node.VersionID); v.expected != 2 || v.mtime != "" {
		t.Errorf("version = expected %d chunks, client_mtime %q; want 2 and none", v.expected, v.mtime)
	}
}

// A file larger than a chunk is cut in chunks of service.UploadChunkSize.
func TestCreate_Chunked_TwoChunks(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	data := testData(service.UploadChunkSize + 1)
	node := fs.create(t, "/big.bin", data)

	if node.ChunkCount != 2 || fs.api.count("POST /dataroom/node/version/"+node.VersionID+"/chunk/") != 2 {
		t.Errorf("ChunkCount = %d, requests = %v; want 2 chunks", node.ChunkCount, fs.api.list())
	}
	if got := fs.readBack(t, node); !bytes.Equal(got, data) {
		t.Error("the file reads back different")
	}
}

// A file that exists gets a new version, on both routes. Streamed, the node
// found in the cached listing takes its version directly: no node creation
// answering 409. The entry keeps the mode and the creation time its listing
// gave it, which the version route does not answer.
func TestCreate_ExistingFile(t *testing.T) {
	for label, size := range map[string]int{"single request": small, "chunked": chunked} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			first := fs.create(t, "/doc.txt", testData(size))
			// What a listing would have told of the node.
			created := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
			listed := first
			listed.Mode, listed.CreatedAt = 0755, created
			fs.upsert("dr1", "/", listed)
			fs.api.reset()

			data := testData(size + 3)
			second := fs.create(t, "/doc.txt", data)
			if second.ID != first.ID || second.VersionID == first.VersionID {
				t.Fatalf("second upload = node %s version %s, want a new version of %s", second.ID, second.VersionID, first.ID)
			}
			if versions := fs.api.nodeVersions(first.ID); len(versions) != 2 {
				t.Errorf("the node holds %d versions, want 2", len(versions))
			}
			if size == chunked {
				wantCalls(t, fs.api,
					"POST /dataroom/node/"+first.ID+"/version",
					"POST /dataroom/node/version/"+second.VersionID+"/chunk/0",
					"POST /dataroom/node/version/"+second.VersionID+"/chunk/1")
			} else {
				wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
			}
			cached := cachedNodes(fs.FS, "dr1", "/")
			if len(cached) != 1 || cached[0].VersionID != second.VersionID || cached[0].Size != int64(size+3) {
				t.Fatalf("listing = %+v, want the new version", cached)
			}
			if size == chunked && (cached[0].Mode != 0755 || !cached[0].CreatedAt.Equal(created)) {
				t.Errorf("listing = mode %v created %v, want those the listing held", cached[0].Mode, cached[0].CreatedAt)
			}
			if got := fs.readBack(t, second); !bytes.Equal(got, data) {
				t.Error("the new version reads back different")
			}
		})
	}
}

// A file the cached listing does not show (created elsewhere since) is found
// after the 409 of the node creation and takes the new version.
func TestCreate_Chunked_ExistingFileNotListed(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	first := fs.create(t, "/doc.txt", testData(small))
	seedNodeCache(fs.FS, map[string]*nodeCacheEntry{"/": {fetchedAt: time.Now()}})
	fs.api.reset()

	second := fs.create(t, "/doc.txt", testData(chunked))
	if second.ID != first.ID {
		t.Errorf("uploaded to node %s, want the existing %s", second.ID, first.ID)
	}
	wantCalls(t, fs.api,
		"POST /dataroom/dr1/node",
		"GET /dataroom/dr1/nodes",
		"POST /dataroom/node/"+first.ID+"/version",
		"POST /dataroom/node/version/"+second.VersionID+"/chunk/0",
		"POST /dataroom/node/version/"+second.VersionID+"/chunk/1")
	if !second.CreatedAt.Equal(storeNodeCreated) {
		t.Errorf("CreatedAt = %v, want the one of the node found", second.CreatedAt)
	}
}

// A streamed upload that fails removes what it created (the node when it was
// new, only its version on a node that existed), returns the error of the
// upload even when that removal is refused. The cache is left as it was for a
// node the upload created; the listing that named a node which existed is
// dropped, since the failure may be that node gone or replaced elsewhere.
func TestCreate_Chunked_FailureDiscards(t *testing.T) {
	cases := map[string]struct {
		existing   bool
		deleteCode int
		wantDelete string // prefix
		wantLog    string
	}{
		"new node": {wantDelete: "DELETE /dataroom/node/f-", wantLog: "cleaned up orphaned node"},
		"existing node": {
			existing: true, wantDelete: "DELETE /dataroom/node/version/v-", wantLog: "discarded the failed version",
		},
		"delete refused": {
			existing: true, deleteCode: http.StatusForbidden,
			wantDelete: "DELETE /dataroom/node/version/v-", wantLog: "could not be cleaned up",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			if tc.existing {
				fs.create(t, "/f.bin", testData(small))
			}
			fs.api.reset()
			chunkFails := refuse("POST /dataroom/node/version/", http.StatusInternalServerError, "chunk upload failed", -1)
			deleteFails := refuse("DELETE ", tc.deleteCode, "no", -1)
			fs.api.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
				return chunkFails(w, r) || tc.deleteCode != 0 && deleteFails(w, r)
			})

			data := testData(chunked)
			_, err := fs.Create(context.Background(), "dr1", "/f.bin", chunked, time.Time{}, bytes.NewReader(data))
			if err == nil || !strings.Contains(err.Error(), "chunk upload failed") {
				t.Fatalf("Create = %v, want the upload error", err)
			}
			if fs.api.count(tc.wantDelete) != 1 || fs.api.count("DELETE ") != 1 {
				t.Errorf("requests = %v, want one %s…", fs.api.list(), tc.wantDelete)
			}
			// The file is told by its identifiers, never by its name.
			if logs := fs.logs.list(); len(logs) != 1 || !strings.Contains(logs[0], tc.wantLog) ||
				!strings.Contains(logs[0], "dataroom dr1, node f-") || strings.Contains(logs[0], "f.bin") {
				t.Errorf("logs = %q, want %q by identifiers and without the name", logs, tc.wantLog)
			}
			switch listing := cachedListing(fs.FS, "dr1", "/"); {
			case tc.existing && listing != nil:
				t.Errorf("listing = %+v, want it dropped after chunks failed on an existing node", listing.Nodes)
			case !tc.existing && (listing == nil || len(listing.Nodes) != 0):
				t.Errorf("listing = %+v, want it untouched", listing)
			}
		})
	}
}

// Chunks refused with a 404 on a node the cache named (deleted elsewhere
// since) drop the listing and the entries of the folder: the next request
// resolves the name again instead of adding versions to a node that is gone.
func TestCreate_Chunked_ChunkFailureOnAnExistingNodeDropsTheCache(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	fs.create(t, "/f.bin", testData(small))
	fs.api.setIntercept(refuse("POST /dataroom/node/version/", http.StatusNotFound, "version not found", -1))

	_, err := fs.Create(context.Background(), "dr1", "/f.bin", chunked, time.Time{}, bytes.NewReader(testData(chunked)))
	if !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("Create = %v, want the 404 of the chunk", err)
	}
	if nodeCacheHas(fs.FS, "dr1", "/") {
		t.Error("the listing still names the node after its chunks answered 404")
	}
}

// A caller that gives up says nothing of the node: the listing is kept.
func TestCreate_Chunked_CancelledOnAnExistingNodeKeepsTheCache(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	fs.create(t, "/f.bin", testData(small))
	before := cachedNodes(fs.FS, "dr1", "/")
	intercept, arrived, release := hold("POST /dataroom/node/version/")
	defer release()
	fs.api.setIntercept(intercept)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := fs.Create(ctx, "dr1", "/f.bin", chunked, time.Time{}, bytes.NewReader(testData(chunked)))
		done <- err
	}()
	<-arrived
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Create = %v, want context.Canceled", err)
	}
	if after := cachedNodes(fs.FS, "dr1", "/"); !slices.Equal(after, before) {
		t.Errorf("listing = %+v, want it untouched: %+v", after, before)
	}
}

// A source that does not hold the size announced sends nothing in a single
// request, and fails a streamed upload, whose version is discarded.
func TestCreate_SourceOfTheWrongSize(t *testing.T) {
	cases := map[string]struct {
		declared, actual int
		wantRequests     int
		wantErr          string
	}{
		"single request, short": {declared: small, actual: small - 4, wantErr: "incomplete upload: wrote 6 of 10 bytes"},
		"single request, long":  {declared: small, actual: small + 1, wantErr: "source is larger than its declared 10 bytes"},
		"empty, long":           {declared: 0, actual: 1, wantErr: "source is larger than its declared 0 bytes"},
		"chunked, short":        {declared: chunked, actual: chunked - 1, wantRequests: 4, wantErr: "source ended after"},
		"chunked, long":         {declared: chunked, actual: chunked + 1, wantRequests: 3, wantErr: "source is larger than"},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			_, err := fs.Create(context.Background(), "dr1", "/f", int64(tc.declared), time.Time{},
				bytes.NewReader(testData(tc.actual)))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Create = %v, want %q", err, tc.wantErr)
			}
			calls := fs.api.list()
			if len(calls) != tc.wantRequests {
				t.Errorf("requests = %v, want %d", calls, tc.wantRequests)
			}
			if tc.wantRequests > 0 && !strings.HasPrefix(calls[len(calls)-1], "DELETE /dataroom/node/f-") {
				t.Errorf("requests = %v, want the node deleted last", calls)
			}
			if len(cachedNodes(fs.FS, "dr1", "/")) != 0 {
				t.Error("the listing gained a file the API never accepted")
			}
		})
	}
}

// reads counts the reads made of a source.
type reads struct {
	r io.Reader
	n int
}

func (r *reads) Read(p []byte) (int, error) {
	r.n++

	return r.r.Read(p)
}

// The source is not read before the upload is accepted: a front end feeding
// it as its client sends relies on that to answer for the destination first.
func TestCreate_ReadsNothingBeforeTheUploadIsAccepted(t *testing.T) {
	for label, size := range map[string]int{"single request": small, "chunked": chunked} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			fs.api.setIntercept(refuse("POST ", http.StatusForbidden, `{"detail":"Create not allowed here"}`, -1))
			for _, path := range []string{"/missing/f", "/"} {
				src := &reads{r: bytes.NewReader(testData(size))}
				if _, err := fs.Create(context.Background(), "dr1", path, int64(size), time.Time{}, src); err == nil {
					t.Errorf("Create(%s) succeeded", path)
				}
				if src.n != 0 {
					t.Errorf("Create(%s) read the source %d times before failing", path, src.n)
				}
			}
			// The version of a streamed file is created before its content is
			// read; a single request has nothing to send without it.
			src := &reads{r: bytes.NewReader(testData(size))}
			_, err := fs.Create(context.Background(), "dr1", "/f", int64(size), time.Time{}, src)
			if !errors.Is(err, ErrForbidden) {
				t.Errorf("Create = %v, want ErrForbidden", err)
			}
			if size == chunked && src.n != 0 {
				t.Errorf("the source was read %d times although the node was refused", src.n)
			}
		})
	}
}

// The errors of an upload carry the sentinels of the package and still match
// what they were made from; a rate limit crosses untouched.
func TestCreate_Errors(t *testing.T) {
	versionLimit := `{"detail":"Maximum number of versions reached (5)"}`
	cases := map[string]struct {
		path    string
		size    int
		refuse  string // "METHOD path" prefix answered code and body
		code    int
		body    string
		want    error
		origin  error // what the error must still match
		noKind  bool  // the error carries no sentinel of the package
		noCalls bool
	}{
		"missing folder":    {path: "/nope/f", size: small, want: ErrNotExist, noCalls: true},
		"parent is a file":  {path: "/doc.txt/f", size: small, want: ErrNotDir, noCalls: true},
		"the dataroom root": {path: "/", size: small, want: ErrIsDir, noCalls: true},
		"forbidden, single request": {
			path: "/f", size: small, refuse: "POST ", code: 403, body: `{"detail":"Create not allowed here"}`,
			want: ErrForbidden,
		},
		"forbidden, version": {
			path: "/doc.txt", size: chunked, refuse: "POST ", code: 403, body: `{"detail":"Add version not allowed"}`,
			want: ErrForbidden,
		},
		"forbidden, chunk": {
			path: "/f", size: chunked, refuse: "POST /dataroom/node/version/", code: 403, body: `{"detail":"no"}`,
			want: ErrForbidden,
		},
		"unauthenticated": {
			path: "/f", size: small, refuse: "POST ", code: 401, body: "no", want: ErrUnauthenticated,
		},
		"storage, single request": {
			path: "/f", size: small, refuse: "POST ", code: 400, body: storageRefusal, want: ErrStorageExceeded,
		},
		"storage, version": {
			path: "/doc.txt", size: chunked, refuse: "POST ", code: 400, body: storageRefusal, want: ErrStorageExceeded,
		},
		"storage, chunk": {
			path: "/f", size: chunked, refuse: "POST /dataroom/node/version/", code: 400, body: storageRefusal,
			want: ErrStorageExceeded,
		},
		"another 400, single request": {
			path: "/f", size: small, refuse: "POST ", code: 400, body: versionLimit, noKind: true,
		},
		"another 400, version": {
			path: "/doc.txt", size: chunked, refuse: "POST ", code: 400, body: versionLimit, noKind: true,
		},
		"name being deleted": {
			path: "/f", size: small, refuse: "POST ", code: 410, body: "gone", want: ErrNameBeingDeleted,
			origin: service.ErrNameBeingDeleted,
		},
		"deleted folder, single request": {
			path: "/a/f", size: small, refuse: "POST ", code: 404, body: `{"detail":"Parent node not found"}`,
			want: ErrNotExist, origin: api.ErrNotFound,
		},
		"deleted folder, chunked": {
			path: "/a/f", size: chunked, refuse: "POST ", code: 404, body: `{"detail":"Parent node not found"}`,
			want: ErrNotExist, origin: api.ErrNotFound,
		},
		"rate limited, single request": {
			path: "/f", size: small, refuse: "POST ", code: 429, body: "slow down", origin: api.ErrRateLimited, noKind: true,
		},
		"rate limited, chunk": {
			path: "/f", size: chunked, refuse: "POST /dataroom/node/version/", code: 429, body: "slow down",
			origin: api.ErrRateLimited, noKind: true,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, map[string][]service.DataroomNodeInfo{
				"/": {
					{ID: "f-doc", Name: "doc.txt", Type: "file", VersionID: "v-doc", Size: 9, ChunkCount: 1},
					{ID: "d-a", Name: "a", Type: "dir"},
				},
				"/a": {},
			})
			if tc.refuse != "" {
				fs.api.setIntercept(refuse(tc.refuse, tc.code, tc.body, -1))
			}
			_, err := fs.Create(context.Background(), "dr1", tc.path, int64(tc.size), time.Time{},
				bytes.NewReader(testData(tc.size)))
			if err == nil {
				t.Fatal("Create succeeded")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("Create = %v, want %v", err, tc.want)
			}
			if tc.origin != nil && !errors.Is(err, tc.origin) {
				t.Errorf("Create = %v, which no longer matches %v", err, tc.origin)
			}
			if tc.code != 0 && httpStatus(err) != tc.code && tc.code != 410 {
				t.Errorf("Create = %v, which lost the API's %d", err, tc.code)
			}
			if tc.noKind && !carriesNoSentinel(err) {
				t.Errorf("Create = %v, want no sentinel of the package", err)
			}
			if tc.noCalls && len(fs.api.list()) != 0 {
				t.Errorf("requests = %v, want none", fs.api.list())
			}
			if tc.code == 404 {
				for _, path := range []string{"/", "/a"} {
					if nodeCacheHas(fs.FS, "dr1", path) {
						t.Errorf("the listing of %s is still cached after its folder turned out to be gone", path)
					}
				}
			}
		})
	}
}

// The API deletes a node whose first version it refuses for lack of storage:
// the cached listing must not keep naming it. A file that has a version stays.
func TestCreate_StorageRefusalForgetsANodeWithoutVersion(t *testing.T) {
	fs := newWriteFS(t, Options{}, map[string][]service.DataroomNodeInfo{"/": {
		{ID: "f-bare", Name: "bare.bin", Type: "file"},
		{ID: "f-doc", Name: "doc.bin", Type: "file", VersionID: "v-doc", Size: 9, ChunkCount: 1},
	}})
	fs.api.setIntercept(refuse("POST ", http.StatusBadRequest, storageRefusal, -1))

	for _, path := range []string{"/bare.bin", "/doc.bin"} {
		_, err := fs.Create(context.Background(), "dr1", path, chunked, time.Time{}, bytes.NewReader(testData(chunked)))
		if !errors.Is(err, ErrStorageExceeded) {
			t.Fatalf("Create(%s) = %v, want ErrStorageExceeded", path, err)
		}
	}
	if got := names(cachedNodes(fs.FS, "dr1", "/")); !slices.Equal(got, []string{"doc.bin"}) {
		t.Errorf("listing = %v, want doc.bin alone", got)
	}
}

// A 400 of the copy route is a storage refusal only when it says so.
func TestCopy_Another400IsNotStorage(t *testing.T) {
	fake := &fakeAPI{reply: status(http.StatusBadRequest, `{"detail":"Maximum number of versions reached (5)"}`)}
	fs := newAPIFS(t, fake, Options{}, tree())
	_, _, err := fs.Copy(context.Background(), "dr1", "/doc.txt", "/x", false)
	if err == nil || errors.Is(err, ErrStorageExceeded) {
		t.Errorf("Copy = %v, want an error that is not ErrStorageExceeded", err)
	}
}

// — initUpload ————————————————————————————————————————————————————————————————

// Overwriting a file whose node is in the cached listing must create the new
// version directly: no CreateDataroomNode answering 409, and no uncached
// listing to find the node again.
func TestInitUpload_OverwriteSkipsConflictAndRelisting(t *testing.T) {
	var calls callLog
	fs, identity := newCachedListingsFS(t, func(w http.ResponseWriter, r *http.Request) {
		calls.add(r.Method + " " + r.URL.Path)
		if r.Method == http.MethodPost && r.URL.Path == "/dataroom/node/f-1/version" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			// The API rejects any chunk beyond the announced count: 10 bytes is one chunk.
			if body["chunk_count_expected"] != float64(1) {
				t.Errorf("chunk_count_expected = %v, want 1", body["chunk_count_expected"])
			}
			fmt.Fprint(w, `{"id":"v-2","created_at":"2026-09-08T10:00:00Z"}`)

			return
		}
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
	}, map[string][]service.DataroomNodeInfo{
		"/": {{ID: "f-1", Name: "doc.txt", Type: "file", VersionID: "v-1"}},
	})
	sess := &service.DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}

	init, err := fs.initUpload(context.Background(), "dr1", "/", "doc.txt", nil, content{size: 10}, sess)
	if err != nil {
		t.Fatalf("initUpload: %v", err)
	}
	if init.NodeID != "f-1" || init.VersionID != "v-2" {
		t.Errorf("init = %+v, want node f-1 / version v-2", init)
	}
	// A pre-existing node must never be deleted if the upload then fails.
	if init.NewNode {
		t.Error("NewNode is true for an overwrite; a failed upload would delete the node")
	}
	if got := calls.list(); len(got) != 1 {
		t.Errorf("issued %d API calls (%v), want 1 (version creation only)", len(got), got)
	}
}

// The cached listing can be up to the TTL old: if the node was deleted
// elsewhere, the shortcut gets a 404 and the upload must still succeed through
// the full path, which recreates the node.
func TestInitUpload_FallsBackWhenCachedNodeIsGone(t *testing.T) {
	for _, gone := range goneStatuses {
		t.Run(http.StatusText(gone), func(t *testing.T) {
			fs, identity := newCachedListingsFS(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/dataroom/node/f-1/version": // the stale node is gone
					http.Error(w, "no such node", gone)
				case r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node":
					fmt.Fprint(w, `{"id":"f-2","name_enc":"x"}`)
				case r.URL.Path == "/dataroom/node/f-2/version":
					fmt.Fprint(w, `{"id":"v-1","created_at":"2026-09-08T10:00:00Z"}`)
				default:
					http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusInternalServerError)
				}
			}, map[string][]service.DataroomNodeInfo{
				"/": {{ID: "f-1", Name: "doc.txt", Type: "file"}},
			})
			sess := &service.DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()}

			init, err := fs.initUpload(context.Background(), "dr1", "/", "doc.txt", nil, content{size: 10}, sess)
			if err != nil {
				t.Fatalf("initUpload fell back but still failed: %v", err)
			}
			if init.NodeID != "f-2" || !init.NewNode {
				t.Errorf("init = %+v, want the recreated node f-2 with NewNode true", init)
			}
			// The listing that named a dead node must not be served to anyone else.
			if nodeCacheHas(fs, "dr1", "/") {
				t.Error("the stale listing was kept after its node turned out to be gone")
			}
		})
	}
}

// — Spool: a new file —————————————————————————————————————————————————————————

// A new file is pending until its first Flush: nothing at the API, the spool
// answers for its size and its time. Writes land at any offset, in any
// order. The spool is one file of mode 0600 in SpoolDir, removed by Close.
func TestSpool_NewFile(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	before := time.Now()
	s := fs.spool(t, "/doc.txt", nil, false)

	if _, exists := s.Node(); exists || !s.Dirty() || s.Size() != 0 || s.ModTime().Before(before) {
		t.Errorf("new spool: exists %v dirty %v size %d mtime %v", exists, s.Dirty(), s.Size(), s.ModTime())
	}
	entries, _ := os.ReadDir(fs.opts.SpoolDir)
	if len(entries) != 1 {
		t.Fatalf("SpoolDir holds %d files, want 1", len(entries))
	}
	if info, err := entries[0].Info(); err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("spool file mode = %v (%v), want 0600", info.Mode().Perm(), err)
	}
	if strings.Contains(entries[0].Name(), "doc") {
		t.Errorf("the spool file %q is named after the file it holds", entries[0].Name())
	}

	mustWriteAt(t, s, []byte("world"), 6)
	mustWriteAt(t, s, []byte("hello"), 0)
	if s.Size() != 11 {
		t.Errorf("Size = %d, want 11", s.Size())
	}
	want := []byte("hello\x00world")
	if got := spoolContent(t, s); !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	if len(fs.api.list()) != 0 {
		t.Fatalf("requests before any Flush: %v", fs.api.list())
	}

	node := mustFlush(t, s)
	wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
	if got, exists := s.Node(); !exists || got != node || s.Dirty() {
		t.Errorf("after Flush: node %+v exists %v dirty %v", got, exists, s.Dirty())
	}
	if node.Name != "doc.txt" || node.Size != 11 {
		t.Errorf("node = %+v", node)
	}
	if listed := cachedNodes(fs.FS, "dr1", "/"); len(listed) != 1 || listed[0] != node {
		t.Errorf("listing = %+v, want the node flushed", listed)
	}
	if got := fs.readBack(t, node); !bytes.Equal(got, want) {
		t.Errorf("read back %q, want %q", got, want)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := spoolFiles(t, fs.FS); n != 0 {
		t.Errorf("SpoolDir holds %d files after Close", n)
	}
}

// A file created and closed without a write (touch) is an empty file at the
// API once flushed.
func TestSpool_Touch(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/empty", nil, false)
	node := mustFlush(t, s)

	wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
	if v := fs.api.version(node.VersionID); node.Size != 0 || v.size != 0 || len(v.chunks) != 0 {
		t.Errorf("node = %+v, version = %+v; want an empty file", node, v)
	}
}

// Closed without a Flush, a spool leaves nothing at the API, nor on disk.
func TestSpool_CloseWithoutFlush(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, testData(100), 0)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if calls := fs.api.list(); len(calls) != 0 {
		t.Errorf("requests = %v, want none", calls)
	}
	if n := spoolFiles(t, fs.FS); n != 0 {
		t.Errorf("SpoolDir holds %d files after Close", n)
	}
	if len(cachedNodes(fs.FS, "dr1", "/")) != 0 {
		t.Error("the listing gained a file that was never flushed")
	}
}

// Flush is idempotent: a second one sends nothing. A write after it makes the
// spool dirty again, and the next Flush sends a second version of the node.
func TestSpool_FlushTwiceThenWrite(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, []byte("first"), 0)
	first := mustFlush(t, s)
	if again := mustFlush(t, s); again != first {
		t.Errorf("second Flush = %+v, want the node of the first", again)
	}
	wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")

	mustWriteAt(t, s, []byte("SECOND"), 2)
	if !s.Dirty() {
		t.Fatal("a write after a Flush left the spool clean")
	}
	second := mustFlush(t, s)
	if second.ID != first.ID || second.VersionID == first.VersionID {
		t.Errorf("second version = %+v, want a new version of %s", second, first.ID)
	}
	if versions := fs.api.nodeVersions(first.ID); len(versions) != 2 {
		t.Errorf("the node holds %d versions, want 2", len(versions))
	}
	if got := fs.readBack(t, second); string(got) != "fiSECOND" {
		t.Errorf("read back %q, want %q", got, "fiSECOND")
	}
}

// Concurrent Flushes send one version: the others find the spool clean.
func TestSpool_ConcurrentFlushes(t *testing.T) {
	for label, size := range map[string]int{"single request": small, "chunked": chunked} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/doc.bin", nil, false)
			mustWriteAt(t, s, testData(size), 0)

			var wg sync.WaitGroup
			nodes := make([]Node, 8)
			for i := range nodes {
				wg.Go(func() {
					var err error
					if nodes[i], err = s.Flush(context.Background()); err != nil {
						t.Errorf("Flush: %v", err)
					}
				})
			}
			wg.Wait()
			for _, n := range nodes {
				if n != nodes[0] {
					t.Errorf("Flush returned %+v and %+v", n, nodes[0])
				}
			}
			if versions := fs.api.nodeVersions(nodes[0].ID); len(versions) != 1 {
				t.Errorf("the node holds %d versions, want 1", len(versions))
			}
		})
	}
}

// A Flush that fails leaves the spool dirty and its content untouched, and
// removes what it created; the next one sends the same content.
func TestSpool_FlushFailsThenSucceeds(t *testing.T) {
	cases := map[string]struct {
		size   int
		refuse string
	}{
		"single request": {size: small, refuse: "POST /dataroom/dr1/node/file"},
		"chunked":        {size: chunked, refuse: "POST /dataroom/node/version/"},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/doc.bin", nil, false)
			data := testData(tc.size)
			mustWriteAt(t, s, data, 0)
			fs.api.setIntercept(refuse(tc.refuse, http.StatusInternalServerError, "boom", 1))

			if _, err := s.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "boom") {
				t.Fatalf("first Flush = %v, want the failure", err)
			}
			if _, exists := s.Node(); exists || !s.Dirty() {
				t.Errorf("after a failed Flush: exists %v dirty %v, want pending and dirty", exists, s.Dirty())
			}
			if tc.size == chunked && fs.api.count("DELETE /dataroom/node/f-") != 1 {
				t.Errorf("requests = %v, want the node of the failed upload deleted", fs.api.list())
			}
			if len(cachedNodes(fs.FS, "dr1", "/")) != 0 {
				t.Error("the listing gained the file of a failed Flush")
			}
			if got := spoolContent(t, s); !bytes.Equal(got, data) {
				t.Error("the failed Flush changed the content of the spool")
			}

			node := mustFlush(t, s)
			if got := fs.readBack(t, node); !bytes.Equal(got, data) {
				t.Error("the second Flush sent another content")
			}
			if s.Dirty() {
				t.Error("the spool is dirty after a Flush that succeeded")
			}
		})
	}
}

// The size the spool has when it is flushed decides the route and the cut:
// exactly a chunk is one chunk, one byte more is two.
func TestSpool_ChunkBoundary(t *testing.T) {
	for label, tc := range map[string]struct{ size, chunks int }{
		"exactly a chunk":    {service.UploadChunkSize, 1},
		"a chunk and a byte": {service.UploadChunkSize + 1, 2},
	} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/big.bin", nil, false)
			data := testData(tc.size)
			// Written in pieces, the last one first.
			const piece = 1 << 20
			for off := (len(data) - 1) / piece * piece; off >= 0; off -= piece {
				mustWriteAt(t, s, data[off:min(off+piece, len(data))], int64(off))
			}
			node := mustFlush(t, s)

			if node.ChunkCount != tc.chunks || node.Size != int64(tc.size) {
				t.Errorf("node = %d bytes in %d chunks, want %d in %d", node.Size, node.ChunkCount, tc.size, tc.chunks)
			}
			if v := fs.api.version(node.VersionID); v.expected != tc.chunks || len(v.chunks) != tc.chunks {
				t.Errorf("version announced %d chunks and holds %d, want %d", v.expected, len(v.chunks), tc.chunks)
			}
			if got := fs.readBack(t, node); !bytes.Equal(got, data) {
				t.Error("the file reads back different")
			}
		})
	}
}

// — Spool: truncation —————————————————————————————————————————————————————————

func TestSpool_Truncate(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, []byte("0123456789"), 0)
	mustFlush(t, s)

	// The same size changes nothing.
	if err := s.Truncate(10); err != nil || s.Dirty() {
		t.Errorf("Truncate to the same size = %v, dirty %v", err, s.Dirty())
	}
	// Longer: zeros.
	if err := s.Truncate(13); err != nil {
		t.Fatalf("Truncate(13): %v", err)
	}
	if got := spoolContent(t, s); string(got) != "0123456789\x00\x00\x00" || !s.Dirty() {
		t.Errorf("grown content = %q, dirty %v", got, s.Dirty())
	}
	// Shorter.
	if err := s.Truncate(4); err != nil {
		t.Fatalf("Truncate(4): %v", err)
	}
	if got := spoolContent(t, s); string(got) != "0123" || s.Size() != 4 {
		t.Errorf("cut content = %q, size %d", got, s.Size())
	}
	// What was cut does not come back.
	if err := s.Truncate(6); err != nil {
		t.Fatalf("Truncate(6): %v", err)
	}
	if got := spoolContent(t, s); string(got) != "0123\x00\x00" {
		t.Errorf("content cut then grown = %q", got)
	}
	node := mustFlush(t, s)
	if got := fs.readBack(t, node); string(got) != "0123\x00\x00" {
		t.Errorf("read back %q", got)
	}
	// To nothing.
	if err := s.Truncate(0); err != nil {
		t.Fatalf("Truncate(0): %v", err)
	}
	if node := mustFlush(t, s); node.Size != 0 || node.ChunkCount != 0 {
		t.Errorf("node after Truncate(0) = %+v", node)
	}
	if err := s.Truncate(-1); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("Truncate(-1) = %v, want os.ErrInvalid", err)
	}
}

// — Spool: an existing file ———————————————————————————————————————————————————

// existingSpool opens a spool on a file of size bytes stored in chunks of
// testChunkSize, whose downloads src counts. The FS still uploads to the API.
func existingSpool(t *testing.T, size int, truncate bool) (*writeFS, *spool, *chunkSource, Node) {
	t.Helper()
	src := newChunkSource(testData(size))
	node := Node{
		ID: "f-old", Name: "doc.bin", Type: TypeFile, VersionID: "v1", Size: int64(size),
		ChunkCount: len(src.chunks), ModTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	fs := newWriteFS(t, Options{ReadChunk: src.read, ChunkSize: testChunkSize}, emptyRoot())
	fs.upsert("dr1", "/", node)

	return fs, fs.spool(t, "/doc.bin", &node, truncate), src, node
}

// allChunks is the count of downloads of a file of n chunks read once.
func allChunks(n int) map[int]int {
	counts := make(map[int]int, n)
	for i := range n {
		counts[i] = 1
	}

	return counts
}

// wantNoChunkFrom fails when a chunk at or past index was downloaded. What a
// truncation kept is read sequentially, so the File may fetch one chunk
// ahead of it: the bound is the chunk after the last one kept.
func wantNoChunkFrom(t *testing.T, src *chunkSource, index int) {
	t.Helper()
	for i, n := range src.counts() {
		if i >= index && n > 0 {
			t.Errorf("chunk %d was downloaded, past what the truncation kept", i)
		}
	}
}

// Opened on an existing file, a spool is clean and downloads nothing until it
// is read or written; the version then comes in once, whole.
func TestSpool_LazyHydration(t *testing.T) {
	for _, first := range []string{"read", "write"} {
		t.Run(first, func(t *testing.T) {
			fs, s, src, node := existingSpool(t, 18, false)
			if got, exists := s.Node(); !exists || got != node || s.Dirty() || s.Size() != 18 ||
				!s.ModTime().Equal(node.ModTime) {
				t.Errorf("opened: node %+v exists %v dirty %v size %d", got, exists, s.Dirty(), s.Size())
			}
			wantCounts(t, src, map[int]int{})

			want := slices.Clone(src.data)
			if first == "write" {
				mustWriteAt(t, s, []byte("XY"), 7)
				copy(want[7:], "XY")
			}
			if got := spoolContent(t, s); !bytes.Equal(got, want) {
				t.Errorf("content = %q, want %q", got, want)
			}
			_ = spoolContent(t, s)
			wantCounts(t, src, allChunks(5))

			// Read only: nothing to send.
			if first == "read" {
				if got := mustFlush(t, s); got != node || len(fs.api.list()) != 0 {
					t.Errorf("Flush of a clean spool = %+v, requests %v", got, fs.api.list())
				}
			}
		})
	}
}

// Truncate(0) before any read or write: the version is never downloaded, and
// the file is flushed empty.
func TestSpool_TruncateToZeroDownloadsNothing(t *testing.T) {
	fs, s, src, _ := existingSpool(t, 18, false)
	if err := s.Truncate(0); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	mustWriteAt(t, s, []byte("new"), 0)
	if got := spoolContent(t, s); string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
	wantCounts(t, src, map[int]int{})
	if !s.Dirty() {
		t.Error("a truncated spool is clean")
	}
	// The single-request route goes by name: the API of this test holds no
	// file of that name, the request is what matters.
	mustFlush(t, s)
	wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
}

// Opened with truncate, an existing file starts empty and dirty, without a
// download, and keeps its node.
func TestSpool_OpenTruncate(t *testing.T) {
	_, s, src, node := existingSpool(t, 18, true)
	if got, exists := s.Node(); !exists || got != node || !s.Dirty() || s.Size() != 0 {
		t.Errorf("opened with truncate: exists %v dirty %v size %d", exists, s.Dirty(), s.Size())
	}
	if got := spoolContent(t, s); len(got) != 0 {
		t.Errorf("content = %q, want none", got)
	}
	wantCounts(t, src, map[int]int{})
}

// A truncation before the version came in only bounds what will: the chunks
// past the new size are not downloaded (bar the one a sequential read fetches
// ahead), and a size grown back reads zeros.
func TestSpool_TruncateBoundsHydration(t *testing.T) {
	_, s, src, _ := existingSpool(t, 18, false)
	if err := s.Truncate(6); err != nil {
		t.Fatalf("Truncate(6): %v", err)
	}
	wantCounts(t, src, map[int]int{})
	if err := s.Truncate(10); err != nil {
		t.Fatalf("Truncate(10): %v", err)
	}
	want := append(slices.Clone(src.data[:6]), 0, 0, 0, 0)
	if got := spoolContent(t, s); !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	wantNoChunkFrom(t, src, 3)
}

// A write from offset 0 that covers the whole file replaces it: nothing of
// the version is downloaded. One byte short of it, the version comes in.
func TestSpool_CoveringWriteSkipsHydration(t *testing.T) {
	_, s, src, _ := existingSpool(t, 18, false)
	data := bytes.Repeat([]byte("z"), 20)
	mustWriteAt(t, s, data, 0)
	if got := spoolContent(t, s); !bytes.Equal(got, data) {
		t.Errorf("content = %q", got)
	}
	wantCounts(t, src, map[int]int{})

	_, s, src, _ = existingSpool(t, 18, false)
	mustWriteAt(t, s, data[:17], 0)
	want := append(slices.Clone(data[:17]), src.data[17])
	if got := spoolContent(t, s); !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	wantCounts(t, src, allChunks(5))
}

// A spool left dirty by a truncation alone still has its version to bring in
// when it is flushed, and sends what the truncation kept.
func TestSpool_FlushHydratesWhatATruncationKept(t *testing.T) {
	fs, s, src, node := existingSpool(t, 18, false)
	if err := s.Truncate(9); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	flushed := mustFlush(t, s)
	if got := fs.api.content(fs.identity, flushed.VersionID); !bytes.Equal(got, src.data[:9]) {
		t.Errorf("flushed %q, want %q", got, src.data[:9])
	}
	wantNoChunkFrom(t, src, 4)
	if flushed.VersionID == node.VersionID {
		t.Error("the Flush returned the version the spool was opened on")
	}
}

// A download that fails leaves the version to be brought in again: the next
// read gets all of it.
func TestSpool_HydrationFailureIsRetried(t *testing.T) {
	_, s, src, _ := existingSpool(t, 18, false)
	boom := errors.New("download failed")
	src.setFail(2, boom)
	if _, err := s.ReadAt(make([]byte, 4), 0); !errors.Is(err, boom) {
		t.Fatalf("ReadAt = %v, want the download error", err)
	}
	if _, err := s.WriteAt([]byte("x"), 3); !errors.Is(err, boom) {
		t.Fatalf("WriteAt = %v, want the download error", err)
	}
	if s.Dirty() {
		t.Error("a write that could not bring the version in made the spool dirty")
	}
	src.setFail(2, nil)
	mustWriteAt(t, s, []byte("x"), 3)
	want := slices.Clone(src.data)
	want[3] = 'x'
	if got := spoolContent(t, s); !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
}

// A file larger than a single request, opened on a node the spool knows, gets
// its version on that node directly, whatever the listing says.
func TestSpool_ExistingNodeTakesTheVersion(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	first := fs.create(t, "/doc.bin", testData(small))
	// The listing no longer shows the file.
	seedNodeCache(fs.FS, map[string]*nodeCacheEntry{"/": {fetchedAt: time.Now()}})
	fs.api.reset()

	s := fs.spool(t, "/doc.bin", &first, true)
	data := testData(chunked)
	mustWriteAt(t, s, data, 0)
	node := mustFlush(t, s)
	wantCalls(t, fs.api,
		"POST /dataroom/node/"+first.ID+"/version",
		"POST /dataroom/node/version/"+node.VersionID+"/chunk/0",
		"POST /dataroom/node/version/"+node.VersionID+"/chunk/1")
	if got := fs.readBack(t, node); !bytes.Equal(got, data) {
		t.Error("the new version reads back different")
	}
}

// — Spool: modification time ——————————————————————————————————————————————————

// Flush declares the time of the last write as client_mtime, or the one set
// on the spool; the node carries it.
func TestSpool_ClientMtime(t *testing.T) {
	for label, size := range map[string]int{"single request": small, "chunked": chunked} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/doc.bin", nil, false)
			before := time.Now()
			mustWriteAt(t, s, testData(size), 0)
			written := s.ModTime()
			if written.Before(before) || written.After(time.Now()) {
				t.Fatalf("ModTime after a write = %v, want now", written)
			}
			node := mustFlush(t, s)
			if got := fs.api.version(node.VersionID).mtime; got != written.UTC().Format(time.RFC3339Nano) {
				t.Errorf("client_mtime = %q, want the time of the write %v", got, written.UTC())
			}
			if !node.ModTime.Equal(written) || !s.ModTime().Equal(written) {
				t.Errorf("node ModTime = %v, spool %v, want %v", node.ModTime, s.ModTime(), written)
			}

			// Set on a dirty spool: kept for the Flush, no request.
			set := time.Date(2020, 2, 3, 4, 5, 6, 0, time.UTC)
			mustWriteAt(t, s, []byte("x"), 0)
			fs.api.reset()
			if err := s.SetModTime(context.Background(), set); err != nil {
				t.Fatalf("SetModTime: %v", err)
			}
			if len(fs.api.list()) != 0 || !s.ModTime().Equal(set) {
				t.Errorf("SetModTime on a dirty spool: requests %v, ModTime %v", fs.api.list(), s.ModTime())
			}
			node = mustFlush(t, s)
			if got := fs.api.version(node.VersionID).mtime; got != set.Format(time.RFC3339Nano) || !node.ModTime.Equal(set) {
				t.Errorf("client_mtime = %q, node ModTime %v, want %v", got, node.ModTime, set)
			}

			// Set on a clean spool: declared at once for the current version.
			later := set.Add(time.Hour)
			fs.api.reset()
			if err := s.SetModTime(context.Background(), later); err != nil {
				t.Fatalf("SetModTime on a clean spool: %v", err)
			}
			wantCalls(t, fs.api, "PATCH /dataroom/node/version/"+node.VersionID)
			if s.Dirty() || !s.ModTime().Equal(later) {
				t.Errorf("after SetModTime on a clean spool: dirty %v, ModTime %v", s.Dirty(), s.ModTime())
			}
			if got, _ := s.Node(); !got.ModTime.Equal(later) {
				t.Errorf("Node().ModTime = %v, want %v", got.ModTime, later)
			}
			if listed := cachedNodes(fs.FS, "dr1", "/"); len(listed) != 1 || !listed[0].ModTime.Equal(later) {
				t.Errorf("listing = %+v, want ModTime %v", listed, later)
			}
		})
	}
}

// A spool told its file moved flushes it there.
func TestSpool_SetPath(t *testing.T) {
	fs := newWriteFS(t, Options{}, map[string][]service.DataroomNodeInfo{
		"/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"/a": {},
	})
	s := fs.spool(t, "/tmp.txt", nil, false)
	mustWriteAt(t, s, []byte("x"), 0)
	s.SetPath("/a/final.txt")
	node := mustFlush(t, s)
	if node.Name != "final.txt" || node.ParentID != "d-a" {
		t.Errorf("node = %+v, want final.txt in d-a", node)
	}
	if listed := cachedNodes(fs.FS, "dr1", "/a"); len(listed) != 1 || len(cachedNodes(fs.FS, "dr1", "/")) != 1 {
		t.Errorf("listing of /a = %+v, want the file there and nothing new at the root", listed)
	}
}

// — Spool: errors —————————————————————————————————————————————————————————————

func TestOpenSpool_Errors(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	ctx := context.Background()
	if _, err := fs.OpenSpool(ctx, "dr1", "/", nil, false); !errors.Is(err, ErrIsDir) {
		t.Errorf("OpenSpool(/) = %v, want ErrIsDir", err)
	}
	dir, link := Node{ID: "d", Name: "d", Type: TypeDir}, Node{ID: "l", Name: "l", Type: TypeSymlink}
	if _, err := fs.OpenSpool(ctx, "dr1", "/d", &dir, false); !errors.Is(err, ErrIsDir) {
		t.Errorf("OpenSpool on a folder = %v, want ErrIsDir", err)
	}
	if _, err := fs.OpenSpool(ctx, "dr1", "/l", &link, true); !errors.Is(err, ErrNotFile) {
		t.Errorf("OpenSpool on a symlink = %v, want ErrNotFile", err)
	}
	if n := spoolFiles(t, fs.FS); n != 0 {
		t.Errorf("SpoolDir holds %d files after refused opens", n)
	}
}

// fullFile is a spool file whose file system runs out of room: it stores
// what fits in room bytes and fails the rest like the kernel does.
type fullFile struct {
	spoolFile
	room int64
	// relief, when set, is the room there is once a write was refused: space
	// freed right after the file system ran out of it.
	relief int64
}

var errNoSpace = &os.PathError{Op: "write", Path: "spool", Err: syscall.ENOSPC}

func (f *fullFile) WriteAt(p []byte, off int64) (int, error) {
	if fits := f.room - off; int64(len(p)) > fits {
		n := 0
		if fits > 0 {
			n, _ = f.spoolFile.WriteAt(p[:fits], off)
		}
		if f.relief > 0 {
			f.room, f.relief = f.relief, 0
		}

		return n, errNoSpace
	}

	return f.spoolFile.WriteAt(p, off)
}

func (f *fullFile) Truncate(size int64) error {
	if size > f.room {
		return errNoSpace
	}

	return f.spoolFile.Truncate(size)
}

// A spool whose file system is full answers ErrSpoolFull, which still is the
// error of the system, to a write, a truncation, the copy of the version
// being modified and the creation of the spool file.
func TestSpool_Full(t *testing.T) {
	limit := func(fs *FS, room int64) {
		fs.newSpoolFile = func(dir string) (spoolFile, error) {
			f, err := createSpoolFile(dir)
			if err != nil {
				return nil, err
			}

			return &fullFile{spoolFile: f, room: room}, nil
		}
	}
	isFull := func(err error) bool { return errors.Is(err, ErrSpoolFull) && errors.Is(err, syscall.ENOSPC) }

	t.Run("write and truncate", func(t *testing.T) {
		fs := newWriteFS(t, Options{}, emptyRoot())
		limit(fs.FS, 8)
		s := fs.spool(t, "/doc.txt", nil, false)
		n, err := s.WriteAt([]byte("0123456789"), 0)
		if n != 8 || !isFull(err) {
			t.Fatalf("WriteAt = (%d, %v), want 8 bytes and ErrSpoolFull", n, err)
		}
		if s.Size() != 8 || string(spoolContent(t, s)) != "01234567" {
			t.Errorf("size = %d, content = %q; want what fitted", s.Size(), spoolContent(t, s))
		}
		if err := s.Truncate(100); !isFull(err) || s.Size() != 8 {
			t.Errorf("Truncate = %v, size %d; want ErrSpoolFull and the size unchanged", err, s.Size())
		}
		// What fitted is still a file that can be flushed.
		if node := mustFlush(t, s); node.Size != 8 {
			t.Errorf("flushed %d bytes, want 8", node.Size)
		}
	})

	t.Run("hydration", func(t *testing.T) {
		src := newChunkSource(testData(18))
		node := Node{ID: "f", Name: "f", Type: TypeFile, VersionID: "v1", Size: 18, ChunkCount: len(src.chunks)}
		fs := newWriteFS(t, Options{ReadChunk: src.read, ChunkSize: testChunkSize}, emptyRoot())
		limit(fs.FS, 8)
		s := fs.spool(t, "/f", &node, false)
		if _, err := s.ReadAt(make([]byte, 4), 0); !isFull(err) {
			t.Errorf("ReadAt = %v, want ErrSpoolFull", err)
		}
		if _, err := s.WriteAt([]byte("x"), 1); !isFull(err) || s.Dirty() {
			t.Errorf("WriteAt = %v, dirty %v; want ErrSpoolFull and a clean spool", err, s.Dirty())
		}
	})

	t.Run("creation", func(t *testing.T) {
		fs := newWriteFS(t, Options{}, emptyRoot())
		fs.newSpoolFile = func(string) (spoolFile, error) { return nil, errNoSpace }
		if _, err := fs.OpenSpool(context.Background(), "dr1", "/f", nil, false); !isFull(err) {
			t.Errorf("OpenSpool = %v, want ErrSpoolFull", err)
		}
	})
}

// A write from offset 0 that covers the whole version needs none of it, but
// only once it is stored: cut short by a full file system, it replaced the
// bytes it wrote and the rest of the version is still the content.
func TestSpool_CoveringWriteCutShort(t *testing.T) {
	isFull := func(err error) bool { return errors.Is(err, ErrSpoolFull) && errors.Is(err, syscall.ENOSPC) }
	open := func(t *testing.T, relief int64) (*writeFS, *spool, *fullFile, []byte) {
		t.Helper()
		src := newChunkSource(testData(18))
		node := Node{ID: "f-old", Name: "doc.bin", Type: TypeFile, VersionID: "v1", Size: 18, ChunkCount: len(src.chunks)}
		fs := newWriteFS(t, Options{ReadChunk: src.read, ChunkSize: testChunkSize}, emptyRoot())
		var file *fullFile
		fs.newSpoolFile = func(dir string) (spoolFile, error) {
			f, err := createSpoolFile(dir)
			if err != nil {
				return nil, err
			}
			file = &fullFile{spoolFile: f, room: 8, relief: relief}

			return file, nil
		}
		fs.upsert("dr1", "/", node)

		return fs, fs.spool(t, "/doc.bin", &node, false), file, src.data
	}
	cutShort := func(t *testing.T, s *spool) {
		t.Helper()
		n, err := s.WriteAt(bytes.Repeat([]byte("z"), 18), 0)
		if n != 8 || !isFull(err) {
			t.Fatalf("WriteAt = (%d, %v), want 8 bytes and ErrSpoolFull", n, err)
		}
		if s.Size() != 18 || !s.Dirty() {
			t.Errorf("size = %d, dirty %v; want 18 bytes and a dirty spool", s.Size(), s.Dirty())
		}
	}
	held := func(s *spool) bool {
		s.mu.Lock()
		defer s.mu.Unlock()

		return s.src != nil
	}

	// Room is back by the time the rest of the version is copied: the spool
	// is whole when WriteAt returns.
	t.Run("room comes back", func(t *testing.T) {
		fs, s, _, version := open(t, 18)
		cutShort(t, s)
		if held(s) {
			t.Error("the version is still held although all of it is in the spool")
		}
		want := append([]byte("zzzzzzzz"), version[8:]...)
		if got := spoolContent(t, s); !bytes.Equal(got, want) {
			t.Errorf("content = %q, want %q", got, want)
		}
		// Read from the fake API, not through FS.Open: Options.ReadChunk only
		// serves the version the spool was opened on.
		if got := fs.api.content(fs.identity, mustFlush(t, s).VersionID); !bytes.Equal(got, want) {
			t.Errorf("flushed %q, want %q", got, want)
		}
	})

	// Still no room: the tail cannot come in. Reads and Flush say so rather
	// than serve a file cut at the bytes written, and the version is kept
	// for when there is room.
	t.Run("still full", func(t *testing.T) {
		fs, s, file, version := open(t, 0)
		cutShort(t, s)
		if n, err := s.ReadAt(make([]byte, 18), 0); !isFull(err) {
			t.Errorf("ReadAt = (%d, %v), want ErrSpoolFull", n, err)
		}
		if _, err := s.Flush(context.Background()); !isFull(err) || len(fs.api.list()) != 0 {
			t.Errorf("Flush = %v, requests %v; want ErrSpoolFull and nothing sent", err, fs.api.list())
		}

		file.room = 18
		want := append([]byte("zzzzzzzz"), version[8:]...)
		got := make([]byte, 18)
		if n, err := s.ReadAt(got, 0); n != 18 || err != nil || !bytes.Equal(got, want) {
			t.Errorf("ReadAt = (%d, %v) %q, want %q", n, err, got, want)
		}
		if held(s) {
			t.Error("the version is still held although all of it is in the spool")
		}
		// Read from the fake API, not through FS.Open: Options.ReadChunk only
		// serves the version the spool was opened on.
		if got := fs.api.content(fs.identity, mustFlush(t, s).VersionID); !bytes.Equal(got, want) {
			t.Errorf("flushed %q, want %q", got, want)
		}
	})

	// A truncation below what the short write stored leaves nothing of the
	// version to bring in.
	t.Run("then truncated", func(t *testing.T) {
		_, s, _, _ := open(t, 0)
		cutShort(t, s)
		if err := s.Truncate(5); err != nil {
			t.Fatalf("Truncate: %v", err)
		}
		if held(s) {
			t.Error("the version is still held although the content keeps none of it")
		}
		if got := spoolContent(t, s); string(got) != "zzzzz" {
			t.Errorf("content = %q, want %q", got, "zzzzz")
		}
	})
}

// — Spool: unlinked ———————————————————————————————————————————————————————————

// Once unlinked, a spool is a local file: it still reads and writes, and
// nothing it is asked makes a request.
func TestSpool_Unlinked(t *testing.T) {
	for _, label := range []string{"pending", "flushed"} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/doc.txt", nil, false)
			mustWriteAt(t, s, []byte("hello"), 0)
			if label == "flushed" {
				mustFlush(t, s)
			}
			fs.api.reset()

			s.Unlinked()
			s.Unlinked()
			if node, exists := s.Node(); exists || node != (Node{}) || s.Dirty() {
				t.Errorf("unlinked: node %+v exists %v dirty %v", node, exists, s.Dirty())
			}
			mustWriteAt(t, s, []byte("HE"), 0)
			if err := s.Truncate(4); err != nil {
				t.Fatalf("Truncate: %v", err)
			}
			if got := spoolContent(t, s); string(got) != "HEll" || s.Dirty() {
				t.Errorf("content = %q, dirty %v; want %q and nothing to send", got, s.Dirty(), "HEll")
			}
			ctx := context.Background()
			if node, err := s.Flush(ctx); err != nil || node != (Node{}) {
				t.Errorf("Flush = (%+v, %v), want a zero node and no error", node, err)
			}
			when := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
			if err := s.SetModTime(ctx, when); err != nil || !s.ModTime().Equal(when) {
				t.Errorf("SetModTime = %v, ModTime %v; want %v", err, s.ModTime(), when)
			}
			if _, exists := s.Node(); exists {
				t.Error("a Flush after Unlinked gave the spool a node")
			}
			if err := s.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			if calls := fs.api.list(); len(calls) != 0 {
				t.Errorf("requests after Unlinked = %v, want none", calls)
			}
		})
	}
}

// Unlinked during a Flush cancels it and waits for it: what the Flush had
// created is removed, the Flush answers no error, and nothing is sent after
// Unlinked returns.
func TestSpool_UnlinkedDuringFlush(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.bin", nil, false)
	mustWriteAt(t, s, testData(chunked), 0)
	intercept, arrived, release := hold("POST /dataroom/node/version/")
	defer release()
	fs.api.setIntercept(intercept)

	type result struct {
		node Node
		err  error
	}
	done := make(chan result, 1)
	go func() {
		node, err := s.Flush(context.Background())
		done <- result{node, err}
	}()
	<-arrived
	s.Unlinked()
	// The Flush is over when Unlinked returns: its cleanup is in the journal.
	if fs.api.count("DELETE /dataroom/node/f-") != 1 {
		t.Errorf("requests = %v, want the node of the cancelled upload deleted", fs.api.list())
	}
	if got := <-done; got.err != nil || got.node != (Node{}) {
		t.Errorf("Flush = (%+v, %v), want a zero node and no error", got.node, got.err)
	}
	if _, exists := s.Node(); exists {
		t.Error("the spool has a node after Unlinked")
	}
	if len(cachedNodes(fs.FS, "dr1", "/")) != 0 {
		t.Error("the listing gained the file of an unlinked spool")
	}

	fs.api.reset()
	fs.api.setIntercept(nil)
	if node, err := s.Flush(context.Background()); err != nil || node != (Node{}) {
		t.Errorf("Flush = (%+v, %v), want a zero node and no error", node, err)
	}
	if calls := fs.api.list(); len(calls) != 0 {
		t.Errorf("requests after Unlinked = %v, want none", calls)
	}
}

// An upload that completes although its file was unlinked meanwhile (the
// cancellation came too late) is undone: the node it created is deleted, a
// version added to the node the front end removed is left to that removal,
// and the listing the upload edited is dropped. The spool is marked unlinked
// by hand: Unlinked itself would cancel the request held here.
func TestSpool_UnlinkedAfterTheUploadCompleted(t *testing.T) {
	for label, existing := range map[string]bool{"pending": false, "existing node": true} {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/doc.txt", nil, false)
			mustWriteAt(t, s, []byte("hello"), 0)
			var nodeID string
			if existing {
				nodeID = mustFlush(t, s).ID
				mustWriteAt(t, s, []byte("HELLO"), 0)
			}
			fs.api.reset()

			arrived, gate := make(chan struct{}), make(chan struct{})
			fs.api.setIntercept(func(_ http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPost {
					close(arrived)
					<-gate
				}

				return false
			})
			done := make(chan error, 1)
			go func() {
				node, err := s.Flush(context.Background())
				if node != (Node{}) {
					err = errors.Join(err, fmt.Errorf("Flush returned the node %+v", node))
				}
				done <- err
			}()
			<-arrived
			s.mu.Lock()
			s.unlinked, s.node, s.exists = true, Node{}, false
			s.mu.Unlock()
			close(gate)
			if err := <-done; err != nil {
				t.Errorf("Flush = %v, want a zero node and no error", err)
			}

			if existing {
				wantCalls(t, fs.api, "POST /dataroom/dr1/node/file")
				if len(fs.api.nodeVersions(nodeID)) != 2 {
					t.Error("the version sent to the unlinked node was deleted: its removal is the front end's")
				}
			} else if calls := fs.api.list(); len(calls) != 2 || calls[0] != "POST /dataroom/dr1/node/file" ||
				!strings.HasPrefix(calls[1], "DELETE /dataroom/node/f-") {
				t.Errorf("requests = %v, want the file created then its node deleted", calls)
			}
			if nodeCacheHas(fs.FS, "dr1", "/") {
				t.Error("the listing the upload edited is still cached")
			}
			if _, exists := s.Node(); exists || s.Dirty() {
				t.Error("the Flush that completed gave the unlinked spool a node")
			}
		})
	}
}

// After Close every method answers ErrClosed, and a second Close does nothing.
func TestSpool_AfterClose(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, []byte("x"), 0)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := context.Background()
	if _, err := s.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrClosed) {
		t.Errorf("ReadAt = %v, want ErrClosed", err)
	}
	if _, err := s.WriteAt([]byte("y"), 0); !errors.Is(err, ErrClosed) {
		t.Errorf("WriteAt = %v, want ErrClosed", err)
	}
	if err := s.Truncate(0); !errors.Is(err, ErrClosed) {
		t.Errorf("Truncate = %v, want ErrClosed", err)
	}
	if _, err := s.Flush(ctx); !errors.Is(err, ErrClosed) {
		t.Errorf("Flush = %v, want ErrClosed", err)
	}
	if err := s.SetModTime(ctx, time.Now()); !errors.Is(err, ErrClosed) {
		t.Errorf("SetModTime = %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if len(fs.api.list()) != 0 {
		t.Errorf("requests = %v, want none", fs.api.list())
	}
}

// Closing a spool opened on an existing file releases the File it would have
// read the version through.
func TestSpool_CloseReleasesTheVersion(t *testing.T) {
	_, s, src, _ := existingSpool(t, 18, false)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrClosed) {
		t.Errorf("ReadAt = %v, want ErrClosed", err)
	}
	wantCounts(t, src, map[int]int{})
}

// — Spool: cancellation and concurrency ———————————————————————————————————————

// hold makes an intercept that keeps the requests starting with prefix
// waiting until release is called or their client leaves; arrived receives
// one value per request held. A request released is then served by the store.
func hold(
	prefix string,
) (intercept func(http.ResponseWriter, *http.Request) bool, arrived chan struct{}, release func()) {
	gate := make(chan struct{})
	arrived = make(chan struct{}, 64)
	var once sync.Once

	return func(_ http.ResponseWriter, r *http.Request) bool {
		if !strings.HasPrefix(r.Method+" "+r.URL.Path, prefix) {
			return false
		}
		// The body is read first: the server only sees its client leave once
		// it has.
		_, _ = io.Copy(io.Discard, r.Body)
		arrived <- struct{}{}
		select {
		case <-gate:
			// The body is spent: the store cannot serve the request any more.
			return false
		case <-r.Context().Done():
			return true
		}
	}, arrived, func() { once.Do(func() { close(gate) }) }
}

// A Flush whose context ends leaves no half version: what it created is
// removed, the spool stays dirty, and a later Flush sends the file.
func TestSpool_FlushCancelled(t *testing.T) {
	cases := map[string]struct {
		size int
		hold string
	}{
		"single request": {size: small, hold: "POST /dataroom/dr1/node/file"},
		"chunked":        {size: chunked, hold: "POST /dataroom/node/version/"},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/doc.bin", nil, false)
			data := testData(tc.size)
			mustWriteAt(t, s, data, 0)
			intercept, arrived, release := hold(tc.hold)
			defer release()
			fs.api.setIntercept(intercept)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, err := s.Flush(ctx)
				done <- err
			}()
			<-arrived
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("Flush = %v, want context.Canceled", err)
			}
			if _, exists := s.Node(); exists || !s.Dirty() {
				t.Errorf("after a cancelled Flush: exists %v dirty %v", exists, s.Dirty())
			}
			if tc.size == chunked && fs.api.count("DELETE /dataroom/node/f-") != 1 {
				t.Errorf("requests = %v, want the node of the cancelled upload deleted", fs.api.list())
			}
			if len(cachedNodes(fs.FS, "dr1", "/")) != 0 {
				t.Error("the listing gained the file of a cancelled Flush")
			}

			// A context already over sends nothing.
			fs.api.reset()
			if _, err := s.Flush(ctx); !errors.Is(err, context.Canceled) || len(fs.api.list()) != 0 {
				t.Errorf("Flush on a context that is over = %v, requests %v", err, fs.api.list())
			}

			fs.api.setIntercept(nil)
			node := mustFlush(t, s)
			if got := fs.readBack(t, node); !bytes.Equal(got, data) {
				t.Error("the Flush after the cancelled one sent another content")
			}
		})
	}
}

// Close during a Flush stops it: the Flush fails with ErrClosed, what it had
// created is removed, and the spool file is gone.
func TestSpool_CloseDuringFlush(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.bin", nil, false)
	mustWriteAt(t, s, testData(chunked), 0)
	intercept, arrived, release := hold("POST /dataroom/node/version/")
	defer release()
	fs.api.setIntercept(intercept)

	done := make(chan error, 1)
	go func() {
		_, err := s.Flush(context.Background())
		done <- err
	}()
	<-arrived
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Errorf("Flush = %v, want ErrClosed", err)
	}
	if fs.api.count("DELETE /dataroom/node/f-") != 1 {
		t.Errorf("requests = %v, want the node of the stopped upload deleted", fs.api.list())
	}
	if n := spoolFiles(t, fs.FS); n != 0 {
		t.Errorf("SpoolDir holds %d files after Close", n)
	}
}

// A write issued during a Flush waits for it, then makes the spool dirty: the
// version sent is one state of the file, and the write is not lost.
func TestSpool_WriteDuringFlush(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.bin", nil, false)
	data := testData(chunked)
	mustWriteAt(t, s, data, 0)

	// The chunk is held on its way in: its body cannot be replayed, so it is
	// refused once released and the first Flush fails. The point is the write.
	started := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	fs.api.setIntercept(func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/dataroom/node/version/") {
			once.Do(func() {
				close(started)
				<-proceed
			})
		}

		return false
	})

	flushed := make(chan Node, 1)
	go func() {
		node, err := s.Flush(context.Background())
		if err != nil {
			t.Errorf("Flush: %v", err)
		}
		flushed <- node
	}()
	<-started
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		if _, err := s.WriteAt([]byte("LATE"), 0); err != nil {
			t.Errorf("WriteAt: %v", err)
		}
	}()
	select {
	case <-wrote:
		t.Fatal("the write landed while the Flush was sending")
	case <-time.After(50 * time.Millisecond):
	}
	if s.Size() != chunked {
		t.Errorf("Size = %d while a write waits, want %d", s.Size(), chunked)
	}
	close(proceed)
	first := <-flushed
	<-wrote

	if got := fs.readBack(t, first); !bytes.Equal(got, data) {
		t.Error("the version flushed holds the write that came after")
	}
	if !s.Dirty() {
		t.Fatal("the write that waited left the spool clean")
	}
	second := mustFlush(t, s)
	want := append([]byte("LATE"), data[4:]...)
	if got := fs.readBack(t, second); !bytes.Equal(got, want) {
		t.Error("the second version does not hold the late write")
	}
}

// Writes, reads, truncations and flushes issued together on one spool, as a
// mounted file system issues them: no race, and the last Flush sends what
// the writers wrote.
func TestSpool_ConcurrentUse(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.bin", nil, false)
	const writers, region, rounds = 8, 4096, 20
	if err := s.Truncate(writers * region); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			block := bytes.Repeat([]byte{"abcdefgh"[w]}, region)
			for range rounds {
				if _, err := s.WriteAt(block, int64(w*region)); err != nil {
					t.Errorf("WriteAt: %v", err)
				}
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			buf := make([]byte, region)
			for i := range rounds {
				if _, err := s.ReadAt(buf, int64(i%writers*region)); err != nil && !errors.Is(err, io.EOF) {
					t.Errorf("ReadAt: %v", err)
				}
				_, _ = s.Size(), s.ModTime()
				_, _ = s.Node()
			}
		})
	}
	wg.Go(func() {
		for i := range rounds {
			// Never below what the writers cover.
			if err := s.Truncate(int64(writers*region + i%2)); err != nil {
				t.Errorf("Truncate: %v", err)
			}
		}
	})
	for range 3 {
		wg.Go(func() {
			for range 3 {
				if _, err := s.Flush(context.Background()); err != nil {
					t.Errorf("Flush: %v", err)
				}
				_ = s.SetModTime(context.Background(), time.Now())
			}
		})
	}
	wg.Wait()

	if err := s.Truncate(writers * region); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	node := mustFlush(t, s)
	var want []byte
	for w := range writers {
		want = append(want, bytes.Repeat([]byte{"abcdefgh"[w]}, region)...)
	}
	if got := fs.readBack(t, node); !bytes.Equal(got, want) {
		t.Error("the last Flush did not send what the writers wrote")
	}
	if s.Dirty() {
		t.Error("the spool is dirty after the last Flush")
	}
}

// Writers on one end, Close on the other: whatever the interleaving, no
// method blocks or panics, and the spool file is gone.
func TestSpool_CloseDuringUse(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.bin", nil, false)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range 200 {
				_, _ = s.WriteAt([]byte("data"), int64(w*1000+i))
				_, _ = s.ReadAt(make([]byte, 4), int64(i))
			}
		})
	}
	wg.Go(func() { _, _ = s.Flush(context.Background()) })
	wg.Go(func() { _ = s.Close() })
	wg.Wait()
	_ = s.Close()
	if n := spoolFiles(t, fs.FS); n != 0 {
		t.Errorf("SpoolDir holds %d files after Close", n)
	}
}

// — A folder that is not listed ———————————————————————————————————————————————

// A node recorded under a folder whose listing is not cached is kept as the
// Entry of its name: the next lookup answers from it instead of asking the
// API, which may not hold the node yet, and a negative Entry of that name
// does not outlive the creation.
func TestUpsert_UnlistedFolderKeepsAnEntry(t *testing.T) {
	fs := New(nil, Options{NegativeTTL: time.Minute})
	t.Cleanup(func() { _ = fs.Close() })
	ek := entryKey("dr1", "/a", "f.txt")
	fs.mu.Lock()
	_ = fs.store.PutEntry(context.Background(), ek, &Entry{FetchedAt: time.Now()})
	fs.mu.Unlock()
	if _, err := fs.Lookup(context.Background(), "dr1", "/a", "f.txt"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Lookup before = %v, want the negative entry", err)
	}

	node := Node{ID: "f-1", ParentID: "d-a", Name: "f.txt", Type: TypeFile, VersionID: "v-1", Mode: 0755}
	fs.upsert("dr1", "/a/", node)
	if e, ok := cachedEntry(fs, "/a", "f.txt"); !ok || e.Node == nil || *e.Node != node {
		t.Fatalf("entry = %+v, want the node", e)
	}
	if got, err := fs.Lookup(context.Background(), "dr1", "/a", "f.txt"); err != nil || got != node {
		t.Errorf("Lookup = (%+v, %v), want the node, without an API", got, err)
	}
	if id, ok := fs.cachedFileID("dr1", "/a", "f.txt"); !ok || id != "f-1" {
		t.Errorf("cachedFileID = (%q, %v), want f-1 from the entry", id, ok)
	}
	if nodeCacheHas(fs, "dr1", "/a") {
		t.Error("upsert made up a listing for a folder that was never listed")
	}

	// A new version of the node keeps what the entry knew and it does not.
	fs.upsert("dr1", "/a", Node{ID: "f-1", ParentID: "d-a", Name: "f.txt", Type: TypeFile, VersionID: "v-2"})
	if e, _ := cachedEntry(fs, "/a", "f.txt"); e == nil || e.Node.VersionID != "v-2" || e.Node.Mode != 0755 {
		t.Errorf("entry = %+v, want version v-2 with the mode kept", e)
	}
	// A folder is not a file to overwrite; a name unknown is a miss.
	fs.upsert("dr1", "/a", Node{ID: "d-1", Name: "sub", Type: TypeDir})
	if id, ok := fs.cachedFileID("dr1", "/a", "sub"); ok {
		t.Errorf("cachedFileID of a folder = (%q, true)", id)
	}
	if _, ok := fs.cachedFileID("dr1", "/a", "nope"); ok {
		t.Error("cachedFileID found a name nothing cached")
	}
}

// A listed folder is edited, and gets no Entry: its listing is what answers.
func TestUpsert_ListedFolderGetsNoEntry(t *testing.T) {
	fs := seeded(map[string]*nodeCacheEntry{"/": {fetchedAt: time.Now()}})
	fs.upsert("dr1", "/", Node{ID: "f-1", Name: "f.txt", Type: TypeFile})
	if _, ok := cachedEntry(fs, "/", "f.txt"); ok {
		t.Error("an Entry was kept beside the listing")
	}
	if got := names(cachedNodes(fs, "dr1", "/")); !slices.Equal(got, []string{"f.txt"}) {
		t.Errorf("listing = %v", got)
	}
}

// A file written under a folder that is not listed is found again without a
// request, and overwritten without the node creation that would answer 409.
func TestCreate_UnderAnUnlistedFolder(t *testing.T) {
	fs := newWriteFS(t, Options{NegativeTTL: time.Minute}, map[string][]service.DataroomNodeInfo{
		"/": {{ID: "d-a", Name: "a", Type: "dir"}},
	})
	first := fs.create(t, "/a/doc.bin", testData(small))
	fs.api.reset()

	if got, err := fs.Lookup(context.Background(), "dr1", "/a", "doc.bin"); err != nil || got != first {
		t.Errorf("Lookup = (%+v, %v), want the file just written", got, err)
	}
	if calls := fs.api.list(); len(calls) != 0 {
		t.Errorf("the lookup asked the API: %v", calls)
	}

	second := fs.create(t, "/a/doc.bin", testData(chunked))
	wantCalls(t, fs.api,
		"POST /dataroom/node/"+first.ID+"/version",
		"POST /dataroom/node/version/"+second.VersionID+"/chunk/0",
		"POST /dataroom/node/version/"+second.VersionID+"/chunk/1")
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt = %v, want the one the entry knew: %v", second.CreatedAt, first.CreatedAt)
	}
}

// A pending spool flushed under a folder that is not listed leaves the same
// trace: the file does not vanish behind a negative Entry.
func TestSpool_FlushUnderAnUnlistedFolder(t *testing.T) {
	fs := newWriteFS(t, Options{NegativeTTL: time.Minute}, map[string][]service.DataroomNodeInfo{
		"/": {{ID: "d-a", Name: "a", Type: "dir"}},
	})
	fs.mu.Lock()
	_ = fs.store.PutEntry(context.Background(), entryKey("dr1", "/a", "new.txt"), &Entry{FetchedAt: time.Now()})
	fs.mu.Unlock()

	s := fs.spool(t, "/a/new.txt", nil, false)
	mustWriteAt(t, s, []byte("x"), 0)
	node := mustFlush(t, s)
	fs.api.reset()
	if got, err := fs.Lookup(context.Background(), "dr1", "/a", "new.txt"); err != nil || got != node {
		t.Errorf("Lookup = (%+v, %v), want the file just flushed", got, err)
	}
	if calls := fs.api.list(); len(calls) != 0 {
		t.Errorf("the lookup asked the API: %v", calls)
	}
}

// — Spool: mode at creation, server-side copy ———————————————————————————————————

// The mode given to a pending spool travels with the request that creates
// the node, single request or node creation: no request of its own. A file
// that exists is sent none.
func TestSpool_SetMode(t *testing.T) {
	for name, size := range map[string]int{"single request": small, "chunked": chunked} {
		t.Run(name, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/run.sh", nil, false)
			s.SetMode(0o750)
			mustWriteAt(t, s, bytes.Repeat([]byte("x"), size), 0)
			node := mustFlush(t, s)
			if node.Mode != 0o750 {
				t.Errorf("mode of the node flushed = %v, want 0750", node.Mode)
			}
			fs.api.mu.Lock()
			stored := fs.api.nodes[node.ID].mode
			fs.api.mu.Unlock()
			if stored != "0750" {
				t.Errorf("access_mode at the API = %q, want 0750", stored)
			}
			if n := fs.api.count("PUT "); n != 0 {
				t.Errorf("%d PUT requests, want the mode sent with the creation: %v", n, fs.api.list())
			}

			// The file exists now: a later mode is not the spool's to send.
			s.SetMode(0o600)
			mustWriteAt(t, s, []byte("y"), 0)
			mustFlush(t, s)
			fs.api.mu.Lock()
			stored = fs.api.nodes[node.ID].mode
			fs.api.mu.Unlock()
			if stored != "0750" {
				t.Errorf("access_mode after a second flush = %q, want 0750 still", stored)
			}
		})
	}
}

// A mode of 0 given to a pending spool is declared as "0000" with the
// creation, and the node returned stores it; a spool given none declares
// none.
func TestSpool_SetModeZero(t *testing.T) {
	for name, size := range map[string]int{"single request": small, "chunked": chunked} {
		t.Run(name, func(t *testing.T) {
			fs := newWriteFS(t, Options{}, emptyRoot())
			s := fs.spool(t, "/locked", nil, false)
			s.SetMode(0)
			mustWriteAt(t, s, bytes.Repeat([]byte("x"), size), 0)
			node := mustFlush(t, s)
			if !node.HasMode() || node.Mode != 0 {
				t.Errorf("node flushed = %+v, want a stored 0", node)
			}
			plain := fs.spool(t, "/plain", nil, false)
			mustWriteAt(t, plain, bytes.Repeat([]byte("x"), size), 0)
			other := mustFlush(t, plain)
			fs.api.mu.Lock()
			stored, none := fs.api.nodes[node.ID].mode, fs.api.nodes[other.ID].mode
			fs.api.mu.Unlock()
			if stored != "0000" || none != "" {
				t.Errorf("access_mode at the API = %q and %q, want 0000 and none", stored, none)
			}
			if other.HasMode() {
				t.Errorf("node flushed without a mode = %+v, want none", other)
			}
		})
	}
}

// CopyFrom makes a pending, empty spool the server-side copy of another
// file: one request, no chunk either way, and a clean spool on the copy that
// reads its content and sends a new version of it once written.
func TestSpool_CopyFrom(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	data := bytes.Repeat([]byte("0123456789abcdef"), chunked/16+1)
	src := fs.create(t, "/src.bin", data)
	s := fs.spool(t, "/copy.bin", nil, false)
	fs.api.reset()

	node, err := s.CopyFrom(context.Background(), "/src.bin")
	if err != nil {
		t.Fatalf("CopyFrom: %v", err)
	}
	wantCalls(t, fs.api, "POST /dataroom/node/"+src.ID+"/copy")
	if node.ID == "" || node.ID == src.ID || node.Size != int64(len(data)) || node.Name != "copy.bin" {
		t.Errorf("copied node = %+v", node)
	}
	if got, exists := s.Node(); !exists || got.ID != node.ID || s.Dirty() || s.Size() != int64(len(data)) {
		t.Errorf("after CopyFrom: node %+v exists %v dirty %v size %d", got, exists, s.Dirty(), s.Size())
	}
	if got := mustFlush(t, s); got.ID != node.ID {
		t.Errorf("Flush of the copy = %+v", got)
	}
	wantCalls(t, fs.api, "POST /dataroom/node/"+src.ID+"/copy")
	if listed, ok := FindNode(cachedNodes(fs.FS, "dr1", "/"), "copy.bin"); !ok || listed.ID != node.ID {
		t.Errorf("the listing does not hold the copy: %+v", listed)
	}

	// The content comes in when it is read; a write then makes a version of
	// the copy, not a new node.
	if got := spoolContent(t, s); !bytes.Equal(got, data) {
		t.Errorf("content of the copy: %d bytes, want the %d of its source", len(got), len(data))
	}
	mustWriteAt(t, s, []byte("Z"), 0)
	if after := mustFlush(t, s); after.ID != node.ID || after.VersionID == node.VersionID {
		t.Errorf("flush after a write = %+v, want a new version of %s", after, node.ID)
	}

	// Asked of a spool that is not pending and empty any more: nothing is sent.
	fs.api.reset()
	if _, err := s.CopyFrom(context.Background(), "/src.bin"); !errors.Is(err, ErrSpoolNotEmpty) {
		t.Errorf("CopyFrom on a file that exists = %v, want ErrSpoolNotEmpty", err)
	}
	written := fs.spool(t, "/other.bin", nil, false)
	mustWriteAt(t, written, []byte("x"), 0)
	if _, err := written.CopyFrom(context.Background(), "/src.bin"); !errors.Is(err, ErrSpoolNotEmpty) {
		t.Errorf("CopyFrom on a spool with content = %v, want ErrSpoolNotEmpty", err)
	}
	wantCalls(t, fs.api)

	// A destination name that is taken: refused, and the spool is as it was.
	taken := fs.spool(t, "/src.bin", nil, false)
	if _, err := taken.CopyFrom(context.Background(), "/copy.bin"); !errors.Is(err, ErrExist) {
		t.Errorf("CopyFrom onto a name that is taken = %v, want ErrExist", err)
	}
	if _, exists := taken.Node(); exists || !taken.Dirty() || taken.Size() != 0 {
		t.Error("a refused CopyFrom changed the spool")
	}
}

// A rename waits for the Flush in flight and then sees the file as that Flush
// left it: a pending spool whose first Flush is on its way is not renamed as
// if the API held nothing.
func TestSpool_RenameWaitsForTheFlush(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, testData(small), 0)
	// Held before its body is read, so that the store serves it once let go.
	arrived, gate := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	defer release()
	fs.api.setIntercept(func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == "/dataroom/dr1/node/file" {
			arrived <- struct{}{}
			<-gate
		}

		return false
	})

	flushed := make(chan error, 1)
	go func() {
		_, err := s.Flush(context.Background())
		flushed <- err
	}()
	<-arrived

	// A caller that gives up while the Flush runs renames nothing.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := s.Rename(ctx, "/other.txt", func(bool) error {
		t.Error("rename called for a caller that gave up")

		return nil
	})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Rename with a context that ends = %v", err)
	}

	type seen struct {
		exists bool
		err    error
	}
	renamed := make(chan seen, 1)
	go func() {
		var got seen
		got.err = s.Rename(context.Background(), "/moved.txt", func(exists bool) error {
			got.exists = exists

			return nil
		})
		renamed <- got
	}()
	select {
	case got := <-renamed:
		t.Fatalf("Rename returned %+v while the Flush was in flight", got)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if err := <-flushed; err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := <-renamed; got.err != nil || !got.exists {
		t.Errorf("Rename = %+v, want the file the Flush created", got)
	}
}

// Rename records the new path only when the rename succeeded; a pending spool
// is told the API holds nothing, and its first Flush goes to the new path.
func TestSpool_Rename(t *testing.T) {
	fs := newWriteFS(t, Options{}, emptyRoot())
	ctx := context.Background()
	s := fs.spool(t, "/doc.txt", nil, false)
	mustWriteAt(t, s, testData(small), 0)

	refused := errors.New("refused")
	if err := s.Rename(ctx, "/no.txt", func(bool) error { return refused }); !errors.Is(err, refused) {
		t.Errorf("Rename = %v, want the error of the rename", err)
	}
	calls := 0
	err := s.Rename(ctx, "/moved.txt", func(exists bool) error {
		calls++
		if exists {
			t.Error("a pending spool was said to exist")
		}

		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("Rename = %v after %d calls", err, calls)
	}
	node, err := s.Flush(ctx)
	if err != nil || node.Name != "moved.txt" {
		t.Fatalf("Flush = (%+v, %v), want the file under its new name", node, err)
	}
	if nodes := cachedNodes(fs.FS, "dr1", "/"); len(nodes) != 1 || nodes[0].Name != "moved.txt" {
		t.Errorf("listing = %+v", nodes)
	}

	s.Unlinked()
	if err := s.Rename(ctx, "/x.txt", func(bool) error { return nil }); !errors.Is(err, ErrNotExist) {
		t.Errorf("Rename of an unlinked spool = %v, want ErrNotExist", err)
	}
	_ = s.Close()
	if err := s.Rename(ctx, "/x.txt", func(bool) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Errorf("Rename of a closed spool = %v, want ErrClosed", err)
	}
}

// Uploads of different files share the slots of Options.UploadConcurrency:
// twelve Create at once never have more than two requests at the API, and
// all of them end.
func TestCreate_UploadsAreBoundedAcrossFiles(t *testing.T) {
	const limit, files = 2, 12
	fs := newWriteFS(t, Options{UploadConcurrency: limit}, map[string][]service.DataroomNodeInfo{
		"/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"/a": {},
	})
	var (
		mu        sync.Mutex
		now, most int
		release   = make(chan struct{})
		arrived   = make(chan struct{}, files)
	)
	fs.api.setIntercept(func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/node/file") {
			return false
		}
		mu.Lock()
		now++
		most = max(most, now)
		mu.Unlock()
		arrived <- struct{}{}
		<-release
		mu.Lock()
		now--
		mu.Unlock()

		return false // the store answers
	})

	errs := make(chan error, files)
	for i := range files {
		go func() {
			data := testData(small)
			_, err := fs.Create(t.Context(), "dr1", fmt.Sprintf("/a/f%02d", i), int64(len(data)), time.Time{},
				bytes.NewReader(data))
			errs <- err
		}()
	}
	for range limit {
		<-arrived
	}
	// The others are waiting for a slot: none reaches the API meanwhile.
	select {
	case <-arrived:
		t.Fatalf("a request beyond the %d slots reached the API", limit)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for range files {
		if err := <-errs; err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	if most != limit {
		t.Errorf("at most %d uploads at once, want %d", most, limit)
	}
	if n := fs.api.count("POST /dataroom/dr1/node/file"); n != files {
		t.Errorf("%d uploads sent, want %d", n, files)
	}
}

// A Create waiting for a slot gives up with its context and sends nothing.
func TestCreate_WaitingForASlotEndsWithTheContext(t *testing.T) {
	fs := newWriteFS(t, Options{UploadConcurrency: 1}, map[string][]service.DataroomNodeInfo{
		"/":  {{ID: "d-a", Name: "a", Type: "dir"}},
		"/a": {},
	})
	fs.uploadSlots <- struct{}{} // the only slot, taken
	defer func() { <-fs.uploadSlots }()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	data := testData(small)
	_, err := fs.Create(ctx, "dr1", "/a/doc.txt", int64(len(data)), time.Time{}, bytes.NewReader(data))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Create = %v, want the context's end", err)
	}
	if n := fs.api.count("POST /dataroom/dr1/node/file"); n != 0 {
		t.Errorf("%d uploads sent, want none", n)
	}
}
