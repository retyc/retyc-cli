//go:build linux

package retycfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// testChunkSize is the size the fake API cuts its files at, and the one the
// FS is told to assume: small, so that a file of a few hundred kilobytes has
// several chunks.
const testChunkSize = 64 << 10

// fakeNode is a node of fakeAPI.
type fakeNode struct {
	id      string
	kind    string // api.NodeTypeFolder, api.NodeTypeFile or api.NodeTypeSymlink
	target  string // of a symlink
	mode    string // access_mode, "" for none
	mime    string // of a file, "" for none
	data    []byte // of a file
	version string // of a file
	mtime   time.Time
}

// fakeVersion is the content of one version, which the API keeps serving
// after the file got a newer one.
type fakeVersion struct {
	data []byte
	pub  string
	// cut is the size of its chunks: the one its uploader chose, and
	// testChunkSize (zero) for a file a test put there.
	cut int
}

// chunkSize returns the size the version is cut at.
func (v fakeVersion) chunkSize() int {
	if v.cut > 0 {
		return v.cut
	}

	return testChunkSize
}

// fakeDataroom is one dataroom of fakeAPI.
type fakeDataroom struct {
	id, title string
	identity  *age.HybridIdentity
	pub, salt string
	children  map[string]map[string]*fakeNode // parent ID ("" for the root) → name → node
	// used and free are the storage counters; hasQuota false is an API
	// without them.
	hasQuota   bool
	used, free int64
}

// fakeAPI is a fake of the dataroom API with real encryption: names, targets,
// MIME types and chunks are encrypted for the session key of their dataroom,
// as the API holds them. It answers the listing, the lookup by name hash, the
// MIME table, the storage counters and the chunks, and counts each kind of
// request. Its write routes are in fakeapi_write_test.go.
type fakeAPI struct {
	t testing.TB

	mu        sync.Mutex
	datarooms map[string]*fakeDataroom
	order     []string
	versions  map[string]fakeVersion
	counts    map[string]int
	nextID    int
	// throttle is the number of chunk requests still to refuse with a 429.
	throttle int
	// cipher keeps the ciphertext of each string: encrypting 200 names on
	// every listing would be most of the time of a test.
	cipher map[string]string
	// uploads are the versions whose chunks are still coming, mimes the MIME
	// types writes declared (dataroom ID, NUL, hash → type), noStorage makes
	// every upload refused for lack of room.
	uploads   map[string]*fakeUpload
	mimes     map[string]string
	noStorage bool
	// locks are the node locks held (lock ID → node ID); lockedElsewhere the
	// nodes another client holds, which answer 423 to a lock.
	locks           map[string]string
	lockedElsewhere map[string]bool
	lockSeq         int
	// undeletable are the nodes whose deletion the API refuses (403).
	undeletable map[string]bool
	// unexpected are the requests the fake does not know, for summary.
	unexpected []string
	// before, when set, sees every request that writes before it is answered,
	// with mu not held: a test holds a request back there.
	before func(r *http.Request)
	// beforeRead is the same for the requests that read (GET).
	beforeRead func(r *http.Request)
	// readOnly makes every write to a dataroom refused 403 DATAROOM_READ_ONLY.
	readOnly bool
}

func newFakeAPI(t testing.TB) *fakeAPI {
	return &fakeAPI{
		t:         t,
		datarooms: make(map[string]*fakeDataroom),
		versions:  make(map[string]fakeVersion),
		counts:    make(map[string]int),
		cipher:    make(map[string]string),
		uploads:   make(map[string]*fakeUpload),
		mimes:     make(map[string]string),
		locks:     make(map[string]string),

		lockedElsewhere: make(map[string]bool),
	}
}

// dataroom adds a dataroom, with storage counters.
func (a *fakeAPI) dataroom(id, title string) *fakeDataroom {
	a.t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		a.t.Fatalf("GenerateKeyPair: %v", err)
	}
	dr := &fakeDataroom{
		id: id, title: title, identity: identity, pub: identity.Recipient().String(), salt: "salt-" + id,
		children: make(map[string]map[string]*fakeNode),
		hasQuota: true, used: 3 << 30, free: 7 << 30,
	}
	a.mu.Lock()
	a.datarooms[id] = dr
	a.order = append(a.order, id)
	a.mu.Unlock()

	return dr
}

// id returns a fresh identifier with the given prefix.
func (a *fakeAPI) newID(prefix string) string {
	a.nextID++

	return prefix + "-" + strconv.Itoa(a.nextID)
}

// put adds or replaces the child name of parent (a folder ID, "" for the
// root) and returns it.
func (a *fakeAPI) put(dr *fakeDataroom, parent, name string, n fakeNode) *fakeNode {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n.id == "" {
		n.id = a.newID("n")
	}
	if n.mtime.IsZero() {
		n.mtime = time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	}
	if n.kind == api.NodeTypeFile {
		n.version = a.newID("v")
		a.versions[n.version] = fakeVersion{data: n.data, pub: dr.pub}
	}
	if dr.children[parent] == nil {
		dr.children[parent] = make(map[string]*fakeNode)
	}
	dr.children[parent][name] = &n

	return &n
}

// dir adds the folder name to parent and returns its ID.
func (a *fakeAPI) dir(dr *fakeDataroom, parent, name string) string {
	return a.put(dr, parent, name, fakeNode{kind: api.NodeTypeFolder}).id
}

// file adds the file name to parent.
func (a *fakeAPI) file(dr *fakeDataroom, parent, name string, data []byte) *fakeNode {
	return a.put(dr, parent, name, fakeNode{kind: api.NodeTypeFile, data: data, mime: "text/plain"})
}

// rewrite gives the file name of parent a new version holding data, as
// another client uploading it would. The node keeps its ID and, unless mtime
// is set, its modification time.
func (a *fakeAPI) rewrite(dr *fakeDataroom, parent, name string, data []byte, mtime time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := dr.children[parent][name]
	n.data = data
	n.version = a.newID("v")
	if !mtime.IsZero() {
		n.mtime = mtime
	}
	a.versions[n.version] = fakeVersion{data: data, pub: dr.pub}
}

// drop removes the child name of parent.
func (a *fakeAPI) drop(dr *fakeDataroom, parent, name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(dr.children[parent], name)
}

// move hangs the child name of parent from the folder to, under the same
// name, as another client moving it would. The node keeps its ID.
func (a *fakeAPI) move(dr *fakeDataroom, parent, name, to string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := dr.children[parent][name]
	delete(dr.children[parent], name)
	if dr.children[to] == nil {
		dr.children[to] = make(map[string]*fakeNode)
	}
	dr.children[to][name] = n
}

// count returns the number of requests of one kind received: listing, lookup,
// chunk, stats, mime or other.
func (a *fakeAPI) count(kind string) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.counts[kind]
}

// resetCounts forgets the requests counted so far.
func (a *fakeAPI) resetCounts() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counts = make(map[string]int)
}

// summary formats the counters, for a failure message.
func (a *fakeAPI) summary() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	kinds := make([]string, 0, len(a.counts))
	for k := range a.counts {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s=%d", k, a.counts[k]))
	}

	if len(a.unexpected) > 0 {
		parts = append(parts, fmt.Sprintf("unexpected=%v", a.unexpected))
	}

	return strings.Join(parts, " ")
}

func hashOf(salt, value string) string {
	h := sha256.Sum256([]byte(salt + value))

	return hex.EncodeToString(h[:])
}

// encryptLocked returns value encrypted for the dataroom. The caller holds mu.
func (a *fakeAPI) encryptLocked(dr *fakeDataroom, value string) string {
	key := dr.id + "\x00" + value
	if enc, ok := a.cipher[key]; ok {
		return enc
	}
	enc, err := crypto.EncryptStringForKeys(value, []string{dr.pub})
	if err != nil {
		a.t.Errorf("EncryptStringForKeys: %v", err)
	}
	a.cipher[key] = enc

	return enc
}

// itemLocked renders a node as the API lists it. The caller holds mu.
func (a *fakeAPI) itemLocked(dr *fakeDataroom, parent, name string, n *fakeNode) map[string]any {
	node := map[string]any{
		"id": n.id, "type": n.kind, "name_enc": a.encryptLocked(dr, name), "name_hash": hashOf(dr.salt, name),
		"type_enc": nil, "parent_id": nil, "created_at": "2026-10-01T10:00:00Z",
	}
	if parent != "" {
		node["parent_id"] = parent
	}
	if n.mode != "" {
		node["access_mode"] = n.mode
	}
	var version any
	switch n.kind {
	case api.NodeTypeSymlink:
		node["target_enc"] = a.encryptLocked(dr, n.target)
	case api.NodeTypeFile:
		if n.mime != "" {
			node["mime_type_id"] = "mime-" + hashOf(dr.salt, n.mime)[:12]
		}
		if n.version == "" {
			// No complete version yet.
			break
		}
		cut := a.versions[n.version].chunkSize()
		chunks := (len(n.data) + cut - 1) / cut
		version = map[string]any{
			"id": n.version, "node_id": n.id, "original_size": len(n.data), "chunk_count": chunks,
			"created_at": "2026-10-02T09:00:00Z", "client_mtime": n.mtime.Format(time.RFC3339Nano),
		}
	}

	return map[string]any{"node": node, "node_version": version}
}

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	a.mu.Lock()
	before, readOnly := a.before, a.readOnly
	if r.Method == http.MethodGet {
		before = a.beforeRead
	}
	a.mu.Unlock()
	if readOnly && len(parts) >= 2 && parts[0] == "dataroom" && r.Method != http.MethodGet {
		w.Header().Set(api.ErrorCodeHeader, api.CodeDataroomReadOnly)
		refuse(w, http.StatusForbidden, `{"detail":"the dataroom is read-only"}`)

		return
	}
	if before != nil {
		before(r)
	}
	if len(parts) >= 2 && parts[0] == "dataroom" && r.Method != http.MethodGet && a.write(w, r, parts) {
		return
	}
	if r.Method != http.MethodGet || len(parts) < 2 || parts[0] != "dataroom" {
		a.other(w, r)

		return
	}
	// /dataroom/node/version/{id}/chunk/{n}
	if len(parts) == 6 && parts[1] == "node" && parts[2] == "version" && parts[4] == "chunk" {
		a.chunk(w, parts[3], parts[5])

		return
	}
	a.mu.Lock()
	dr := a.datarooms[parts[1]]
	a.mu.Unlock()
	switch {
	case dr == nil:
		a.other(w, r)
	case len(parts) == 3 && parts[2] == "nodes":
		a.nodes(w, r, dr)
	case len(parts) == 3 && parts[2] == "mime-types":
		a.mimeTypes(w, dr)
	case len(parts) == 3 && parts[2] == "stats":
		a.stats(w, dr)
	default:
		a.other(w, r)
	}
}

// other refuses a request the fake does not know, and counts it: a test that
// expects none fails on the counter.
func (a *fakeAPI) other(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.counts["other"]++
	a.unexpected = append(a.unexpected, r.Method+" "+r.URL.Path)
	a.mu.Unlock()
	http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
}

// nodes answers a lookup by name hash or a listing.
func (a *fakeAPI) nodes(w http.ResponseWriter, r *http.Request, dr *fakeDataroom) {
	parent := r.URL.Query().Get("parent_id")
	hash := r.URL.Query().Get("name_hash")
	a.mu.Lock()
	switch {
	case hash == "":
		a.counts["listing"]++
	case !desktopProbe(dr.salt, hash):
		a.counts["lookup"]++
	}
	names := make([]string, 0, len(dr.children[parent]))
	for name := range dr.children[parent] {
		names = append(names, name)
	}
	slices.Sort(names)
	items := []any{}
	for _, name := range names {
		if hash == "" || hashOf(dr.salt, name) == hash {
			items = append(items, a.itemLocked(dr, parent, name, dr.children[parent][name]))
		}
	}
	a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "total": len(items), "pages": 1, "page": 1})
}

// desktopProbe reports whether hash is the one of a name the desktop session
// of a developer looks for at the root of every new mount (the trash, the
// volume information of file managers). Those lookups are not the test's,
// come when they please, and are left out of the counters; a CI runner makes
// none.
func desktopProbe(salt, hash string) bool {
	for _, name := range []string{
		".Trash", ".Trash-" + strconv.Itoa(os.Getuid()), ".hidden", ".xdg-volume-info", "autorun.inf", ".directory",
	} {
		if hashOf(salt, name) == hash {
			return true
		}
	}

	return false
}

// mimeTypes answers the MIME table: one row per type a file of the dataroom
// carries.
func (a *fakeAPI) mimeTypes(w http.ResponseWriter, dr *fakeDataroom) {
	a.mu.Lock()
	a.counts["mime"]++
	seen := map[string]bool{}
	rows := []any{}
	for _, children := range dr.children {
		for _, n := range children {
			if n.mime == "" || seen[n.mime] {
				continue
			}
			seen[n.mime] = true
			hash := hashOf(dr.salt, n.mime)
			rows = append(rows, map[string]any{
				"id": "mime-" + hash[:12], "hash": hash, "name_enc": a.encryptLocked(dr, n.mime),
			})
		}
	}
	a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(rows)
}

func (a *fakeAPI) stats(w http.ResponseWriter, dr *fakeDataroom) {
	a.mu.Lock()
	a.counts["stats"]++
	body := map[string]any{"files_count": 1, "versions_count": 1, "files_encrypted_size": 1}
	if dr.hasQuota {
		body["storage_used"], body["storage_free"] = dr.used, dr.free
	}
	a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(body)
}

// chunk answers one encrypted chunk of a version.
func (a *fakeAPI) chunk(w http.ResponseWriter, versionID, indexText string) {
	a.mu.Lock()
	a.counts["chunk"]++
	v, ok := a.versions[versionID]
	throttled := a.throttle > 0
	if throttled {
		a.throttle--
	}
	a.mu.Unlock()
	if throttled {
		http.Error(w, "No more requests allowed", http.StatusTooManyRequests)

		return
	}
	index, err := strconv.Atoi(indexText)
	cut := v.chunkSize()
	if !ok || err != nil || index < 0 || index*cut >= len(v.data) {
		http.Error(w, "Not Found", http.StatusNotFound)

		return
	}
	plain := v.data[index*cut : min((index+1)*cut, len(v.data))]
	enc, err := crypto.EncryptBinaryForKey(plain, v.pub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}
	_, _ = w.Write(enc)
}

// testData returns size bytes that differ at every offset a chunk boundary
// could shift them to.
func testData(size int, seed byte) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7+i/251) ^ seed
	}

	return data
}

// — Mounting ————————————————————————————————————————————————————————————————

// requireFUSE skips a test that mounts when the machine cannot: no /dev/fuse,
// or no fusermount3 helper for a user who is not root. In CI it fails
// instead: the mounted tests are the ones that prove the driver, and a runner
// without FUSE must not turn them green by skipping them.
func requireFUSE(t testing.TB) {
	t.Helper()
	missing := func(format string, args ...any) {
		if os.Getenv("CI") != "" {
			t.Fatalf("FUSE is required in CI: "+format, args...)
		}
		t.Skipf("FUSE unavailable: "+format, args...)
	}
	f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		missing("%v", err)
	}
	_ = f.Close()
	if os.Geteuid() == 0 {
		return
	}
	for _, helper := range []string{"fusermount3", "fusermount"} {
		if _, err := exec.LookPath(helper); err == nil {
			return
		}
	}
	missing("no fusermount3 helper and not root")
}

// logRecorder collects what the driver and the tree under it (vfs) report
// through their Options.Logf.
type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (l *logRecorder) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// forget drops what was recorded so far.
func (l *logRecorder) forget() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = nil
}

func (l *logRecorder) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return strings.Join(l.lines, "\n")
}

// mounted is a filesystem mounted for a test.
type mounted struct {
	dir  string
	srv  *Server
	tree *vfs.FS
	api  *fakeAPI
	logs *logRecorder
}

// mountOptions are what a test changes of a mount.
type mountOptions struct {
	driver Options
	// ttl is the TTL of the listing cache, a minute when zero.
	ttl time.Duration
	// listAhead lets vfs list a folder whose names are looked up one after
	// the other, as a real mount does. Not by default: the desktop session
	// of a developer probes the root of every new mount (see desktopProbe),
	// and the listing of the root those probes start, with the first lookup
	// of the test, would land in its counters when it pleases.
	listAhead bool
}

// mountFS mounts the datarooms of a in a temporary folder: the dataroom
// opts.driver.DataroomID, or all of them. The filesystem is unmounted, and
// checked to be, when the test ends.
func mountFS(t *testing.T, a *fakeAPI, opts mountOptions) *mounted {
	t.Helper()
	requireFUSE(t)
	// Before the unmount is registered: the folder is then removed after it,
	// and RemoveAll never walks into the mount.
	dir := t.TempDir()

	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false,
		// As cmd builds it: one CLIENT span per round trip.
		api.WrapTransport(telemetry.RoundTripper))

	// One recorder for the driver and for the tree, as cmd gives both the
	// same Logf: a test that looks for a name in the logs sees all of them.
	m := &mounted{dir: dir, api: a, logs: &logRecorder{}}
	tree := vfs.New(client, vfs.Options{
		Logf:        m.logs.logf,
		TTL:         opts.ttl,
		NegativeTTL: vfs.DefaultNegativeTTL,
		ChunkSize:   testChunkSize,

		NoListingAhead: !opts.listAhead,
		ListDatarooms: func(context.Context) ([]vfs.Dataroom, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.counts["datarooms"]++
			list := make([]vfs.Dataroom, 0, len(a.order))
			for _, id := range a.order {
				list = append(list, vfs.Dataroom{ID: id, Title: a.datarooms[id].title})
			}

			return list, nil
		},
	})
	a.mu.Lock()
	for id, dr := range a.datarooms {
		tree.SeedSession(id, &service.DataroomSession{Identity: dr.identity, PublicKey: dr.pub, NameSalt: dr.salt})
	}
	a.mu.Unlock()

	m.tree = tree
	driver := opts.driver
	driver.Logf = m.logs.logf
	if driver.UnmountGrace == 0 {
		driver.UnmountGrace = 2 * time.Second
	}
	mnt, err := Mount(context.Background(), tree, dir, driver)
	if err != nil {
		_ = tree.Close()
		t.Fatalf("Mount: %v", err)
	}
	m.srv = mnt
	t.Cleanup(func() {
		if err := mnt.Unmount(); err != nil {
			t.Errorf("Unmount: %v", err)
		}
		_ = tree.Close()
		if still, err := isMounted(mnt.mountpoint); err != nil || still {
			t.Errorf("%s is still mounted (err %v)", mnt.mountpoint, err)
		}
		if logs := m.logs.text(); strings.Contains(logs, "detaching") {
			t.Errorf("the mount point was busy at the end of the test:\n%s", logs)
		}
	})
	// Registered last, so run first: the journal as the test left it.
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("what the driver did, for the failure above:\n%s", m.journal(diagnosticRecords))
		}
	})

	return m
}

// diagnosticRecords is the number of operations a failed test prints.
const diagnosticRecords = 60

// journal returns the last operations of the access log, at most limit of
// them, one per line with the errno each one answered, then what the driver
// reported through Options.Logf. An errno alone names the Go error where
// toErrno maps a single one to it: EINTR is a request whose context ended
// (context.Canceled), because its caller was being killed or the drain of a
// shutdown was over (see driver.guard).
func (m *mounted) journal(limit uint64) string {
	var b []byte
	l := m.srv.drv.log
	l.mu.Lock()
	first := l.oldestLocked()
	if l.next-first > limit {
		first = l.next - limit
	}
	for seq := first; seq < l.next; seq++ {
		b = l.ring[seq%uint64(len(l.ring))].appendTo(b)
	}
	l.mu.Unlock()
	if logs := m.logs.text(); logs != "" {
		b = append(b, "driver log:\n"...)
		b = append(b, logs...)
	}

	return string(b)
}
