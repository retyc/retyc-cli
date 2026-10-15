package vfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// — Helpers ———————————————————————————————————————————————————————————————————

// apiCall is one request a fake API received.
type apiCall struct {
	method, path string
	query        url.Values
	body         map[string]any
}

func (c apiCall) String() string { return c.method + " " + c.path }

// fakeAPI is a fake API server: reply answers each request, and every request
// is recorded with its JSON body.
type fakeAPI struct {
	mu    sync.Mutex
	calls []apiCall
	// reply answers a request; it returns false for one it does not know,
	// which is then a 500.
	reply func(w http.ResponseWriter, call apiCall) bool
}

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := apiCall{method: r.Method, path: r.URL.Path, query: r.URL.Query()}
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &call.body)
	}
	a.mu.Lock()
	a.calls = append(a.calls, call)
	a.mu.Unlock()
	if a.reply == nil || !a.reply(w, call) {
		http.Error(w, "unexpected "+call.String(), http.StatusInternalServerError)
	}
}

// list returns the requests received, as "METHOD path".
func (a *fakeAPI) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	calls := make([]string, len(a.calls))
	for i, c := range a.calls {
		calls[i] = c.String()
	}

	return calls
}

// only returns the requests whose "METHOD path" starts with prefix.
func (a *fakeAPI) only(prefix string) []apiCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	var calls []apiCall
	for _, c := range a.calls {
		if strings.HasPrefix(c.String(), prefix) {
			calls = append(calls, c)
		}
	}

	return calls
}

// status makes a reply that answers every request with status and body.
func status(code int, body string) func(http.ResponseWriter, apiCall) bool {
	return func(w http.ResponseWriter, _ apiCall) bool {
		http.Error(w, body, code)

		return true
	}
}

// newAPIFS returns an FS on the fake API with an unlocked session for
// dataroom "dr1" and the given listings, keyed by path, cached. The client
// sends a request once: a 429 is not replayed.
func newAPIFS(t *testing.T, fake *fakeAPI, opts Options, listings map[string][]service.DataroomNodeInfo) *FS {
	t.Helper()
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	client := api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false,
		api.WithRetry(time.Millisecond, 1))

	fs := New(client, opts)
	fs.SeedSession("dr1", &service.DataroomSession{Identity: identity, PublicKey: identity.Recipient().String()})
	for path, nodes := range listings {
		seedNodeCache(fs, map[string]*nodeCacheEntry{path: {nodes: nodes, fetchedAt: time.Now()}})
	}

	return fs
}

// tree is the listings most mutation tests start from: a file and two folders
// at the root, one of them holding a file.
func tree() map[string][]service.DataroomNodeInfo {
	return map[string][]service.DataroomNodeInfo{
		"/": {
			{ID: "f-doc", Name: "doc.txt", Type: "file", VersionID: "v-doc", Size: 9, ChunkCount: 1},
			{ID: "f-old", Name: "old.txt", Type: "file", VersionID: "v-old"},
			{ID: "d-full", Name: "full", Type: "dir"},
			{ID: "d-empty", Name: "empty", Type: "dir"},
		},
		"/full":  {{ID: "f-in", Name: "in.txt", Type: "file", VersionID: "v-in"}},
		"/empty": {},
	}
}

// names returns the names of nodes, sorted.
func names(nodes []Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Name
	}
	slices.Sort(out)

	return out
}

// storageRefusal is the body of the 400 the API answers to a write that
// exceeds the storage.
const storageRefusal = `{"detail":"Requested file size 9 exceeds maximum allowed storage size 5"}`

// carriesNoSentinel reports whether err carries none of the sentinels of the
// package.
func carriesNoSentinel(err error) bool {
	var kind *kindError

	return !errors.As(err, &kind)
}

// — Mkdir ———————————————————————————————————————————————————————————————————————

// Mkdir creates the folder under the parent's ID read from the cached listing,
// returns its node, and leaves both listings ready: the parent's names the
// folder, the folder's own is empty.
func TestMkdir_CreatesAndCaches(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.String() != "POST /dataroom/dr1/node" {
			return false
		}
		fmt.Fprint(w, `{"id":"d-new","name_enc":"x"}`)

		return true
	}}
	fs := newAPIFS(t, fake, Options{}, tree())

	node, err := fs.Mkdir(context.Background(), "dr1", "/full/new")
	if err != nil || node.ID != "d-new" || node.Name != "new" || node.Type != TypeDir {
		t.Fatalf("Mkdir = (%+v, %v), want the new folder", node, err)
	}
	calls := fake.only("POST")
	if len(calls) != 1 || calls[0].body["parent_id"] != "d-full" || calls[0].body["type"] != api.NodeTypeFolder {
		t.Errorf("requests = %+v, want one folder creation under d-full", calls)
	}
	if got := names(cachedNodes(fs, "dr1", "/full")); !slices.Equal(got, []string{"in.txt", "new"}) {
		t.Errorf("parent listing = %v, want in.txt and new", got)
	}
	if l := cachedListing(fs, "dr1", "/full/new"); l == nil || len(l.Nodes) != 0 {
		t.Errorf("listing of the new folder = %+v, want an empty one", l)
	}
}

// What refuses a Mkdir carries the sentinel of the package and the error it
// came from.
func TestMkdir_Errors(t *testing.T) {
	cases := map[string]struct {
		path     string
		reply    func(http.ResponseWriter, apiCall) bool
		want     error
		also     error // the original error, still matched
		requests int
	}{
		"parent missing":   {path: "/nowhere/new", want: ErrNotExist},
		"parent is a file": {path: "/doc.txt/new", want: ErrNotDir, also: os.ErrInvalid},
		"name taken at the root": {
			path: "/new", reply: status(http.StatusConflict, "taken"), want: ErrExist, also: api.ErrConflict, requests: 1,
		},
		"forbidden": {
			path: "/new", reply: status(http.StatusForbidden, "viewer"), want: ErrForbidden, requests: 1,
		},
		"unauthenticated": {
			path: "/new", reply: status(http.StatusUnauthorized, "expired"), want: ErrUnauthenticated, requests: 1,
		},
		"the root itself": {path: "/", want: ErrExist},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: tc.reply}
			fs := newAPIFS(t, fake, Options{}, tree())
			_, err := fs.Mkdir(context.Background(), "dr1", tc.path)
			if !errors.Is(err, tc.want) {
				t.Errorf("Mkdir(%s) = %v, want %v", tc.path, err, tc.want)
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Errorf("Mkdir(%s) = %v, which no longer matches %v", tc.path, err, tc.also)
			}
			if got := len(fake.list()); got != tc.requests {
				t.Errorf("%d request(s) %v, want %d", got, fake.list(), tc.requests)
			}
		})
	}
}

// A parent the cached listing names and the API no longer has (404, or 410
// while its purge is pending) is ErrNotExist, and its listings are dropped.
func TestMkdir_ParentDeletedElsewhere(t *testing.T) {
	for _, code := range goneStatuses {
		fake := &fakeAPI{reply: status(code, "gone")}
		fs := newAPIFS(t, fake, Options{}, tree())
		_, err := fs.Mkdir(context.Background(), "dr1", "/full/new")
		if !errors.Is(err, ErrNotExist) || !errors.Is(err, api.ErrNotFound) {
			t.Errorf("%d: Mkdir = %v, want ErrNotExist carrying the API's answer", code, err)
		}
		if nodeCacheHas(fs, "dr1", "/") || nodeCacheHas(fs, "dr1", "/full") {
			t.Errorf("%d: the listings naming the deleted parent are still cached", code)
		}
	}
}

// — Remove ——————————————————————————————————————————————————————————————————————

// Without recursive a folder that has children is ErrNotEmpty and nothing is
// deleted: the API would delete the whole tree. An empty folder and a file are
// deleted; with recursive the folder goes whatever it holds.
//
// Whether a folder is empty is asked of the API, whatever its cached listing
// says: every listing of the tree is cached and fresh here, and the folder is
// listed all the same. The last case is the one that matters: the cache says
// empty, the API holds a file another client created, and the folder stays.
func TestRemove_NonRecursiveRefusesANonEmptyFolder(t *testing.T) {
	cases := map[string]struct {
		path      string
		recursive bool
		onAPI     map[string]string // what the API lists in the folder, by node ID
		want      error
		listed    bool // the folder is listed first
		deleted   string
	}{
		"non-empty folder": {path: "/full", onAPI: map[string]string{"f-in": "in.txt"}, want: ErrNotEmpty, listed: true},
		"empty folder":     {path: "/empty", onAPI: map[string]string{}, listed: true, deleted: "d-empty"},
		"file":             {path: "/doc.txt", deleted: "f-doc"},
		"non-empty folder, recursive": {
			path: "/full", recursive: true, onAPI: map[string]string{"f-in": "in.txt"}, deleted: "d-full",
		},
		"folder the cache lists empty and the API does not": {
			path: "/empty", onAPI: map[string]string{"f-x": "x.txt"}, want: ErrNotEmpty, listed: true,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			var pub string
			fake := &fakeAPI{}
			fake.reply = func(w http.ResponseWriter, call apiCall) bool {
				switch {
				case call.method == http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				case call.String() == "GET /dataroom/dr1/nodes" && tc.onAPI != nil:
					fmt.Fprint(w, nodesPageJSON(t, pub, tc.onAPI))
				default:
					return false
				}

				return true
			}
			fs := newAPIFS(t, fake, Options{}, tree())
			sess, _ := fs.Session(context.Background(), "dr1")
			pub = sess.PublicKey

			err := fs.Remove(context.Background(), "dr1", tc.path, tc.recursive)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Remove(%s) = %v, want %v", tc.path, err, tc.want)
			}
			var want []string
			if tc.listed {
				want = append(want, "GET /dataroom/dr1/nodes")
			}
			if tc.deleted != "" {
				want = append(want, "DELETE /dataroom/node/"+tc.deleted)
			}
			if got := fake.list(); !slices.Equal(got, want) {
				t.Errorf("requests = %v, want %v", got, want)
			}
			_, name := SplitPath(tc.path)
			listed := slices.Contains(names(cachedNodes(fs, "dr1", "/")), name)
			if listed != (tc.want != nil) {
				t.Errorf("%s listed in the parent = %v after Remove = %v", name, listed, err)
			}
			if tc.want == nil && nodeCacheHas(fs, "dr1", tc.path) {
				t.Errorf("the listing of the removed %s is still cached", tc.path)
			}
		})
	}
}

// The emptiness of a folder is read from the API when its listing is not
// cached: one listing, then the refusal.
func TestRemove_NonRecursiveListsAnUncachedFolder(t *testing.T) {
	var pub string
	fake := &fakeAPI{}
	fake.reply = func(w http.ResponseWriter, call apiCall) bool {
		if call.String() != "GET /dataroom/dr1/nodes" {
			return false
		}
		fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-x": "x.txt"}))

		return true
	}
	listings := tree()
	delete(listings, "/full")
	fs := newAPIFS(t, fake, Options{}, listings)
	sess, _ := fs.Session(context.Background(), "dr1")
	pub = sess.PublicKey

	if err := fs.Remove(context.Background(), "dr1", "/full", false); !errors.Is(err, ErrNotEmpty) {
		t.Errorf("Remove = %v, want ErrNotEmpty", err)
	}
	if got := fake.list(); !slices.Equal(got, []string{"GET /dataroom/dr1/nodes"}) {
		t.Errorf("requests = %v, want the folder listed and nothing deleted", got)
	}
}

// A path that names nothing is ErrNotExist without a request; a node the API
// no longer has is ErrNotExist carrying its answer, after one retry against a
// fresh listing.
func TestRemove_Missing(t *testing.T) {
	fs := newAPIFS(t, &fakeAPI{}, Options{}, tree())
	if err := fs.Remove(context.Background(), "dr1", "/nothing", true); !errors.Is(err, ErrNotExist) {
		t.Errorf("Remove(/nothing) = %v, want ErrNotExist", err)
	}
	if err := fs.Remove(context.Background(), "dr1", "/", true); err == nil {
		t.Error("Remove(/) succeeded")
	}

	var pub string
	fake := &fakeAPI{}
	fake.reply = func(w http.ResponseWriter, call apiCall) bool {
		switch call.String() {
		case "DELETE /dataroom/node/f-doc":
			http.Error(w, "gone", http.StatusNotFound)
		case "GET /dataroom/dr1/nodes":
			fmt.Fprint(w, nodesPageJSON(t, pub, map[string]string{"f-doc": "doc.txt"}))
		default:
			return false
		}

		return true
	}
	fs = newAPIFS(t, fake, Options{}, tree())
	sess, _ := fs.Session(context.Background(), "dr1")
	sess.AssumeLegacyAPI() // the retry lists the folder (lookup_test.go has it by name)
	pub = sess.PublicKey
	err := fs.Remove(context.Background(), "dr1", "/doc.txt", true)
	if !errors.Is(err, ErrNotExist) || !errors.Is(err, api.ErrNotFound) {
		t.Errorf("Remove of a node gone on the API = %v, want ErrNotExist carrying the 404", err)
	}
	want := []string{"DELETE /dataroom/node/f-doc", "GET /dataroom/dr1/nodes", "DELETE /dataroom/node/f-doc"}
	if got := fake.list(); !slices.Equal(got, want) {
		t.Errorf("requests = %v, want %v", got, want)
	}
}

// — Rename ——————————————————————————————————————————————————————————————————————

// mimeTable answers the MIME table route: an empty table on an API that has
// the node types, 404 on one that predates them.
func mimeTable(w http.ResponseWriter, legacy bool) {
	if legacy {
		http.Error(w, "Not Found", http.StatusNotFound)

		return
	}
	fmt.Fprint(w, `[]`)
}

// Without replace the rename is the PUT WebDAV always sent: no replace field.
// With it, the same single PUT carries "replace": true, and the node takes the
// place of the file it replaced in the cached listing.
func TestRename_ReplaceIsOnePut(t *testing.T) {
	for _, replace := range []bool{false, true} {
		fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
			switch call.String() {
			case "GET /dataroom/dr1/mime-types":
				mimeTable(w, false)
			case "PUT /dataroom/node/f-doc":
				w.WriteHeader(http.StatusNoContent)
			default:
				return false
			}

			return true
		}}
		fs := newAPIFS(t, fake, Options{}, tree())

		if err := fs.Rename(context.Background(), "dr1", "/doc.txt", "/old.txt", replace); err != nil {
			t.Fatalf("Rename(replace=%v) = %v", replace, err)
		}
		puts := fake.only("PUT")
		if len(puts) != 1 || len(fake.only("DELETE")) != 0 {
			t.Fatalf("replace=%v: requests = %v, want one PUT and no DELETE", replace, fake.list())
		}
		body := puts[0].body
		if got, sent := body["replace"]; sent != replace || (replace && got != true) {
			t.Errorf("replace=%v: body = %v, want the replace field only when asked", replace, body)
		}
		if parent, sent := body["parent_id"]; !sent || parent != nil || body["name_enc"] == nil || body["name_hash"] == nil {
			t.Errorf("replace=%v: body = %v, want the new name and an explicit root parent", replace, body)
		}
		root := cachedNodes(fs, "dr1", "/")
		var holders []string
		for _, n := range root {
			if n.Name == "old.txt" {
				holders = append(holders, n.ID)
			}
		}
		if !slices.Equal(holders, []string{"f-doc"}) || slices.Contains(names(root), "doc.txt") {
			t.Errorf("replace=%v: root listing = %+v, want f-doc alone under old.txt", replace, root)
		}
	}
}

// On an API that predates the node types the replace field would be ignored,
// and the rename would not replace: nothing is sent, the error says why.
func TestRename_ReplaceNeedsTheNodeTypesAPI(t *testing.T) {
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.String() != "GET /dataroom/dr1/mime-types" {
			return false
		}
		mimeTable(w, true)

		return true
	}}
	fs := newAPIFS(t, fake, Options{}, tree())

	err := fs.Rename(context.Background(), "dr1", "/doc.txt", "/old.txt", true)
	if !errors.Is(err, ErrReplaceUnsupported) || !errors.Is(err, service.ErrReplaceUnsupported) {
		t.Errorf("Rename(replace) on a legacy API = %v, want ErrReplaceUnsupported", err)
	}
	if len(fake.only("PUT")) != 0 {
		t.Errorf("requests = %v, want no PUT", fake.list())
	}
	if got := names(cachedNodes(fs, "dr1", "/")); !slices.Contains(got, "doc.txt") {
		t.Errorf("root listing = %v, want it untouched", got)
	}
}

// The refusals of a rename, as the API words them.
func TestRename_Errors(t *testing.T) {
	cases := map[string]struct {
		src, dst string
		replace  bool
		put      func(http.ResponseWriter, apiCall) bool
		want     error
		also     error
	}{
		"destination exists": {
			src: "/doc.txt", dst: "/old.txt",
			put:  status(http.StatusConflict, `{"detail":"Duplicate node name hash in the same folder"}`),
			want: ErrExist, also: api.ErrConflict,
		},
		"replace onto a folder": {
			src: "/doc.txt", dst: "/empty", replace: true,
			put:  status(http.StatusConflict, `{"detail":"Cannot replace a folder"}`),
			want: ErrIsDir, also: api.ErrConflict,
		},
		"replace not allowed": {
			src: "/doc.txt", dst: "/old.txt", replace: true,
			put:  status(http.StatusForbidden, `{"detail":"Replace not allowed"}`),
			want: ErrForbidden,
		},
		"source missing":               {src: "/nothing", dst: "/x", want: ErrNotExist},
		"destination folder missing":   {src: "/doc.txt", dst: "/nowhere/x", want: ErrNotExist},
		"destination parent is a file": {src: "/doc.txt", dst: "/old.txt/x", want: ErrNotDir, also: os.ErrInvalid},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				if call.String() == "GET /dataroom/dr1/mime-types" {
					mimeTable(w, false)

					return true
				}

				return tc.put != nil && call.method == http.MethodPut && tc.put(w, call)
			}}
			fs := newAPIFS(t, fake, Options{}, tree())
			err := fs.Rename(context.Background(), "dr1", tc.src, tc.dst, tc.replace)
			if !errors.Is(err, tc.want) {
				t.Errorf("Rename = %v, want %v", err, tc.want)
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Errorf("Rename = %v, which no longer matches %v", err, tc.also)
			}
			if tc.put == nil && len(fake.only("PUT")) != 0 {
				t.Errorf("requests = %v, want no PUT", fake.list())
			}
			// A conflict at the root is genuine: the PUT is not repeated.
			if tc.put != nil && len(fake.only("PUT")) != 1 {
				t.Errorf("requests = %v, want one PUT", fake.list())
			}
		})
	}
}

// — Copy ————————————————————————————————————————————————————————————————————————

// copyReply answers the server-side copy of f-doc with a sealed version.
func copyReply(w http.ResponseWriter) {
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprint(w, `{"node":{"id":"f-copy","type":"file","name_enc":"x","type_enc":null,"mime_type_id":null,`+
		`"access_mode":"0644","parent_id":null},"node_version":{"id":"v-copy","node_id":"f-copy",`+
		`"original_size":9,"chunk_count":1,"chunk_count_expected":1,"version_number":1,`+
		`"created_at":"2026-10-10T12:00:00Z"}}`)
}

// A copy onto a free name creates the node; onto a file, with replace, it
// deletes that file first and says so.
func TestCopy_NewAndReplaced(t *testing.T) {
	for dst, wantReplaced := range map[string]bool{"/full/copy.txt": false, "/old.txt": true} {
		fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
			switch call.String() {
			case "POST /dataroom/node/f-doc/copy":
				copyReply(w)
			case "DELETE /dataroom/node/f-old":
				w.WriteHeader(http.StatusNoContent)
			default:
				return false
			}

			return true
		}}
		fs := newAPIFS(t, fake, Options{}, tree())

		node, replaced, err := fs.Copy(context.Background(), "dr1", "/doc.txt", dst, true)
		_, name := SplitPath(dst)
		if err != nil || replaced != wantReplaced || node.ID != "f-copy" || node.Name != name || node.Size != 9 {
			t.Fatalf("Copy to %s = (%+v, %v, %v), want f-copy, replaced %v", dst, node, replaced, err, wantReplaced)
		}
		want := []string{"POST /dataroom/node/f-doc/copy"}
		if wantReplaced {
			want = []string{"DELETE /dataroom/node/f-old", "POST /dataroom/node/f-doc/copy"}
		}
		if got := fake.list(); !slices.Equal(got, want) {
			t.Errorf("requests to %s = %v, want %v", dst, got, want)
		}
		parent, _ := SplitPath(dst)
		var holders []string
		for _, n := range cachedNodes(fs, "dr1", parent) {
			if n.Name == name {
				holders = append(holders, n.ID)
			}
		}
		if !slices.Equal(holders, []string{"f-copy"}) {
			t.Errorf("destination listing names %v under %s, want the copy alone", holders, name)
		}
	}
}

// A failed copy tells the step that failed and carries the sentinel of what
// went wrong.
func TestCopy_Errors(t *testing.T) {
	cases := map[string]struct {
		src, dst string
		replace  bool
		copy     func(http.ResponseWriter, apiCall) bool
		step     CopyStep
		want     error
		requests int
	}{
		"source missing":   {src: "/nothing", dst: "/x", step: CopySource, want: ErrNotExist},
		"source is folder": {src: "/full", dst: "/x", step: CopySource, want: ErrIsDir},
		"destination folder missing": {
			src: "/doc.txt", dst: "/nowhere/x", step: CopyDestinationFolder, want: ErrNotExist,
		},
		"destination folder is a file": {
			src: "/doc.txt", dst: "/old.txt/x", step: CopyDestinationFolder, want: ErrNotDir,
		},
		"same node": {src: "/doc.txt", dst: "/doc.txt", replace: true, step: CopyDestination, want: ErrSameNode},
		"destination exists": {
			src: "/doc.txt", dst: "/old.txt", step: CopyDestination, want: ErrExist,
		},
		"destination is a folder": {
			src: "/doc.txt", dst: "/empty", replace: true, step: CopyDestination, want: ErrIsDir,
		},
		"name taken": {
			src: "/doc.txt", dst: "/x", copy: status(http.StatusConflict, "taken"),
			step: CopyTransfer, want: ErrExist, requests: 1,
		},
		"source gone": {
			src: "/doc.txt", dst: "/x", copy: status(http.StatusGone, "gone"),
			step: CopyTransfer, want: ErrNotExist, requests: 1,
		},
		"storage exceeded": {
			src: "/doc.txt", dst: "/x", copy: status(http.StatusBadRequest, storageRefusal),
			step: CopyTransfer, want: ErrStorageExceeded, requests: 1,
		},
		"forbidden": {
			src: "/doc.txt", dst: "/x", copy: status(http.StatusForbidden, "viewer"),
			step: CopyTransfer, want: ErrForbidden, requests: 1,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: tc.copy}
			fs := newAPIFS(t, fake, Options{}, tree())
			_, _, err := fs.Copy(context.Background(), "dr1", tc.src, tc.dst, tc.replace)
			var failed *CopyError
			if !errors.As(err, &failed) || failed.Step != tc.step || !errors.Is(err, tc.want) {
				t.Errorf("Copy = %v (%+v), want %v at step %d", err, failed, tc.want, tc.step)
			}
			if got := len(fake.list()); got != tc.requests {
				t.Errorf("%d request(s) %v, want %d", got, fake.list(), tc.requests)
			}
		})
	}
}

// The API holds the name of the file just deleted until its purge has run: the
// copy is tried again while it answers 409, for Options.CopyReplaceWait.
func TestCopy_ReplaceWaitsForPurge(t *testing.T) {
	var conflicts atomic.Int32
	conflicts.Store(2)
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		switch {
		case call.method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case conflicts.Add(-1) >= 0:
			http.Error(w, "held", http.StatusConflict)
		default:
			copyReply(w)
		}

		return true
	}}
	opts := Options{CopyReplaceRetry: time.Millisecond, CopyReplaceWait: 50 * time.Millisecond}
	fs := newAPIFS(t, fake, opts, tree())

	if _, replaced, err := fs.Copy(context.Background(), "dr1", "/doc.txt", "/old.txt", true); err != nil || !replaced {
		t.Fatalf("Copy = (replaced %v, %v), want the copy once the name is free", replaced, err)
	}
	if got := len(fake.only("POST")); got != 3 {
		t.Errorf("%d copies sent, want 3", got)
	}
}

// — Sentinels ———————————————————————————————————————————————————————————————————

// A request the API rate limit defeated crosses every mutation as it is: it
// still matches api.ErrRateLimited, keeps its Retry-After, and carries no
// sentinel of the package, nor the step of a copy.
func TestMutations_RateLimitCrossesUnwrapped(t *testing.T) {
	limited := func(w http.ResponseWriter, _ apiCall) bool {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "No more requests allowed", http.StatusTooManyRequests)

		return true
	}
	ctx := context.Background()
	mutations := map[string]func(fs *FS) error{
		"Mkdir": func(fs *FS) error {
			_, err := fs.Mkdir(ctx, "dr1", "/new")

			return err
		},
		"Remove": func(fs *FS) error { return fs.Remove(ctx, "dr1", "/doc.txt", true) },
		"Rename": func(fs *FS) error { return fs.Rename(ctx, "dr1", "/doc.txt", "/x", false) },
		"Copy": func(fs *FS) error {
			_, _, err := fs.Copy(ctx, "dr1", "/doc.txt", "/x", false)

			return err
		},
		"Copy onto a file": func(fs *FS) error {
			_, _, err := fs.Copy(ctx, "dr1", "/doc.txt", "/old.txt", true)

			return err
		},
		"Chmod":      func(fs *FS) error { return fs.Chmod(ctx, "dr1", "/doc.txt", 0o600) },
		"SetModTime": func(fs *FS) error { return fs.SetModTime(ctx, "dr1", "/doc.txt", time.Now()) },
	}
	for label, mutate := range mutations {
		t.Run(label, func(t *testing.T) {
			fs := newAPIFS(t, &fakeAPI{reply: limited}, Options{}, tree())
			err := mutate(fs)
			if !errors.Is(err, api.ErrRateLimited) {
				t.Fatalf("error = %v, want api.ErrRateLimited", err)
			}
			if !carriesNoSentinel(err) {
				t.Errorf("the rate limit was given a sentinel of vfs: %v", err)
			}
			var failed *CopyError
			if errors.As(err, &failed) {
				t.Errorf("the rate limit was wrapped in a CopyError (step %d)", failed.Step)
			}
			if got := api.RetryAfter(err); got != 7*time.Second {
				t.Errorf("Retry-After = %v, want 7s", got)
			}
		})
	}
}

// A sentinel is added to an error, never put in its place: the message is the
// original one, and errors.Is / errors.As still reach what it was made from.
func TestSentinelsKeepTheOriginalError(t *testing.T) {
	original := fmt.Errorf("moving node: %w", &api.HTTPError{Status: http.StatusForbidden, Body: "Replace not allowed"})
	err := classify(original)

	if err.Error() != original.Error() {
		t.Errorf("message = %q, want the original %q", err.Error(), original.Error())
	}
	var httpErr *api.HTTPError
	if !errors.Is(err, ErrForbidden) || !errors.As(err, &httpErr) || httpErr.Status != http.StatusForbidden {
		t.Errorf("classify(403) = %v, want ErrForbidden still carrying the HTTPError", err)
	}

	// The supervisors of `webdav serve` read the exit code from these.
	for _, noToken := range []error{auth.ErrNoToken, auth.ErrNoRefreshToken} {
		wrapped := classify(fmt.Errorf("Put: %w", noToken))
		if !errors.Is(wrapped, ErrUnauthenticated) || !errors.Is(wrapped, noToken) {
			t.Errorf("classify(%v) = %v, want ErrUnauthenticated still matching it", noToken, wrapped)
		}
	}
	if got := classify(&api.HTTPError{Status: http.StatusUnauthorized}); !errors.Is(got, ErrUnauthenticated) {
		t.Errorf("classify(401) = %v, want ErrUnauthenticated", got)
	}

	plain := errors.New("connection reset")
	if got := classify(plain); got != plain {
		t.Errorf("classify of an unrelated error = %v, want it untouched", got)
	}
	if classify(nil) != nil {
		t.Error("classify(nil) is not nil")
	}

	// The standard library's tests of a missing file do not unwrap: a bare
	// ErrNotExist must stay the standard error.
	if !os.IsNotExist(ErrNotExist) || !os.IsExist(ErrExist) {
		t.Error("ErrNotExist / ErrExist are no longer the errors of the standard library")
	}
}
