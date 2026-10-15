package vfs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

// — Symlink —————————————————————————————————————————————————————————————————————

// symlinkAPI answers the probe of the node types and the symlink route with
// the node the API would store.
func symlinkAPI(legacy bool) *fakeAPI {
	return &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		switch call.String() {
		case "GET /dataroom/dr1/mime-types":
			mimeTable(w, legacy)
		case "POST /dataroom/dr1/node/symlink":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":"l-new","name_enc":"x","type":"symlink","access_mode":"0777",`+
				`"created_at":"2026-10-13T08:00:00Z"}`)
		default:
			return false
		}

		return true
	}}
}

// Symlink sends the name and the target encrypted for the session key, under
// the parent's ID read from the cached listing, and leaves the link in that
// listing.
func TestSymlink_CreatesAndCaches(t *testing.T) {
	for parent, wantParent := range map[string]any{"/full": "d-full", "/": nil} {
		fake := symlinkAPI(false)
		fs := newAPIFS(t, fake, Options{}, tree())
		sess, err := fs.Session(context.Background(), "dr1")
		if err != nil {
			t.Fatalf("Session: %v", err)
		}

		node, err := fs.Symlink(context.Background(), "dr1", joinPath(parent, "link"), "../doc.txt")
		if err != nil {
			t.Fatalf("Symlink under %s = %v", parent, err)
		}
		if node.ID != "l-new" || node.Name != "link" || node.Type != TypeSymlink || node.Target != "../doc.txt" ||
			node.Size != int64(len("../doc.txt")) || node.Mode.Perm() != 0o777 || node.CreatedAt.IsZero() {
			t.Errorf("Symlink under %s = %+v, want the link with its target, size, mode and creation time", parent, node)
		}
		if want, _ := wantParent.(string); node.ParentID != want {
			t.Errorf("ParentID = %q, want %q", node.ParentID, want)
		}
		posts := fake.only("POST")
		if len(posts) != 1 {
			t.Fatalf("requests = %v, want one creation", fake.list())
		}
		body := posts[0].body
		if parentID, sent := body["parent_id"]; !sent || parentID != wantParent {
			t.Errorf("parent_id = %v (sent %v), want %v", parentID, sent, wantParent)
		}
		if hash, _ := body["name_hash"].(string); len(hash) != 64 {
			t.Errorf("name_hash = %q, want a SHA-256 in hex", hash)
		}
		for field, want := range map[string]string{"name_enc": "link", "target_enc": "../doc.txt"} {
			enc, _ := body[field].(string)
			if got, decErr := crypto.DecryptToString(enc, sess.Identity); decErr != nil || got != want {
				t.Errorf("%s decrypts to (%q, %v), want %q", field, got, decErr, want)
			}
		}
		if _, sent := body["type"]; sent {
			t.Errorf("body = %v: the route takes no type", body)
		}
		got, found := FindNode(cachedNodes(fs, "dr1", parent), "link")
		if !found || got.Type != TypeSymlink || got.Target != "../doc.txt" {
			t.Errorf("listing of %s = %+v, want it to hold the link", parent, cachedNodes(fs, "dr1", parent))
		}
		if looked, err := fs.Lookup(context.Background(), "dr1", parent, "link"); err != nil || looked.ID != "l-new" {
			t.Errorf("Lookup = (%+v, %v), want the link, from the cache", looked, err)
		}
	}
}

// What refuses a Symlink carries the sentinel of the package and the error
// it came from.
func TestSymlink_Errors(t *testing.T) {
	cases := map[string]struct {
		path     string
		legacy   bool
		post     func(http.ResponseWriter, apiCall) bool
		want     error
		also     error
		requests int // creations sent
	}{
		"parent missing":   {path: "/nowhere/l", want: ErrNotExist},
		"parent is a file": {path: "/doc.txt/l", want: ErrNotDir, also: os.ErrInvalid},
		"the root itself":  {path: "/", want: ErrExist},
		"name taken at the root": {
			path: "/doc.txt", post: status(http.StatusConflict, "taken"), want: ErrExist, also: api.ErrConflict, requests: 1,
		},
		"forbidden": {
			path: "/l", post: status(http.StatusForbidden, `{"detail":"Create not allowed here"}`),
			want: ErrForbidden, requests: 1,
		},
		"unauthenticated": {
			path: "/l", post: status(http.StatusUnauthorized, "expired"), want: ErrUnauthenticated, requests: 1,
		},
		"rate limited": {
			path: "/l", post: status(http.StatusTooManyRequests, "slow down"), want: api.ErrRateLimited, requests: 1,
		},
		"legacy API": {path: "/l", legacy: true, want: ErrSymlinkUnsupported, also: service.ErrSymlinkUnsupported},
		"API without the route": {
			path: "/l", post: status(http.StatusMethodNotAllowed, "Method Not Allowed"),
			want: ErrSymlinkUnsupported, requests: 1,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				if call.String() == "GET /dataroom/dr1/mime-types" {
					mimeTable(w, tc.legacy)

					return true
				}

				return tc.post != nil && call.method == http.MethodPost && tc.post(w, call)
			}}
			fs := newAPIFS(t, fake, Options{}, tree())
			_, err := fs.Symlink(context.Background(), "dr1", tc.path, "target")
			if !errors.Is(err, tc.want) {
				t.Errorf("Symlink(%s) = %v, want %v", tc.path, err, tc.want)
			}
			if tc.also != nil && !errors.Is(err, tc.also) {
				t.Errorf("Symlink(%s) = %v, which no longer matches %v", tc.path, err, tc.also)
			}
			if tc.want == api.ErrRateLimited && !carriesNoSentinel(err) {
				t.Errorf("Symlink = %v: a rate limit takes no sentinel", err)
			}
			if got := len(fake.only("POST")); got != tc.requests {
				t.Errorf("%d creation(s) %v, want %d", got, fake.list(), tc.requests)
			}
		})
	}
}

// A 409 under a folder whose cached ID the API no longer has is not a name
// taken: the parent is resolved afresh and, unchanged, the conflict is
// genuine and reported once. A parent gone (404, 410) is ErrNotExist and its
// listings are dropped.
func TestSymlink_StaleParent(t *testing.T) {
	for _, code := range goneStatuses {
		fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
			if call.String() == "GET /dataroom/dr1/mime-types" {
				mimeTable(w, false)

				return true
			}

			return call.method == http.MethodPost && status(code, "gone")(w, call)
		}}
		fs := newAPIFS(t, fake, Options{}, tree())
		_, err := fs.Symlink(context.Background(), "dr1", "/full/l", "t")
		if !errors.Is(err, ErrNotExist) || !errors.Is(err, api.ErrNotFound) {
			t.Errorf("%d: Symlink = %v, want ErrNotExist carrying the API's answer", code, err)
		}
		if nodeCacheHas(fs, "dr1", "/") || nodeCacheHas(fs, "dr1", "/full") {
			t.Errorf("%d: the listings naming the deleted parent are still cached", code)
		}
	}
}

// — Access ——————————————————————————————————————————————————————————————————————

// The role comes from the list, the state of the plan from the detail; what
// the API does not tell never makes a dataroom read-only.
func TestAccess(t *testing.T) {
	wr := func(v bool) string { return fmt.Sprintf(`"writable":%v`, v) }
	viewer := Access{Role: "viewer", Writable: true, ReadOnly: true}
	cases := map[string]struct {
		role   string // "" leaves the field out of the list
		detail string // the writable field of the detail, "" to leave it out
		want   Access
	}{
		"editor, writable":   {role: "editor", detail: wr(true), want: Access{Role: "editor", Writable: true}},
		"viewer":             {role: "viewer", detail: wr(true), want: viewer},
		"owner over plan":    {role: "owner", detail: wr(false), want: Access{Role: "owner", ReadOnly: true}},
		"older API":          {want: Access{Writable: true}},
		"no flag, a viewer":  {role: "viewer", want: viewer},
		"no role, over plan": {detail: wr(false), want: Access{ReadOnly: true}},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				switch call.String() {
				case "GET /dataroom":
					role := ""
					if tc.role != "" {
						role = `,"role":"` + tc.role + `"`
					}
					fmt.Fprint(w, `{"items":[{"id":"other","title":"Other","role":"viewer"},`+
						`{"id":"dr1","title":"Docs"`+role+`}],"total":2,"page":1,"pages":1}`)
				case "GET /dataroom/dr1":
					detail := ""
					if tc.detail != "" {
						detail = "," + tc.detail
					}
					// The detail carries no role: the list is where it is read.
					fmt.Fprint(w, `{"id":"dr1","title":"Docs"`+detail+`}`)
				default:
					return false
				}

				return true
			}}
			fs := newAPIFS(t, fake, Options{}, nil)
			for range 2 {
				got, err := fs.Access(context.Background(), "dr1")
				if err != nil || got != tc.want {
					t.Fatalf("Access = (%+v, %v), want %+v", got, err, tc.want)
				}
			}
			// The list is cached, the detail is not.
			want := []string{"GET /dataroom", "GET /dataroom/dr1", "GET /dataroom/dr1"}
			if got := fake.list(); !slices.Equal(got, want) {
				t.Errorf("requests = %v, want %v", got, want)
			}
			list, err := fs.Datarooms(context.Background())
			if err != nil || len(list) != 2 || list[0].ID != "dr1" || list[0].Role != tc.role || list[1].Role != "viewer" {
				t.Errorf("Datarooms = (%+v, %v), want the roles of the list", list, err)
			}
		})
	}
}

// A dataroom the list does not name has no known role, hence is not a
// viewer's; one the API refuses carries the sentinel of the refusal.
func TestAccess_UnlistedAndRefused(t *testing.T) {
	detail := map[string]func(http.ResponseWriter, apiCall) bool{}
	fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
		if call.String() == "GET /dataroom" {
			fmt.Fprint(w, `{"items":[],"total":0,"page":1,"pages":1}`)

			return true
		}
		reply, ok := detail[call.path]

		return ok && reply(w, call)
	}}
	detail["/dataroom/dr1"] = func(w http.ResponseWriter, _ apiCall) bool {
		fmt.Fprint(w, `{"id":"dr1","title":"Docs","writable":true}`)

		return true
	}
	detail["/dataroom/gone"] = status(http.StatusNotFound, "Not Found")
	detail["/dataroom/closed"] = status(http.StatusForbidden, "no")
	detail["/dataroom/busy"] = status(http.StatusTooManyRequests, "slow down")
	fs := newAPIFS(t, fake, Options{}, nil)

	if got, err := fs.Access(context.Background(), "dr1"); err != nil || got != (Access{Writable: true}) {
		t.Errorf("Access of an unlisted dataroom = (%+v, %v), want writable with no role", got, err)
	}
	for id, want := range map[string]error{"gone": ErrNotExist, "closed": ErrForbidden, "busy": api.ErrRateLimited} {
		if _, err := fs.Access(context.Background(), id); !errors.Is(err, want) {
			t.Errorf("Access(%s) = %v, want %v", id, err, want)
		}
	}
}

// — Rename: a folder onto a file ————————————————————————————————————————————————

// A folder renamed with replace onto a name a file holds is ErrNotDir, and
// nothing is sent: the API would replace the file by the folder. The
// destination is read from the cached listing, at no request. A folder onto a
// free name, and onto itself, goes through.
func TestRename_FolderNeverReplacesAFile(t *testing.T) {
	cases := map[string]struct {
		dst  string
		want error
		puts int
	}{
		"onto a file":             {dst: "/doc.txt", want: ErrNotDir},
		"onto a file in a folder": {dst: "/full/in.txt", want: ErrNotDir},
		"onto a free name":        {dst: "/full/moved", puts: 1},
		"onto itself":             {dst: "/empty", puts: 1},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				switch call.String() {
				case "GET /dataroom/dr1/mime-types":
					mimeTable(w, false)
				case "PUT /dataroom/node/d-empty":
					w.WriteHeader(http.StatusNoContent)
				default:
					return false
				}

				return true
			}}
			fs := newAPIFS(t, fake, Options{}, tree())
			err := fs.Rename(context.Background(), "dr1", "/empty", tc.dst, true)
			if !errors.Is(err, tc.want) {
				t.Errorf("Rename = %v, want %v", err, tc.want)
			}
			if got := len(fake.only("PUT")); got != tc.puts {
				t.Errorf("requests = %v, want %d PUT", fake.list(), tc.puts)
			}
			// Nothing but the probe of the replace and the PUT: the check
			// itself asked the API nothing.
			for _, call := range fake.list() {
				if call != "GET /dataroom/dr1/mime-types" && call != "PUT /dataroom/node/d-empty" {
					t.Errorf("unexpected request %s", call)
				}
			}
			if tc.want != nil && !slices.Contains(names(cachedNodes(fs, "dr1", "/")), "empty") {
				t.Errorf("root listing = %v, want it untouched", names(cachedNodes(fs, "dr1", "/")))
			}
		})
	}
}

// Without replace nothing is looked up: the API refuses a name that is taken.
// And a file renamed with replace is not looked up either, the API refusing a
// folder holder by itself.
func TestRename_DestinationLookedUpForAFolderWithReplaceOnly(t *testing.T) {
	for label, tc := range map[string]struct {
		src     string
		node    string
		replace bool
	}{
		"folder without replace": {src: "/full", node: "d-full"},
		"file with replace":      {src: "/doc.txt", node: "f-doc", replace: true},
	} {
		fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
			switch call.String() {
			case "GET /dataroom/dr1/mime-types":
				mimeTable(w, false)
			case "PUT /dataroom/node/" + tc.node:
				w.WriteHeader(http.StatusNoContent)
			default:
				return false
			}

			return true
		}}
		// The listing of the destination folder is not cached: a lookup of the
		// destination would be a request.
		listings := tree()
		delete(listings, "/empty")
		fs := newAPIFS(t, fake, Options{}, listings)
		if err := fs.Rename(context.Background(), "dr1", tc.src, "/empty/x", tc.replace); err != nil {
			t.Errorf("%s: Rename = %v", label, err)
		}
		if gets := fake.only("GET /dataroom/dr1/nodes"); len(gets) != 0 {
			t.Errorf("%s: requests = %v, want no lookup of the destination", label, fake.list())
		}
	}
}

// Under a folder that is not listed, the destination of a folder costs one
// lookup by name: a file found there refuses the rename, a free name lets it
// through. A lookup that fails says nothing of the destination: nothing is
// renamed.
func TestRename_FolderOntoAnUnlistedDestination(t *testing.T) {
	// The name as the API stores it, set once the session is known: a lookup
	// answers a node whose name decrypts to the one asked.
	var nameEnc string
	cases := map[string]struct {
		lookup func(http.ResponseWriter, apiCall) bool
		want   error
		puts   int
	}{
		"free": {lookup: func(w http.ResponseWriter, _ apiCall) bool {
			fmt.Fprint(w, `{"items":[],"total":0,"page":1,"pages":1}`)

			return true
		}, puts: 1},
		"held by a file": {lookup: func(w http.ResponseWriter, call apiCall) bool {
			fmt.Fprintf(w, `{"items":[{"node":{"id":"f-held","name_enc":%q,"name_hash":%q,"type":"file",`+
				`"parent_id":"d-empty"}}],"total":1,"page":1,"pages":1}`, nameEnc, call.query.Get("name_hash"))

			return true
		}, want: ErrNotDir},
		"lookup refused": {lookup: status(http.StatusTooManyRequests, "slow down"), want: api.ErrRateLimited},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				switch call.String() {
				case "GET /dataroom/dr1/mime-types":
					mimeTable(w, false)
				case "GET /dataroom/dr1/nodes":
					return call.query.Get("name_hash") != "" && tc.lookup(w, call)
				case "PUT /dataroom/node/d-full":
					w.WriteHeader(http.StatusNoContent)
				default:
					return false
				}

				return true
			}}
			listings := tree()
			delete(listings, "/empty")
			fs := newAPIFS(t, fake, Options{}, listings)
			sess, err := fs.Session(context.Background(), "dr1")
			if err != nil {
				t.Fatalf("Session: %v", err)
			}
			if nameEnc, err = crypto.EncryptStringForKeys("x", []string{sess.PublicKey}); err != nil {
				t.Fatalf("EncryptStringForKeys: %v", err)
			}
			err = fs.Rename(context.Background(), "dr1", "/full", "/empty/x", true)
			if !errors.Is(err, tc.want) {
				t.Errorf("Rename = %v, want %v", err, tc.want)
			}
			if got := len(fake.only("PUT")); got != tc.puts {
				t.Errorf("requests = %v, want %d PUT", fake.list(), tc.puts)
			}
			if got := len(fake.only("GET /dataroom/dr1/nodes")); got != 1 {
				t.Errorf("requests = %v, want one lookup of the destination", fake.list())
			}
		})
	}
}
