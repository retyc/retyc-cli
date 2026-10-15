package vfs

import (
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
)

// noContent answers every request 204.
func noContent(w http.ResponseWriter, _ apiCall) bool {
	w.WriteHeader(http.StatusNoContent)

	return true
}

// nodeNamed returns the node of the cached listing of parent that carries name.
func nodeNamed(t *testing.T, fs *FS, parent, name string) Node {
	t.Helper()
	for _, n := range cachedNodes(fs, "dr1", parent) {
		if n.Name == name {
			return n
		}
	}
	t.Fatalf("%s is not in the cached listing of %s", name, parent)

	return Node{}
}

func TestWithExecutable(t *testing.T) {
	for _, tc := range []struct {
		mode       os.FileMode
		executable bool
		want       os.FileMode
	}{
		{0, true, 0o755},      // no stored mode: starts from DefaultFileMode
		{0, false, 0o644},     // idem
		{0o644, true, 0o755},  // x for whoever may read
		{0o600, true, 0o700},  // and nobody else
		{0o640, true, 0o750},  // group reads, group executes
		{0o755, false, 0o644}, // every x bit cleared
		{0o755, true, 0o755},  // unchanged
		{0o200, true, 0o300},  // write-only owner still gets x
	} {
		if got := WithExecutable(tc.mode, tc.executable); got != tc.want {
			t.Errorf("WithExecutable(%o, %v) = %o, want %o", tc.mode, tc.executable, got, tc.want)
		}
	}
}

// Chmod stores the mode with one PUT that carries nothing else, and updates
// the cached listing in place; a mode that does not change costs no request.
func TestChmod_SetsTheModeAndTheListing(t *testing.T) {
	fake := &fakeAPI{reply: noContent}
	fs := newAPIFS(t, fake, Options{}, tree())
	ctx := context.Background()

	if err := fs.Chmod(ctx, "dr1", "/doc.txt", 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	calls := fake.only("")
	if len(calls) != 1 || calls[0].String() != "PUT /dataroom/node/f-doc" ||
		len(calls[0].body) != 1 || calls[0].body["access_mode"] != "0600" {
		t.Fatalf("requests = %+v, want one PUT carrying access_mode 0600 alone", calls)
	}
	if n := nodeNamed(t, fs, "/", "doc.txt"); n.Mode != 0o600 || n.VersionID != "v-doc" || n.Size != 9 {
		t.Errorf("cached node = %+v, want mode 0600 and the rest kept", n)
	}

	if err := fs.Chmod(ctx, "dr1", "/doc.txt", 0o600); err != nil {
		t.Fatalf("Chmod (unchanged): %v", err)
	}
	if err := fs.SetExecutable(ctx, "dr1", "/doc.txt", false); err != nil {
		t.Fatalf("SetExecutable (unchanged): %v", err)
	}
	if got := len(fake.list()); got != 1 {
		t.Errorf("%d requests after two changes to the same mode, want 1", got)
	}

	if err := fs.SetExecutable(ctx, "dr1", "/doc.txt", true); err != nil {
		t.Fatalf("SetExecutable: %v", err)
	}
	if n := nodeNamed(t, fs, "/", "doc.txt"); n.Mode != 0o700 {
		t.Errorf("mode after SetExecutable = %o, want 0700", n.Mode)
	}
}

// A chmod to 0 is a mode like any other: sent as "0000" to a file that stores
// none, kept as a stored 0 (not as no mode, which front ends present with
// their default), and a later +x starts from it, not from the default.
func TestChmod_ExplicitZero(t *testing.T) {
	fake := &fakeAPI{reply: noContent}
	fs := newAPIFS(t, fake, Options{}, tree())
	ctx := context.Background()

	if n := nodeNamed(t, fs, "/", "doc.txt"); n.HasMode() {
		t.Fatalf("doc.txt stores mode %v already, the test wants none", n.Mode)
	}
	if err := fs.Chmod(ctx, "dr1", "/doc.txt", 0); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	calls := fake.only("")
	if len(calls) != 1 || calls[0].body["access_mode"] != "0000" {
		t.Fatalf("requests = %+v, want one PUT carrying access_mode 0000", calls)
	}
	if n := nodeNamed(t, fs, "/", "doc.txt"); !n.HasMode() || n.Mode != 0 {
		t.Errorf("cached node = %+v, want a stored 0", n)
	}
	if err := fs.Chmod(ctx, "dr1", "/doc.txt", 0); err != nil {
		t.Fatalf("Chmod (unchanged): %v", err)
	}
	if got := len(fake.list()); got != 1 {
		t.Errorf("%d requests after two chmod to 0, want 1", got)
	}
	if err := fs.SetExecutable(ctx, "dr1", "/doc.txt", true); err != nil {
		t.Fatalf("SetExecutable: %v", err)
	}
	if n := nodeNamed(t, fs, "/", "doc.txt"); n.Mode != 0o100 {
		t.Errorf("mode after SetExecutable = %o, want 0100", n.Mode)
	}
}

// keepKnown keeps the cached mode only when the new node carries none: an
// explicit 0 replaces it, and is kept in turn.
func TestKeepKnown_Mode(t *testing.T) {
	cached := Node{ID: "n", Mode: 0o640, ModeSet: true}
	if got := keepKnown(Node{ID: "n"}, cached); got.Mode != 0o640 || !got.HasMode() {
		t.Errorf("no mode over 0640 = %+v, want 0640 kept", got)
	}
	zero := Node{ID: "n", ModeSet: true}
	if got := keepKnown(zero, cached); got.Mode != 0 || !got.HasMode() {
		t.Errorf("explicit 0 over 0640 = %+v, want a stored 0", got)
	}
	if got := keepKnown(Node{ID: "n"}, zero); got.Mode != 0 || !got.HasMode() {
		t.Errorf("no mode over an explicit 0 = %+v, want the stored 0 kept", got)
	}
}

// The refusals of a chmod and of a change of modification time.
func TestAttrs_Errors(t *testing.T) {
	ctx := context.Background()
	change := map[string]func(fs *FS, path string) error{
		"Chmod":      func(fs *FS, path string) error { return fs.Chmod(ctx, "dr1", path, 0o600) },
		"SetModTime": func(fs *FS, path string) error { return fs.SetModTime(ctx, "dr1", path, time.Now()) },
	}
	cases := map[string]struct {
		path          string
		reply         func(http.ResponseWriter, apiCall) bool
		want          error
		also          error
		dropsListing  bool
		wantsRequests int
	}{
		"missing": {path: "/nothing", want: ErrNotExist},
		"folder":  {path: "/full", want: ErrIsDir},
		"deleted elsewhere": {
			path: "/doc.txt", reply: status(http.StatusNotFound, "gone"),
			want: ErrNotExist, also: api.ErrNotFound, dropsListing: true, wantsRequests: 1,
		},
		"forbidden": {
			path: "/doc.txt", reply: status(http.StatusForbidden, "viewer"), want: ErrForbidden, wantsRequests: 1,
		},
		"locked": {
			path: "/doc.txt", reply: status(http.StatusLocked, "held"), want: api.ErrLocked, wantsRequests: 1,
		},
	}
	for op, do := range change {
		for label, tc := range cases {
			t.Run(op+"/"+label, func(t *testing.T) {
				fake := &fakeAPI{reply: tc.reply}
				fs := newAPIFS(t, fake, Options{}, tree())
				err := do(fs, tc.path)
				if !errors.Is(err, tc.want) || (tc.also != nil && !errors.Is(err, tc.also)) {
					t.Errorf("error = %v, want %v (and %v)", err, tc.want, tc.also)
				}
				if got := len(fake.list()); got != tc.wantsRequests {
					t.Errorf("%d request(s) %v, want %d", got, fake.list(), tc.wantsRequests)
				}
				if nodeCacheHas(fs, "dr1", "/") == tc.dropsListing {
					t.Errorf("root listing cached = %v, want the opposite", !tc.dropsListing)
				}
			})
		}
	}
}

// SetModTime declares the time on the file's current version (PATCH, no new
// version) and the cached listing reports it at once.
func TestSetModTime_PatchesTheVersionAndTheListing(t *testing.T) {
	fake := &fakeAPI{reply: noContent}
	fs := newAPIFS(t, fake, Options{}, tree())
	mtime := time.Date(2025, 3, 4, 5, 6, 7, 800, time.FixedZone("CET", 3600))

	if err := fs.SetModTime(context.Background(), "dr1", "/doc.txt", mtime); err != nil {
		t.Fatalf("SetModTime: %v", err)
	}
	calls := fake.only("")
	if len(calls) != 1 || calls[0].String() != "PATCH /dataroom/node/version/v-doc" {
		t.Fatalf("requests = %v, want one PATCH of the current version", fake.list())
	}
	sent, err := time.Parse(time.RFC3339Nano, calls[0].body["client_mtime"].(string))
	if err != nil || !sent.Equal(mtime) {
		t.Errorf("client_mtime = %v (%v), want %v", calls[0].body["client_mtime"], err, mtime)
	}
	if n := nodeNamed(t, fs, "/", "doc.txt"); !n.ModTime.Equal(mtime) || n.VersionID != "v-doc" || n.Size != 9 {
		t.Errorf("cached node = %+v, want the new time and the rest kept", n)
	}
	// The listing was edited, not dropped: the others are still there.
	if got := names(cachedNodes(fs, "dr1", "/")); !slices.Equal(got, []string{"doc.txt", "empty", "full", "old.txt"}) {
		t.Errorf("root listing = %v, want its four nodes", got)
	}
}

// A file without a version has no time to declare.
func TestSetModTime_NoVersion(t *testing.T) {
	fake := &fakeAPI{}
	fs := newAPIFS(t, fake, Options{}, map[string][]service.DataroomNodeInfo{
		"/": {{ID: "f-new", Name: "pending", Type: "file"}},
	})
	if err := fs.SetModTime(context.Background(), "dr1", "/pending", time.Now()); err == nil {
		t.Error("SetModTime succeeded on a file without version")
	}
	if len(fake.list()) != 0 {
		t.Errorf("requests = %v, want none", fake.list())
	}
}
