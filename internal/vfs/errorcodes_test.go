package vfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
)

// refuseCoded answers a refusal of the API, with its X-Error-Code when code is set.
func refuseCoded(w http.ResponseWriter, status int, code, detail string) {
	if code != "" {
		w.Header().Set(api.ErrorCodeHeader, code)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"detail":%q}`, detail)
}

// — Rename ——————————————————————————————————————————————————————————————————————

// With an error code, a 409 on a rename is read by its code, never by its
// detail: CONCURRENT_UPDATE is tried once more (replace or not), NAME_TAKEN is
// ErrExist at once without re-resolving the destination folder,
// REPLACE_TARGET_IS_FOLDER is ErrIsDir whatever the detail says.
func TestRename_CodedConflicts(t *testing.T) {
	cases := map[string]struct {
		code, detail string
		replace      bool
		conflicts    int32
		want         error // nil: the rename passes
		puts         int
	}{
		"concurrent update, replace": {
			code: api.CodeConcurrentUpdate, detail: "retry", replace: true, conflicts: 1, puts: 2,
		},
		"concurrent update, plain rename": {
			code: api.CodeConcurrentUpdate, detail: "retry", conflicts: 1, puts: 2,
		},
		"concurrent update twice": {
			code: api.CodeConcurrentUpdate, detail: "retry", replace: true, conflicts: 2, want: ErrExist, puts: 2,
		},
		"name taken on a replace is not retried": {
			code: api.CodeNameTaken, detail: "Name taken concurrently, please retry", replace: true,
			conflicts: 2, want: ErrExist, puts: 1,
		},
		"name taken with the former folder detail": {
			code: api.CodeNameTaken, detail: replaceFolderDetail, replace: true, conflicts: 2, want: ErrExist, puts: 1,
		},
		"target is a folder, another detail": {
			code: api.CodeReplaceTargetIsFolder, detail: "held by a folder", replace: true,
			conflicts: 2, want: ErrIsDir, puts: 1,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			var left atomic.Int32
			left.Store(tc.conflicts)
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				switch {
				case call.String() == "GET /dataroom/dr1/mime-types":
					mimeTable(w, false)
				case call.method == http.MethodPut && left.Add(-1) >= 0:
					refuseCoded(w, http.StatusConflict, tc.code, tc.detail)
				case call.method == http.MethodPut:
					w.WriteHeader(http.StatusNoContent)
				default:
					return false // a listing would answer 500
				}

				return true
			}}
			fs := newAPIFS(t, fake, Options{}, tree())

			// Into a sub-folder: a 409 without a code there has the folder
			// listed afresh.
			err := fs.Rename(context.Background(), "dr1", "/doc.txt", "/full/x", tc.replace)
			if tc.want == nil && err != nil {
				t.Errorf("Rename = %v, want the second attempt to pass", err)
			}
			if tc.want != nil && (!errors.Is(err, tc.want) || !errors.Is(err, api.ErrConflict)) {
				t.Errorf("Rename = %v, want %v carrying the 409", err, tc.want)
			}
			if got := len(fake.only("PUT")); got != tc.puts {
				t.Errorf("%d PUT(s) %v, want %d", got, fake.list(), tc.puts)
			}
			if got := len(fake.only("GET /dataroom/dr1/nodes")); got != 0 {
				t.Errorf("requests = %v, want no listing", fake.list())
			}
		})
	}
}

// — Mkdir ———————————————————————————————————————————————————————————————————————

// CONCURRENT_UPDATE on a folder creation is tried once more; NAME_TAKEN is
// ErrExist after one request, as a 409 without a code.
func TestMkdir_CodedConflicts(t *testing.T) {
	for label, tc := range map[string]struct {
		path  string
		code  string
		want  error
		posts int
	}{
		"concurrent update": {path: "/new", code: api.CodeConcurrentUpdate, posts: 2},
		"name taken":        {path: "/new", code: api.CodeNameTaken, want: ErrExist, posts: 1},
		// Under a folder, a coded 409 is not a parent deleted elsewhere (that
		// is a 404 PARENT_NOT_FOUND): nothing is listed again.
		"name taken in a folder": {path: "/full/new", code: api.CodeNameTaken, want: ErrExist, posts: 1},
	} {
		t.Run(label, func(t *testing.T) {
			var left atomic.Int32
			left.Store(1)
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				if call.String() != "POST /dataroom/dr1/node" {
					return false
				}
				if left.Add(-1) >= 0 {
					refuseCoded(w, http.StatusConflict, tc.code, "conflict")

					return true
				}
				fmt.Fprint(w, `{"id":"d-new","name_enc":"x"}`)

				return true
			}}
			fs := newAPIFS(t, fake, Options{}, tree())

			_, err := fs.Mkdir(context.Background(), "dr1", tc.path)
			if tc.want == nil && err != nil {
				t.Errorf("Mkdir = %v, want the second attempt to pass", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("Mkdir = %v, want %v", err, tc.want)
			}
			if got := len(fake.only("POST")); got != tc.posts {
				t.Errorf("%d POST(s) %v, want %d", got, fake.list(), tc.posts)
			}
			if got := len(fake.only("GET /dataroom/dr1/nodes")); got != 0 {
				t.Errorf("requests = %v, want no listing", fake.list())
			}
		})
	}
}

// — Copy ————————————————————————————————————————————————————————————————————————

// An API with error codes frees a name with its delete: NAME_TAKEN on the copy
// that follows is another holder and ends the wait at once; CONCURRENT_UPDATE
// is tried again like a 409 without a code.
func TestCopy_ReplaceCodedConflicts(t *testing.T) {
	for label, tc := range map[string]struct {
		code   string
		copies int
		fails  bool
	}{
		"name taken":        {code: api.CodeNameTaken, copies: 1, fails: true},
		"concurrent update": {code: api.CodeConcurrentUpdate, copies: 3},
	} {
		t.Run(label, func(t *testing.T) {
			var conflicts atomic.Int32
			conflicts.Store(2)
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				switch {
				case call.method == http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				case conflicts.Add(-1) >= 0:
					refuseCoded(w, http.StatusConflict, tc.code, "held")
				default:
					copyReply(w)
				}

				return true
			}}
			// A wait long enough that a name taken waited for would show.
			opts := Options{CopyReplaceRetry: time.Millisecond, CopyReplaceWait: time.Minute}
			fs := newAPIFS(t, fake, opts, tree())

			_, replaced, err := fs.Copy(context.Background(), "dr1", "/doc.txt", "/old.txt", true)
			var failed *CopyError
			switch {
			case tc.fails && (!errors.Is(err, ErrExist) || !errors.As(err, &failed) || failed.Step != CopyTransfer):
				t.Errorf("Copy = %v, want ErrExist at the transfer step", err)
			case !tc.fails && (err != nil || !replaced):
				t.Errorf("Copy = (replaced %v, %v), want the copy once retried", replaced, err)
			}
			if got := len(fake.only("POST")); got != tc.copies {
				t.Errorf("%d copies sent, want %d", got, tc.copies)
			}
		})
	}
}

// A 404 or 410 of the copy route names the resource gone through its code:
// the source (NODE_*) or the folder copied into (PARENT_*). Only the listing
// that named it is dropped. Without a code, both are.
func TestCopy_CodedGoneNamesTheResource(t *testing.T) {
	for label, tc := range map[string]struct {
		status  int
		code    string
		step    CopyStep
		srcKept bool // the listing of the source's folder
		dstKept bool // the listing that names the destination folder
	}{
		"source deleted": {
			status: http.StatusGone, code: api.CodeNodeDeleted, step: CopySource, dstKept: true,
		},
		"source not found": {
			status: http.StatusNotFound, code: api.CodeNodeNotFound, step: CopySource, dstKept: true,
		},
		"destination folder gone": {
			status: http.StatusGone, code: api.CodeParentDeleted, step: CopyDestinationFolder, srcKept: true,
		},
		"destination folder absent": {
			status: http.StatusNotFound, code: api.CodeParentNotFound, step: CopyDestinationFolder, srcKept: true,
		},
		"no code": {status: http.StatusNotFound, step: CopyTransfer},
		"another code": {
			status: http.StatusNotFound, code: api.CodeDataroomNotFound, step: CopyTransfer,
		},
	} {
		t.Run(label, func(t *testing.T) {
			fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
				if call.method != http.MethodPost {
					return false
				}
				refuseCoded(w, tc.status, tc.code, "gone")

				return true
			}}
			fs := newAPIFS(t, fake, Options{}, tree())

			_, _, err := fs.Copy(context.Background(), "dr1", "/full/in.txt", "/empty/x", false)
			var failed *CopyError
			if !errors.As(err, &failed) || failed.Step != tc.step || !errors.Is(err, ErrNotExist) {
				t.Fatalf("Copy = %v, want ErrNotExist at step %d", err, tc.step)
			}
			if kept := cachedListing(fs, "dr1", "/full") != nil; kept != tc.srcKept {
				t.Errorf("listing of the source's folder kept = %v, want %v", kept, tc.srcKept)
			}
			if kept := cachedListing(fs, "dr1", "/") != nil; kept != tc.dstKept {
				t.Errorf("listing naming the destination folder kept = %v, want %v", kept, tc.dstKept)
			}
		})
	}
}

// — Read-only dataroom —————————————————————————————————————————————————————————

// A 403 DATAROOM_READ_ONLY is ErrReadOnly on every write, in addition to
// ErrForbidden; a 403 without that code is ErrForbidden alone.
func TestWrites_ReadOnlyDataroom(t *testing.T) {
	ctx := context.Background()
	writes := map[string]func(fs *FS) error{
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
		"Chmod":      func(fs *FS) error { return fs.Chmod(ctx, "dr1", "/doc.txt", 0o600) },
		"SetModTime": func(fs *FS) error { return fs.SetModTime(ctx, "dr1", "/doc.txt", time.Now()) },
		"Symlink": func(fs *FS) error {
			_, err := fs.Symlink(ctx, "dr1", "/ln", "doc.txt")

			return err
		},
		"Create": func(fs *FS) error {
			_, err := fs.Create(ctx, "dr1", "/new.txt", 3, time.Time{}, bytes.NewReader([]byte("abc")))

			return err
		},
	}
	for _, code := range []string{api.CodeDataroomReadOnly, api.CodeRoleForbidden, ""} {
		for label, write := range writes {
			t.Run(label+"/"+code, func(t *testing.T) {
				fake := &fakeAPI{reply: func(w http.ResponseWriter, call apiCall) bool {
					if call.String() == "GET /dataroom/dr1/mime-types" {
						mimeTable(w, false)

						return true
					}
					refuseCoded(w, http.StatusForbidden, code, "refused")

					return true
				}}
				fs := newAPIFS(t, fake, Options{}, tree())

				err := write(fs)
				if !errors.Is(err, ErrForbidden) {
					t.Errorf("error = %v, want ErrForbidden", err)
				}
				if readOnly := errors.Is(err, ErrReadOnly); readOnly != (code == api.CodeDataroomReadOnly) {
					t.Errorf("error = %v, ErrReadOnly = %v", err, readOnly)
				}
				var httpErr *api.HTTPError
				if !errors.As(err, &httpErr) || httpErr.Status != http.StatusForbidden {
					t.Errorf("error = %v, want the 403 in the chain", err)
				}
			})
		}
	}
}

// — Chunk size route ————————————————————————————————————————————————————————————

// A 404 that carries an error code is the size route's own answer: the route
// exists, the chunk does not, and the read fails like on any other refusal of
// the request, where a 404 without a code is the ambiguous one (see
// TestFile_MissingChunkIsNotAMissingRoute).
func TestFile_CodedNotFoundIsNotAMissingRoute(t *testing.T) {
	data := testData(23)
	for _, code := range []string{api.CodeChunkNotFound, api.CodeVersionNotFound} {
		t.Run(code, func(t *testing.T) {
			a := newSizeAPI(t)
			a.mu.Lock()
			a.head, a.headCode = http.StatusNotFound, code
			a.mu.Unlock()
			fs := a.fs(Options{})
			n := a.store("v1", data, 6)
			f, err := fs.Open(context.Background(), "dr1", n)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = f.Close() }()

			_, err = f.ReadAt(make([]byte, 1), 21)
			if api.ErrorCode(err) != code || !errors.Is(err, api.ErrNotFound) {
				t.Fatalf("ReadAt = %v, want the coded 404", err)
			}
			wantRequests(t, a, "HEAD v1/0")
			if fs.chunkSizes.routeAbsent() {
				t.Error("a coded 404 made the route absent")
			}
			fs.chunkSizes.mu.Lock()
			route := fs.chunkSizes.route
			fs.chunkSizes.mu.Unlock()
			if route != sizeRoutePresent {
				t.Errorf("route = %d, want present", route)
			}
		})
	}
}
