package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"testing"
	"time"
)

// The node type decides file or folder; without it (an API that predates the
// field) the absence of a MIME ciphertext does, as it always has.
func TestDataroomNode_IsFolder(t *testing.T) {
	enc := "enc"
	cases := []struct {
		name string
		node DataroomNode
		want bool
	}{
		{"typed folder", DataroomNode{Type: NodeTypeFolder}, true},
		{"typed file, legacy MIME", DataroomNode{Type: NodeTypeFile, TypeEnc: &enc}, false},
		{"typed file, MIME row", DataroomNode{Type: NodeTypeFile}, false},
		{"symlink (reserved)", DataroomNode{Type: NodeTypeSymlink}, false},
		{"untyped folder", DataroomNode{}, true},
		{"untyped file", DataroomNode{TypeEnc: &enc}, false},
	}
	for _, tc := range cases {
		if got := tc.node.IsFolder(); got != tc.want {
			t.Errorf("%s: IsFolder() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A listing of the new API decodes with its type, MIME row, mode and
// timestamps; one of the old API decodes as before.
func TestDataroomNodeItem_Decode(t *testing.T) {
	var item DataroomNodeItem
	err := json.Unmarshal([]byte(`{"node":{"id":"n","type":"file","name_enc":"e","name_hash":"h","type_enc":null,`+
		`"mime_type_id":"mt","access_mode":"0755","parent_id":null,"created_user_id":"u",`+
		`"created_at":"2026-10-01T10:00:00Z"},`+
		`"node_version":{"id":"v","node_id":"n","original_size":5,"chunk_count":1,"chunk_count_expected":1,`+
		`"version_number":2,"created_at":"2026-10-02T10:00:00Z","client_mtime":"2024-05-06T07:08:09Z",`+
		`"copied_from_version_id":null},"max_version_number":2,"capabilities":{"can_read":true}}`), &item)
	if err != nil {
		t.Fatal(err)
	}
	n := item.Node
	if n.IsFolder() || n.MimeTypeID == nil || *n.MimeTypeID != "mt" || n.AccessMode != "0755" || n.NameHash != "h" ||
		n.CreatedAt.IsZero() {
		t.Errorf("node = %+v", n)
	}
	v := item.Version
	if !v.Complete() || !v.ModTime().Equal(time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)) {
		t.Errorf("version = %+v", v)
	}

	var legacy DataroomNodeItem
	if err := json.Unmarshal([]byte(`{"node":{"id":"n","name_enc":"e","type_enc":null,"parent_id":null},`+
		`"node_version":null}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if !legacy.Node.IsFolder() || legacy.Node.Type != "" {
		t.Errorf("legacy node = %+v, want an untyped folder", legacy.Node)
	}
}

// Without a client_mtime the version's creation time stands in; a version
// with fewer stored chunks than announced is incomplete.
func TestDataroomNodeVersion_ModTimeAndComplete(t *testing.T) {
	created := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	v := DataroomNodeVersion{CreatedAt: created, ChunkCount: 1, ChunkCountExpected: ptr(3)}
	if !v.ModTime().Equal(created) {
		t.Errorf("ModTime() = %v, want %v", v.ModTime(), created)
	}
	if v.Complete() {
		t.Error("1 of 3 chunks reads as complete")
	}
	v.ChunkCount = 3
	if !v.Complete() {
		t.Error("3 of 3 chunks reads as incomplete")
	}
	if !(&DataroomNodeVersion{ChunkCount: 0}).Complete() {
		t.Error("a version without chunk_count_expected reads as incomplete")
	}
}

func TestAccessMode_ParseAndFormat(t *testing.T) {
	cases := []struct {
		in   string
		mode fs.FileMode
		ok   bool
		out  string
	}{
		{"0644", 0o644, true, "0644"},
		{"644", 0o644, true, "0644"},
		{"0o755", 0o755, true, "0755"},
		{"4755", 0o755 | fs.ModeSetuid, true, "4755"},
		{"2755", 0o755 | fs.ModeSetgid, true, "2755"},
		{"1777", 0o777 | fs.ModeSticky, true, "1777"},
		{"", 0, false, ""},
		{"abc", 0, false, ""},
		{"17777", 0, false, ""},
	}
	for _, tc := range cases {
		mode, ok := ParseAccessMode(tc.in)
		if ok != tc.ok || mode != tc.mode {
			t.Errorf("ParseAccessMode(%q) = %v, %v; want %v, %v", tc.in, mode, ok, tc.mode, tc.ok)
		}
		if ok && FormatAccessMode(mode) != tc.out {
			t.Errorf("FormatAccessMode(%v) = %q, want %q", mode, FormatAccessMode(mode), tc.out)
		}
	}
	// Type bits never reach the API: a directory formats as its permissions.
	if got := FormatAccessMode(fs.ModeDir | 0o750); got != "0750" {
		t.Errorf("FormatAccessMode(dir 0750) = %q", got)
	}
}

// HTTPError keeps the historical messages and sentinel matches, and exposes
// the API's stable detail codes.
func TestHTTPError(t *testing.T) {
	err := statusError(http.StatusUnprocessableEntity, []byte(`{"detail":"mime_type_unknown"}`))
	if ErrorDetail(err) != DetailMimeTypeUnknown {
		t.Errorf("ErrorDetail = %q", ErrorDetail(err))
	}
	if err.Error() != `API error 422: {"detail":"mime_type_unknown"}` {
		t.Errorf("Error() = %q", err.Error())
	}
	wrapped := fmt.Errorf("creating node: %w", err)
	if ErrorDetail(wrapped) != DetailMimeTypeUnknown {
		t.Error("detail lost through wrapping")
	}
	var httpErr *HTTPError
	if !errors.As(wrapped, &httpErr) || httpErr.Status != 422 {
		t.Errorf("errors.As = %v / %+v", errors.As(wrapped, &httpErr), httpErr)
	}

	for _, tc := range []struct {
		status   int
		matches  []error
		excludes []error
		prefix   string
	}{
		{http.StatusConflict, []error{ErrConflict}, []error{ErrNotFound, ErrGone}, "conflict: "},
		{http.StatusNotFound, []error{ErrNotFound}, []error{ErrGone, ErrConflict}, "API error 404: "},
		{http.StatusGone, []error{ErrNotFound, ErrGone}, []error{ErrConflict}, "API error 410: "},
		{http.StatusBadRequest, nil, []error{ErrNotFound, ErrGone, ErrConflict}, "API error 400: "},
	} {
		err := statusError(tc.status, []byte("body"))
		for _, m := range tc.matches {
			if !errors.Is(err, m) {
				t.Errorf("%d: does not match %v", tc.status, m)
			}
		}
		for _, m := range tc.excludes {
			if errors.Is(err, m) {
				t.Errorf("%d: matches %v", tc.status, m)
			}
		}
		if got := err.Error(); len(got) < len(tc.prefix) || got[:len(tc.prefix)] != tc.prefix {
			t.Errorf("%d: Error() = %q, want prefix %q", tc.status, got, tc.prefix)
		}
	}
	if ErrorDetail(statusError(500, []byte("plain text"))) != "" || ErrorDetail(errors.New("x")) != "" {
		t.Error("detail found where there is none")
	}
	if ErrorDetail(statusError(422, []byte(`{"detail":[{"loc":["body"],"msg":"x"}]}`))) != "" {
		t.Error("a structured validation detail is not a code")
	}
}
