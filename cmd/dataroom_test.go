package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// — parseRetycURI —————————————————————————————————————————————————————————————

func TestParseRetycURI_Valid(t *testing.T) {
	tests := []struct {
		input      string
		wantDrID   string
		wantPath   string
	}{
		{"retyc://dr-123", "dr-123", "/"},
		{"retyc://dr-123/", "dr-123", "/"},
		{"retyc://dr-123/docs", "dr-123", "/docs"},
		{"retyc://dr-123/docs/report.pdf", "dr-123", "/docs/report.pdf"},
		{"retyc://019d3de3-cba2-76d0-962d-7817e9858661/folder", "019d3de3-cba2-76d0-962d-7817e9858661", "/folder"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			uri, err := parseRetycURI(tt.input)
			if err != nil {
				t.Fatalf("parseRetycURI(%q) error = %v", tt.input, err)
			}
			if uri.dataroomID != tt.wantDrID {
				t.Errorf("dataroomID = %q, want %q", uri.dataroomID, tt.wantDrID)
			}
			if uri.path != tt.wantPath {
				t.Errorf("path = %q, want %q", uri.path, tt.wantPath)
			}
		})
	}
}

func TestParseRetycURI_Invalid(t *testing.T) {
	tests := []struct {
		input string
	}{
		{""},
		{"retyc://"},
		{"/just/a/path"},
		{"s3://bucket/key"},
		{"retyc:no-slashes"},
		{"http://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseRetycURI(tt.input)
			if err == nil {
				t.Errorf("parseRetycURI(%q) expected error, got nil", tt.input)
			}
		})
	}
}

// — hasGlob ———————————————————————————————————————————————————————————————————

func TestHasGlob(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"*.go", true},
		{"file?.txt", true},
		{"[abc]", true},
		{"report.pdf", false},
		{"Documents", false},
		{"", false},
		{"*", true},
		{"a*b", true},
		{"no-special-chars", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := hasGlob(tt.input); got != tt.want {
				t.Errorf("hasGlob(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// — nodeNameHash ——————————————————————————————————————————————————————————————

func TestNodeNameHash_NoSalt(t *testing.T) {
	name := "report.pdf"
	h := sha256.Sum256([]byte(name))
	want := hex.EncodeToString(h[:])

	got := nodeNameHash(name, "")
	if got != want {
		t.Errorf("nodeNameHash(%q, \"\") = %q, want %q", name, got, want)
	}
}

func TestNodeNameHash_WithSalt(t *testing.T) {
	name := "report.pdf"
	salt := "abc123"
	h := sha256.Sum256([]byte(salt + name))
	want := hex.EncodeToString(h[:])

	got := nodeNameHash(name, salt)
	if got != want {
		t.Errorf("nodeNameHash(%q, %q) = %q, want %q", name, salt, got, want)
	}
}

func TestNodeNameHash_SaltChangesOutput(t *testing.T) {
	name := "document.txt"
	withoutSalt := nodeNameHash(name, "")
	withSalt := nodeNameHash(name, "my-salt")

	if withoutSalt == withSalt {
		t.Error("nodeNameHash with and without salt returned the same hash")
	}
}

func TestNodeNameHash_DifferentSaltsProduceDifferentHashes(t *testing.T) {
	name := "file.go"
	h1 := nodeNameHash(name, "salt1")
	h2 := nodeNameHash(name, "salt2")

	if h1 == h2 {
		t.Error("different salts produced the same hash")
	}
}

func TestNodeNameHash_Length(t *testing.T) {
	got := nodeNameHash("any-name.pdf", "any-salt")
	if len(got) != 64 {
		t.Errorf("hash length = %d, want 64 (hex SHA-256)", len(got))
	}
}

// — splitPathParent ———————————————————————————————————————————————————————————

func TestSplitPathParent(t *testing.T) {
	tests := []struct {
		input      string
		wantParent string
		wantName   string
	}{
		{"/Documents/report.pdf", "/Documents", "report.pdf"},
		{"/Documents/Reports", "/Documents", "Reports"},
		{"/file.txt", "/", "file.txt"},
		{"file.txt", "/", "file.txt"},
		{"/a/b/c/d", "/a/b/c", "d"},
		// trailing slash is stripped
		{"/Documents/Reports/", "/Documents", "Reports"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parent, name := splitPathParent(tt.input)
			if parent != tt.wantParent {
				t.Errorf("splitPathParent(%q) parent = %q, want %q", tt.input, parent, tt.wantParent)
			}
			if name != tt.wantName {
				t.Errorf("splitPathParent(%q) name = %q, want %q", tt.input, name, tt.wantName)
			}
		})
	}
}

// — isConflict ————————————————————————————————————————————————————————————————

func TestIsConflict(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("API error 409: Duplicate node name hash in the same folder"), true},
		{fmt.Errorf("API error 400: bad request"), false},
		{fmt.Errorf("API error 500: internal server error"), false},
		{fmt.Errorf("network timeout"), false},
		{fmt.Errorf("wrapping: %w", fmt.Errorf("API error 409: conflict")), true},
	}

	for _, tt := range tests {
		got := isConflict(tt.err)
		if got != tt.want {
			t.Errorf("isConflict(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
