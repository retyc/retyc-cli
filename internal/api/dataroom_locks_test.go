package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLockDataroomNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method != http.MethodPost || r.URL.Path != "/dataroom/node/n-1/lock" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		// The lease is clamped to the server's bounds.
		if body["kind"] != "exclusive" || body["timeout"] != float64(LockTimeoutMax) {
			t.Errorf("body = %v", body)
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"l-1","node_id":"n-1","dataroom_id":"dr-1","user_id":"u","kind":"exclusive",`+
			`"expires_at":"2026-10-10T12:05:00Z","created_at":"2026-10-10T12:00:00Z","token":"tok"}`)
	}))
	defer srv.Close()
	lock, err := newTestClient(srv).LockDataroomNode(context.Background(), "n-1", LockExclusive, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if lock.ID != "l-1" || lock.Token != "tok" || lock.ExpiresAt.IsZero() {
		t.Errorf("lock = %+v", lock)
	}
}

// A 423 is ErrLocked; it matches no other sentinel.
func TestLockDataroomNode_Locked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"Another lock excludes this one"}`, http.StatusLocked)
	}))
	defer srv.Close()
	_, err := newTestClient(srv).LockDataroomNode(context.Background(), "n-1", LockShared, 60)
	if !errors.Is(err, ErrLocked) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
		t.Errorf("err = %v, want ErrLocked only", err)
	}
}

// Refresh and release carry the token in X-Lock-Token; a refresh below the
// minimum lease is raised to it.
func TestRefreshAndUnlockDataroomNodeLock(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("X-Lock-Token"))
		switch r.Method {
		case http.MethodPut:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["timeout"] != float64(LockTimeoutMin) {
				t.Errorf("timeout = %v, want %d", body["timeout"], LockTimeoutMin)
			}
			fmt.Fprint(w, `{"id":"l-1","node_id":"n-1","dataroom_id":"dr-1","user_id":"u","kind":"shared",`+
				`"expires_at":"2026-10-10T12:05:00Z","created_at":"2026-10-10T12:00:00Z"}`)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	c := newTestClient(srv)
	lock, err := c.RefreshDataroomNodeLock(context.Background(), "l-1", "tok", 1)
	if err != nil || lock.ID != "l-1" || lock.Token != "" {
		t.Fatalf("refresh = %+v, %v", lock, err)
	}
	if err := c.UnlockDataroomNode(context.Background(), "l-1", "tok"); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /dataroom/node/lock/l-1 tok", "DELETE /dataroom/node/lock/l-1 tok"}
	if len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Errorf("requests = %v, want %v", seen, want)
	}
}

func TestListDataroomLocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dataroom/dr-1/locks", "/dataroom/node/n-1/locks":
			fmt.Fprint(w, `[{"id":"l-1","node_id":"n-1","dataroom_id":"dr-1","user_id":"u","kind":"shared",`+
				`"expires_at":"2026-10-10T12:05:00Z","created_at":"2026-10-10T12:00:00Z"}]`)
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	c := newTestClient(srv)
	byDR, err := c.ListDataroomLocks(context.Background(), "dr-1")
	if err != nil || len(byDR) != 1 || byDR[0].ID != "l-1" {
		t.Errorf("ListDataroomLocks = %+v, %v", byDR, err)
	}
	byNode, err := c.ListDataroomNodeLocks(context.Background(), "n-1")
	if err != nil || len(byNode) != 1 || byNode[0].Kind != LockShared {
		t.Errorf("ListDataroomNodeLocks = %+v, %v", byNode, err)
	}
}

// A copy is accepted (202) with its new node and an empty version that
// announces the chunks to come.
func TestCopyDataroomNode(t *testing.T) {
	parent := "p-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method != http.MethodPost || r.URL.Path != "/dataroom/node/n-src/copy" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if body["parent_id"] != "p-1" || body["name_enc"] != "E" || body["name_hash"] != "H" {
			t.Errorf("body = %v", body)
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"node":{"id":"n-copy","type":"file","name_enc":"E","type_enc":null,"mime_type_id":"mt",`+
			`"access_mode":"0644","parent_id":"p-1"},"node_version":{"id":"v-copy","node_id":"n-copy",`+
			`"original_size":9000000,"chunk_count":0,"chunk_count_expected":2,"version_number":1,`+
			`"created_at":"2026-10-10T12:00:00Z","copied_from_version_id":"v-src"},"max_version_number":1,`+
			`"capabilities":{}}`)
	}))
	defer srv.Close()
	item, err := newTestClient(srv).CopyDataroomNode(context.Background(), "n-src", &parent, "E", "H")
	if err != nil {
		t.Fatal(err)
	}
	v := item.Version
	if item.Node.ID != "n-copy" || v == nil || v.Complete() || *v.ChunkCountExpected != 2 ||
		v.CopiedFromVersionID == nil || *v.CopiedFromVersionID != "v-src" {
		t.Errorf("item = %+v / %+v", item.Node, v)
	}
}

func TestGetDataroomNodeVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dataroom/node/version/v-1" {
			t.Errorf("path = %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"v-1","node_id":"n-1","original_size":9,"chunk_count":2,"chunk_count_expected":2,`+
			`"version_number":1,"created_at":"2026-10-10T12:00:00Z"}`)
	}))
	defer srv.Close()
	v, err := newTestClient(srv).GetDataroomNodeVersion(context.Background(), "v-1")
	if err != nil || !v.Complete() || v.ChunkCount != 2 {
		t.Errorf("version = %+v, %v", v, err)
	}
}

func TestFormatLockTimeout(t *testing.T) {
	if got := FormatLockTimeout(120); got != "Second-120" {
		t.Errorf("FormatLockTimeout = %q", got)
	}
}
