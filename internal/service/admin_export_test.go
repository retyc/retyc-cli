package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"golang.org/x/oauth2"
)

// — ensureExportDir ———————————————————————————————————————————————————————————

func TestEnsureExportDir_CreatesMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "export")
	if err := ensureExportDir(dir); err != nil {
		t.Fatalf("ensureExportDir() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("export dir not created: %v", err)
	}
}

func TestEnsureExportDir_AcceptsEmptyExisting(t *testing.T) {
	dir := t.TempDir()
	if err := ensureExportDir(dir); err != nil {
		t.Fatalf("ensureExportDir() error = %v", err)
	}
}

func TestEnsureExportDir_RejectsNonEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureExportDir(dir); err == nil {
		t.Fatal("expected error for non-empty directory")
	}
}

func TestEnsureExportDir_RejectsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureExportDir(file); err == nil {
		t.Fatal("expected error when path is a regular file")
	}
}

// — writeJSONFile —————————————————————————————————————————————————————————————

func TestWriteJSONFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := writeJSONFile(path, map[string]int{"n": 42}); err != nil {
		t.Fatalf("writeJSONFile() error = %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is our own TempDir + constant name
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]int
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got["n"] != 42 {
		t.Errorf("n = %d, want 42", got["n"])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

// — buildDataroomMeta —————————————————————————————————————————————————————————

func TestBuildDataroomMeta(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dr := &api.AdminDataroom{
		ID: "dr1", Title: "Legal", Status: "active",
		OwnerID: "u1", OwnerEmail: "o@x.co",
		SessionPublicKey: "age1pq1aaa", CreatedAt: created,
	}
	users := []api.AdminDataroomUser{{UserID: "u1", Email: "o@x.co", Role: "owner"}}

	t.Run("exportable", func(t *testing.T) {
		meta := buildDataroomMeta(dr, users, true, "")
		if !meta.Exportable || meta.Reason != "" {
			t.Errorf("meta = %+v, want exportable without reason", meta)
		}
		if meta.Title != "Legal" || len(meta.Users) != 1 || meta.SessionPublicKey != "age1pq1aaa" {
			t.Errorf("unexpected meta: %+v", meta)
		}
	})

	t.Run("not exportable carries the reason", func(t *testing.T) {
		meta := buildDataroomMeta(dr, users, false, "never rekeyed")
		if meta.Exportable || meta.Reason != "never rekeyed" {
			t.Errorf("meta = %+v, want non-exportable with reason", meta)
		}
	})
}

// — decorateMessages ——————————————————————————————————————————————————————————

func TestDecorateMessages(t *testing.T) {
	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	chatEnc, err := crypto.EncryptStringForKeys("hello world", []string{sess.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	eventType := "file_downloaded"
	msgs := []api.AdminDataroomMessage{
		{ID: "m1", MessageType: "chat", ContentEnc: &chatEnc},
		{ID: "m2", MessageType: "event", EventType: &eventType},
	}

	t.Run("chat decrypted with session identity", func(t *testing.T) {
		out := decorateMessages(msgs, sess)
		if out[0].Content == nil || *out[0].Content != "hello world" {
			t.Errorf("chat content = %v, want decrypted", out[0].Content)
		}
		if out[1].Content != nil {
			t.Error("event message must not get a content field")
		}
	})

	t.Run("no identity leaves content encrypted", func(t *testing.T) {
		out := decorateMessages(msgs, nil)
		if out[0].Content != nil {
			t.Error("content must stay nil without an identity")
		}
		if out[0].ContentEnc == nil || *out[0].ContentEnc != chatEnc {
			t.Error("content_enc must be preserved")
		}
	})

	t.Run("wrong identity leaves content encrypted", func(t *testing.T) {
		other, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		out := decorateMessages(msgs, other)
		if out[0].Content != nil {
			t.Error("content must stay nil when decryption fails")
		}
	})
}

// — AdminExportAll end-to-end —————————————————————————————————————————————————

// exportFixture serves a minimal but complete admin API for two datarooms:
// dr-open (session key encrypted for the organization key) and dr-locked (session
// key encrypted for another key). All crypto is real.
func newExportFixtureServer(t *testing.T, orgPub, otherPub string) (*httptest.Server, string) {
	t.Helper()

	sess, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sessPub := sess.Recipient().String()

	openKeyEnc, err := crypto.EncryptStringForKeys(sess.String(), []string{orgPub})
	if err != nil {
		t.Fatal(err)
	}
	lockedKeyEnc, err := crypto.EncryptStringForKeys(sess.String(), []string{otherPub})
	if err != nil {
		t.Fatal(err)
	}

	fileContent := []byte("clear content of report")
	chunk, err := crypto.EncryptBinaryForKey(fileContent, sessPub)
	if err != nil {
		t.Fatal(err)
	}
	rootContent := []byte("root readme")
	rootChunk, err := crypto.EncryptBinaryForKey(rootContent, sessPub)
	if err != nil {
		t.Fatal(err)
	}
	rootFileName, err := crypto.EncryptStringForKeys("readme.md", []string{sessPub})
	if err != nil {
		t.Fatal(err)
	}
	chatEnc, err := crypto.EncryptStringForKeys("bonjour", []string{sessPub})
	if err != nil {
		t.Fatal(err)
	}

	folderName, err := crypto.EncryptStringForKeys("docs", []string{sessPub})
	if err != nil {
		t.Fatal(err)
	}
	fileName, err := crypto.EncryptStringForKeys("report.txt", []string{sessPub})
	if err != nil {
		t.Fatal(err)
	}

	page := func(items string, total int) string {
		return fmt.Sprintf(`{"items":%s,"total":%d,"page":1,"pages":1}`, items, total)
	}
	drJSON := func(id, title, keyEnc string) string {
		return fmt.Sprintf(`{"id":%q,"title":%q,"status":"active","owner_id":"u1","owner_email":"o@x.co",
			"session_private_key_enc":%q,"session_public_key":%q,"created_at":"2026-01-01T00:00:00Z"}`,
			id, title, keyEnc, sessPub)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /organization", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"org1","name":"ACME","kind":"company","max_members":10,
			"current_plan_id":null,"dataroom_event_retention_days":30,"created_at":"2026-01-01T00:00:00Z"}`)
	})
	mux.HandleFunc("GET /organization/quota", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"current_plan_id":null,"current_user_count":1,"max_user_count":10,
			"is_over_quota":false,"owner_email":"o@x.co"}`)
	})
	mux.HandleFunc("GET /organization/members", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, page(`[{"id":"u1","email":"o@x.co","full_name":"Owner","organization_role":"owner",
			"status":"active","created_at":"2026-01-01T00:00:00Z"}]`, 1))
	})
	mux.HandleFunc("GET /organization/member/u1", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"id":"u1","email":"o@x.co","full_name":"Owner","organization_role":"owner",
			"status":"active","created_at":"2026-01-01T00:00:00Z",
			"identity":{"id":"kc1","email_verified":true,"totp":false,"membership_type":"MANAGED"}}`)
	})
	mux.HandleFunc("GET /organization/blacklist-domains", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, page(`[{"id":"d1","domain_name":"spam.com","created_at":"2026-01-01T00:00:00Z"}]`, 1))
	})
	mux.HandleFunc("GET /dataroom", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, page("["+drJSON("dr-open", "Open Room", openKeyEnc)+","+
			drJSON("dr-locked", "Locked Room", lockedKeyEnc)+"]", 2))
	})
	mux.HandleFunc("GET /dataroom/dr-open", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, drJSON("dr-open", "Open Room", openKeyEnc))
	})
	mux.HandleFunc("GET /dataroom/dr-locked", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, drJSON("dr-locked", "Locked Room", lockedKeyEnc))
	})
	mux.HandleFunc("GET /dataroom/{id}/users", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"user_id":"u1","email":"o@x.co","full_name":"Owner","role":"owner",
			"public_key":"age1pq1zzz","expected_public_key":null,"key_mismatch":false,
			"is_service_account":false,"created_at":"2026-01-01T00:00:00Z"}]`)
	})
	mux.HandleFunc("GET /dataroom/dr-open/messages", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, page(fmt.Sprintf(`[
			{"id":"m1","message_type":"chat","event_type":null,"event_data":null,"content_enc":%q,
			 "user_email":"o@x.co","user_display_name":"Owner","created_at":"2026-01-02T00:00:00Z"},
			{"id":"m2","message_type":"event","event_type":"file_downloaded","event_data":{"k":"v"},
			 "content_enc":null,"user_email":null,"user_display_name":null,"created_at":"2026-01-03T00:00:00Z"}]`,
			chatEnc), 2))
	})
	mux.HandleFunc("GET /dataroom/dr-locked/messages", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, page(`[{"id":"m3","message_type":"event","event_type":"user_added","event_data":null,
			"content_enc":null,"user_email":null,"user_display_name":null,"created_at":"2026-01-04T00:00:00Z"}]`, 1))
	})
	mux.HandleFunc("GET /dataroom/dr-open/nodes", func(w http.ResponseWriter, _ *http.Request) {
		// The root-level file comes FIRST: the export must not depend on a
		// subfolder download having created the data/ directory beforehand.
		fmt.Fprint(w, page(fmt.Sprintf(`[
			{"id":"n-root","parent_id":null,"is_folder":false,"name_enc":%q,"type_enc":null,
			 "version_id":"v2","version_number":1,"chunk_count":1,"encrypted_size":%d,"original_size":%d,
			 "created_at":"2026-01-01T00:00:00Z"},
			{"id":"n-dir","parent_id":null,"is_folder":true,"name_enc":%q,"type_enc":null,
			 "created_at":"2026-01-01T00:00:00Z"},
			{"id":"n-file","parent_id":"n-dir","is_folder":false,"name_enc":%q,"type_enc":null,
			 "version_id":"v1","version_number":1,"chunk_count":1,"encrypted_size":%d,"original_size":%d,
			 "created_at":"2026-01-01T00:00:00Z"}]`,
			rootFileName, len(rootChunk), len(rootContent),
			folderName, fileName, len(chunk), len(fileContent)), 3))
	})
	mux.HandleFunc("GET /dataroom/node/n-file/download/0", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(chunk)
	})
	mux.HandleFunc("GET /dataroom/node/n-root/download/0", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(rootChunk)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, string(fileContent)
}

// readExportFile reads a file from the export output tree of the test.
func readExportFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(parts...)) //nolint:gosec // G304: our own TempDir + constant names
	if err != nil {
		t.Fatalf("reading %v: %v", parts, err)
	}

	return data
}

func newExportTestClient(srv *httptest.Server) *api.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "ryc_test", TokenType: "Bearer"})

	return api.New(srv.URL, "retyc-test/1.0", ts, false, false)
}

func TestAdminExportAll(t *testing.T) {
	orgKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv, fileContent := newExportFixtureServer(t, orgKey.Recipient().String(), other.Recipient().String())
	out := filepath.Join(t.TempDir(), "export")

	result, err := AdminExportAll(context.Background(), newExportTestClient(srv), orgKey,
		AdminExportParams{OutputDir: out, CLIVersion: "test"}, nil, nil)
	if err != nil {
		t.Fatalf("AdminExportAll() error = %v", err)
	}

	// Top-level JSON files exist and parse.
	for _, f := range []string{"export.json", "organization.json", "members.json", "blacklist_domains.json"} {
		data, err := os.ReadFile(filepath.Join(out, f)) //nolint:gosec // G304: our own TempDir + constant names
		if err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Errorf("%s is not valid JSON: %v", f, err)
		}
	}

	// Members carry the Keycloak identity detail.
	var members []api.AdminMemberDetail
	data, _ := os.ReadFile(filepath.Join(out, "members.json")) //nolint:gosec // G304: our own TempDir + constant name
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].Identity == nil || members[0].Identity.MembershipType != "MANAGED" {
		t.Errorf("members.json = %+v, want detail with identity", members)
	}

	// Exportable dataroom: meta, decrypted data tree, decrypted chat message.
	var openMeta AdminExportDataroomMeta
	if err := json.Unmarshal(readExportFile(t, out, "datarooms", "dr-open", "meta.json"), &openMeta); err != nil {
		t.Fatal(err)
	}
	if !openMeta.Exportable || openMeta.Title != "Open Room" || len(openMeta.Users) != 1 {
		t.Errorf("dr-open meta = %+v", openMeta)
	}

	got := readExportFile(t, out, "datarooms", "dr-open", "data", "docs", "report.txt")
	if string(got) != fileContent {
		t.Errorf("file content = %q, want %q", got, fileContent)
	}
	if root := readExportFile(t, out, "datarooms", "dr-open", "data", "readme.md"); string(root) != "root readme" {
		t.Errorf("root file content = %q, want %q", root, "root readme")
	}

	var openMsgs []AdminExportMessage
	if err := json.Unmarshal(readExportFile(t, out, "datarooms", "dr-open", "messages", "0.json"), &openMsgs); err != nil {
		t.Fatal(err)
	}
	if len(openMsgs) != 2 || openMsgs[0].Content == nil || *openMsgs[0].Content != "bonjour" {
		t.Errorf("dr-open messages = %+v, want decrypted chat", openMsgs)
	}

	// Locked dataroom: meta with exportable=false, messages kept, no data dir.
	var lockedMeta AdminExportDataroomMeta
	if err := json.Unmarshal(readExportFile(t, out, "datarooms", "dr-locked", "meta.json"), &lockedMeta); err != nil {
		t.Fatal(err)
	}
	if lockedMeta.Exportable || lockedMeta.Reason == "" {
		t.Errorf("dr-locked meta = %+v, want non-exportable with reason", lockedMeta)
	}
	if _, err := os.Stat(filepath.Join(out, "datarooms", "dr-locked", "data")); !os.IsNotExist(err) {
		t.Error("dr-locked must not have a data directory")
	}
	if _, err := os.Stat(filepath.Join(out, "datarooms", "dr-locked", "messages", "0.json")); err != nil {
		t.Errorf("dr-locked messages missing: %v", err)
	}

	// Manifest reflects counts and the skipped dataroom.
	m := result.Manifest
	if m.Members != 1 || m.BlacklistDomains != 1 || m.Datarooms != 2 || m.DataroomsExported != 1 {
		t.Errorf("manifest counts = %+v", m)
	}
	if len(m.DataroomsSkipped) != 1 || m.DataroomsSkipped[0].ID != "dr-locked" {
		t.Errorf("manifest skipped = %+v", m.DataroomsSkipped)
	}
	if len(m.Errors) != 0 {
		t.Errorf("manifest errors = %v, want none", m.Errors)
	}
}

// TestAdminExportAll_TransientErrorIsAnErrorNotASkip: only a genuine
// "organization key cannot open it" is a skip. Any other failure while
// resolving the session (API 502, timeout, ...) must be recorded in
// manifest.errors so the caller exits non-zero instead of silently shipping an
// export missing a decryptable dataroom's content.
func TestAdminExportAll_TransientErrorIsAnErrorNotASkip(t *testing.T) {
	orgKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fixture, _ := newExportFixtureServer(t, orgKey.Recipient().String(), other.Recipient().String())
	target, err := url.Parse(fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// dr-open is decryptable, but its detail fetch fails transiently.
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/dataroom/dr-open" {
			http.Error(w, "bad gateway", http.StatusBadGateway)

			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(flaky.Close)
	out := filepath.Join(t.TempDir(), "export")

	result, err := AdminExportAll(context.Background(), newExportTestClient(flaky), orgKey,
		AdminExportParams{OutputDir: out, CLIVersion: "test"}, nil, nil)
	if err != nil {
		t.Fatalf("AdminExportAll() error = %v", err)
	}
	m := result.Manifest
	if len(m.Errors) != 1 || !strings.Contains(m.Errors[0], "dr-open") {
		t.Errorf("manifest errors = %v, want one error for dr-open", m.Errors)
	}
	if len(m.DataroomsSkipped) != 1 || m.DataroomsSkipped[0].ID != "dr-locked" {
		t.Errorf("manifest skipped = %+v, want only dr-locked", m.DataroomsSkipped)
	}
	if m.DataroomsExported != 0 {
		t.Errorf("DataroomsExported = %d, want 0", m.DataroomsExported)
	}
}
