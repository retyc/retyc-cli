package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListTransfers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share" {
			t.Errorf("path = %q, want /share", r.URL.Path)
		}

		if got := r.URL.Query().Get("list_type"); got != "sent" {
			t.Errorf("list_type = %q, want sent", got)
		}

		if got := r.URL.Query().Get("page"); got != "1" {
			t.Errorf("page = %q, want 1", got)
		}

		title := "My Transfer"
		_ = json.NewEncoder(w).Encode(TransferPage{
			Items: []Transfer{{ID: "abc", Title: &title, Status: "active", CreatedAt: time.Now()}},
			Total: 1,
			Page:  1,
			Pages: 1,
		})
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListTransfers(context.Background(), "sent", 1)
	if err != nil {
		t.Fatalf("ListTransfers() error = %v", err)
	}

	if page.Total != 1 {
		t.Errorf("Total = %d, want 1", page.Total)
	}

	if len(page.Items) != 1 || page.Items[0].ID != "abc" {
		t.Errorf("Items[0].ID = %q, want abc", page.Items[0].ID)
	}
}

func TestGetTransferDetails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share/share-id-123/details" {
			t.Errorf("path = %q, want /share/share-id-123/details", r.URL.Path)
		}

		webURL := "https://retyc.com/t/share-id-123"
		_ = json.NewEncoder(w).Encode(TransferDetails{WebURL: webURL})
	}))
	defer srv.Close()

	details, err := newTestClient(srv).GetTransferDetails(context.Background(), "share-id-123")
	if err != nil {
		t.Fatalf("GetTransferDetails() error = %v", err)
	}

	if details.WebURL != "https://retyc.com/t/share-id-123" {
		t.Errorf("WebURL = %q, want https://retyc.com/t/share-id-123", details.WebURL)
	}
}

func TestListFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share/share-abc/files" {
			t.Errorf("path = %q, want /share/share-abc/files", r.URL.Path)
		}

		if got := r.URL.Query().Get("page"); got != "2" {
			t.Errorf("page = %q, want 2", got)
		}

		_ = json.NewEncoder(w).Encode(TransferFilePage{
			Items: []TransferFile{{ID: "file-1", OriginalSize: 1024}},
			Total: 1,
			Page:  2,
			Pages: 2,
		})
	}))
	defer srv.Close()

	fp, err := newTestClient(srv).ListFiles(context.Background(), "share-abc", 2)
	if err != nil {
		t.Fatalf("ListFiles() error = %v", err)
	}

	if len(fp.Items) != 1 || fp.Items[0].ID != "file-1" {
		t.Errorf("Items[0].ID = %q, want file-1", fp.Items[0].ID)
	}
}

func TestCreateShare_WithEmails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("Decode() error = %v", err)
		}

		emails, ok := body["emails"].([]any)
		if !ok || len(emails) != 1 {
			t.Errorf("emails = %v, want a slice with 1 item", body["emails"])
		}

		_ = json.NewEncoder(w).Encode(ShareCreateResponse{ID: "new-share-id", Slug: "abc123"})
	}))
	defer srv.Close()

	title := "Test Transfer"

	resp, err := newTestClient(srv).CreateShare(context.Background(), 3600, &title, true, []string{"user@example.com"})
	if err != nil {
		t.Fatalf("CreateShare() error = %v", err)
	}

	if resp.ID != "new-share-id" {
		t.Errorf("ID = %q, want new-share-id", resp.ID)
	}
}

func TestCreateShare_NilEmails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("Decode() error = %v", err)
		}

		// nil emails should be normalised to an empty array, not JSON null.
		emails, ok := body["emails"].([]any)
		if !ok {
			t.Errorf("emails should be a JSON array, got %T: %v", body["emails"], body["emails"])
		}

		if len(emails) != 0 {
			t.Errorf("emails length = %d, want 0", len(emails))
		}

		_ = json.NewEncoder(w).Encode(ShareCreateResponse{ID: "share-id"})
	}))
	defer srv.Close()

	_, err := newTestClient(srv).CreateShare(context.Background(), 3600, nil, false, nil)
	if err != nil {
		t.Fatalf("CreateShare() nil emails error = %v", err)
	}
}

func TestCompleteTransfer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share/share-xyz/complete" {
			t.Errorf("path = %q, want /share/share-xyz/complete", r.URL.Path)
		}

		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req := CompleteTransferRequest{
		SessionPrivateKeyEnc: "enc-priv-key",
		SessionPublicKey:     "pub-key",
	}

	if err := newTestClient(srv).CompleteTransfer(context.Background(), "share-xyz", req); err != nil {
		t.Fatalf("CompleteTransfer() error = %v", err)
	}
}

func TestForceDeleteTransfer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share/pending-id/force" {
			t.Errorf("path = %q, want /share/pending-id/force", r.URL.Path)
		}

		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).ForceDeleteTransfer(context.Background(), "pending-id"); err != nil {
		t.Fatalf("ForceDeleteTransfer() error = %v", err)
	}
}

func TestDisableTransfer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share/to-disable" {
			t.Errorf("path = %q, want /share/to-disable", r.URL.Path)
		}

		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DisableTransfer(context.Background(), "to-disable"); err != nil {
		t.Fatalf("DisableTransfer() error = %v", err)
	}
}

func TestEnableTransfer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/share/to-enable/re-enable" {
			t.Errorf("path = %q, want /share/to-enable/re-enable", r.URL.Path)
		}

		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := newTestClient(srv).EnableTransfer(context.Background(), "to-enable"); err != nil {
		t.Fatalf("EnableTransfer() error = %v", err)
	}
}

func TestUploadChunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/file/file-id-abc/3" {
			t.Errorf("path = %q, want /file/file-id-abc/3", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := newTestClient(srv).UploadChunk(context.Background(), "file-id-abc", 3, []byte("chunk")); err != nil {
		t.Fatalf("UploadChunk() error = %v", err)
	}
}

func TestDownloadChunk(t *testing.T) {
	expected := []byte("decrypted chunk data")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/file/file-id-xyz/0" {
			t.Errorf("path = %q, want /file/file-id-xyz/0", r.URL.Path)
		}

		_, _ = w.Write(expected)
	}))
	defer srv.Close()

	got, err := newTestClient(srv).DownloadChunk(context.Background(), "file-id-xyz", 0)
	if err != nil {
		t.Fatalf("DownloadChunk() error = %v", err)
	}

	if string(got) != string(expected) {
		t.Errorf("DownloadChunk() = %q, want %q", got, expected)
	}
}
