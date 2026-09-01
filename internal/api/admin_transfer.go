package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// AdminTransferRecipient is a transfer recipient with its key status.
type AdminTransferRecipient struct {
	Email             *string `json:"email"`
	UserID            *string `json:"user_id"`
	UserFullName      *string `json:"user_full_name"`
	PublicKey         *string `json:"public_key"`
	ExpectedPublicKey *string `json:"expected_public_key"`
	KeyMismatch       bool    `json:"key_mismatch"`
	KeyEncrypted      bool    `json:"key_encrypted"`
	IsExternal        bool    `json:"is_external"`
	IsServiceAccount  bool    `json:"is_service_account"`
}

// AdminTransfer is a transfer sent by a member of the organization.
// SessionPrivateKeyEnc is nil when the organization key was not enabled
// when the transfer was created.
type AdminTransfer struct {
	ID                   string                   `json:"id"`
	Title                string                   `json:"title"`
	Status               string                   `json:"status"`
	WebURL               string                   `json:"web_url"`
	UsePassphrase        bool                     `json:"use_passphrase"`
	IsPublicUpload       bool                     `json:"is_public_upload"`
	IsOnError            bool                     `json:"is_on_error"`
	SessionPublicKey     string                   `json:"session_public_key"`
	SessionPrivateKeyEnc *string                  `json:"session_private_key_enc"`
	EphemeralPublicKey   *string                  `json:"ephemeral_public_key"`
	Recipients           []AdminTransferRecipient `json:"recipients"`
	CreatedAt            time.Time                `json:"created_at"`
	ExpiresAt            *time.Time               `json:"expires_at"`
	DisabledAt           *time.Time               `json:"disabled_at"`
	EnabledAt            *time.Time               `json:"enabled_at"`
	DeletedAt            *time.Time               `json:"deleted_at"`
}

// AdminTrackingEvent is one download event.
type AdminTrackingEvent struct {
	CreatedAt time.Time `json:"created_at"`
	FileID    string    `json:"file_id"`
}

// AdminTrackingRecipient groups download events by recipient or anonymous session.
type AdminTrackingRecipient struct {
	Email    *string              `json:"email"`
	FullName *string              `json:"full_name"`
	Events   []AdminTrackingEvent `json:"events"`
}

// AdminTrackingFile describes a file referenced by tracking events.
type AdminTrackingFile struct {
	ID              string  `json:"id"`
	CustomModelName *string `json:"custom_model_name"`
	OriginalSize    int64   `json:"original_size"`
	EncryptedSize   int64   `json:"encrypted_size"`
	ChunkCount      int     `json:"chunk_count"`
}

// AdminTransferTracking is the download tracking data of a transfer.
type AdminTransferTracking struct {
	TotalDownloadCount int                      `json:"total_download_count"`
	IdentifiedCount    int                      `json:"identified_count"`
	AnonymousCount     int                      `json:"anonymous_count"`
	Truncated          bool                     `json:"truncated"`
	Identified         []AdminTrackingRecipient `json:"identified"`
	Anonymous          []AdminTrackingRecipient `json:"anonymous"`
	Files              []AdminTrackingFile      `json:"files"`
}

// AdminListTransfers returns one page of the transfers sent by members of the
// organization, optionally filtered by status and sender user ID.
func (c *Client) AdminListTransfers(
	ctx context.Context, status, userID string, page int,
) (*AdminPage[AdminTransfer], error) {
	q := url.Values{}
	q.Set("page", fmt.Sprint(page))
	q.Set("size", "100")
	if status != "" {
		q.Set("status", status)
	}
	if userID != "" {
		q.Set("user_id", userID)
	}
	var p AdminPage[AdminTransfer]
	if err := c.Get(ctx, "/transfer/sent?"+q.Encode(), &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// AdminGetTransfer returns one transfer of the organization.
func (c *Client) AdminGetTransfer(ctx context.Context, transferID string) (*AdminTransfer, error) {
	var tr AdminTransfer
	if err := c.Get(ctx, "/transfer/"+transferID, &tr); err != nil {
		return nil, err
	}

	return &tr, nil
}

// AdminDisableTransfer disables a transfer (soft, reversible).
func (c *Client) AdminDisableTransfer(ctx context.Context, transferID string) error {
	return c.Delete(ctx, "/transfer/"+transferID)
}

// AdminEnableTransfer re-enables a previously disabled transfer.
func (c *Client) AdminEnableTransfer(ctx context.Context, transferID string) error {
	return c.Put(ctx, "/transfer/"+transferID+"/re-enable", nil, nil)
}

// AdminForceDeleteTransfer permanently removes the transfer data; the record
// itself is soft-deleted.
func (c *Client) AdminForceDeleteTransfer(ctx context.Context, transferID string) error {
	return c.Delete(ctx, "/transfer/"+transferID+"/force")
}

// AdminGetTransferTracking returns the download tracking data of a transfer.
func (c *Client) AdminGetTransferTracking(ctx context.Context, transferID string) (*AdminTransferTracking, error) {
	var tr AdminTransferTracking
	if err := c.Get(ctx, "/transfer/"+transferID+"/tracking", &tr); err != nil {
		return nil, err
	}

	return &tr, nil
}

// AdminRekeyTransfer pushes the session key re-encrypted by the caller for all
// current recipients, the organization service account included.
func (c *Client) AdminRekeyTransfer(ctx context.Context, transferID, sessionPrivKeyEnc string) error {
	data, err := json.Marshal(map[string]string{"session_private_key_enc": sessionPrivKeyEnc})
	if err != nil {
		return err
	}

	return c.Put(ctx, "/transfer/"+transferID+"/rekey", bytes.NewReader(data), nil)
}
