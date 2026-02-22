// Package api — transfer-related types and API methods.
package api

import (
	"context"
	"fmt"
	"time"
)

// TransferStatus represents the lifecycle status of a transfer.
type TransferStatus string

// Transfer represents a single transfer returned by the API.
// Field names match the JSON keys of the ShareModel schema.
type Transfer struct {
	ID         string         `json:"id"`
	Title      *string        `json:"title"`
	Status     TransferStatus `json:"status"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  *time.Time     `json:"expires_at"`
	DisabledAt *time.Time     `json:"disabled_at"`
	Slug       string         `json:"slug"`
	OwnerID    *string        `json:"owner_id"`
}

// TransferPage is a paginated list of transfers.
type TransferPage struct {
	Items []Transfer `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Size  int        `json:"size"`
	Pages int        `json:"pages"`
}

// ListTransfers returns a paginated list of transfers.
// listType must be "sent" or "received".
func (c *Client) ListTransfers(ctx context.Context, listType string, page int) (*TransferPage, error) {
	path := fmt.Sprintf("/share?list_type=%s&page=%d", listType, page)
	var result TransferPage
	if err := c.Get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TransferRecipient is a recipient of a transfer.
type TransferRecipient struct {
	ID           *string `json:"id"`
	ShareID      string  `json:"share_id"`
	UserID       *string `json:"user_id"`
	Email        *string `json:"email"`
	PublicKey    *string `json:"public_key"`
	IsExternal   bool    `json:"is_external"`
	KeyEncrypted bool    `json:"key_encrypted"`
	UserFullName *string `json:"user_full_name"`
}

// TransferDetails is the full view of a transfer returned by GET /share/{id}/details.
type TransferDetails struct {
	ID                   *string             `json:"id"`
	Title                *string             `json:"title"`
	Status               TransferStatus      `json:"status"`
	CreatedAt            *time.Time          `json:"created_at"`
	EnabledAt            *time.Time          `json:"enabled_at"`
	ExpiresAt            *time.Time          `json:"expires_at"`
	DisabledAt           *time.Time          `json:"disabled_at"`
	Slug                 string              `json:"slug"`
	UsePassphrase        bool                `json:"use_passphrase"`
	MessageEnc           *string             `json:"message_enc"`
	SessionPrivateKeyEnc *string             `json:"session_private_key_enc"`
	SessionPublicKey     *string             `json:"session_public_key"`
	Recipients           []TransferRecipient `json:"recipients"`
}

// TransferFile is a single encrypted file within a transfer.
type TransferFile struct {
	ID            string `json:"id"`
	NameEnc       string `json:"name_enc"`
	TypeEnc       string `json:"type_enc"`
	OriginalSize  int64  `json:"original_size"`
	EncryptedSize int64  `json:"encrypted_size"`
	ChunkCount    int    `json:"chunk_count"`
}

// TransferFilePage is a paginated list of transfer files.
type TransferFilePage struct {
	Items []TransferFile `json:"items"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
	Pages int            `json:"pages"`
}

// GetTransferDetails fetches the full details of a transfer by its ID.
func (c *Client) GetTransferDetails(ctx context.Context, shareID string) (*TransferDetails, error) {
	var result TransferDetails
	if err := c.Get(ctx, "/share/"+shareID+"/details", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListFiles returns a paginated list of encrypted files for a given transfer.
func (c *Client) ListFiles(ctx context.Context, shareID string, page int) (*TransferFilePage, error) {
	path := fmt.Sprintf("/share/%s/files?page=%d", shareID, page)
	var result TransferFilePage
	if err := c.Get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
