// Package api — transfer-related types and API methods.
package api

import (
	"bytes"
	"context"
	"encoding/json"
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
	ID                                *string             `json:"id"`
	Title                             *string             `json:"title"`
	Status                            TransferStatus      `json:"status"`
	CreatedAt                         *time.Time          `json:"created_at"`
	EnabledAt                         *time.Time          `json:"enabled_at"`
	ExpiresAt                         *time.Time          `json:"expires_at"`
	DisabledAt                        *time.Time          `json:"disabled_at"`
	Slug                              string              `json:"slug"`
	WebURL                            string              `json:"web_url"`
	UsePassphrase                     bool                `json:"use_passphrase"`
	MessageEnc                        *string             `json:"message_enc"`
	SessionPrivateKeyEnc              *string             `json:"session_private_key_enc"`
	SessionPublicKey                  *string             `json:"session_public_key"`
	EphemeralPrivateKeyEnc            *string             `json:"ephemeral_private_key_enc"`
	EphemeralPublicKey                *string             `json:"ephemeral_public_key"`
	SessionPrivateKeyEncForPassphrase *string             `json:"session_private_key_enc_for_passphrase"`
	Recipients                        []TransferRecipient `json:"recipients"`
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

// ShareCreateResponse is the response from POST /share.
type ShareCreateResponse struct {
	ID         string   `json:"id"`
	Slug       string   `json:"slug"`
	PublicKeys []string `json:"public_keys"`
}

// FileModel is the response from POST /share/{id}/file.
type FileModel struct {
	ID         string `json:"id"`
	ChunkCount int    `json:"chunk_count"`
}

// CompleteTransferRequest is the body for PUT /share/{id}/complete.
type CompleteTransferRequest struct {
	SessionPrivateKeyEnc              string  `json:"session_private_key_enc"`
	SessionPublicKey                  string  `json:"session_public_key"`
	EphemeralPrivateKeyEnc            *string `json:"ephemeral_private_key_enc,omitempty"`
	EphemeralPublicKey                *string `json:"ephemeral_public_key,omitempty"`
	SessionPrivateKeyEncForPassphrase *string `json:"session_private_key_enc_for_passphrase,omitempty"`
	MessageEnc                        *string `json:"message_enc,omitempty"`
}

// CreateShare creates a new transfer on the server.
// emails is the list of recipient email addresses; pass nil or empty for no recipients.
func (c *Client) CreateShare(ctx context.Context, expires int, title *string, usePassphrase bool, emails []string) (*ShareCreateResponse, error) {
	if emails == nil {
		emails = []string{}
	}
	body := map[string]any{
		"emails":         emails,
		"expires":        expires,
		"title":          title,
		"use_passphrase": usePassphrase,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result ShareCreateResponse
	if err := c.Post(ctx, "/share", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateFile registers an encrypted file within a transfer and returns its metadata.
func (c *Client) CreateFile(ctx context.Context, shareID, nameEnc, typeEnc string, originalSize int64) (*FileModel, error) {
	body := map[string]any{
		"name_enc":      nameEnc,
		"type_enc":      typeEnc,
		"original_size": originalSize,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result FileModel
	if err := c.Post(ctx, "/share/"+shareID+"/file", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UploadChunk uploads a single encrypted file chunk (binary AGE, multipart/form-data).
func (c *Client) UploadChunk(ctx context.Context, fileID string, chunkID int, data []byte) error {
	path := fmt.Sprintf("/file/%s/%d", fileID, chunkID)
	return c.PostMultipartChunk(ctx, path, data)
}

// DownloadChunk downloads a single encrypted file chunk (raw binary AGE).
func (c *Client) DownloadChunk(ctx context.Context, fileID string, chunkID int) ([]byte, error) {
	path := fmt.Sprintf("/file/%s/%d", fileID, chunkID)
	return c.GetBytes(ctx, path)
}

// CompleteTransfer finalizes a transfer after all files have been uploaded.
func (c *Client) CompleteTransfer(ctx context.Context, shareID string, req CompleteTransferRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return c.Put(ctx, "/share/"+shareID+"/complete", bytes.NewReader(data), nil)
}

// DisableTransfer disables (soft-deletes) a transfer by its ID.
func (c *Client) DisableTransfer(ctx context.Context, shareID string) error {
	return c.Delete(ctx, "/share/"+shareID)
}

// EnableTransfer re-enables a previously disabled transfer.
func (c *Client) EnableTransfer(ctx context.Context, shareID string) error {
	return c.Put(ctx, "/share/"+shareID+"/re-enable", nil, nil)
}
