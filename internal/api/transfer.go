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
