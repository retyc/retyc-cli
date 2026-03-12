// Package api — user-related types and API methods.
package api

import (
	"context"
	"time"
)

// UserInfo holds the authenticated user's profile information as returned by GET /user/me.
type UserInfo struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	FullName           *string `json:"full_name"`
	OrganizationRole   string  `json:"organization_role"`
	OrganizationPlanID string  `json:"organization_plan_id"`
	PublicKey          string  `json:"public_key"`
}

// userMeResponse is the top-level wrapper returned by GET /user/me.
type userMeResponse struct {
	User UserInfo `json:"user"`
}

// GetMe retrieves the authenticated user's profile.
func (c *Client) GetMe(ctx context.Context) (*UserInfo, error) {
	var result userMeResponse
	if err := c.Get(ctx, "/user/me", &result); err != nil {
		return nil, err
	}

	return &result.User, nil
}

// UserKey holds the user's active AGE encryption key pair as stored by the API.
// PrivateKeyEnc contains the AGE private key encrypted with the user's passphrase
// (AGE scrypt recipient). It must be decrypted locally before use.
type UserKey struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	PublicKey     string    `json:"public_key"`
	PrivateKeyEnc string    `json:"private_key_enc"`
	CreatedAt     time.Time `json:"created_at"`
}

// GetActiveKey retrieves the authenticated user's active encryption key.
// Returns nil if the user has no active key registered.
func (c *Client) GetActiveKey(ctx context.Context) (*UserKey, error) {
	var result *UserKey
	if err := c.Get(ctx, "/user/me/key/active", &result); err != nil {
		return nil, err
	}

	return result, nil
}
