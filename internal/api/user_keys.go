// Package api — user key routes (private surface, user token): listing,
// registration and revocation of the keys of the user.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// ErrKeyRotationInProgress is matched by the 409 of POST /user/me/keys and
// POST /machine/me/key when a rotation is already under way. It also matches
// ErrConflict.
var ErrKeyRotationInProgress = errors.New("key rotation already in progress")

// Details of the 409 answers (these routes send no X-Error-Code).
const (
	keyRotationInProgressDetail = "Key rotation already in progress"
)

// UserKeyStatus is the state of a user key.
type UserKeyStatus string

// User key states returned by GET /user/me/keys/all.
const (
	UserKeyActive  UserKeyStatus = "active"
	UserKeyPending UserKeyStatus = "pending"
	UserKeyRevoked UserKeyStatus = "revoked"
)

// UserKeyInfo is one key of GET /user/me/keys/all. PrivateKeyEnc is nil when
// the API no longer holds it.
type UserKeyInfo struct {
	ID            string        `json:"id"`
	UserID        string        `json:"user_id"`
	PublicKey     string        `json:"public_key"`
	PrivateKeyEnc *string       `json:"private_key_enc"`
	CreatedAt     time.Time     `json:"created_at"`
	DeletedAt     *time.Time    `json:"deleted_at"`
	Status        UserKeyStatus `json:"status"`
}

// conflictSentinel wraps a 409 with the sentinel its detail designates, among
// the given detail to sentinel pairs. Any other error is returned untouched.
func conflictSentinel(err error, sentinels map[string]error) error {
	var httpErr *HTTPError
	if err == nil || !errors.As(err, &httpErr) || httpErr.Status != http.StatusConflict {
		return err
	}

	if sentinel, ok := sentinels[httpErr.Detail()]; ok {
		return &sentinelError{sentinel: sentinel, err: err}
	}

	return err
}

// ListUserKeys returns all the keys of the user, most recent first.
func (c *Client) ListUserKeys(ctx context.Context) ([]UserKeyInfo, error) {
	var out []UserKeyInfo
	if err := c.Get(ctx, "/user/me/keys/all", &out); err != nil {
		return nil, err
	}

	if out == nil {
		out = []UserKeyInfo{}
	}

	return out, nil
}

// CreateUserKey registers a new key, which turns the active one into pending.
// A rotation already under way is matched by ErrKeyRotationInProgress.
func (c *Client) CreateUserKey(ctx context.Context, publicKey, privateKeyEnc string) error {
	data, err := json.Marshal(map[string]string{
		"public_key":      publicKey,
		"private_key_enc": privateKeyEnc,
	})
	if err != nil {
		return err
	}

	err = c.Post(ctx, "/user/me/keys", bytes.NewReader(data), nil)

	return conflictSentinel(err, map[string]error{keyRotationInProgressDetail: ErrKeyRotationInProgress})
}

// RevokeUserKey revokes a key. It is idempotent on a revoked key; the API
// refuses the active one with a 400.
func (c *Client) RevokeUserKey(ctx context.Context, keyID string) error {
	return c.Delete(ctx, "/user/me/key/"+url.PathEscape(keyID))
}
