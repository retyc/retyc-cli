package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// AdminDataroom is a dataroom owned by a member of the organization.
// SessionPrivateKeyEnc is re-encrypted for the organization service account
// when the dataroom has been rekeyed for the organization key.
type AdminDataroom struct {
	ID                   string     `json:"id"`
	Title                string     `json:"title"`
	Status               string     `json:"status"`
	OwnerID              string     `json:"owner_id"`
	OwnerEmail           string     `json:"owner_email"`
	SessionPrivateKeyEnc string     `json:"session_private_key_enc"`
	SessionPublicKey     string     `json:"session_public_key"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            *time.Time `json:"expires_at"`
	DeletedAt            *time.Time `json:"deleted_at"`
}

// AdminDataroomUser is a dataroom member with its key status.
type AdminDataroomUser struct {
	UserID            string    `json:"user_id"`
	Email             string    `json:"email"`
	FullName          string    `json:"full_name"`
	Role              string    `json:"role"`
	PublicKey         *string   `json:"public_key"`
	ExpectedPublicKey *string   `json:"expected_public_key"`
	KeyMismatch       bool      `json:"key_mismatch"`
	IsServiceAccount  bool      `json:"is_service_account"`
	CreatedAt         time.Time `json:"created_at"`
}

// AdminDataroomMessage is one entry of a dataroom activity feed.
// ContentEnc (chat) and the *_enc entries of EventData stay encrypted with the
// dataroom session key.
type AdminDataroomMessage struct {
	ID              string         `json:"id"`
	MessageType     string         `json:"message_type"`
	EventType       *string        `json:"event_type"`
	EventData       map[string]any `json:"event_data"`
	ContentEnc      *string        `json:"content_enc"`
	UserEmail       *string        `json:"user_email"`
	UserDisplayName *string        `json:"user_display_name"`
	CreatedAt       time.Time      `json:"created_at"`
}

// AdminDataroomNode is a node flattened with its latest downloadable version.
// Version fields are nil for folders and for files without uploaded content.
type AdminDataroomNode struct {
	ID            string    `json:"id"`
	ParentID      *string   `json:"parent_id"`
	IsFolder      bool      `json:"is_folder"`
	NameEnc       string    `json:"name_enc"`
	TypeEnc       *string   `json:"type_enc"`
	CreatedUserID *string   `json:"created_user_id"`
	VersionID     *string   `json:"version_id"`
	VersionNumber *int      `json:"version_number"`
	ChunkCount    *int      `json:"chunk_count"`
	EncryptedSize *int64    `json:"encrypted_size"`
	OriginalSize  *int64    `json:"original_size"`
	CreatedAt     time.Time `json:"created_at"`
}

// AdminListDatarooms returns one page of the organization's datarooms,
// optionally filtered by owner user ID.
func (c *Client) AdminListDatarooms(ctx context.Context, userID string, page int) (*AdminPage[AdminDataroom], error) {
	q := url.Values{}
	q.Set("page", fmt.Sprint(page))
	q.Set("size", "100")
	if userID != "" {
		q.Set("user_id", userID)
	}
	var p AdminPage[AdminDataroom]
	if err := c.Get(ctx, "/dataroom?"+q.Encode(), &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// AdminGetDataroom returns one dataroom of the organization.
func (c *Client) AdminGetDataroom(ctx context.Context, dataroomID string) (*AdminDataroom, error) {
	var dr AdminDataroom
	if err := c.Get(ctx, "/dataroom/"+dataroomID, &dr); err != nil {
		return nil, err
	}

	return &dr, nil
}

// AdminDeleteDataroom deletes a dataroom of the organization.
func (c *Client) AdminDeleteDataroom(ctx context.Context, dataroomID string) error {
	return c.Delete(ctx, "/dataroom/"+dataroomID)
}

// AdminListDataroomUsers returns all users of a dataroom (not paginated).
func (c *Client) AdminListDataroomUsers(ctx context.Context, dataroomID string) ([]AdminDataroomUser, error) {
	var users []AdminDataroomUser
	if err := c.Get(ctx, "/dataroom/"+dataroomID+"/users", &users); err != nil {
		return nil, err
	}

	return users, nil
}

// AdminListDataroomMessages returns one page of the dataroom activity feed.
func (c *Client) AdminListDataroomMessages(
	ctx context.Context, dataroomID string, page int,
) (*AdminPage[AdminDataroomMessage], error) {
	var p AdminPage[AdminDataroomMessage]
	path := fmt.Sprintf("/dataroom/%s/messages?page=%d&size=100", dataroomID, page)
	if err := c.Get(ctx, path, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// AdminListDataroomNodes returns one page of every node of a dataroom, at every depth.
func (c *Client) AdminListDataroomNodes(
	ctx context.Context, dataroomID string, page int,
) (*AdminPage[AdminDataroomNode], error) {
	var p AdminPage[AdminDataroomNode]
	path := fmt.Sprintf("/dataroom/%s/nodes?page=%d&size=100", dataroomID, page)
	if err := c.Get(ctx, path, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// AdminTransferDataroomOwnership transfers the dataroom to an admin member.
func (c *Client) AdminTransferDataroomOwnership(ctx context.Context, dataroomID, userID string) error {
	return c.Put(ctx, "/dataroom/"+dataroomID+"/ownership/"+userID, nil, nil)
}

// AdminRemoveDataroomUser removes a user from a dataroom. The caller must
// follow up with AdminRekeyDataroom for the removal to take effect cryptographically.
func (c *Client) AdminRemoveDataroomUser(ctx context.Context, dataroomID, userID string) error {
	return c.Delete(ctx, "/dataroom/"+dataroomID+"/user/"+userID)
}

// AdminDownloadNodeChunk downloads one encrypted chunk of the latest version of
// a file node. Chunks are numbered from 0 to chunk_count-1.
func (c *Client) AdminDownloadNodeChunk(ctx context.Context, nodeID string, chunkID int) ([]byte, error) {
	return c.GetBytes(ctx, fmt.Sprintf("/dataroom/node/%s/download/%d", nodeID, chunkID))
}

// AdminRekeyDataroom pushes the session key re-encrypted by the caller for all
// current members, the organization service account included. The server
// stores the blob as-is and re-encrypts nothing.
func (c *Client) AdminRekeyDataroom(ctx context.Context, dataroomID, sessionPrivKeyEnc string) error {
	data, err := json.Marshal(map[string]string{"session_private_key_enc": sessionPrivKeyEnc})
	if err != nil {
		return err
	}

	return c.Put(ctx, "/dataroom/"+dataroomID+"/rekey", bytes.NewReader(data), nil)
}
