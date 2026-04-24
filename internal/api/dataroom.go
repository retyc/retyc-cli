// Package api — dataroom-related types and API methods.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Dataroom represents a dataroom returned by the API.
type Dataroom struct {
	ID                   string    `json:"id"`
	Title                string    `json:"title"`
	SessionPublicKey     string    `json:"session_public_key"`
	SessionPrivateKeyEnc string    `json:"session_private_key_enc"`
	// NodeNameSaltEnc is an armored AGE ciphertext (session key) containing
	// the per-dataroom salt used as prefix for node name hashing. Nil when not set.
	NodeNameSaltEnc *string   `json:"node_name_salt_enc"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// DataroomPage is a paginated list of datarooms.
type DataroomPage struct {
	Items []Dataroom `json:"items"`
	Total int        `json:"total"`
	Page  int        `json:"page"`
	Pages int        `json:"pages"`
}

// DataroomStats holds aggregate statistics for a dataroom.
type DataroomStats struct {
	FilesCount         int   `json:"files_count"`
	VersionsCount      int   `json:"versions_count"`
	FilesEncryptedSize int64 `json:"files_encrypted_size"`
}

// DataroomUser is a member of a dataroom with their role and encryption keys.
type DataroomUser struct {
	UserID           string  `json:"user_id"`
	UserEmail        string  `json:"user_email"`
	UserFullName     string  `json:"user_full_name"`
	Role             string  `json:"role"`
	PublicKey        string  `json:"public_key"`
	CurrentPublicKey *string `json:"current_public_key"`
}

// DataroomNodeVersion is a specific version of a file node.
// Note: type_enc is a request-only field (NodeVersionCreateRequest); it is not
// returned by the API and therefore not present in this response struct.
type DataroomNodeVersion struct {
	ID           string    `json:"id"`
	NodeID       string    `json:"node_id"`
	OriginalSize int64     `json:"original_size"`
	ChunkCount   int       `json:"chunk_count"`
	CreatedAt    time.Time `json:"created_at"`
}

// DataroomNode is a node (file or directory) in a dataroom.
// TypeEnc is nil for directories, non-nil for files.
type DataroomNode struct {
	ID       string  `json:"id"`
	NameEnc  string  `json:"name_enc"`
	TypeEnc  *string `json:"type_enc"`
	ParentID *string `json:"parent_id"`
}

// DataroomNodeCreateResponse is the response from POST /dataroom/{id}/node.
type DataroomNodeCreateResponse struct {
	ID      string `json:"id"`
	NameEnc string `json:"name_enc"`
}

// DataroomNodeItem combines a node with its current version (nil for directories).
type DataroomNodeItem struct {
	Node    DataroomNode         `json:"node"`
	Version *DataroomNodeVersion `json:"node_version"`
}

// DataroomNodePage is a paginated list of node items.
type DataroomNodePage struct {
	Items []DataroomNodeItem `json:"items"`
	Total int                `json:"total"`
	Pages int                `json:"pages"`
	Page  int                `json:"page"`
}

// ListDatarooms returns a paginated list of datarooms.
func (c *Client) ListDatarooms(ctx context.Context, page int) (*DataroomPage, error) {
	var result DataroomPage
	if err := c.Get(ctx, fmt.Sprintf("/dataroom/?page=%d", page), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDataroom fetches a single dataroom by its ID.
func (c *Client) GetDataroom(ctx context.Context, dataroomID string) (*Dataroom, error) {
	var result Dataroom
	if err := c.Get(ctx, "/dataroom/"+dataroomID, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDataroomStats fetches aggregate statistics for a dataroom.
func (c *Client) GetDataroomStats(ctx context.Context, dataroomID string) (*DataroomStats, error) {
	var result DataroomStats
	if err := c.Get(ctx, "/dataroom/"+dataroomID+"/stats", &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDataroomUsers returns all members of a dataroom.
func (c *Client) GetDataroomUsers(ctx context.Context, dataroomID string) ([]DataroomUser, error) {
	var result []DataroomUser
	if err := c.Get(ctx, "/dataroom/"+dataroomID+"/users", &result); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateDataroom creates a new dataroom with the given title, session keypair, and
// optionally an encrypted name salt (nodeNameSaltEnc). Pass nil to omit the salt.
func (c *Client) CreateDataroom(
	ctx context.Context, title, sessionPrivKeyEnc, sessionPubKey string, nodeNameSaltEnc *string,
) (*Dataroom, error) {
	body := map[string]any{
		"title":                   title,
		"session_private_key_enc": sessionPrivKeyEnc,
		"session_public_key":      sessionPubKey,
		"node_name_salt_enc":      nodeNameSaltEnc,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result Dataroom
	if err := c.Post(ctx, "/dataroom/", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteDataroom permanently removes a dataroom and all its contents.
func (c *Client) DeleteDataroom(ctx context.Context, dataroomID string) error {
	return c.Delete(ctx, "/dataroom/"+dataroomID)
}

// AddDataroomUser adds a user to a dataroom with the given role.
func (c *Client) AddDataroomUser(ctx context.Context, dataroomID, email, role string) (*DataroomUser, error) {
	body := map[string]any{
		"user_email": email,
		"role":       role,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result DataroomUser
	if err := c.Post(ctx, "/dataroom/"+dataroomID+"/users", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// RemoveDataroomUser removes a user from a dataroom.
func (c *Client) RemoveDataroomUser(ctx context.Context, dataroomID, userID string) error {
	return c.Delete(ctx, "/dataroom/"+dataroomID+"/user/"+userID)
}

// RekeyDataroom re-encrypts the session private key for all current members.
// Call this after adding or removing a user to update their access.
func (c *Client) RekeyDataroom(ctx context.Context, dataroomID, sessionPrivKeyEnc string) error {
	body := map[string]any{
		"session_private_key_enc": sessionPrivKeyEnc,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	return c.Put(ctx, "/dataroom/"+dataroomID+"/users/rekey", bytes.NewReader(data), nil)
}

// ListDataroomNodes returns a paginated list of nodes in a dataroom folder.
// parentID nil lists the root; non-nil lists children of the given folder.
func (c *Client) ListDataroomNodes(
	ctx context.Context, dataroomID string, parentID *string, page, size int,
) (*DataroomNodePage, error) {
	path := fmt.Sprintf("/dataroom/%s/nodes?page=%d&size=%d", dataroomID, page, size)
	if parentID != nil {
		path += "&parent_id=" + *parentID
	}
	var result DataroomNodePage
	if err := c.Get(ctx, path, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDataroomNode fetches a single node and its current version by node ID.
func (c *Client) GetDataroomNode(ctx context.Context, nodeID string) (*DataroomNodeItem, error) {
	var result DataroomNodeItem
	if err := c.Get(ctx, "/dataroom/node/"+nodeID, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateDataroomNode creates a new node (file or directory) in a dataroom.
// typeEnc nil creates a directory; non-nil creates a file node.
func (c *Client) CreateDataroomNode(
	ctx context.Context,
	dataroomID, nameEnc, nameHash string,
	typeEnc *string,
	parentID *string,
) (*DataroomNodeCreateResponse, error) {
	body := map[string]any{
		"name_enc":  nameEnc,
		"name_hash": nameHash,
		"type_enc":  typeEnc,
		"parent_id": parentID,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result DataroomNodeCreateResponse
	if err := c.Post(ctx, "/dataroom/"+dataroomID+"/node", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateDataroomNode renames or moves a node.
func (c *Client) UpdateDataroomNode(ctx context.Context, nodeID, nameEnc, nameHash string, parentID *string) error {
	body := map[string]any{
		"name_enc":  nameEnc,
		"name_hash": nameHash,
		"parent_id": parentID,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	return c.Put(ctx, "/dataroom/node/"+nodeID, bytes.NewReader(data), nil)
}

// DeleteDataroomNode permanently removes a node and all its versions.
func (c *Client) DeleteDataroomNode(ctx context.Context, nodeID string) error {
	return c.Delete(ctx, "/dataroom/node/"+nodeID)
}

// CreateDataroomNodeVersion creates a new version for a file node.
func (c *Client) CreateDataroomNodeVersion(
	ctx context.Context, nodeID string, originalSize int64, typeEnc string,
) (*DataroomNodeVersion, error) {
	body := map[string]any{
		"original_size": originalSize,
		"type_enc":      typeEnc,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result DataroomNodeVersion
	if err := c.Post(ctx, "/dataroom/node/"+nodeID+"/version", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// UploadDataroomChunk uploads a single encrypted chunk for a node version.
func (c *Client) UploadDataroomChunk(ctx context.Context, versionID string, chunkID int, data []byte) error {
	path := fmt.Sprintf("/dataroom/node/version/%s/chunk/%d", versionID, chunkID)

	return c.PostMultipartChunk(ctx, path, data)
}

// DownloadDataroomChunk downloads a single encrypted chunk from a node version.
func (c *Client) DownloadDataroomChunk(ctx context.Context, versionID string, chunkID int) ([]byte, error) {
	path := fmt.Sprintf("/dataroom/node/version/%s/chunk/%d", versionID, chunkID)

	return c.GetBytes(ctx, path)
}
