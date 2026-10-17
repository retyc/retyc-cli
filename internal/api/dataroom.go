// Package api — dataroom-related types and API methods.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Dataroom represents a dataroom returned by the API.
type Dataroom struct {
	ID                   string `json:"id"`
	Title                string `json:"title"`
	SessionPublicKey     string `json:"session_public_key"`
	SessionPrivateKeyEnc string `json:"session_private_key_enc"`
	// NodeNameSaltEnc is an armored AGE ciphertext (session key) containing
	// the per-dataroom salt used as prefix for node name hashing. Nil when not set.
	NodeNameSaltEnc *string   `json:"node_name_salt_enc"`
	CreatedAt       time.Time `json:"created_at"`
	// ExpiresAt and DeletedAt are nil when the dataroom has no expiry or is
	// not deleted.
	ExpiresAt *time.Time `json:"expires_at"`
	DeletedAt *time.Time `json:"deleted_at"`
	// Role is the current user's role: owner, admin, editor, contributor or
	// viewer. Empty on an API that predates the field.
	Role string `json:"role,omitempty"`
	// Status is active, expired or deleted.
	Status string `json:"status,omitempty"`
	// Revision is bumped by every change a listing shows; the node listings
	// answer it as their ETag.
	Revision int64 `json:"revision"`
	// Label is the organization label attached to the dataroom, nil when none.
	Label *DataroomLabel `json:"label"`
	// VersioningEnabled is false when the dataroom keeps a single complete
	// version per file: every upload replaces the previous one, purged at
	// once. Nil when the API predates the setting (versioning on).
	VersioningEnabled *bool `json:"versioning_enabled,omitempty"`
	// StorageCapacity is the reserved capacity in bytes (thick provisioning),
	// nil when the dataroom draws on its owner's plan instead.
	StorageCapacity *int64 `json:"storage_capacity,omitempty"`
	StorageUsed     int64  `json:"storage_used"`
	// Writable is false when the plan of the dataroom's owner refuses writes.
	// Only the detail (GET /dataroom/{id}) reports it: nil in the list, and on
	// an API that predates it. Read it through CanWrite.
	Writable *bool `json:"writable,omitempty"`
}

// DataroomLabel is the public shape of an organization label.
type DataroomLabel struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Color       string  `json:"color"`
	Description *string `json:"description"`
}

// RoleViewer is the role that may read a dataroom and change nothing in it.
const RoleViewer = "viewer"

// CanWrite reports whether the owner's plan allows writes: true unless the
// API says otherwise, so an API that does not tell refuses nothing.
func (d *Dataroom) CanWrite() bool {
	return d.Writable == nil || *d.Writable
}

// Versioning reports whether the dataroom keeps every version of a file.
func (d *Dataroom) Versioning() bool {
	return d.VersioningEnabled == nil || *d.VersioningEnabled
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
	// AllowedStorageSize is what is left of the owner's plan, in bytes; negative
	// when the plan is exceeded.
	AllowedStorageSize int64 `json:"allowed_storage_size,omitempty"`
	// StorageCapacity is the reserved capacity in bytes, nil when the dataroom
	// is bounded by the owner's plan instead (see Dataroom.StorageCapacity).
	StorageCapacity *int64 `json:"storage_capacity,omitempty"`
	// StorageUsed counts every stored version, including those pending purge.
	// Nil on an API that predates the storage counters.
	StorageUsed *int64 `json:"storage_used,omitempty"`
	// StorageFree is capacity minus used, or the owner's plan remainder when
	// unbounded; never negative.
	StorageFree int64 `json:"storage_free,omitempty"`
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
// Note: the MIME fields are request-only (NodeVersionCreateRequest); they are
// not returned by the API and therefore not present in this response struct.
type DataroomNodeVersion struct {
	ID           string `json:"id"`
	NodeID       string `json:"node_id"`
	OriginalSize int64  `json:"original_size"`
	ChunkCount   int    `json:"chunk_count"`
	// ChunkCountExpected is the count announced at creation; a version whose
	// ChunkCount is below it is still being uploaded (or copied). Nil on an
	// API that does not report it.
	ChunkCountExpected *int `json:"chunk_count_expected,omitempty"`
	// VersionNumber is 1 for the version that created the node.
	VersionNumber int       `json:"version_number,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	// ClientMtime is the modification time the uploading client declared, nil
	// when it declared none: CreatedAt is then the best available timestamp.
	ClientMtime *time.Time `json:"client_mtime,omitempty"`
	// CopiedFromVersionID is set on a version made by a server-side copy.
	CopiedFromVersionID *string `json:"copied_from_version_id,omitempty"`
}

// ModTime returns the modification time to present for the version: the
// client-declared one when there is one, its creation time otherwise.
func (v *DataroomNodeVersion) ModTime() time.Time {
	if v.ClientMtime != nil {
		return *v.ClientMtime
	}

	return v.CreatedAt
}

// Complete reports whether every announced chunk has been stored. A version
// from an API that does not report chunk_count_expected is taken as complete.
func (v *DataroomNodeVersion) Complete() bool {
	return v.ChunkCountExpected == nil || v.ChunkCount >= *v.ChunkCountExpected
}

// Node types reported in DataroomNode.Type.
const (
	NodeTypeFile   = "file"
	NodeTypeFolder = "folder"
	// NodeTypeSymlink is a POSIX symbolic link: no version, no MIME type, its
	// target in TargetEnc. Created through POST /dataroom/{id}/node/symlink.
	NodeTypeSymlink = "symlink"
)

// DataroomNode is a node (file, folder or symlink) in a dataroom.
//
// Type tells the kinds apart. It is empty on an API that predates it, where a
// nil TypeEnc meant a folder; IsFolder, IsFile and IsSymlink cover both. A
// file's MIME type is either a row of the dataroom's MIME table (MimeTypeID)
// or, on a file not migrated to it yet, the legacy per-node ciphertext TypeEnc.
type DataroomNode struct {
	ID         string  `json:"id"`
	Type       string  `json:"type,omitempty"`
	NameEnc    string  `json:"name_enc"`
	NameHash   string  `json:"name_hash,omitempty"`
	TypeEnc    *string `json:"type_enc"`
	MimeTypeID *string `json:"mime_type_id,omitempty"`
	// TargetEnc is a symlink's target, encrypted for the session key and never
	// read by the server; nil on files and folders.
	TargetEnc *string `json:"target_enc,omitempty"`
	// AccessMode is the POSIX mode as an octal string ("0644"), empty on an
	// API that does not store one; see ParseAccessMode.
	AccessMode string    `json:"access_mode,omitempty"`
	ParentID   *string   `json:"parent_id"`
	CreatedAt  time.Time `json:"created_at,omitzero"`
}

// IsFolder reports whether the node is a folder: by its type when the API
// reports one, by the absence of a MIME ciphertext on an older API.
func (n *DataroomNode) IsFolder() bool {
	if n.Type != "" {
		return n.Type == NodeTypeFolder
	}

	return n.TypeEnc == nil
}

// IsSymlink reports whether the node is a symbolic link. An API without the
// type field has none.
func (n *DataroomNode) IsSymlink() bool {
	return n.Type == NodeTypeSymlink
}

// IsFile reports whether the node is a regular file: the kind that carries
// versions, and the only one an upload may add a version to.
func (n *DataroomNode) IsFile() bool {
	return !n.IsFolder() && !n.IsSymlink()
}

// POSIX special bits, which Go's fs.FileMode keeps apart from the permission
// bits (fs.ModeSetuid and friends) while the API stores the raw octal value.
const (
	posixSetuid = 0o4000
	posixSetgid = 0o2000
	posixSticky = 0o1000
)

// ParseAccessMode parses the octal mode string of a node ("0644", "0o755",
// up to "7777") into a file mode. An empty or malformed string yields 0, false.
func ParseAccessMode(s string) (fs.FileMode, bool) {
	s = strings.TrimPrefix(s, "0o")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || v > 0o7777 {
		return 0, false
	}
	mode := fs.FileMode(v & 0o777)
	if v&posixSetuid != 0 {
		mode |= fs.ModeSetuid
	}
	if v&posixSetgid != 0 {
		mode |= fs.ModeSetgid
	}
	if v&posixSticky != 0 {
		mode |= fs.ModeSticky
	}

	return mode, true
}

// FormatAccessMode formats the permission and special bits of mode the way
// the API stores them: four octal digits ("0644").
func FormatAccessMode(mode fs.FileMode) string {
	v := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		v |= posixSetuid
	}
	if mode&fs.ModeSetgid != 0 {
		v |= posixSetgid
	}
	if mode&fs.ModeSticky != 0 {
		v |= posixSticky
	}

	return fmt.Sprintf("%04o", v)
}

// DataroomNodeItem combines a node with its current version (nil for directories).
type DataroomNodeItem struct {
	Node    DataroomNode         `json:"node"`
	Version *DataroomNodeVersion `json:"node_version"`
}

// DataroomMimeType is a row of a dataroom's MIME table: the MIME type is
// stored once per dataroom, encrypted for the session key, and file nodes
// reference it by ID. Hash is sha256(salt + type), the same construction as
// name_hash, so a client can tell whether a type is already known before
// sending its ciphertext.
type DataroomMimeType struct {
	ID      string `json:"id"`
	Hash    string `json:"hash"`
	NameEnc string `json:"name_enc"`
}

// NodeMIME is the MIME type of a file node in one of the two forms the API
// accepts: the shared table form (Hash, plus NameEnc when the dataroom may
// not know the hash yet) or the legacy per-node ciphertext (TypeEnc). The two
// forms are exclusive (422 when both are sent).
type NodeMIME struct {
	TypeEnc string
	Hash    string
	NameEnc string
}

// fields adds the MIME form to a request body.
func (m NodeMIME) fields(body map[string]any) {
	switch {
	case m.TypeEnc != "":
		body["type_enc"] = m.TypeEnc
	case m.Hash != "":
		body["mime_hash"] = m.Hash
		if m.NameEnc != "" {
			body["mime_name_enc"] = m.NameEnc
		}
	}
}

// formFields adds the MIME form to a multipart request.
func (m NodeMIME) formFields(fields []formField) []formField {
	switch {
	case m.TypeEnc != "":
		fields = append(fields, formField{"type_enc", m.TypeEnc})
	case m.Hash != "":
		fields = append(fields, formField{"mime_hash", m.Hash})
		if m.NameEnc != "" {
			fields = append(fields, formField{"mime_name_enc", m.NameEnc})
		}
	}

	return fields
}

// Refusal codes of the MIME table as an API without X-Error-Code put them in
// HTTPError.Detail: the fallback of CodeMimeTypeUnknown / CodeMimeTypesLimit,
// read only when the refusal carries no code (the new API no longer puts
// them in the detail).
const (
	// DetailMimeTypeUnknown (422): the hash is not in the table and no
	// ciphertext came with it; resend with NameEnc.
	DetailMimeTypeUnknown = "mime_type_unknown"
	// DetailMimeTypesLimit (400): the dataroom already holds its maximum
	// number of distinct MIME types; fall back to TypeEnc.
	DetailMimeTypesLimit = "mime_types_limit"
)

// DataroomNodePage is a paginated list of node items.
type DataroomNodePage struct {
	Items []DataroomNodeItem `json:"items"`
	Total int                `json:"total"`
	Pages int                `json:"pages"`
	Page  int                `json:"page"`
}

// ListDatarooms returns a paginated list of datarooms.
func (c *Client) ListDatarooms(ctx context.Context, page, size int) (*DataroomPage, error) {
	var result DataroomPage
	if err := c.Get(ctx, fmt.Sprintf("/dataroom?page=%d&size=%d", page, size), &result); err != nil {
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

// UpdateDataroom applies a partial update to a dataroom and returns it as stored.
func (c *Client) UpdateDataroom(ctx context.Context, dataroomID string, u DataroomUpdate) (*Dataroom, error) {
	data, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	var result Dataroom
	if err := c.Patch(ctx, "/dataroom/"+dataroomID, bytes.NewReader(data), &result); err != nil {
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

// DataroomOptions are the dataroom settings a creation or an update may set;
// nil fields are not sent and keep the server default or current value.
type DataroomOptions struct {
	// VersioningEnabled false keeps one complete version per file, the last
	// one written.
	VersioningEnabled *bool `json:"versioning_enabled,omitempty"`
	// StorageCapacity reserves bytes on the owner's plan (thick provisioning).
	// An update can only enlarge it.
	StorageCapacity *int64 `json:"storage_capacity,omitempty"`
}

// DataroomUpdate is a partial dataroom update (PATCH /dataroom/{id}); nil
// fields are not sent.
type DataroomUpdate struct {
	Title *string `json:"title,omitempty"`
	DataroomOptions
}

// CreateDataroom creates a new dataroom with the given title, session keypair, and
// optionally an encrypted name salt (nodeNameSaltEnc). Pass nil to omit the salt.
//
// organizationKey, when not empty, is the organization key the session
// private key was also encrypted for: the API then attaches the
// organization's service account to the dataroom, or answers 409
// MASTER_KEY_MISMATCH when the key is no longer the organization's. Empty, it
// is not sent and nothing is attached.
func (c *Client) CreateDataroom(
	ctx context.Context, title, sessionPrivKeyEnc, sessionPubKey string, nodeNameSaltEnc *string,
	organizationKey string, opts DataroomOptions,
) (*Dataroom, error) {
	body := map[string]any{
		"title":                   title,
		"session_private_key_enc": sessionPrivKeyEnc,
		"session_public_key":      sessionPubKey,
	}
	if nodeNameSaltEnc != nil {
		body["node_name_salt_enc"] = *nodeNameSaltEnc
	}
	if organizationKey != "" {
		body["master_public_key"] = organizationKey
	}
	if opts.VersioningEnabled != nil {
		body["versioning_enabled"] = *opts.VersioningEnabled
	}
	if opts.StorageCapacity != nil {
		body["storage_capacity"] = *opts.StorageCapacity
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result Dataroom
	if err := c.Post(ctx, "/dataroom", bytes.NewReader(data), &result); err != nil {
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
	result, _, err := c.ListDataroomNodesIfChanged(ctx, dataroomID, parentID, page, size, "")

	return result, err
}

// ListDataroomNodesIfChanged is ListDataroomNodes for a caller that holds a
// listing of the dataroom and the ETag it came with: etag, when not empty, is
// sent as If-None-Match, and an unchanged dataroom answers ErrNotModified
// without a page to decrypt. The ETag of the answer is returned, "" on an API
// that sends none.
//
// The ETag is the dataroom's revision, not the folder's: every change a
// listing shows, anywhere in the dataroom, moves it.
func (c *Client) ListDataroomNodesIfChanged(
	ctx context.Context, dataroomID string, parentID *string, page, size int, etag string,
) (*DataroomNodePage, string, error) {
	path := fmt.Sprintf("/dataroom/%s/nodes?page=%d&size=%d", dataroomID, page, size)
	if parentID != nil {
		path += "&parent_id=" + *parentID
	}
	var result DataroomNodePage
	newETag, err := c.getIfNoneMatch(ctx, path, etag, &result)
	if err != nil {
		return nil, "", err
	}

	return &result, newETag, nil
}

// FindDataroomNodeByHash looks a node up by its name hash under parentID (nil
// for the root), through the index that enforces name uniqueness: one request
// whatever the folder's size, no listing to decrypt. It returns nil when no
// node holds the hash, which includes a node pending deletion.
//
// Only an API that supports the lookup may be asked: an older one ignores the
// parameter and answers the folder's first page, whose first item would be
// taken for the match. The caller is responsible for that check (the service
// probes the MIME table route, introduced together with the lookup); the
// returned node's own hash is verified as a last defence.
func (c *Client) FindDataroomNodeByHash(
	ctx context.Context, dataroomID string, parentID *string, nameHash string,
) (*DataroomNodeItem, error) {
	path := "/dataroom/" + dataroomID + "/nodes?name_hash=" + nameHash
	if parentID != nil {
		path += "&parent_id=" + *parentID
	}
	var result DataroomNodePage
	if err := c.Get(ctx, path, &result); err != nil {
		return nil, err
	}
	if len(result.Items) == 0 {
		return nil, nil
	}
	item := result.Items[0]
	if item.Node.NameHash != "" && item.Node.NameHash != nameHash {
		return nil, fmt.Errorf("name hash lookup answered node %s with another hash", item.Node.ID)
	}

	return &item, nil
}

// ListDataroomMimeTypes returns the dataroom's MIME table. It answers 404 on
// an API that predates the table.
func (c *Client) ListDataroomMimeTypes(ctx context.Context, dataroomID string) ([]DataroomMimeType, error) {
	var result []DataroomMimeType
	if err := c.Get(ctx, "/dataroom/"+dataroomID+"/mime-types", &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDataroomNode fetches a single node's metadata by node ID.
// The API returns a flat node (DataroomNodeModel) without any version information;
// use ListDataroomNodes to obtain a node together with its current version.
func (c *Client) GetDataroomNode(ctx context.Context, nodeID string) (*DataroomNode, error) {
	var result DataroomNode
	if err := c.Get(ctx, "/dataroom/node/"+nodeID, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// NodeCreate describes a node to create (POST /dataroom/{id}/node).
type NodeCreate struct {
	ParentID *string // nil for the dataroom root
	NameEnc  string
	NameHash string
	Folder   bool
	MIME     NodeMIME // files only
	// AccessMode is the octal mode string ("0644"); empty for the server
	// default (0644 for a file, 0755 for a folder).
	AccessMode string
}

// CreateDataroomNode creates a new node (file or directory) in a dataroom and
// returns it as stored, MIME row ID included.
//
// The node type is sent both as the explicit type and, for a file in the
// legacy MIME form, as type_enc: an API that predates the type field decides
// file or folder on type_enc alone, and ignores the fields it does not know.
func (c *Client) CreateDataroomNode(ctx context.Context, dataroomID string, p NodeCreate) (*DataroomNode, error) {
	body := map[string]any{
		"name_enc":  p.NameEnc,
		"name_hash": p.NameHash,
		"parent_id": p.ParentID,
		"type":      NodeTypeFile,
	}
	if p.Folder {
		body["type"] = NodeTypeFolder
	} else {
		p.MIME.fields(body)
	}
	if p.AccessMode != "" {
		body["access_mode"] = p.AccessMode
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var result DataroomNode
	if err := c.Post(ctx, "/dataroom/"+dataroomID+"/node", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// SymlinkCreate describes a symbolic link to create
// (POST /dataroom/{id}/node/symlink).
type SymlinkCreate struct {
	ParentID *string // nil for the dataroom root
	NameEnc  string
	NameHash string
	// TargetEnc is the target as the client wrote it, armored AGE for the
	// session key: the server never reads it.
	TargetEnc string
}

// CreateDataroomSymlink creates a symbolic link node and returns it as
// stored (201). The access mode is left to the server (0777, as lstat reports
// a link on Linux). 409 when the name is taken in the folder, 404 when the
// parent is missing, 403 when the user may not create there.
func (c *Client) CreateDataroomSymlink(ctx context.Context, dataroomID string, p SymlinkCreate) (*DataroomNode, error) {
	data, err := json.Marshal(map[string]any{
		"name_enc":   p.NameEnc,
		"name_hash":  p.NameHash,
		"parent_id":  p.ParentID,
		"target_enc": p.TargetEnc,
	})
	if err != nil {
		return nil, err
	}
	var result DataroomNode
	if err := c.Post(ctx, "/dataroom/"+dataroomID+"/node/symlink", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// NodeUpdate describes a change to a node (PUT /dataroom/node/{id}). A field
// left nil is not sent, and the API leaves it as it is; NameEnc and NameHash
// go together. Moving to the root is an explicit null parent_id, hence
// SetParent: a nil ParentID with SetParent false means "do not move".
//
// Replace asks the API to replace a live file holding the target name, in the
// transaction of the rename: the file is deleted with its versions and the
// node takes its name. A folder holding the name answers 409
// REPLACE_TARGET_IS_FOLDER ("Cannot replace a folder" from an API without
// codes), a file the caller may not delete 403 REPLACE_FORBIDDEN.
// It is sent only when true: an API without the field refuses it (422) or,
// older still, ignores it.
type NodeUpdate struct {
	NameEnc    *string
	NameHash   *string
	ParentID   *string
	SetParent  bool
	AccessMode *string
	Replace    bool
}

// UpdateDataroomNode renames, moves or chmods a node.
func (c *Client) UpdateDataroomNode(ctx context.Context, nodeID string, u NodeUpdate) error {
	body := map[string]any{}
	if u.NameEnc != nil {
		body["name_enc"] = *u.NameEnc
	}
	if u.NameHash != nil {
		body["name_hash"] = *u.NameHash
	}
	if u.SetParent {
		body["parent_id"] = u.ParentID
	}
	if u.AccessMode != nil {
		body["access_mode"] = *u.AccessMode
	}
	if u.Replace {
		body["replace"] = true
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	return c.Put(ctx, "/dataroom/node/"+nodeID, bytes.NewReader(data), nil)
}

// RenameDataroomNode renames nodeID and moves it under parentID (nil for the
// dataroom root).
func (c *Client) RenameDataroomNode(ctx context.Context, nodeID, nameEnc, nameHash string, parentID *string) error {
	return c.UpdateDataroomNode(ctx, nodeID, NodeUpdate{
		NameEnc: &nameEnc, NameHash: &nameHash, ParentID: parentID, SetParent: true,
	})
}

// SetDataroomNodeAccessMode changes the POSIX mode of a node (octal string,
// "0755") without creating a version.
func (c *Client) SetDataroomNodeAccessMode(ctx context.Context, nodeID, accessMode string) error {
	return c.UpdateDataroomNode(ctx, nodeID, NodeUpdate{AccessMode: &accessMode})
}

// SetDataroomVersionClientMtime declares the modification time of an existing
// version (PATCH /dataroom/node/version/{id}) without creating a new one.
func (c *Client) SetDataroomVersionClientMtime(ctx context.Context, versionID string, mtime time.Time) error {
	data, err := json.Marshal(map[string]any{"client_mtime": mtime.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}

	return c.Patch(ctx, "/dataroom/node/version/"+versionID, bytes.NewReader(data), nil)
}

// DeleteDataroomNode permanently removes a node and all its versions.
func (c *Client) DeleteDataroomNode(ctx context.Context, nodeID string) error {
	return c.Delete(ctx, "/dataroom/node/"+nodeID)
}

// DeleteDataroomNodeVersion removes a single version of a file node, leaving the
// node and its other versions in place. It requires the can_delete capability
// (privileged roles), like DeleteDataroomNode.
func (c *Client) DeleteDataroomNodeVersion(ctx context.Context, versionID string) error {
	return c.Delete(ctx, "/dataroom/node/version/"+versionID)
}

// VersionCreate describes a version to add to a file node
// (POST /dataroom/node/{id}/version).
type VersionCreate struct {
	OriginalSize int64
	// ChunkCount is announced up front (chunk_count_expected): the API rejects
	// any chunk index outside [0, ChunkCount) with 422, and never lets a chunk
	// already stored be overwritten, so it must match exactly what the upload
	// will send.
	ChunkCount int
	MIME       NodeMIME
	// ClientMtime is the source file's modification time, nil when unknown
	// (a stream without one, e.g. a WebDAV PUT).
	ClientMtime *time.Time
}

// CreateDataroomNodeVersion creates a new version for a file node.
func (c *Client) CreateDataroomNodeVersion(
	ctx context.Context, nodeID string, p VersionCreate,
) (*DataroomNodeVersion, error) {
	body := map[string]any{
		"original_size":        p.OriginalSize,
		"chunk_count_expected": p.ChunkCount,
	}
	p.MIME.fields(body)
	if p.ClientMtime != nil {
		body["client_mtime"] = p.ClientMtime.UTC().Format(time.RFC3339Nano)
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

// FileNodeCreate describes a file to create in a single request, node,
// version and content together (POST /dataroom/{id}/node/file).
type FileNodeCreate struct {
	ParentID     *string // nil for the dataroom root
	NameEnc      string
	NameHash     string
	MIME         NodeMIME
	OriginalSize int64
	// Overwrite makes a file already holding the name get the upload as its
	// next version instead of a 409; a 409 then means a folder holds the
	// name, or it was taken concurrently.
	Overwrite   bool
	AccessMode  string     // octal string, empty for the server default
	ClientMtime *time.Time // nil when unknown
	// Chunk is the whole encrypted content as one chunk, nil for an empty
	// file, so the file must fit in one chunk.
	Chunk []byte
}

// CreateDataroomFileNode creates a file node, its version and its content in a
// single request. The server discards what a failed request created.
func (c *Client) CreateDataroomFileNode(
	ctx context.Context, dataroomID string, p FileNodeCreate,
) (*DataroomNodeItem, error) {
	fields := []formField{
		{"name_enc", p.NameEnc},
		{"name_hash", p.NameHash},
		{"type", NodeTypeFile},
		{"original_size", strconv.FormatInt(p.OriginalSize, 10)},
		{"overwrite", strconv.FormatBool(p.Overwrite)},
	}
	fields = p.MIME.formFields(fields)
	if p.ParentID != nil {
		fields = append(fields, formField{"parent_id", *p.ParentID})
	}
	if p.AccessMode != "" {
		fields = append(fields, formField{"access_mode", p.AccessMode})
	}
	if p.ClientMtime != nil {
		fields = append(fields, formField{"client_mtime", p.ClientMtime.UTC().Format(time.RFC3339Nano)})
	}
	var result DataroomNodeItem
	path := "/dataroom/" + dataroomID + "/node/file?unsafe_write=" + strconv.FormatBool(c.unsafeWrite)
	if err := c.postMultipart(ctx, path, fields, p.Chunk, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// UploadDataroomChunk uploads a single encrypted chunk for a node version.
func (c *Client) UploadDataroomChunk(ctx context.Context, versionID string, chunkID int, data []byte) error {
	path := fmt.Sprintf("/dataroom/node/version/%s/chunk/%d?unsafe_write=%t", versionID, chunkID, c.unsafeWrite)

	return c.PostMultipartChunk(ctx, path, data)
}

// DownloadDataroomChunk downloads a single encrypted chunk from a node version.
func (c *Client) DownloadDataroomChunk(ctx context.Context, versionID string, chunkID int) ([]byte, error) {
	return c.DownloadDataroomChunkLimit(ctx, versionID, chunkID, 0)
}

// DownloadDataroomChunkLimit is DownloadDataroomChunk for a caller that knows
// how large an encrypted chunk may be: a chunk of more than limit bytes is
// refused with ErrChunkTooLarge, before its body is read when the response
// announces its length, and no more than limit bytes are ever held. A limit
// of zero or less is no limit.
func (c *Client) DownloadDataroomChunkLimit(
	ctx context.Context, versionID string, chunkID int, limit int64,
) ([]byte, error) {
	path := fmt.Sprintf("/dataroom/node/version/%s/chunk/%d", versionID, chunkID)

	return c.getChunk(ctx, path, limit)
}

// DataroomChunkEncryptedSize returns the size in bytes of a chunk as stored,
// that is encrypted, without downloading it: a HEAD on the chunk route, whose
// Content-Length is that size. The API reads it from the object store at
// every call and counts the call in its rate limit, and a version never
// changes: callers keep the answer.
//
// A 404 (ErrNotFound) is a version the API does not know or a chunk the store
// does not hold, and is not retried as a download is; a 410 (ErrGone) a
// version pending deletion. An API that predates the route answers 405, and
// the error then matches ErrNoChunkSize, as does a 2xx without a usable
// Content-Length; behind some proxies such an API answers 404, which nothing
// here tells from a missing chunk.
func (c *Client) DataroomChunkEncryptedSize(ctx context.Context, versionID string, chunkID int) (int64, error) {
	path := fmt.Sprintf("/dataroom/node/version/%s/chunk/%d", versionID, chunkID)
	size, err := c.headContentLength(ctx, path)
	var httpErr *HTTPError
	switch {
	case errors.As(err, &httpErr) &&
		(httpErr.Status == http.StatusMethodNotAllowed || httpErr.Status == http.StatusNotImplemented):
		return 0, fmt.Errorf("%w: %w", ErrNoChunkSize, err)
	case err != nil:
		return 0, err
	case size <= 0:
		return 0, fmt.Errorf("%w: Content-Length %d", ErrNoChunkSize, size)
	}

	return size, nil
}
