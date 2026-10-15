// Package service contains the business logic shared between the CLI and the MCP server.
package service

import (
	"io/fs"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
)

// ProgressFn is called after each chunk is processed during an upload or download.
// filename is the file being processed, chunkBytes is the plaintext byte count for
// this chunk, and totalSize is the total file size in bytes.
// A nil ProgressFn disables progress reporting.
type ProgressFn func(filename string, chunkBytes int, totalSize int64)

// PassphraseReader returns the user's AGE key passphrase.
// CLI implementation: reads RETYC_KEY_PASSPHRASE env var, then prompts on the terminal.
// MCP implementation: reads RETYC_KEY_PASSPHRASE env var only (no terminal prompt).
type PassphraseReader func() (string, error)

// — Transfer result types ————————————————————————————————————————————————————

// ListTransfersResult holds a paginated list of transfers.
type ListTransfersResult struct {
	Items []api.Transfer
	Total int
	Pages int
	Page  int
}

// TransferFileInfo holds the decrypted metadata of a single file in a transfer.
type TransferFileInfo struct {
	ID         string
	Name       string
	MIMEType   string
	Size       int64
	ChunkCount int
}

// TransferInfoResult holds the decrypted details of a transfer.
type TransferInfoResult struct {
	Details *api.TransferDetails
	Message string
	Files   []TransferFileInfo
}

// SendTransferParams holds the parameters for creating and uploading a new transfer.
type SendTransferParams struct {
	FilePaths          []string
	Title              string
	Message            string
	Passphrase         string
	GeneratePassphrase bool
	ToEmails           []string
	ExpireSecs         int
}

// SendTransferResult holds the result of a successful transfer upload.
type SendTransferResult struct {
	ID         string
	WebURL     string
	Passphrase string
}

// DownloadTransferParams holds the parameters for downloading a transfer.
type DownloadTransferParams struct {
	ShareID    string
	OutputDir  string
	Passphrase string // optional — only needed when the user has no key for this transfer
}

// DownloadTransferResult holds the result of a successful transfer download.
type DownloadTransferResult struct {
	OutputDir string
	Files     []string
}

// — Dataroom result types ————————————————————————————————————————————————————

// ListDataroomsResult holds every dataroom of the user, all pages fetched.
type ListDataroomsResult struct {
	Items []api.Dataroom
	Total int
}

// CreateDataroomResult holds the result of a dataroom creation.
type CreateDataroomResult struct {
	ID    string
	Title string
}

// DataroomInfoResult holds the full metadata of a dataroom.
type DataroomInfoResult struct {
	Dataroom *api.Dataroom
	Stats    *api.DataroomStats
	Users    []api.DataroomUser
}

// DataroomNodeInfo holds the decrypted metadata of a single dataroom node.
type DataroomNodeInfo struct {
	ID         string
	Name       string
	Type       string // "file", "dir" or "symlink"
	MIMEType   string // decrypted MIME type; empty for directories and symlinks
	Size       int64  // a file's size; a symlink's target length, as lstat reports it
	VersionID  string // non-empty for file nodes; the current version's ID
	ChunkCount int    // number of encrypted chunks; used for direct download without GetDataroomNode
	// target is a symlink's decrypted target, "" on files and folders. Kept
	// unexported so the JSON shape emitted by the MCP server does not change;
	// read it through Target.
	target string
	// modTime is the modification time to present: for a file the one its
	// uploader declared, else the current version's creation time; for a
	// folder its creation time (zero on an API that reports none). Kept
	// unexported so the JSON shape emitted by the MCP server does not change;
	// read it through ModTime.
	modTime time.Time
	// mode is the node's POSIX mode when the API stores one, zero otherwise.
	// Unexported for the same reason; read it through Mode.
	mode fs.FileMode
	// modeSet tells that the API stores mode, an explicit 0 included; read
	// it through HasMode.
	modeSet bool
	// parentID is the ID of the folder holding the node, "" for a child of
	// the dataroom root. Unexported for the same reason; read it through
	// ParentID.
	parentID string
	// createdAt is when the node itself was created (zero on an API that
	// reports none), whatever versions it got since. Unexported for the same
	// reason; read it through CreatedAt.
	createdAt time.Time
	// sealed is the encrypted fields of the node as the API answered them,
	// empty when the node does not come from an answer that carries them.
	// Unexported for the same reason; read it through Sealed.
	sealed SealedNode
}

// SealedNode is the encrypted fields of a node exactly as the API sent them:
// what a cache that must not hold a decrypted name keeps in their place (see
// DataroomSession.OpenSealed). A zero NameEnc means there is no sealed form.
type SealedNode struct {
	// NameEnc is the node's name_enc, TargetEnc a symlink's target_enc.
	NameEnc   string
	TargetEnc string
	// MIMETypeID is the row of the dataroom's MIME table a file references,
	// TypeEnc the per-node ciphertext of a file that still carries its own.
	MIMETypeID string
	TypeEnc    string
}

// Sealed returns the encrypted fields of the node as the API answered them,
// the zero value when the route that produced n does not answer the node.
func (n DataroomNodeInfo) Sealed() SealedNode { return n.sealed }

// ParentID returns the ID of the folder holding the node, "" for a child of
// the dataroom root.
func (n DataroomNodeInfo) ParentID() string { return n.parentID }

// CreatedAt returns when the node itself was created, or the zero time when
// the API reports none. For a file it differs from ModTime as soon as the
// file got a second version or a declared modification time.
func (n DataroomNodeInfo) CreatedAt() time.Time { return n.createdAt }

// WithOrigin returns a copy of n carrying parentID as the folder that holds
// it ("" for the dataroom root) and createdAt as its creation time.
func (n DataroomNodeInfo) WithOrigin(parentID string, createdAt time.Time) DataroomNodeInfo {
	n.parentID, n.createdAt = parentID, createdAt

	return n
}

// ModTime returns the node's modification time (see modTime), or the zero
// time when the API reports none.
func (n DataroomNodeInfo) ModTime() time.Time { return n.modTime }

// Target returns a symlink's target as its creator wrote it (relative or
// absolute, resolved by nothing here), "" for a file or a folder.
func (n DataroomNodeInfo) Target() string { return n.target }

// Mode returns the POSIX permission bits stored with the node, or 0 when the
// API stores none (see HasMode): the caller then applies its own default.
func (n DataroomNodeInfo) Mode() fs.FileMode { return n.mode }

// HasMode reports whether the API stores a mode for the node: an explicit
// "0000" is one, and Mode is then 0.
func (n DataroomNodeInfo) HasMode() bool { return n.modeSet || n.mode != 0 }

// WithMode returns a copy of n carrying mode as its POSIX mode, stored even
// when it is 0.
func (n DataroomNodeInfo) WithMode(mode fs.FileMode) DataroomNodeInfo {
	n.mode, n.modeSet = mode, true

	return n
}

// WithModTime returns a copy of n carrying t as its modification time.
func (n DataroomNodeInfo) WithModTime(t time.Time) DataroomNodeInfo {
	n.modTime = t

	return n
}
