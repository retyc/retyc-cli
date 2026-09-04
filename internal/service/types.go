// Package service contains the business logic shared between the CLI and the MCP server.
package service

import (
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

// ListDataroomsResult holds a paginated list of datarooms.
type ListDataroomsResult struct {
	Items []api.Dataroom
	Total int
	Pages int
	Page  int
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
	Type       string // "file" or "dir"
	MIMEType   string // decrypted MIME type; empty for directories
	Size       int64
	VersionID  string // non-empty for file nodes; the current version's ID
	ChunkCount int    // number of encrypted chunks; used for direct download without GetDataroomNode
	// modTime is the current version's creation time (zero for folders). Kept
	// unexported so the JSON shape emitted by the MCP server does not change;
	// read it through ModTime.
	modTime time.Time
}

// ModTime returns the current version's creation time, or the zero time for
// folders and versionless nodes.
func (n DataroomNodeInfo) ModTime() time.Time { return n.modTime }

// WithModTime returns a copy of n carrying t as its modification time.
func (n DataroomNodeInfo) WithModTime(t time.Time) DataroomNodeInfo {
	n.modTime = t

	return n
}
