// Package service contains the business logic shared between the CLI and the MCP server.
package service

import "github.com/retyc/retyc-cli/internal/api"

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
	ID   string
	Name string
	Type string // "file" or "dir"
	Size int64
}
