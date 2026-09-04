// Package cmd — --json output support shared by every command.
//
// Convention: stdout carries command results only; prompts, spinners,
// progress bars and warnings always go to stderr. With --json, results are
// encoded as JSON on stdout and errors as {"error": "..."} on stderr, so a
// script can rely on stdout being valid JSON whenever the exit code is 0.
//
// The JSON view types below are CLI-only. They are deliberately separate
// from the internal/service result structs, which are marshalled as-is by
// the MCP server: tagging those would change the MCP output.
package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
)

// jsonOutput is bound to the --json persistent flag on rootCmd.
var jsonOutput bool

// errJSONNeedsYes is returned by commands that would prompt for confirmation
// when --json is set without --yes.
var errJSONNeedsYes = errors.New("--yes is required for this command when --json is set")

// printJSON writes v as indented JSON on stdout.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(v)
}

// printError writes err on stderr, as {"error": "..."} when --json is set.
func printError(err error) {
	if !jsonOutput {
		fmt.Fprintln(os.Stderr, err)

		return
	}
	b, mErr := json.Marshal(struct {
		Error string `json:"error"`
	}{err.Error()})
	if mErr != nil {
		fmt.Fprintln(os.Stderr, err)

		return
	}
	fmt.Fprintln(os.Stderr, string(b))
}

// confirm asks the user to confirm prompt on stderr and returns true when
// they answer y. It returns true without prompting when yes is set. When
// --json is set and yes is not, it returns an error instead of prompting: a
// script consuming JSON on stdout has no good way to answer interactively.
func confirm(prompt string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if jsonOutput {
		return false, errJSONNeedsYes
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(os.Stderr)

	return strings.ToLower(strings.TrimSpace(answer)) == "y", nil
}

// — Generic views ——————————————————————————————————————————————————————————————

// pagedJSON is the JSON shape of every paginated listing.
type pagedJSON[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
	Page  int `json:"page"`
	Pages int `json:"pages"`
}

// newPagedJSON builds a pagedJSON, never leaving items nil (→ [] not null).
func newPagedJSON[T any](items []T, total, page, pages int) pagedJSON[T] {
	if items == nil {
		items = []T{}
	}

	return pagedJSON[T]{Items: items, Total: total, Page: page, Pages: pages}
}

// itemsJSON is the JSON shape of a listing that was fully paged in.
type itemsJSON[T any] struct {
	Items []T `json:"items"`
}

func newItemsJSON[T any](items []T) itemsJSON[T] {
	return itemsJSON[T]{Items: nonNil(items)}
}

// nonNil returns s, or an empty slice when s is nil (→ [] not null).
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}

	return s
}

// idStatusJSON acknowledges a state change on a single resource.
type idStatusJSON struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// — Auth / version ——————————————————————————————————————————————————————————————

type authLoginJSON struct {
	Authenticated bool   `json:"authenticated"`
	OfflineToken  string `json:"offline_token,omitempty"`
}

type authStatusJSON struct {
	Authenticated bool       `json:"authenticated"`
	Offline       bool       `json:"offline"`
	Refreshed     bool       `json:"refreshed"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Reason        string     `json:"reason,omitempty"`
}

type versionJSON struct {
	Version   string `json:"version"`
	BuildMode string `json:"build_mode"`
}

// — Transfers ————————————————————————————————————————————————————————————————————

type transferFileJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	MIMEType   string `json:"mime_type"`
	Size       int64  `json:"size"`
	ChunkCount int    `json:"chunk_count"`
}

type transferInfoJSON struct {
	Details *api.TransferDetails `json:"details"`
	Message string               `json:"message"`
	Files   []transferFileJSON   `json:"files"`
}

func newTransferInfoJSON(r *service.TransferInfoResult) transferInfoJSON {
	files := make([]transferFileJSON, 0, len(r.Files))
	for _, f := range r.Files {
		files = append(files, transferFileJSON{f.ID, f.Name, f.MIMEType, f.Size, f.ChunkCount})
	}

	return transferInfoJSON{Details: r.Details, Message: r.Message, Files: files}
}

type transferCreateJSON struct {
	ID         string `json:"id"`
	WebURL     string `json:"web_url"`
	Passphrase string `json:"passphrase,omitempty"`
}

// downloadJSON is the result of a download into a local directory.
type downloadJSON struct {
	OutputDir string   `json:"output_dir"`
	Files     []string `json:"files"`
}

// — Datarooms ————————————————————————————————————————————————————————————————————

type dataroomNodeJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	MIMEType   string `json:"mime_type,omitempty"`
	Size       int64  `json:"size"`
	VersionID  string `json:"version_id,omitempty"`
	ChunkCount int    `json:"chunk_count"`
}

func newDataroomNodesJSON(nodes []service.DataroomNodeInfo) []dataroomNodeJSON {
	out := make([]dataroomNodeJSON, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, dataroomNodeJSON{n.ID, n.Name, n.Type, n.MIMEType, n.Size, n.VersionID, n.ChunkCount})
	}

	return out
}

type dataroomCreateJSON struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type dataroomInfoJSON struct {
	Dataroom *api.Dataroom      `json:"dataroom"`
	Stats    *api.DataroomStats `json:"stats,omitempty"`
	Users    []api.DataroomUser `json:"users"`
}

// — Admin ————————————————————————————————————————————————————————————————————————

type adminOrgInfoJSON struct {
	Organization *api.AdminOrganization `json:"organization"`
	Quota        *api.AdminQuota        `json:"quota"`
}

type adminDataroomInfoJSON struct {
	Dataroom              *api.AdminDataroom      `json:"dataroom"`
	Users                 []api.AdminDataroomUser `json:"users"`
	OrganizationKeyAccess string                  `json:"organization_key_access"`
}

type adminNodeJSON struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Name          string `json:"name"`
	IsFolder      bool   `json:"is_folder"`
	Size          int64  `json:"size"`
	ChunkCount    int    `json:"chunk_count"`
	VersionNumber int    `json:"version_number"`
	HasContent    bool   `json:"has_content"`
}

func newAdminNodesJSON(nodes []service.AdminNodeInfo) []adminNodeJSON {
	out := make([]adminNodeJSON, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, adminNodeJSON{
			n.ID, n.Path, n.Name, n.IsFolder, n.Size, n.ChunkCount, n.VersionNumber, n.HasContent,
		})
	}

	return out
}

type adminDownloadJSON struct {
	OutputDir       string   `json:"output_dir"`
	Downloaded      []string `json:"downloaded"`
	SkippedFolders  []string `json:"skipped_folders"`
	SkippedExisting []string `json:"skipped_existing"`
}

type rekeyJSON struct {
	Reencrypted int      `json:"reencrypted"`
	Skipped     []string `json:"skipped"`
}

func newRekeyJSON(r *service.AdminRekeyResult) rekeyJSON {
	return rekeyJSON{Reencrypted: r.Reencrypted, Skipped: nonNil(r.Skipped)}
}
