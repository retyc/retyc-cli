package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// AdminExportParams configures a full organization export.
type AdminExportParams struct {
	OutputDir  string
	CLIVersion string
}

// AdminExportSkipped records a dataroom left out of the export and why.
type AdminExportSkipped struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// AdminExportManifest is written to export.json at the end of the export.
type AdminExportManifest struct {
	ExportedAt        time.Time            `json:"exported_at"`
	CLIVersion        string               `json:"cli_version"`
	OrganizationID    string               `json:"organization_id"`
	Members           int                  `json:"members"`
	BlacklistDomains  int                  `json:"blacklist_domains"`
	Datarooms         int                  `json:"datarooms"`
	DataroomsExported int                  `json:"datarooms_exported"`
	DataroomsSkipped  []AdminExportSkipped `json:"datarooms_skipped,omitempty"`
	Errors            []string             `json:"errors,omitempty"`
	Limitations       []string             `json:"limitations"`
}

// AdminExportDataroomMeta is written to datarooms/{id}/meta.json: the
// dataroom metadata in clear text, its users, and whether the content could
// be decrypted with the organization key.
type AdminExportDataroomMeta struct {
	ID               string                  `json:"id"`
	Title            string                  `json:"title"`
	Status           string                  `json:"status"`
	OwnerID          string                  `json:"owner_id"`
	OwnerEmail       string                  `json:"owner_email"`
	SessionPublicKey string                  `json:"session_public_key"`
	CreatedAt        time.Time               `json:"created_at"`
	ExpiresAt        *time.Time              `json:"expires_at,omitempty"`
	DeletedAt        *time.Time              `json:"deleted_at,omitempty"`
	Exportable       bool                    `json:"exportable"`
	Reason           string                  `json:"reason,omitempty"`
	Users            []api.AdminDataroomUser `json:"users"`
}

// AdminExportMessage is one activity entry as written to messages/N.json:
// the raw API message plus, for chat messages the session key could open,
// the decrypted content. ContentEnc is always preserved as received.
type AdminExportMessage struct {
	api.AdminDataroomMessage
	Content *string `json:"content,omitempty"`
}

// AdminExportResult is returned by AdminExportAll.
type AdminExportResult struct {
	Manifest AdminExportManifest
}

// adminExportOrganization is the shape of organization.json.
type adminExportOrganization struct {
	Organization *api.AdminOrganization `json:"organization"`
	Quota        *api.AdminQuota        `json:"quota"`
}

// ensureExportDir accepts a missing path (created 0700) or an existing empty
// directory, and refuses anything else: an export never overwrites data.
func ensureExportDir(path string) error {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(path, 0o700)
	case err != nil:
		return fmt.Errorf("checking output directory: %w", err)
	case !info.IsDir():
		return fmt.Errorf("output path %s is not a directory", path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("reading output directory: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("output directory %s is not empty: refusing to overwrite", path)
	}

	return nil
}

// writeJSONFile writes v as indented JSON with 0600 permissions.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}

// buildDataroomMeta assembles the meta.json content for one dataroom.
func buildDataroomMeta(
	dr *api.AdminDataroom, users []api.AdminDataroomUser, exportable bool, reason string,
) AdminExportDataroomMeta {
	return AdminExportDataroomMeta{
		ID:               dr.ID,
		Title:            dr.Title,
		Status:           dr.Status,
		OwnerID:          dr.OwnerID,
		OwnerEmail:       dr.OwnerEmail,
		SessionPublicKey: dr.SessionPublicKey,
		CreatedAt:        dr.CreatedAt,
		ExpiresAt:        dr.ExpiresAt,
		DeletedAt:        dr.DeletedAt,
		Exportable:       exportable,
		Reason:           reason,
		Users:            users,
	}
}

// decorateMessages wraps raw activity messages, decrypting chat content with
// identity when possible. A nil identity or a failed decryption leaves the
// message as received, content_enc intact.
func decorateMessages(msgs []api.AdminDataroomMessage, identity age.Identity) []AdminExportMessage {
	out := make([]AdminExportMessage, 0, len(msgs))
	for _, m := range msgs {
		em := AdminExportMessage{AdminDataroomMessage: m}
		if identity != nil && m.MessageType == "chat" && m.ContentEnc != nil {
			if content, err := crypto.DecryptToString(*m.ContentEnc, identity); err == nil {
				em.Content = &content
			}
		}
		out = append(out, em)
	}

	return out
}

// exportDataroomMessages writes the activity feed of a dataroom as one JSON
// file per API page (messages/0.json, 1.json, ...), chat content decrypted
// when identity allows. Batches are kept as served: no merging.
func exportDataroomMessages(
	ctx context.Context, client *api.Client, dataroomID, dir string, identity age.Identity,
) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating messages directory: %w", err)
	}
	for page := 1; ; page++ {
		p, err := client.AdminListDataroomMessages(ctx, dataroomID, page)
		if err != nil {
			return fmt.Errorf("listing messages page %d: %w", page, err)
		}
		if err := writeJSONFile(
			filepath.Join(dir, fmt.Sprintf("%d.json", page-1)), decorateMessages(p.Items, identity),
		); err != nil {
			return err
		}
		if page >= p.Pages {
			return nil
		}
	}
}

// exportDataroom writes meta.json, messages/ and (when the organization key opens
// the session key) the decrypted data/ tree for one dataroom.
// It returns whether the content was exported and the skip reason otherwise.
func exportDataroom(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity,
	dr *api.AdminDataroom, dir string, progress ProgressFn,
) (exported bool, reason string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, "", fmt.Errorf("creating dataroom directory: %w", err)
	}

	users, err := client.AdminListDataroomUsers(ctx, dr.ID)
	if err != nil {
		return false, "", fmt.Errorf("listing users: %w", err)
	}

	sess, sessErr := ResolveAdminDataroomSession(ctx, client, orgKey, dr.ID)
	exportable := sessErr == nil
	if !exportable {
		reason = sessErr.Error()
	}

	if err := writeJSONFile(filepath.Join(dir, "meta.json"),
		buildDataroomMeta(dr, users, exportable, reason)); err != nil {
		return false, reason, err
	}

	var identity age.Identity
	if exportable {
		identity = sess.Identity
	}
	if err := exportDataroomMessages(ctx, client, dr.ID, filepath.Join(dir, "messages"), identity); err != nil {
		return false, reason, err
	}

	if !exportable {
		return false, reason, nil
	}

	if _, err := AdminDownloadNodes(ctx, client, orgKey, dr.ID, "", filepath.Join(dir, "data"), progress); err != nil {
		return false, "", fmt.Errorf("downloading content: %w", err)
	}

	return true, "", nil
}

// AdminExportAll exports the whole organization into outputDir: organization
// and quota, members with their identity details, blacklisted domains, and
// every dataroom (metadata, activity feed, and decrypted content when the
// organization key allows). Transfers are not covered: the admin API exposes no
// file download for them. A dataroom failure is recorded in the manifest and
// the export continues; the caller decides how to surface manifest errors.
func AdminExportAll(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity,
	params AdminExportParams, progress ProgressFn, logf func(format string, args ...any),
) (*AdminExportResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := ensureExportDir(params.OutputDir); err != nil {
		return nil, err
	}

	manifest := AdminExportManifest{
		ExportedAt: time.Now().UTC(),
		CLIVersion: params.CLIVersion,
		Limitations: []string{
			"transfers are not exported: the admin API exposes no transfer file download",
		},
	}

	org, err := client.AdminGetOrganization(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching organization: %w", err)
	}
	quota, err := client.AdminGetQuota(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching quota: %w", err)
	}
	manifest.OrganizationID = org.ID
	if err := writeJSONFile(filepath.Join(params.OutputDir, "organization.json"),
		adminExportOrganization{Organization: org, Quota: quota}); err != nil {
		return nil, err
	}

	members, err := exportMembers(ctx, client, params.OutputDir)
	if err != nil {
		return nil, err
	}
	manifest.Members = members
	logf("Exported %d member(s)", members)

	domains, err := api.GetAllAdminPages[api.AdminDomain](ctx, client, func(page int) string {
		return fmt.Sprintf("/organization/blacklist-domains?page=%d&size=100", page)
	})
	if err != nil {
		return nil, fmt.Errorf("listing blacklist domains: %w", err)
	}
	if err := writeJSONFile(filepath.Join(params.OutputDir, "blacklist_domains.json"), domains); err != nil {
		return nil, err
	}
	manifest.BlacklistDomains = len(domains)

	datarooms, err := api.GetAllAdminPages[api.AdminDataroom](ctx, client, func(page int) string {
		return fmt.Sprintf("/dataroom?page=%d&size=100", page)
	})
	if err != nil {
		return nil, fmt.Errorf("listing datarooms: %w", err)
	}
	manifest.Datarooms = len(datarooms)

	for i := range datarooms {
		dr := &datarooms[i]
		logf("Dataroom %s (%s)…", dr.Title, dr.ID)
		dir := filepath.Join(params.OutputDir, "datarooms", dr.ID)
		exported, reason, err := exportDataroom(ctx, client, orgKey, dr, dir, progress)
		switch {
		case err != nil:
			// Record and keep going: a partial reversibility export beats an
			// aborted one, and the manifest keeps the failure visible.
			manifest.Errors = append(manifest.Errors, fmt.Sprintf("dataroom %s (%s): %v", dr.ID, dr.Title, err))
			logf("  ERROR: %v", err)
		case exported:
			manifest.DataroomsExported++
		default:
			manifest.DataroomsSkipped = append(manifest.DataroomsSkipped,
				AdminExportSkipped{ID: dr.ID, Title: dr.Title, Reason: reason})
			logf("  skipped: %s", reason)
		}
	}

	if err := writeJSONFile(filepath.Join(params.OutputDir, "export.json"), manifest); err != nil {
		return nil, err
	}

	return &AdminExportResult{Manifest: manifest}, nil
}

// exportMembers writes members.json (list merged with per-member identity
// details) and returns the member count.
func exportMembers(ctx context.Context, client *api.Client, outputDir string) (int, error) {
	var details []api.AdminMemberDetail
	for page := 1; ; page++ {
		p, err := client.AdminListMembers(ctx, "", true, page)
		if err != nil {
			return 0, fmt.Errorf("listing members: %w", err)
		}
		for _, m := range p.Items {
			d, err := client.AdminGetMember(ctx, m.ID)
			if err != nil {
				return 0, fmt.Errorf("fetching member %s: %w", m.ID, err)
			}
			details = append(details, *d)
		}
		if page >= p.Pages {
			break
		}
	}
	if err := writeJSONFile(filepath.Join(outputDir, "members.json"), details); err != nil {
		return 0, err
	}

	return len(details), nil
}
